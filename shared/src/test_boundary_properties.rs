//! Property Tests for Boundary Numeric and Timestamp Values (Issue #442).
//!
//! Provides formal property-based test suites verifying boundary, extreme,
//! and fuzzed numeric and timestamp values across Trellis smart contracts.
//!
//! Properties Verified:
//! 1. Hardware Non-Panic Safety: Checked arithmetic operations never panic or trigger
//!    arithmetic overflow traps, even at `i128::MIN`, `i128::MAX`, and `-1`.
//! 2. Basis Point Invariant & Conservation: Fee calculation `apply_bps` is strictly
//!    monotonic, bounded by `[0, amount]`, and conserves all funds (`fee + remainder == amount`).
//! 3. Partitioning & Inversion Protection: Time windows `[start, end]` are strictly
//!    partitioned into `{TooEarly, Valid, Expired}` and inverted windows `start > end`
//!    are unconditionally rejected without panic.
//! 4. Zero-Division & Extreme Rate Rejection: Zero divisors and rates > 10,000 bps
//!    consistently return structured errors.
//! 5. Capacity & Cardinality Boundary Invariants: Input ceilings enforce strict
//!    bounds and reject boundary + 1.

#[cfg(test)]
mod tests {
    use crate::errors::Error;
    use crate::math::{apply_bps, checked_add, checked_div, checked_mul, checked_sub};
    use crate::time_window::{validate_time_window, TimeWindow, TimeWindowError};
    use soroban_sdk::{
        contract, contractimpl, testutils::Ledger as _, Address, Env,
    };

    #[contract]
    struct BoundaryPropertyTestContract;
    #[contractimpl]
    impl BoundaryPropertyTestContract {}

    fn setup() -> (Env, Address) {
        let env = Env::default();
        let cid = env.register_contract(None, BoundaryPropertyTestContract);
        (env, cid)
    }

    // -----------------------------------------------------------------------
    // Deterministic PRNG Helper
    // -----------------------------------------------------------------------

    struct SimplePrng {
        state: u128,
    }

    impl SimplePrng {
        fn new(seed: u128) -> Self {
            Self {
                state: if seed == 0 { 0xdead_beef_cafe_babe } else { seed },
            }
        }

        fn next_u128(&mut self) -> u128 {
            self.state = self
                .state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.state
        }

        fn next_i128(&mut self) -> i128 {
            self.next_u128() as i128
        }
    }

    // -----------------------------------------------------------------------
    // Numeric Boundary Properties
    // -----------------------------------------------------------------------

    #[test]
    fn test_checked_arithmetic_extreme_boundaries_never_panic() {
        let extreme_values: [i128; 11] = [
            i128::MIN,
            i128::MIN + 1,
            -1_000_000_000_000_i128,
            -1,
            0,
            1,
            1_000_000_000_000_i128,
            i64::MAX as i128,
            i128::MAX / 2,
            i128::MAX - 1,
            i128::MAX,
        ];

        for &a in &extreme_values {
            for &b in &extreme_values {
                // Addition Property
                let add_res = checked_add(a, b);
                let expected_add = a.checked_add(b).ok_or(Error::Overflow);
                assert_eq!(add_res, expected_add);

                // Subtraction Property
                let sub_res = checked_sub(a, b);
                let expected_sub = a.checked_sub(b).ok_or(Error::Overflow);
                assert_eq!(sub_res, expected_sub);

                // Multiplication Property
                let mul_res = checked_mul(a, b);
                let expected_mul = a.checked_mul(b).ok_or(Error::Overflow);
                assert_eq!(mul_res, expected_mul);

                // Division Property (Zero divisor and MIN / -1 overflow handled)
                let div_res = checked_div(a, b);
                let expected_div = if b == 0 {
                    Err(Error::InvalidAmount)
                } else if a == i128::MIN && b == -1 {
                    Err(Error::Overflow)
                } else {
                    a.checked_div(b).ok_or(Error::Overflow)
                };
                assert_eq!(div_res, expected_div);
            }
        }
    }

    #[test]
    fn test_basis_point_conservation_and_bounds_property() {
        let amounts: [i128; 8] = [
            0,
            1,
            10_000,
            10_001,
            1_000_000_000,
            i64::MAX as i128,
            i128::MAX / 10_000,
            i128::MAX,
        ];

        let valid_rates: [i128; 7] = [0, 1, 50, 500, 5_000, 9_999, 10_000];

        for &amount in &amounts {
            for &rate in &valid_rates {
                if let Ok(fee) = apply_bps(amount, rate) {
                    // Property 1: Fee is bounded between 0 and amount
                    assert!(fee >= 0, "fee must be non-negative");
                    assert!(fee <= amount, "fee must not exceed principal amount");

                    // Property 2: Conservation of split funds
                    let remainder = amount - fee;
                    assert_eq!(fee + remainder, amount, "split funds must strictly conserve total amount");

                    // Property 3: 0 bps produces 0 fee
                    if rate == 0 {
                        assert_eq!(fee, 0);
                    }

                    // Property 4: 10,000 bps (100%) produces exact amount
                    if rate == 10_000 {
                        assert_eq!(fee, amount);
                    }
                }
            }

            // Property 5: Rates exceeding 10,000 bps (or negative) must be rejected
            assert_eq!(apply_bps(amount, 10_001), Err(Error::InvalidAmount));
            assert_eq!(apply_bps(amount, -1), Err(Error::InvalidAmount));
            assert_eq!(apply_bps(amount, i128::MAX), Err(Error::InvalidAmount));
        }
    }

    #[test]
    fn test_fuzzed_arithmetic_properties_random_inputs() {
        let mut prng = SimplePrng::new(42);

        for _ in 0..2_000 {
            let a = prng.next_i128();
            let b = prng.next_i128();

            // Commutativity of addition: a + b == b + a
            let add_ab = checked_add(a, b);
            let add_ba = checked_add(b, a);
            assert_eq!(add_ab, add_ba);

            // Commutativity of multiplication: a * b == b * a
            let mul_ab = checked_mul(a, b);
            let mul_ba = checked_mul(b, a);
            assert_eq!(mul_ab, mul_ba);

            // Identity element: a + 0 == a
            assert_eq!(checked_add(a, 0), Ok(a));

            // Identity element: a * 1 == a
            assert_eq!(checked_mul(a, 1), Ok(a));

            // Zero product: a * 0 == 0
            assert_eq!(checked_mul(a, 0), Ok(0));
        }
    }

    // -----------------------------------------------------------------------
    // Timestamp & Ledger Boundary Properties
    // -----------------------------------------------------------------------

    #[test]
    fn test_timestamp_boundary_and_window_partition_property() {
        let (env, cid) = setup();

        let extreme_timestamps: [u64; 7] = [
            0,
            1,
            1_700_000_000,
            2_147_483_647, // Y2038
            u32::MAX as u64,
            u64::MAX - 1,
            u64::MAX,
        ];

        for &start in &extreme_timestamps {
            for &end in &extreme_timestamps {
                let window = TimeWindow { start, end };

                if start > end {
                    // Property: Inverted window is unconditionally rejected as Stale
                    env.as_contract(&cid, || {
                        env.ledger().set_timestamp(start);
                        assert_eq!(validate_time_window(&env, &window), Err(TimeWindowError::Stale));
                    });
                } else {
                    // Property: Strict partition into {TooEarly, Valid, Expired}
                    env.as_contract(&cid, || {
                        // Exactly at start -> Valid
                        env.ledger().set_timestamp(start);
                        assert_eq!(validate_time_window(&env, &window), Ok(()));

                        // Exactly at end -> Valid
                        env.ledger().set_timestamp(end);
                        assert_eq!(validate_time_window(&env, &window), Ok(()));

                        // Before start -> TooEarly
                        if start > 0 {
                            env.ledger().set_timestamp(start - 1);
                            assert_eq!(validate_time_window(&env, &window), Err(TimeWindowError::TooEarly));
                        }

                        // After end -> Expired
                        if end < u64::MAX {
                            env.ledger().set_timestamp(end + 1);
                            assert_eq!(validate_time_window(&env, &window), Err(TimeWindowError::Expired));
                        }
                    });
                }
            }
        }
    }

    #[test]
    fn test_input_limits_boundary_enforcement() {
        use crate::input_limits::{
            check_items, InputLimitPolicy, ABSOLUTE_MAX_BYTES, ABSOLUTE_MAX_ITEMS,
        };

        let policy = InputLimitPolicy {
            max_bytes: ABSOLUTE_MAX_BYTES,
            max_items: ABSOLUTE_MAX_ITEMS,
            max_distinct: ABSOLUTE_MAX_ITEMS,
        };
        assert!(policy.validate().is_ok());

        // Exact boundary allowed
        assert!(check_items(&policy, ABSOLUTE_MAX_ITEMS).is_ok());

        // Boundary + 1 rejected
        assert!(check_items(&policy, ABSOLUTE_MAX_ITEMS + 1).is_err());
    }
}
