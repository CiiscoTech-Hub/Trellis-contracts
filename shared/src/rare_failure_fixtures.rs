//! Deterministic Rare-Failure Fixture Generator for Trellis smart contracts (#493).
//!
//! Generates synthetic, reproducible test fixtures covering low-probability,
//! high-impact edge cases and catastrophic failures:
//! - Clock skew / timestamp rewinds / epoch boundaries.
//! - Storage TTL exhaustion and archiver lockouts.
//! - Extreme arithmetic boundaries (i128::MAX, precision underflow, divide-by-zero).
//! - Cross-contract cascade dropouts and downstream reverts.
//! - Payload corruption and tampered signatures.

use soroban_sdk::{
    contracttype, symbol_short, Address, Bytes, Env, Symbol, Vec,
};

/// Maximum fixtures that can be generated in a single batch to respect Soroban CPU/RAM budgets.
pub const MAX_FIXTURES_PER_BATCH: u32 = 50;

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RareFailureCategory {
    /// Ledger clock anomalies (rewind, extreme skew, epoch boundaries).
    LedgerClockSkew = 1,
    /// Storage TTL anomalies (0 ledgers remaining, archiver collision, footprint overflow).
    StorageTtlExhaustion = 2,
    /// Arithmetic extremes (i128::MAX overflow, negative balance breach, rounding loss).
    ArithmeticBoundary = 3,
    /// Multi-contract communication failures (oracle timeout, SAC revert, orphan lock).
    CrossContractCascade = 4,
    /// Malformed/tampered inputs (bit flips, hash mismatch, truncated payload).
    PayloadCorruption = 5,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RareFailureSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RareFailureError {
    /// Caller is not authorized to generate or validate test fixtures.
    Unauthorized = 4301,
    /// Generation seed cannot be zero.
    InvalidSeed = 4302,
    /// Requested fixture count exceeds MAX_FIXTURES_PER_BATCH.
    BatchLimitExceeded = 4303,
    /// Anomaly simulation validation failed to assert expected behavior.
    SimulationValidationFailed = 4304,
    /// Category requested is unsupported or invalid.
    CategoryNotSupported = 4305,
    /// Requested batch size must be at least 1.
    EmptyBatch = 4306,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratorConfig {
    pub seed: u64,
    pub max_fixtures: u32,
    pub allow_critical: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RareFailureFixture {
    pub fixture_id: u64,
    pub category: RareFailureCategory,
    pub severity: RareFailureSeverity,
    pub seed: u64,
    pub anomaly_name: Symbol,
    pub simulated_ledger: u32,
    pub simulated_timestamp: u64,
    pub simulated_numeric_arg: i128,
    pub simulated_byte_payload: Bytes,
    pub expected_error_code: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum DataKey {
    AuthorizedGenerator(Address),
    LastBatchSeed,
}

// ---------------------------------------------------------------------------
// PRNG Helper (Deterministic XorShift64*)
// ---------------------------------------------------------------------------

struct XorShift64Star {
    state: u64,
}

impl XorShift64Star {
    fn new(seed: u64) -> Self {
        let s = if seed == 0 { 0x853c_49e6_748f_ea9b } else { seed };
        Self { state: s }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }
}

// ---------------------------------------------------------------------------
// Access Control
// ---------------------------------------------------------------------------

pub fn register_fixture_generator(env: &Env, admin: &Address, generator: &Address) {
    admin.require_auth();
    env.storage()
        .instance()
        .set(&DataKey::AuthorizedGenerator(generator.clone()), &true);
}

pub fn is_authorized_generator(env: &Env, caller: &Address) -> bool {
    env.storage()
        .instance()
        .get(&DataKey::AuthorizedGenerator(caller.clone()))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Generator Engine
// ---------------------------------------------------------------------------

/// Generates a deterministic batch of rare-failure test fixtures based on `config.seed`.
pub fn generate_rare_failure_batch(
    env: &Env,
    caller: &Address,
    config: GeneratorConfig,
) -> Result<Vec<RareFailureFixture>, RareFailureError> {
    if !is_authorized_generator(env, caller) {
        return Err(RareFailureError::Unauthorized);
    }
    caller.require_auth();

    if config.seed == 0 {
        return Err(RareFailureError::InvalidSeed);
    }
    if config.max_fixtures == 0 {
        return Err(RareFailureError::EmptyBatch);
    }
    if config.max_fixtures > MAX_FIXTURES_PER_BATCH {
        return Err(RareFailureError::BatchLimitExceeded);
    }

    let mut rng = XorShift64Star::new(config.seed);
    let mut fixtures = Vec::new(env);

    let categories = [
        RareFailureCategory::LedgerClockSkew,
        RareFailureCategory::StorageTtlExhaustion,
        RareFailureCategory::ArithmeticBoundary,
        RareFailureCategory::CrossContractCascade,
        RareFailureCategory::PayloadCorruption,
    ];

    for i in 0..config.max_fixtures {
        let fixture_id = (i as u64) + 1;
        let cat_idx = (rng.next_u32() as usize) % categories.len();
        let category = categories[cat_idx];

        let severity = if !config.allow_critical {
            RareFailureSeverity::High
        } else {
            match rng.next_u32() % 4 {
                0 => RareFailureSeverity::Low,
                1 => RareFailureSeverity::Medium,
                2 => RareFailureSeverity::High,
                _ => RareFailureSeverity::Critical,
            }
        };

        let (name, ledger, ts, num_arg, expected_err) = match category {
            RareFailureCategory::LedgerClockSkew => {
                let skew_type = rng.next_u32() % 3;
                if skew_type == 0 {
                    (symbol_short!("clk_rew"), 100, 10, 0, 104) // Timestamp rewind (Expired)
                } else if skew_type == 1 {
                    (symbol_short!("clk_leap"), 500_000_000, u64::MAX - 1000, 0, 105) // Far future overflow
                } else {
                    (symbol_short!("clk_zero"), 0, 0, 0, 106) // Zero timestamp
                }
            }
            RareFailureCategory::StorageTtlExhaustion => {
                let ttl_type = rng.next_u32() % 2;
                if ttl_type == 0 {
                    (symbol_short!("ttl_zero"), 5000, 1000, 0, 201) // TTL zero (Archived)
                } else {
                    (symbol_short!("ttl_edge"), 5000, 1000, 1, 202) // 1 ledger left (Expiring)
                }
            }
            RareFailureCategory::ArithmeticBoundary => {
                let arith_type = rng.next_u32() % 3;
                if arith_type == 0 {
                    (symbol_short!("num_ovfl"), 1000, 1000, i128::MAX, 301) // Overflow
                } else if arith_type == 1 {
                    (symbol_short!("num_undr"), 1000, 1000, -1, 302) // Negative breach
                } else {
                    (symbol_short!("num_zero"), 1000, 1000, 0, 303) // Zero denominator
                }
            }
            RareFailureCategory::CrossContractCascade => {
                let drop_type = rng.next_u32() % 2;
                if drop_type == 0 {
                    (symbol_short!("casc_to"), 2000, 2000, 504, 401) // Timeout
                } else {
                    (symbol_short!("casc_rvt"), 2000, 2000, 500, 402) // Downstream revert
                }
            }
            RareFailureCategory::PayloadCorruption => {
                let corr_type = rng.next_u32() % 2;
                if corr_type == 0 {
                    (symbol_short!("pay_flip"), 3000, 3000, 0xDEAD, 501) // Bit flip
                } else {
                    (symbol_short!("pay_trmp"), 3000, 3000, 0xBEEF, 502) // Tampered hash
                }
            }
        };

        let mut payload_bytes = Bytes::new(env);
        let b1 = (rng.next_u32() & 0xFF) as u8;
        let b2 = ((rng.next_u32() >> 8) & 0xFF) as u8;
        payload_bytes.push_back(b1);
        payload_bytes.push_back(b2);

        fixtures.push_back(RareFailureFixture {
            fixture_id,
            category,
            severity,
            seed: config.seed,
            anomaly_name: name,
            simulated_ledger: ledger,
            simulated_timestamp: ts,
            simulated_numeric_arg: num_arg,
            simulated_byte_payload: payload_bytes,
            expected_error_code: expected_err,
        });
    }

    env.storage()
        .instance()
        .set(&DataKey::LastBatchSeed, &config.seed);

    env.events().publish(
        (symbol_short!("rare_gen"), symbol_short!("batch")),
        (config.seed, config.max_fixtures),
    );

    Ok(fixtures)
}

/// Validates whether a simulated fixture's invariants hold (non-panic and correct error classification).
pub fn validate_simulated_fixture(
    fixture: &RareFailureFixture,
) -> Result<bool, RareFailureError> {
    if fixture.fixture_id == 0 || fixture.seed == 0 {
        return Err(RareFailureError::SimulationValidationFailed);
    }

    match fixture.category {
        RareFailureCategory::LedgerClockSkew => {
            if fixture.expected_error_code < 100 || fixture.expected_error_code > 199 {
                return Err(RareFailureError::SimulationValidationFailed);
            }
        }
        RareFailureCategory::StorageTtlExhaustion => {
            if fixture.expected_error_code < 200 || fixture.expected_error_code > 299 {
                return Err(RareFailureError::SimulationValidationFailed);
            }
        }
        RareFailureCategory::ArithmeticBoundary => {
            if fixture.expected_error_code < 300 || fixture.expected_error_code > 399 {
                return Err(RareFailureError::SimulationValidationFailed);
            }
        }
        RareFailureCategory::CrossContractCascade => {
            if fixture.expected_error_code < 400 || fixture.expected_error_code > 499 {
                return Err(RareFailureError::SimulationValidationFailed);
            }
        }
        RareFailureCategory::PayloadCorruption => {
            if fixture.expected_error_code < 500 || fixture.expected_error_code > 599 {
                return Err(RareFailureError::SimulationValidationFailed);
            }
        }
    }

    Ok(true)
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
pub mod tests {
    use super::*;
    use soroban_sdk::{
        contract, contractimpl,
        testutils::Address as _,
        Env,
    };

    #[contract]
    pub struct RareFailureTestContract;

    #[contractimpl]
    impl RareFailureTestContract {}

    fn setup_env() -> (Env, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, RareFailureTestContract);
        let admin = Address::generate(&env);
        let generator = Address::generate(&env);
        (env, contract_id, admin, generator)
    }

    fn reg_gen(env: &Env, cid: &Address, admin: &Address, generator: &Address) {
        env.as_contract(cid, || register_fixture_generator(env, admin, generator));
    }

    fn gen_batch(
        env: &Env,
        cid: &Address,
        caller: &Address,
        config: GeneratorConfig,
    ) -> Result<Vec<RareFailureFixture>, RareFailureError> {
        env.as_contract(cid, || generate_rare_failure_batch(env, caller, config))
    }

    #[test]
    fn test_normal_rare_failure_fixture_generation() {
        let (env, contract_id, admin, generator) = setup_env();

        reg_gen(&env, &contract_id, &admin, &generator);
        assert!(env.as_contract(&contract_id, || is_authorized_generator(&env, &generator)));

        let config = GeneratorConfig {
            seed: 0xCAFE_BABE_1234,
            max_fixtures: 10,
            allow_critical: true,
        };

        let fixtures = gen_batch(&env, &contract_id, &generator, config)
            .expect("generation should succeed");

        assert_eq!(fixtures.len(), 10);

        // Verify each generated fixture is structurally valid
        for i in 0..fixtures.len() {
            let f = fixtures.get(i).unwrap();
            assert!(f.fixture_id > 0);
            assert_eq!(validate_simulated_fixture(&f), Ok(true));
        }
    }

    #[test]
    fn test_reproducibility_and_retry_with_identical_seed() {
        let (env, contract_id, admin, generator) = setup_env();

        reg_gen(&env, &contract_id, &admin, &generator);

        let seed = 0x5EED_9876_FEDC;
        let config1 = GeneratorConfig {
            seed,
            max_fixtures: 5,
            allow_critical: false,
        };

        let batch1 = gen_batch(&env, &contract_id, &generator, config1.clone()).unwrap();
        let batch2 = gen_batch(&env, &contract_id, &generator, config1).unwrap();

        assert_eq!(batch1.len(), batch2.len());

        // Identical seed must produce bit-for-bit identical fixtures
        for i in 0..batch1.len() {
            let f1 = batch1.get(i).unwrap();
            let f2 = batch2.get(i).unwrap();
            assert_eq!(f1.category, f2.category);
            assert_eq!(f1.severity, f2.severity);
            assert_eq!(f1.anomaly_name, f2.anomaly_name);
            assert_eq!(f1.simulated_numeric_arg, f2.simulated_numeric_arg);
            assert_eq!(f1.expected_error_code, f2.expected_error_code);
        }
    }

    #[test]
    fn test_failure_paths_invalid_seed_and_batch_limits() {
        let (env, contract_id, admin, generator) = setup_env();

        reg_gen(&env, &contract_id, &admin, &generator);

        // Zero seed rejected
        let bad_seed = GeneratorConfig {
            seed: 0,
            max_fixtures: 5,
            allow_critical: true,
        };
        assert_eq!(
            gen_batch(&env, &contract_id, &generator, bad_seed),
            Err(RareFailureError::InvalidSeed)
        );

        // Empty batch rejected
        let empty_batch = GeneratorConfig {
            seed: 42,
            max_fixtures: 0,
            allow_critical: true,
        };
        assert_eq!(
            gen_batch(&env, &contract_id, &generator, empty_batch),
            Err(RareFailureError::EmptyBatch)
        );

        // Batch over limit rejected
        let over_limit = GeneratorConfig {
            seed: 42,
            max_fixtures: MAX_FIXTURES_PER_BATCH + 1,
            allow_critical: true,
        };
        assert_eq!(
            gen_batch(&env, &contract_id, &generator, over_limit),
            Err(RareFailureError::BatchLimitExceeded)
        );
    }

    #[test]
    fn test_authorization_rejects_unregistered_callers() {
        let (env, contract_id, _admin, _generator) = setup_env();
        let stranger = Address::generate(&env);

        env.as_contract(&contract_id, || {
            let config = GeneratorConfig {
                seed: 12345,
                max_fixtures: 5,
                allow_critical: true,
            };

            let res = generate_rare_failure_batch(&env, &stranger, config);
            assert_eq!(res, Err(RareFailureError::Unauthorized));
        });
    }
}
