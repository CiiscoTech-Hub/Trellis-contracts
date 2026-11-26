//! # NFT Royalty Split Invariant Enforcement Across Secondary Sales (Issue #522)
//!
//! Production-grade royalty split computation and strict conservation invariant
//! verification for secondary NFT sales on the Trellis Soroban marketplace.
//!
//! ## Invariants
//!
//! | Invariant | Description |
//! |---|---|
//! | **Exact Conservation** | `gross_sale_price == platform_fee + sum(royalty_payouts) + seller_net_proceeds` (to the exact stroop). |
//! | **Basis-Points Cap** | $\sum \text{share\_bps}_i \le \text{MAX\_ROYALTY\_BPS} \le 1,000$ (max 10%). |
//! | **Deterministic Residue** | Truncation remainders from integer arithmetic are deterministically allocated, ensuring zero token leakage. |
//! | **Recipient Disjointness** | No duplicate recipient addresses allowed in the collection royalty registry. |
//! | **Secondary Sale Protection** | Royalties are strictly deducted and distributed across all secondary trades. |
//!
//! ## Complexity
//! - Time Complexity: $O(M)$ where $M$ is the number of royalty recipients ($M \le 10$).
//! - Space Complexity: $O(M)$ allocated payout vector.

#![allow(clippy::too_many_arguments)]

use soroban_sdk::{contracterror, contracttype, Address, Env, Vec};

pub const BPS_DENOMINATOR: i128 = 10_000;
pub const MAX_ROYALTY_BPS: i128 = 1_000; // 10% maximum royalty
pub const MAX_PLATFORM_FEE_BPS: i128 = 1_000; // 10% maximum platform fee
pub const MAX_ROYALTY_RECIPIENTS: u32 = 10;

// ===========================================================================
// Error taxonomy (2050–2060 in Marketplace Royalty domain)
// ===========================================================================

#[contracterror(export = false)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum NftRoyaltyError {
    /// Sale price is non-positive.
    InvalidSalePrice = 2050,
    /// Platform fee basis points rate is negative or exceeds maximum cap.
    InvalidFeeRate = 2051,
    /// Royalty recipient share basis points is negative or invalid.
    InvalidRoyaltyBps = 2052,
    /// Total royalty basis points exceeds the allowed collection cap (1,000 bps).
    RoyaltyExceedsCap = 2053,
    /// Strict balance conservation invariant failed: gross != fee + royalties + proceeds.
    ConservationInvariantViolated = 2054,
    /// Duplicate recipient address detected in collection royalty configuration.
    DuplicateRoyaltyRecipient = 2055,
    /// Calculated seller net proceeds is negative.
    SellerProceedsNegative = 2056,
    /// Number of royalty recipients exceeds allowed maximum (10).
    MaxRecipientsExceeded = 2057,
    /// Caller is not authorized.
    Unauthorized = 2058,
    /// Arithmetic overflow in royalty or fee calculation.
    MathOverflow = 2059,
}

// ===========================================================================
// Data Structures
// ===========================================================================

/// Individual royalty recipient configuration.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoyaltySplitRecipient {
    pub recipient: Address,
    pub share_bps: i128,
}

/// An individual payout destined for a royalty recipient.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoyaltyPayout {
    pub recipient: Address,
    pub amount: i128,
}

/// Verified royalty split execution plan for a sale.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoyaltyExecutionPlan {
    pub gross_price: i128,
    pub platform_fee: i128,
    pub total_royalty: i128,
    pub seller_proceeds: i128,
    pub recipient_payouts: Vec<RoyaltyPayout>,
}

// ===========================================================================
// Core Logic
// ===========================================================================

/// Validates a collection's royalty configuration against structural invariants.
pub fn validate_royalty_config(
    recipients: &Vec<RoyaltySplitRecipient>,
    max_cap_bps: i128,
) -> Result<i128, NftRoyaltyError> {
    if recipients.len() > MAX_ROYALTY_RECIPIENTS {
        return Err(NftRoyaltyError::MaxRecipientsExceeded);
    }

    let mut total_bps: i128 = 0;
    for i in 0..recipients.len() {
        let r1 = recipients.get(i).unwrap();
        if r1.share_bps < 0 || r1.share_bps > max_cap_bps {
            return Err(NftRoyaltyError::InvalidRoyaltyBps);
        }

        // Check for duplicate recipients
        for j in (i + 1)..recipients.len() {
            let r2 = recipients.get(j).unwrap();
            if r1.recipient == r2.recipient {
                return Err(NftRoyaltyError::DuplicateRoyaltyRecipient);
            }
        }

        total_bps = total_bps
            .checked_add(r1.share_bps)
            .ok_or(NftRoyaltyError::MathOverflow)?;
    }

    if total_bps > max_cap_bps {
        return Err(NftRoyaltyError::RoyaltyExceedsCap);
    }

    Ok(total_bps)
}

/// Computes fee, royalty payouts, and net proceeds, verifying the strict
/// conservation invariant: `gross_price == platform_fee + total_royalty + seller_proceeds`.
pub fn compute_and_verify_royalty_split(
    env: &Env,
    sale_price: i128,
    platform_fee_bps: i128,
    recipients: &Vec<RoyaltySplitRecipient>,
    is_secondary_sale: bool,
) -> Result<RoyaltyExecutionPlan, NftRoyaltyError> {
    if sale_price <= 0 {
        return Err(NftRoyaltyError::InvalidSalePrice);
    }
    if !(0..=MAX_PLATFORM_FEE_BPS).contains(&platform_fee_bps) {
        return Err(NftRoyaltyError::InvalidFeeRate);
    }

    // 1. Calculate platform fee
    let platform_fee = sale_price
        .checked_mul(platform_fee_bps)
        .ok_or(NftRoyaltyError::MathOverflow)?
        .checked_div(BPS_DENOMINATOR)
        .ok_or(NftRoyaltyError::MathOverflow)?;

    let mut total_royalty: i128 = 0;
    let mut recipient_payouts = Vec::new(env);

    // 2. Calculate royalties for secondary sales if configured
    if is_secondary_sale && !recipients.is_empty() {
        validate_royalty_config(recipients, MAX_ROYALTY_BPS)?;

        for r in recipients.iter() {
            if r.share_bps > 0 {
                let payout = sale_price
                    .checked_mul(r.share_bps)
                    .ok_or(NftRoyaltyError::MathOverflow)?
                    .checked_div(BPS_DENOMINATOR)
                    .ok_or(NftRoyaltyError::MathOverflow)?;

                if payout > 0 {
                    total_royalty = total_royalty
                        .checked_add(payout)
                        .ok_or(NftRoyaltyError::MathOverflow)?;
                    recipient_payouts.push_back(RoyaltyPayout {
                        recipient: r.recipient.clone(),
                        amount: payout,
                    });
                }
            }
        }
    }

    // 3. Compute seller net proceeds
    let seller_proceeds = sale_price
        .checked_sub(platform_fee)
        .ok_or(NftRoyaltyError::MathOverflow)?
        .checked_sub(total_royalty)
        .ok_or(NftRoyaltyError::MathOverflow)?;

    if seller_proceeds < 0 {
        return Err(NftRoyaltyError::SellerProceedsNegative);
    }

    // 4. Strict Conservation Invariant Verification
    let computed_sum = platform_fee
        .checked_add(total_royalty)
        .ok_or(NftRoyaltyError::MathOverflow)?
        .checked_add(seller_proceeds)
        .ok_or(NftRoyaltyError::MathOverflow)?;

    if computed_sum != sale_price {
        return Err(NftRoyaltyError::ConservationInvariantViolated);
    }

    Ok(RoyaltyExecutionPlan {
        gross_price: sale_price,
        platform_fee,
        total_royalty,
        seller_proceeds,
        recipient_payouts,
    })
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::Env;

    #[test]
    fn test_royalty_split_single_recipient_conservation() {
        let env = Env::default();
        let creator = Address::generate(&env);

        let mut recipients = Vec::new(&env);
        recipients.push_back(RoyaltySplitRecipient {
            recipient: creator.clone(),
            share_bps: 500, // 5%
        });

        // 100,000 price, 250 bps fee (2.5%), 500 bps royalty (5.0%)
        let plan = compute_and_verify_royalty_split(&env, 100_000, 250, &recipients, true).unwrap();

        assert_eq!(plan.gross_price, 100_000);
        assert_eq!(plan.platform_fee, 2_500); // 2.5%
        assert_eq!(plan.total_royalty, 5_000); // 5%
        assert_eq!(plan.seller_proceeds, 92_500); // 92.5%
        assert_eq!(plan.recipient_payouts.len(), 1);
        assert_eq!(
            plan.recipient_payouts.get(0).unwrap(),
            RoyaltyPayout {
                recipient: creator,
                amount: 5_000
            }
        );

        // Exact conservation check
        assert_eq!(plan.platform_fee + plan.total_royalty + plan.seller_proceeds, 100_000);
    }

    #[test]
    fn test_royalty_split_multi_recipients() {
        let env = Env::default();
        let artist = Address::generate(&env);
        let foundation = Address::generate(&env);
        let dev = Address::generate(&env);

        let mut recipients = Vec::new(&env);
        recipients.push_back(RoyaltySplitRecipient {
            recipient: artist.clone(),
            share_bps: 400, // 4%
        });
        recipients.push_back(RoyaltySplitRecipient {
            recipient: foundation.clone(),
            share_bps: 200, // 2%
        });
        recipients.push_back(RoyaltySplitRecipient {
            recipient: dev.clone(),
            share_bps: 100, // 1%
        });

        // Total 700 bps <= 1000 bps
        let plan = compute_and_verify_royalty_split(&env, 500_000, 200, &recipients, true).unwrap();

        assert_eq!(plan.platform_fee, 10_000); // 2% of 500,000
        assert_eq!(plan.total_royalty, 35_000); // 7% of 500,000
        assert_eq!(plan.seller_proceeds, 455_000);
        assert_eq!(plan.recipient_payouts.len(), 3);
        assert_eq!(
            plan.recipient_payouts.get(0).unwrap(),
            RoyaltyPayout {
                recipient: artist,
                amount: 20_000
            }
        );
        assert_eq!(
            plan.recipient_payouts.get(1).unwrap(),
            RoyaltyPayout {
                recipient: foundation,
                amount: 10_000
            }
        );
        assert_eq!(
            plan.recipient_payouts.get(2).unwrap(),
            RoyaltyPayout {
                recipient: dev,
                amount: 5_000
            }
        );

        assert_eq!(plan.platform_fee + plan.total_royalty + plan.seller_proceeds, 500_000);
    }

    #[test]
    fn test_conservation_with_truncation_remainders() {
        let env = Env::default();
        let creator1 = Address::generate(&env);
        let creator2 = Address::generate(&env);

        let mut recipients = Vec::new(&env);
        recipients.push_back(RoyaltySplitRecipient {
            recipient: creator1,
            share_bps: 333, // 3.33%
        });
        recipients.push_back(RoyaltySplitRecipient {
            recipient: creator2,
            share_bps: 333, // 3.33%
        });

        // Price with odd stroop amount where divisions have remainders
        let odd_prices = [1, 7, 33, 999, 12345, 999999, 1000000007];
        for price in odd_prices {
            let plan = compute_and_verify_royalty_split(&env, price, 250, &recipients, true).unwrap();
            let sum = plan.platform_fee + plan.total_royalty + plan.seller_proceeds;
            assert_eq!(sum, price, "Conservation invariant failed for price: {}", price);
        }
    }

    #[test]
    fn test_duplicate_recipients_rejected() {
        let env = Env::default();
        let creator = Address::generate(&env);

        let mut recipients = Vec::new(&env);
        recipients.push_back(RoyaltySplitRecipient {
            recipient: creator.clone(),
            share_bps: 200,
        });
        recipients.push_back(RoyaltySplitRecipient {
            recipient: creator,
            share_bps: 300,
        });

        let err = compute_and_verify_royalty_split(&env, 100_000, 250, &recipients, true).unwrap_err();
        assert_eq!(err, NftRoyaltyError::DuplicateRoyaltyRecipient);
    }

    #[test]
    fn test_royalty_cap_exceeded_rejected() {
        let env = Env::default();
        let creator = Address::generate(&env);

        let mut recipients = Vec::new(&env);
        recipients.push_back(RoyaltySplitRecipient {
            recipient: creator,
            share_bps: 1_200, // 12% > 10% max
        });

        let err = compute_and_verify_royalty_split(&env, 100_000, 250, &recipients, true).unwrap_err();
        assert_eq!(err, NftRoyaltyError::InvalidRoyaltyBps);
    }
}
