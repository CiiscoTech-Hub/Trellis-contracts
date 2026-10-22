//! Balance, ownership and entitlement transition checks (Issue #266).
//!
//! Every state-changing aid path funnels through these checks before it
//! commits, so a transition that would break an invariant is rejected with
//! [`AidError::InvariantViolation`] (or the matching lifecycle error) and,
//! because a failed invocation is rolled back, leaves no state behind.
//!
//! | Invariant | Enforced by |
//! |---|---|
//! | **Balance** — every escrowed liability is fully backed: an inflow raises the contract's token balance by exactly the recorded amount. | [`escrow_in`] |
//! | **Ownership** — a record's donor, recipient, token, escrowed total and tranche count never change after creation. | [`commit`] |
//! | **Lifecycle** — `Settled` / `Refunded` are terminal; `Pending` and `PartiallyClaimed` only move forward. | [`commit`] |
//! | **Entitlement** — milestone tranches sum to the escrowed total, and the record's status reflects what is still unclaimed, so no payout can exceed the remaining escrow. | [`settle_milestones`] |
//!
//! Costs: [`commit`] is O(1); [`settle_milestones`] is one O(m) pass over the
//! record's `m` tranches, which the caller has already loaded; [`escrow_in`]
//! adds two `balance` reads to the token transfer it wraps.

use soroban_sdk::{token, Address, Env, Vec};

use crate::{storage, AidError, AidMilestone, AidRecord, AidStatus};

/// Pulls `amount` from `from` into escrow and verifies the contract's balance
/// grew by exactly `amount`. A token that delivers less (fee-on-transfer) or
/// more (rebasing) than requested would leave recorded liabilities out of
/// step with real holdings, so the whole call is rejected instead.
pub(crate) fn escrow_in(
    env: &Env,
    token: &Address,
    from: &Address,
    amount: i128,
) -> Result<(), AidError> {
    let client = token::Client::new(env, token);
    let this = env.current_contract_address();
    let before = client.balance(&this);
    client.transfer(from, &this, &amount);
    if client.balance(&this).checked_sub(before) != Some(amount) {
        return Err(AidError::InvariantViolation);
    }
    Ok(())
}

/// Persists `after` as the next state of `before` once the ownership and
/// lifecycle invariants hold.
pub(crate) fn commit(env: &Env, before: &AidRecord, after: &AidRecord) -> Result<(), AidError> {
    if before.id != after.id
        || before.donor != after.donor
        || before.recipient != after.recipient
        || before.token != after.token
        || before.amount != after.amount
        || before.milestone_count != after.milestone_count
    {
        return Err(AidError::InvariantViolation);
    }
    ensure_status_transition(before.status, after.status)?;
    storage::set_aid(env, after.id, after);
    Ok(())
}

fn ensure_status_transition(from: AidStatus, to: AidStatus) -> Result<(), AidError> {
    use AidStatus::{PartiallyClaimed, Pending, Refunded, Settled};
    match (from, to) {
        (Settled, _) => Err(AidError::AlreadyClaimed),
        (Refunded, _) => Err(AidError::AlreadyRefunded),
        (Pending | PartiallyClaimed, Settled | Refunded | PartiallyClaimed) => Ok(()),
        (Pending | PartiallyClaimed, Pending) => Err(AidError::InvariantViolation),
    }
}

/// Entitlement still held in escrow for a milestone program, plus the status
/// that amount implies (`Settled` once nothing is left, `PartiallyClaimed`
/// once anything was paid out, otherwise `Pending`).
///
/// Fails when the tranches no longer sum to the escrowed total, which would
/// mean some payout could draw on another record's escrow.
pub(crate) fn settle_milestones(
    record: &AidRecord,
    milestones: &Vec<AidMilestone>,
) -> Result<(i128, AidStatus), AidError> {
    if milestones.len() != record.milestone_count {
        return Err(AidError::InvariantViolation);
    }
    let mut total: i128 = 0;
    let mut unclaimed: i128 = 0;
    for m in milestones.iter() {
        total = total.checked_add(m.amount).ok_or(AidError::InvariantViolation)?;
        if !m.claimed {
            unclaimed = unclaimed.checked_add(m.amount).ok_or(AidError::InvariantViolation)?;
        }
    }
    if total != record.amount {
        return Err(AidError::InvariantViolation);
    }
    let status = if unclaimed == 0 {
        AidStatus::Settled
    } else if unclaimed < total {
        AidStatus::PartiallyClaimed
    } else {
        AidStatus::Pending
    };
    Ok((unclaimed, status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AidContractClient;
    use soroban_sdk::testutils::{Address as _, Ledger};
    use soroban_sdk::{contract, contractimpl, symbol_short};

    const EXPIRY: u32 = 100;

    struct Fixture {
        env: Env,
        client: AidContractClient<'static>,
        token: token::Client<'static>,
        contract: Address,
        admin: Address,
        donor: Address,
        recipient: Address,
        inspector: Address,
    }

    fn setup() -> Fixture {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let donor = Address::generate(&env);
        let token_addr = env.register_stellar_asset_contract(admin.clone());
        token::StellarAssetClient::new(&env, &token_addr).mint(&donor, &10_000);
        let contract = env.register_contract(None, crate::AidContract);
        let client = AidContractClient::new(&env, &contract);
        client.initialize(&admin, &Address::generate(&env), &token_addr, &3600);
        let inspector = Address::generate(&env);
        client.set_inspector(&admin, &inspector, &true);
        Fixture {
            client,
            token: token::Client::new(&env, &token_addr),
            contract,
            admin,
            donor,
            recipient: Address::generate(&env),
            inspector,
            env,
        }
    }

    impl Fixture {
        fn milestone_aid(&self, amounts: &[i128]) -> u64 {
            let mut milestones = Vec::new(&self.env);
            for amount in amounts {
                milestones.push_back(AidMilestone {
                    description: symbol_short!("tranche"),
                    amount: *amount,
                    verified: false,
                    claimed: false,
                });
            }
            self.client
                .create_milestone_aid(&self.donor, &self.recipient, &milestones, &EXPIRY)
        }

        fn status(&self, aid_id: u64) -> AidStatus {
            self.client.get_aid(&aid_id).unwrap().status
        }

        fn escrow(&self) -> i128 {
            self.token.balance(&self.contract)
        }

        fn expire(&self) {
            self.env.ledger().with_mut(|l| l.sequence_number = EXPIRY + 1);
        }
    }

    #[test]
    fn claim_aid_cannot_bypass_milestone_verification() {
        let fx = setup();
        let id = fx.milestone_aid(&[300, 700]);
        assert_eq!(
            fx.client.try_claim_aid(&id, &fx.recipient),
            Err(Ok(AidError::InvalidArgument))
        );
        assert_eq!(fx.escrow(), 1_000);
        assert_eq!(fx.token.balance(&fx.recipient), 0);
    }

    #[test]
    fn milestone_claims_track_entitlement_until_settled() {
        let fx = setup();
        let id = fx.milestone_aid(&[300, 700]);
        fx.client.verify_milestone(&fx.inspector, &id, &0);
        fx.client.claim_aid_milestone(&fx.recipient, &id, &0);
        assert_eq!(fx.status(id), AidStatus::PartiallyClaimed);
        assert_eq!(fx.escrow(), 700);

        assert_eq!(
            fx.client.try_claim_aid_milestone(&fx.recipient, &id, &0),
            Err(Ok(AidError::MilestoneAlreadyClaimed))
        );
        // Retry path: an unverified claim fails, then succeeds once verified.
        assert_eq!(
            fx.client.try_claim_aid_milestone(&fx.recipient, &id, &1),
            Err(Ok(AidError::MilestoneNotVerified))
        );
        fx.client.verify_milestone(&fx.inspector, &id, &1);
        fx.client.claim_aid_milestone(&fx.recipient, &id, &1);

        assert_eq!(fx.status(id), AidStatus::Settled);
        assert_eq!(fx.escrow(), 0);
        assert_eq!(fx.token.balance(&fx.recipient), 1_000);
    }

    #[test]
    fn refund_returns_every_unclaimed_tranche() {
        let fx = setup();
        let id = fx.milestone_aid(&[300, 200, 500]);
        fx.client.verify_milestone(&fx.inspector, &id, &0);
        fx.client.claim_aid_milestone(&fx.recipient, &id, &0);
        fx.client.verify_milestone(&fx.inspector, &id, &1);
        fx.expire();

        assert_eq!(
            fx.client.try_refund_aid(&id, &fx.donor),
            Err(Ok(AidError::InvalidArgument))
        );
        fx.client.refund_milestone_aid(&fx.donor, &id);

        assert_eq!(fx.status(id), AidStatus::Refunded);
        assert_eq!(fx.escrow(), 0);
        assert_eq!(fx.token.balance(&fx.donor), 10_000 - 300);
        assert_eq!(
            fx.client.try_refund_milestone_aid(&fx.donor, &id),
            Err(Ok(AidError::AlreadyRefunded))
        );
    }

    #[test]
    fn fully_claimed_program_cannot_be_refunded() {
        let fx = setup();
        let id = fx.milestone_aid(&[400]);
        fx.client.verify_milestone(&fx.inspector, &id, &0);
        fx.client.claim_aid_milestone(&fx.recipient, &id, &0);
        fx.expire();
        assert_eq!(
            fx.client.try_refund_milestone_aid(&fx.donor, &id),
            Err(Ok(AidError::AlreadyClaimed))
        );
        assert_eq!(fx.token.balance(&fx.recipient), 400);
    }

    #[test]
    fn partially_claimed_record_cannot_be_deleted() {
        let fx = setup();
        let id = fx.milestone_aid(&[300, 700]);
        fx.client.verify_milestone(&fx.inspector, &id, &0);
        fx.client.claim_aid_milestone(&fx.recipient, &id, &0);
        assert_eq!(
            fx.client.try_delete_aid(&fx.admin, &id),
            Err(Ok(AidError::CannotDeletePending))
        );
    }

    #[test]
    fn only_owners_can_move_entitlements() {
        let fx = setup();
        let id = fx.milestone_aid(&[300, 700]);
        let stranger = Address::generate(&fx.env);

        assert_eq!(
            fx.client.try_verify_milestone(&stranger, &id, &0),
            Err(Ok(AidError::Unauthorized))
        );
        fx.client.verify_milestone(&fx.inspector, &id, &0);
        assert_eq!(
            fx.client.try_claim_aid_milestone(&stranger, &id, &0),
            Err(Ok(AidError::Unauthorized))
        );
        fx.expire();
        assert_eq!(
            fx.client.try_refund_milestone_aid(&stranger, &id),
            Err(Ok(AidError::Unauthorized))
        );
        assert_eq!(fx.escrow(), 1_000);
    }

    /// SEP-41-shaped token that keeps one unit of every transfer as a fee.
    #[contract]
    struct FeeToken;

    #[contractimpl]
    impl FeeToken {
        pub fn mint(env: Env, to: Address, amount: i128) {
            let balance = Self::balance(env.clone(), to.clone());
            env.storage().persistent().set(&to, &(balance + amount));
        }

        pub fn balance(env: Env, id: Address) -> i128 {
            env.storage().persistent().get(&id).unwrap_or(0)
        }

        pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
            from.require_auth();
            Self::mint(env.clone(), from, -amount);
            Self::mint(env, to, amount - 1);
        }
    }

    #[test]
    fn escrow_rejects_tokens_that_deliver_less_than_requested() {
        let env = Env::default();
        env.mock_all_auths();
        let token_addr = env.register_contract(None, FeeToken);
        let donor = Address::generate(&env);
        FeeTokenClient::new(&env, &token_addr).mint(&donor, &1_000);
        let client = AidContractClient::new(&env, &env.register_contract(None, crate::AidContract));
        let admin = Address::generate(&env);
        client.initialize(&admin, &Address::generate(&env), &token_addr, &3600);
        let recipient = Address::generate(&env);

        assert_eq!(
            client.try_create_aid(&donor, &recipient, &100, &EXPIRY, &None),
            Err(Ok(soroban_sdk::Error::from_contract_error(
                AidError::InvariantViolation as u32
            )))
        );
        assert_eq!(client.get_aid(&0), None);
        assert_eq!(FeeTokenClient::new(&env, &token_addr).balance(&donor), 1_000);
    }
}
