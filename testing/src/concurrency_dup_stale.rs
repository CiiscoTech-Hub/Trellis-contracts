//! Concurrency tests for duplicate submissions and stale versions (Issue #293).
//!
//! These tests exercise the deterministic interleaving harness to verify that:
//! - Duplicate submissions of the same operation are idempotent.
//! - Stale-version submissions are rejected without corrupting state.
//! - Mixed concurrent actor sequences preserve invariants.
//!
//! All tests are deterministic — no thread-level concurrency. The harness
//! serializes actor submissions against live contract state, exactly as
//! Soroban's ledger applies them.

#[cfg(test)]
mod tests {
    extern crate std;

    use crate::concurrency::{MultiActorConcurrencyHarness, MutationAttempt};
    use crate::helpers::{advance_ledger_sequence, reset_ledger_to_genesis};
    use shared::errors::Error;
    use shared::stale_state::{
        check_before_replay, complete_operation, enqueue, resolve_conflict, ConflictResolution,
        QueuedOperationStatus, StateSnapshot,
    };
    use soroban_sdk::{
        symbol_short,
        testutils::{Address as _, Ledger as _},
        token, Address, Bytes, BytesN, Env, Symbol,
    };
    use treasury_contract::{TimeWindow, TreasuryContract, TreasuryContractClient};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn snapshot(ledger: u32) -> StateSnapshot {
        StateSnapshot {
            wallet_revision: 1,
            api_revision: 1,
            ledger_sequence: ledger,
        }
    }

    fn op_id(env: &Env, seed: u8) -> BytesN<32> {
        BytesN::from_array(env, &[seed; 32])
    }

    fn setup_treasury() -> (
        Env,
        TreasuryContractClient<'static>,
        Address,
        Address,
        Address,
        Symbol,
    ) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, TreasuryContract);
        let client = TreasuryContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let actor2 = Address::generate(&env);
        let token_address = env.register_stellar_asset_contract(admin.clone());
        let category = symbol_short!("reserve");

        client.initialize(&admin, &1_000);
        client.add_treasury_manager(&admin, &actor2);
        token::StellarAssetClient::new(&env, &token_address).mint(&admin, &5_000);
        client.deposit(&admin, &token_address, &category, &5_000);

        (env, client, admin, actor2, token_address, category)
    }

    // -----------------------------------------------------------------------
    // Duplicate submission tests (stale_state queue)
    // -----------------------------------------------------------------------

    #[test]
    fn duplicate_enqueue_with_same_payload_is_idempotent() {
        let env = Env::default();
        let id = op_id(&env, 1);
        let payload = Bytes::from_slice(&env, b"withdraw_100");
        let snap = snapshot(0);

        let first = enqueue(&env, &id, &payload, snap).unwrap();
        assert_eq!(first.status, QueuedOperationStatus::Pending);
        assert_eq!(first.attempts, 0);

        let second = enqueue(&env, &id, &payload, snap).unwrap();
        assert_eq!(second.status, QueuedOperationStatus::Pending);
        assert_eq!(second.attempts, 0);
    }

    #[test]
    fn duplicate_enqueue_with_different_payload_rejected() {
        let env = Env::default();
        let id = op_id(&env, 2);
        let snap = snapshot(0);

        enqueue(&env, &id, &Bytes::from_slice(&env, b"action_a"), snap).unwrap();

        let result = enqueue(&env, &id, &Bytes::from_slice(&env, b"action_b"), snap);
        assert_eq!(
            result,
            Err(shared::stale_state::QueueError::OperationIdConflict)
        );
    }

    #[test]
    fn completed_operation_blocks_duplicate_replay() {
        let env = Env::default();
        let id = op_id(&env, 3);
        let payload = Bytes::from_slice(&env, b"transfer");
        let snap = snapshot(0);

        enqueue(&env, &id, &payload, snap).unwrap();

        let claimed = check_before_replay(&env, &id, snap).unwrap();
        assert_eq!(claimed.status, QueuedOperationStatus::InProgress);

        complete_operation(&env, &id).unwrap();

        let after = check_before_replay(&env, &id, snap).unwrap();
        assert_eq!(after.status, QueuedOperationStatus::Completed);
    }

    #[test]
    fn double_complete_is_rejected() {
        let env = Env::default();
        let id = op_id(&env, 4);
        let payload = Bytes::from_slice(&env, b"pay");
        let snap = snapshot(0);

        enqueue(&env, &id, &payload, snap).unwrap();
        check_before_replay(&env, &id, snap).unwrap();
        complete_operation(&env, &id).unwrap();

        let err = complete_operation(&env, &id);
        assert_eq!(
            err,
            Err(shared::stale_state::QueueError::OperationNotInProgress)
        );
    }

    // -----------------------------------------------------------------------
    // Stale version tests (stale_state detection)
    // -----------------------------------------------------------------------

    #[test]
    fn stale_ledger_version_parks_operation_as_conflict() {
        let env = Env::default();
        let id = op_id(&env, 10);
        let payload = Bytes::from_slice(&env, b"withdraw");
        let prepared = snapshot(100);

        enqueue(&env, &id, &payload, prepared).unwrap();

        let current = snapshot(101);
        let result = check_before_replay(&env, &id, current).unwrap();
        assert_eq!(result.status, QueuedOperationStatus::Conflict);
        assert_eq!(
            result.conflict_reason,
            shared::stale_state::StaleStateReason::LedgerAdvanced
        );
    }

    #[test]
    fn stale_wallet_revision_parks_operation_as_conflict() {
        let env = Env::default();
        let id = op_id(&env, 11);
        let payload = Bytes::from_slice(&env, b"claim");
        let prepared = StateSnapshot {
            wallet_revision: 1,
            api_revision: 1,
            ledger_sequence: 100,
        };

        enqueue(&env, &id, &payload, prepared).unwrap();

        let current = StateSnapshot {
            wallet_revision: 2,
            ..prepared
        };
        let result = check_before_replay(&env, &id, current).unwrap();
        assert_eq!(result.status, QueuedOperationStatus::Conflict);
        assert_eq!(
            result.conflict_reason,
            shared::stale_state::StaleStateReason::WalletChanged
        );
    }

    #[test]
    fn conflict_resolution_retry_updates_expected_snapshot() {
        let env = Env::default();
        let id = op_id(&env, 12);
        let payload = Bytes::from_slice(&env, b"retry_me");
        let prepared = snapshot(100);

        enqueue(&env, &id, &payload, prepared).unwrap();

        let stale = snapshot(105);
        check_before_replay(&env, &id, stale).unwrap();

        let resolved =
            resolve_conflict(&env, &id, ConflictResolution::RetryWithLatest, stale).unwrap();
        assert_eq!(resolved.status, QueuedOperationStatus::Pending);
        assert_eq!(resolved.expected.ledger_sequence, 105);
    }

    #[test]
    fn conflict_resolution_discard_tombstones_operation() {
        let env = Env::default();
        let id = op_id(&env, 13);
        let payload = Bytes::from_slice(&env, b"discard_me");
        let prepared = snapshot(100);

        enqueue(&env, &id, &payload, prepared).unwrap();

        let stale = snapshot(200);
        check_before_replay(&env, &id, stale).unwrap();

        let discarded =
            resolve_conflict(&env, &id, ConflictResolution::Discard, stale).unwrap();
        assert_eq!(discarded.status, QueuedOperationStatus::Discarded);
    }

    // -----------------------------------------------------------------------
    // Multi-actor interleaving with duplicate + stale scenarios
    // -----------------------------------------------------------------------

    #[derive(Debug, Eq, PartialEq)]
    enum Outcome {
        Applied,
        StaleVersion,
        Rejected(Error),
    }

    #[test]
    fn concurrent_duplicate_withdrawals_execute_exactly_once() {
        let (env, client, admin, actor2, token, category) = setup_treasury();
        let recipient = Address::generate(&env);

        let action_id = Symbol::new(&env, "dup_withdraw");
        client.schedule_withdraw(
            &admin,
            &action_id,
            &token,
            &recipient,
            &500,
            &category,
            &TimeWindow {
                not_before: 0,
                expires_at: 100,
            },
        );

        let mut harness = MultiActorConcurrencyHarness::new();
        harness.retry_storm(
            MutationAttempt {
                actor: admin.clone(),
                request_id: 1,
                expected_revision: 0,
                attempt: 0,
                mutation: action_id.clone(),
            },
            3,
        );

        let outcomes = harness.run(|attempt| {
            match client.try_execute_scheduled_withdraw(&attempt.actor, &attempt.mutation) {
                Ok(Ok(())) => Outcome::Applied,
                Err(Ok(error)) => Outcome::Rejected(error),
                _ => Outcome::Rejected(Error::InvalidArgument),
            }
        });

        assert_eq!(outcomes[0], Outcome::Applied);
        assert!(outcomes[1..]
            .iter()
            .all(|o| matches!(o, Outcome::Rejected(_))));

        assert_eq!(client.category_balance(&token, &category), 4_500);
        assert_eq!(
            token::StellarAssetClient::new(&env, &token).balance(&recipient),
            500
        );
    }

    #[test]
    fn stale_actor_rejected_while_fresh_actor_succeeds() {
        let (env, client, admin, actor2, token, category) = setup_treasury();
        let recipient = Address::generate(&env);

        let action_a = Symbol::new(&env, "stale_race_a");
        let action_b = Symbol::new(&env, "stale_race_b");
        client.schedule_withdraw(
            &admin,
            &action_a,
            &token,
            &recipient,
            &1_000,
            &category,
            &TimeWindow {
                not_before: 0,
                expires_at: 100,
            },
        );
        client.schedule_withdraw(
            &admin,
            &action_b,
            &token,
            &recipient,
            &1_000,
            &category,
            &TimeWindow {
                not_before: 0,
                expires_at: 100,
            },
        );

        let mut harness = MultiActorConcurrencyHarness::new();
        harness.queue(MutationAttempt {
            actor: admin.clone(),
            request_id: 10,
            expected_revision: 0,
            attempt: 0,
            mutation: action_a,
        });
        harness.queue(MutationAttempt {
            actor: actor2.clone(),
            request_id: 11,
            expected_revision: 0,
            attempt: 0,
            mutation: action_b,
        });

        let mut revision = 0_u64;
        let outcomes = harness.run(|attempt| {
            if attempt.expected_revision != revision {
                return Outcome::StaleVersion;
            }
            match client.try_execute_scheduled_withdraw(&attempt.actor, &attempt.mutation) {
                Ok(Ok(())) => {
                    revision += 1;
                    Outcome::Applied
                }
                Err(Ok(error)) => Outcome::Rejected(error),
                _ => Outcome::Rejected(Error::InvalidArgument),
            }
        });

        assert_eq!(outcomes[0], Outcome::Applied);
        assert_eq!(outcomes[1], Outcome::StaleVersion);

        assert_eq!(client.category_balance(&token, &category), 4_000);
    }

    #[test]
    fn three_actors_only_first_succeeds_rest_are_stale() {
        let (env, client, admin, actor2, token, category) = setup_treasury();
        let actor3 = Address::generate(&env);
        client.add_treasury_manager(&admin, &actor3);
        let recipient = Address::generate(&env);

        let a1 = Symbol::new(&env, "tri_race_a");
        let a2 = Symbol::new(&env, "tri_race_b");
        let a3 = Symbol::new(&env, "tri_race_c");

        for (action, amount) in [(&a1, 500_i128), (&a2, 500), (&a3, 500)] {
            client.schedule_withdraw(
                &admin,
                action,
                &token,
                &recipient,
                &amount,
                &category,
                &TimeWindow {
                    not_before: 0,
                    expires_at: 100,
                },
            );
        }

        let mut harness = MultiActorConcurrencyHarness::new();
        harness.queue(MutationAttempt {
            actor: admin.clone(),
            request_id: 20,
            expected_revision: 0,
            attempt: 0,
            mutation: a1,
        });
        harness.queue(MutationAttempt {
            actor: actor2,
            request_id: 21,
            expected_revision: 0,
            attempt: 0,
            mutation: a2,
        });
        harness.queue(MutationAttempt {
            actor: actor3,
            request_id: 22,
            expected_revision: 0,
            attempt: 0,
            mutation: a3,
        });

        let mut revision = 0_u64;
        let outcomes = harness.run(|attempt| {
            if attempt.expected_revision != revision {
                return Outcome::StaleVersion;
            }
            match client.try_execute_scheduled_withdraw(&attempt.actor, &attempt.mutation) {
                Ok(Ok(())) => {
                    revision += 1;
                    Outcome::Applied
                }
                Err(Ok(error)) => Outcome::Rejected(error),
                _ => Outcome::Rejected(Error::InvalidArgument),
            }
        });

        assert_eq!(outcomes[0], Outcome::Applied);
        assert_eq!(outcomes[1], Outcome::StaleVersion);
        assert_eq!(outcomes[2], Outcome::StaleVersion);

        assert_eq!(client.category_balance(&token, &category), 4_500);
    }

    #[test]
    fn expired_time_window_rejects_all_duplicate_attempts() {
        let (env, client, admin, _actor2, token, category) = setup_treasury();
        let recipient = Address::generate(&env);

        let action_id = Symbol::new(&env, "expired_dup");
        client.schedule_withdraw(
            &admin,
            &action_id,
            &token,
            &recipient,
            &100,
            &category,
            &TimeWindow {
                not_before: 0,
                expires_at: 5,
            },
        );

        env.ledger().set_timestamp(5);

        let mut harness = MultiActorConcurrencyHarness::new();
        harness.retry_storm(
            MutationAttempt {
                actor: admin.clone(),
                request_id: 30,
                expected_revision: 0,
                attempt: 0,
                mutation: action_id,
            },
            2,
        );

        let outcomes = harness.run(|attempt| {
            match client.try_execute_scheduled_withdraw(&attempt.actor, &attempt.mutation) {
                Ok(Ok(())) => Outcome::Applied,
                Err(Ok(error)) => Outcome::Rejected(error),
                _ => Outcome::Rejected(Error::InvalidArgument),
            }
        });

        assert!(outcomes
            .iter()
            .all(|o| *o == Outcome::Rejected(Error::ActionExpired)));

        assert_eq!(client.category_balance(&token, &category), 5_000);
    }
}
