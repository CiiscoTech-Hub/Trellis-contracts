//! Safe cancellation and cleanup for long-running jobs (Issue #444).
//!
//! Covers cancelling pending, in-backoff and dead-lettered jobs, the cleanup
//! that follows (indexes, queue capacity, dedupe key), idempotent retries of a
//! cancel request, and the admin-only authorization path.

#![cfg(test)]

extern crate std;

use soroban_sdk::testutils::Address as _;
use soroban_sdk::{contract, contractimpl, Address, BytesN, Env};

use crate::auth::set_admin;
use crate::errors::Error;
use crate::jobs::{
    cancel_job, configure_queue_capacity, dead_letter_job_ids, dedupe_key_u64, enqueue_job,
    get_cancellation, get_job, pending_job_ids, reprocess_job, requeue_dead_letter, run_due_job,
    EnqueueOutcome, Job, JobError, JobHandler, JobPayload, JobStatus, RetryPolicy, RunOutcome,
};

#[contract]
pub struct CancelFixture;

#[contractimpl]
impl CancelFixture {
    pub fn noop(_env: Env) {}
}

/// Always fails with a retryable error.
struct FailingHandler;

impl JobHandler for FailingHandler {
    fn handle(&self, _env: &Env, _job: &Job) -> Result<(), Error> {
        Err(Error::Expired)
    }
}

/// Always succeeds.
struct OkHandler;

impl JobHandler for OkHandler {
    fn handle(&self, _env: &Env, _job: &Job) -> Result<(), Error> {
        Ok(())
    }
}

fn key(env: &Env, value: u64) -> BytesN<32> {
    dedupe_key_u64(env, 0x6361_6e63, value)
}

fn setup(env: &Env) -> (Address, Address) {
    env.mock_all_auths();
    let admin = Address::generate(env);
    let contract_id = env.register_contract(None, CancelFixture);
    env.as_contract(&contract_id, || {
        set_admin(env, &admin);
    });
    (contract_id, admin)
}

fn created(outcome: EnqueueOutcome) -> u64 {
    match outcome {
        EnqueueOutcome::Created(id) => id,
        other => panic!("expected a new job, got {:?}", other),
    }
}

#[test]
fn cancelling_a_pending_job_removes_it_from_the_queue() {
    let env = Env::default();
    let (contract_id, admin) = setup(&env);

    let id = env.as_contract(&contract_id, || {
        created(enqueue_job(&env, JobPayload::None, key(&env, 1), 0, None).unwrap())
    });
    env.as_contract(&contract_id, || {
        let job = cancel_job(&env, &admin, id, 7).unwrap();
        assert_eq!(job.status, JobStatus::Cancelled);
        assert_eq!(get_job(&env, id).unwrap().status, JobStatus::Cancelled);
        assert_eq!(pending_job_ids(&env).len(), 0);

        let record = get_cancellation(&env, id).unwrap();
        assert_eq!(record.previous_status, JobStatus::Pending);
        assert_eq!(record.reason, 7);
        assert_eq!(record.cancelled_by, admin);
        assert_eq!(record.attempts, 0);

        let worker = Address::generate(&env);
        assert_eq!(
            run_due_job(&env, &worker, 100, &OkHandler).unwrap(),
            RunOutcome::Empty
        );
    });
}

#[test]
fn a_job_in_backoff_can_be_cancelled_between_attempts() {
    let env = Env::default();
    let (contract_id, admin) = setup(&env);
    let worker = Address::generate(&env);

    let id = env.as_contract(&contract_id, || {
        let id = created(enqueue_job(&env, JobPayload::None, key(&env, 2), 0, None).unwrap());
        let RunOutcome::Retried(job) = run_due_job(&env, &worker, 0, &FailingHandler).unwrap()
        else {
            panic!("expected a retry")
        };
        assert_eq!(job.attempts, 1);
        id
    });
    env.as_contract(&contract_id, || {
        cancel_job(&env, &admin, id, 0).unwrap();
        assert_eq!(get_cancellation(&env, id).unwrap().attempts, 1);
        // Neither the scheduler nor an explicit reprocess runs it again.
        assert_eq!(
            run_due_job(&env, &worker, 1_000_000, &OkHandler).unwrap(),
            RunOutcome::Empty
        );
        assert_eq!(
            reprocess_job(&env, &worker, id, 1_000_000, &OkHandler),
            Err(JobError::Cancelled)
        );
    });
}

#[test]
fn cancelling_a_dead_letter_cleans_the_dead_letter_index() {
    let env = Env::default();
    let (contract_id, admin) = setup(&env);
    let worker = Address::generate(&env);

    let id = env.as_contract(&contract_id, || {
        let id = created(
            enqueue_job(&env, JobPayload::None, key(&env, 3), 0, Some(RetryPolicy::no_retry()))
                .unwrap(),
        );
        let RunOutcome::DeadLettered(_) = run_due_job(&env, &worker, 0, &FailingHandler).unwrap()
        else {
            panic!("expected a dead letter")
        };
        id
    });
    env.as_contract(&contract_id, || {
        cancel_job(&env, &admin, id, 0).unwrap();
        assert_eq!(dead_letter_job_ids(&env).len(), 0);
        assert_eq!(
            get_cancellation(&env, id).unwrap().previous_status,
            JobStatus::DeadLettered
        );
    });
    env.as_contract(&contract_id, || {
        // A cancelled job is not a dead letter any more, so it cannot be requeued.
        assert_eq!(
            requeue_dead_letter(&env, &admin, id, 10),
            Err(JobError::NotRetryable)
        );
    });
}

#[test]
fn cancellation_frees_queue_capacity_and_releases_the_dedupe_key() {
    let env = Env::default();
    let (contract_id, admin) = setup(&env);

    env.as_contract(&contract_id, || {
        configure_queue_capacity(&env, &admin, 1).unwrap();
    });
    let first = env.as_contract(&contract_id, || {
        let first = created(enqueue_job(&env, JobPayload::None, key(&env, 4), 0, None).unwrap());
        assert_eq!(
            enqueue_job(&env, JobPayload::None, key(&env, 5), 0, None),
            Err(JobError::QueueFull)
        );
        first
    });
    env.as_contract(&contract_id, || {
        cancel_job(&env, &admin, first, 0).unwrap();
    });
    env.as_contract(&contract_id, || {
        // The slot is free again, and the cancelled work can be re-enqueued
        // under its original key as a brand-new job.
        let again = created(enqueue_job(&env, JobPayload::None, key(&env, 4), 0, None).unwrap());
        assert_ne!(again, first);
        assert_eq!(get_job(&env, first).unwrap().status, JobStatus::Cancelled);
        assert_eq!(get_job(&env, again).unwrap().status, JobStatus::Pending);
    });
}

#[test]
fn repeating_a_cancel_is_idempotent() {
    let env = Env::default();
    let (contract_id, admin) = setup(&env);

    let id = env.as_contract(&contract_id, || {
        created(enqueue_job(&env, JobPayload::None, key(&env, 6), 0, None).unwrap())
    });
    env.as_contract(&contract_id, || {
        cancel_job(&env, &admin, id, 1).unwrap();
    });
    env.as_contract(&contract_id, || {
        let job = cancel_job(&env, &admin, id, 2).unwrap();
        assert_eq!(job.status, JobStatus::Cancelled);
        // The first cancellation's record is kept.
        assert_eq!(get_cancellation(&env, id).unwrap().reason, 1);
    });
}

#[test]
fn completed_or_missing_jobs_cannot_be_cancelled() {
    let env = Env::default();
    let (contract_id, admin) = setup(&env);
    let worker = Address::generate(&env);

    let id = env.as_contract(&contract_id, || {
        let id = created(enqueue_job(&env, JobPayload::None, key(&env, 7), 0, None).unwrap());
        let RunOutcome::Succeeded(_) = run_due_job(&env, &worker, 0, &OkHandler).unwrap() else {
            panic!("expected success")
        };
        id
    });
    env.as_contract(&contract_id, || {
        assert_eq!(
            cancel_job(&env, &admin, id, 0),
            Err(JobError::AlreadyCompleted)
        );
        assert_eq!(get_cancellation(&env, id), None);
    });
    env.as_contract(&contract_id, || {
        assert_eq!(cancel_job(&env, &admin, 999, 0), Err(JobError::NotFound));
    });
}

#[test]
fn only_the_admin_can_cancel() {
    let env = Env::default();
    let (contract_id, _admin) = setup(&env);
    let stranger = Address::generate(&env);

    env.as_contract(&contract_id, || {
        let id = created(enqueue_job(&env, JobPayload::None, key(&env, 8), 0, None).unwrap());
        assert_eq!(
            cancel_job(&env, &stranger, id, 0),
            Err(JobError::Unauthorized)
        );
        assert_eq!(get_job(&env, id).unwrap().status, JobStatus::Pending);
        assert_eq!(pending_job_ids(&env).len(), 1);
    });
}
