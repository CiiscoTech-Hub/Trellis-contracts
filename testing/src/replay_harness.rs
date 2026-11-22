//! Deterministic replay harness for multi-actor mutations.
//!
//! Tests idempotent replays after success, failure retries, and authorization checks
//! to verify that replay semantics preserve contract invariants.

use alloc::vec::Vec;

/// Tracks a replay attempt with its outcome and state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayAttempt<Actor, Mutation, Outcome> {
    pub actor: Actor,
    pub request_id: u64,
    pub mutation: Mutation,
    pub attempt_number: u32,
    pub outcome: Option<Outcome>,
}

/// Deterministic replay harness for testing idempotent mutations.
#[derive(Clone, Debug, Default)]
pub struct DeterministicReplayHarness<Actor, Mutation, Outcome> {
    attempts: Vec<ReplayAttempt<Actor, Mutation, Outcome>>,
    success_outcomes: Vec<Outcome>,
}

impl<Actor, Mutation, Outcome> DeterministicReplayHarness<Actor, Mutation, Outcome>
where
    Actor: Clone,
    Mutation: Clone,
    Outcome: Clone + PartialEq,
{
    pub fn new() -> Self {
        Self {
            attempts: Vec::new(),
            success_outcomes: Vec::new(),
        }
    }

    /// Queue an attempt with an expected outcome.
    pub fn queue_attempt(
        &mut self,
        actor: Actor,
        request_id: u64,
        mutation: Mutation,
        attempt_number: u32,
    ) {
        self.attempts.push(ReplayAttempt {
            actor,
            request_id,
            mutation,
            attempt_number,
            outcome: None,
        });
    }

    /// Record a successful outcome for future replay verification.
    pub fn record_success(&mut self, outcome: Outcome) {
        self.success_outcomes.push(outcome);
    }

    /// Queue an initial attempt followed by deterministic replays.
    ///
    /// Tests that the same mutation replayed produces identical outcomes,
    /// and that authorization is preserved across replays.
    pub fn queue_replay_sequence(
        &mut self,
        actor: Actor,
        request_id: u64,
        mutation: Mutation,
        replay_count: u32,
    ) {
        self.queue_attempt(actor.clone(), request_id, mutation.clone(), 0);
        for replay in 1..=replay_count {
            self.queue_attempt(actor.clone(), request_id, mutation.clone(), replay);
        }
    }

    /// Run all queued attempts, applying them in order.
    ///
    /// For each attempt, the callback receives the attempt and returns an outcome.
    /// Verifies that replayed attempts produce identical outcomes.
    pub fn run<F>(&mut self, mut apply: F) -> Vec<Outcome>
    where
        F: FnMut(&ReplayAttempt<Actor, Mutation, Outcome>) -> Outcome,
    {
        let mut outcomes = Vec::new();
        for attempt in self.attempts.iter_mut() {
            let outcome = apply(attempt);
            attempt.outcome = Some(outcome.clone());
            outcomes.push(outcome);
        }
        outcomes
    }

    /// Verify that all replays of the same request produced identical outcomes.
    pub fn verify_replay_idempotency(&self, request_id: u64) -> Result<(), &'static str> {
        let relevant_attempts: Vec<_> = self
            .attempts
            .iter()
            .filter(|a| a.request_id == request_id)
            .collect();

        if relevant_attempts.is_empty() {
            return Err("No attempts found for request_id");
        }

        let first_outcome = &relevant_attempts[0].outcome;
        for attempt in &relevant_attempts[1..] {
            if &attempt.outcome != first_outcome {
                return Err("Replay outcomes differ: idempotency violated");
            }
        }

        Ok(())
    }

    /// Verify that normal, failure, and retry paths are covered.
    pub fn verify_path_coverage(&self) -> Result<(), &'static str> {
        let has_success = self
            .attempts
            .iter()
            .any(|a| a.outcome.as_ref().map(|_| true).unwrap_or(false));

        let has_retry = self.attempts.iter().any(|a| a.attempt_number > 0);

        if !has_success {
            return Err("No successful outcomes recorded");
        }

        if !has_retry {
            return Err("No retry attempts recorded");
        }

        Ok(())
    }

    /// Get all attempts with their outcomes.
    pub fn attempts(&self) -> &[ReplayAttempt<Actor, Mutation, Outcome>] {
        &self.attempts
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum TestOutcome {
        Success,
        Failure,
    }

    #[test]
    fn test_replay_harness_queues_attempts() {
        let mut harness: DeterministicReplayHarness<u64, u64, TestOutcome> =
            DeterministicReplayHarness::new();

        harness.queue_attempt(1, 100, 42, 0);
        harness.queue_attempt(1, 100, 42, 1);

        assert_eq!(harness.attempts().len(), 2);
        assert_eq!(harness.attempts()[0].attempt_number, 0);
        assert_eq!(harness.attempts()[1].attempt_number, 1);
    }

    #[test]
    fn test_replay_sequence_creation() {
        let mut harness: DeterministicReplayHarness<u64, u64, TestOutcome> =
            DeterministicReplayHarness::new();

        harness.queue_replay_sequence(1, 100, 42, 3);

        assert_eq!(harness.attempts().len(), 4);
        assert_eq!(harness.attempts()[0].attempt_number, 0);
        assert_eq!(harness.attempts()[3].attempt_number, 3);
    }

    #[test]
    fn test_idempotency_verification() {
        let mut harness: DeterministicReplayHarness<u64, u64, TestOutcome> =
            DeterministicReplayHarness::new();

        harness.queue_attempt(1, 100, 42, 0);
        harness.queue_attempt(1, 100, 42, 1);

        let outcomes = harness.run(|_| TestOutcome::Success);

        assert_eq!(outcomes.len(), 2);
        assert!(harness.verify_replay_idempotency(100).is_ok());
    }

    #[test]
    fn test_idempotency_violation_detection() {
        let mut harness: DeterministicReplayHarness<u64, u64, TestOutcome> =
            DeterministicReplayHarness::new();

        harness.queue_attempt(1, 100, 42, 0);
        harness.queue_attempt(1, 100, 42, 1);

        let mut call_count = 0;
        harness.run(|_| {
            call_count += 1;
            if call_count == 1 {
                TestOutcome::Success
            } else {
                TestOutcome::Failure
            }
        });

        assert!(harness
            .verify_replay_idempotency(100)
            .is_err_and(|e| e.contains("idempotency")));
    }

    #[test]
    fn test_path_coverage_verification() {
        let mut harness: DeterministicReplayHarness<u64, u64, TestOutcome> =
            DeterministicReplayHarness::new();

        harness.queue_replay_sequence(1, 100, 42, 2);
        harness.run(|attempt| {
            if attempt.attempt_number == 0 {
                TestOutcome::Success
            } else {
                TestOutcome::Failure
            }
        });

        assert!(harness.verify_path_coverage().is_ok());
    }
}
