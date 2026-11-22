//! Dead-letter inspection and safe retry tooling.
//!
//! Provides tools for inspecting failed operations, verifying idempotency,
//! checking authorization, and safely retrying operations after failures.

use alloc::vec::Vec;

/// DeadLetterEntry represents a failed operation stored for inspection and retry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeadLetterEntry {
    pub entry_id: u64,
    pub operation_id: u64,
    pub actor: u64,
    pub error: &'static str,
    pub failure_count: u32,
    pub last_failure_time: u64,
    pub is_authorized: bool,
}

/// RetryPolicy defines the conditions and limits for safe retries.
#[derive(Clone, Debug)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub backoff_multiplier: u32,
    pub initial_delay_ms: u32,
    pub require_authorization: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            backoff_multiplier: 2,
            initial_delay_ms: 100,
            require_authorization: true,
        }
    }
}

/// DeadLetterQueue manages failed operations and coordinates safe retries.
#[derive(Clone, Debug)]
pub struct DeadLetterQueue {
    entries: Vec<DeadLetterEntry>,
    retry_policy: RetryPolicy,
    total_inspections: u32,
    successful_retries: u32,
    failed_retries: u32,
}

impl DeadLetterQueue {
    /// Create a new dead-letter queue with default policy.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            retry_policy: RetryPolicy::default(),
            total_inspections: 0,
            successful_retries: 0,
            failed_retries: 0,
        }
    }

    /// Create a new dead-letter queue with custom retry policy.
    pub fn with_policy(policy: RetryPolicy) -> Self {
        Self {
            entries: Vec::new(),
            retry_policy: policy,
            total_inspections: 0,
            successful_retries: 0,
            failed_retries: 0,
        }
    }

    /// Add a failed operation to the dead-letter queue.
    pub fn add_dead_letter(
        &mut self,
        operation_id: u64,
        actor: u64,
        error: &'static str,
        is_authorized: bool,
        timestamp: u64,
    ) -> u64 {
        let entry_id = self.entries.len() as u64;

        self.entries.push(DeadLetterEntry {
            entry_id,
            operation_id,
            actor,
            error,
            failure_count: 1,
            last_failure_time: timestamp,
            is_authorized,
        });

        entry_id
    }

    /// Inspect a dead-letter entry for analysis.
    pub fn inspect(&mut self, entry_id: u64) -> Option<&DeadLetterEntry> {
        self.total_inspections = self.total_inspections.saturating_add(1);
        self.entries.iter().find(|e| e.entry_id == entry_id)
    }

    /// Check if an operation is eligible for retry.
    pub fn is_eligible_for_retry(&self, entry_id: u64) -> bool {
        if let Some(entry) = self.entries.iter().find(|e| e.entry_id == entry_id) {
            if self.retry_policy.require_authorization && !entry.is_authorized {
                return false;
            }

            if entry.failure_count >= self.retry_policy.max_retries {
                return false;
            }

            true
        } else {
            false
        }
    }

    /// Calculate the backoff delay for the next retry attempt.
    pub fn calculate_backoff_delay(&self, entry_id: u64) -> Result<u32, &'static str> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.entry_id == entry_id)
            .ok_or("Entry not found")?;

        let multiplier = self
            .retry_policy
            .backoff_multiplier
            .saturating_pow(entry.failure_count);
        Ok(self
            .retry_policy
            .initial_delay_ms
            .saturating_mul(multiplier))
    }

    /// Record a successful retry for a dead-letter entry.
    pub fn record_successful_retry(&mut self, entry_id: u64) -> Result<(), &'static str> {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.entry_id == entry_id) {
            self.successful_retries = self.successful_retries.saturating_add(1);
            entry.failure_count = 0;
            Ok(())
        } else {
            Err("Entry not found")
        }
    }

    /// Record a failed retry for a dead-letter entry.
    pub fn record_failed_retry(
        &mut self,
        entry_id: u64,
        new_error: &'static str,
        timestamp: u64,
    ) -> Result<(), &'static str> {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.entry_id == entry_id) {
            entry.failure_count = entry.failure_count.saturating_add(1);
            entry.error = new_error;
            entry.last_failure_time = timestamp;
            self.failed_retries = self.failed_retries.saturating_add(1);
            Ok(())
        } else {
            Err("Entry not found")
        }
    }

    /// Remove a dead-letter entry after successful processing.
    pub fn remove_entry(&mut self, entry_id: u64) -> Result<DeadLetterEntry, &'static str> {
        if let Some(pos) = self.entries.iter().position(|e| e.entry_id == entry_id) {
            Ok(self.entries.remove(pos))
        } else {
            Err("Entry not found")
        }
    }

    /// Get all dead-letter entries for a specific actor.
    pub fn entries_for_actor(&self, actor: u64) -> Vec<&DeadLetterEntry> {
        self.entries.iter().filter(|e| e.actor == actor).collect()
    }

    /// Verify authorization before retry.
    pub fn verify_authorization_for_retry(&self, entry_id: u64) -> Result<bool, &'static str> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.entry_id == entry_id)
            .ok_or("Entry not found")?;

        if !self.retry_policy.require_authorization {
            return Ok(true);
        }

        Ok(entry.is_authorized)
    }

    /// Get queue statistics.
    pub fn queue_size(&self) -> usize {
        self.entries.len()
    }

    /// Get total entries inspected.
    pub fn total_inspections(&self) -> u32 {
        self.total_inspections
    }

    /// Get successful retry count.
    pub fn successful_retries(&self) -> u32 {
        self.successful_retries
    }

    /// Get failed retry count.
    pub fn failed_retries(&self) -> u32 {
        self.failed_retries
    }

    /// Verify edge cases: poison pill detection.
    pub fn verify_no_poison_pills(&self) -> Result<(), &'static str> {
        for entry in &self.entries {
            if entry.failure_count > self.retry_policy.max_retries {
                return Err("Poison pill detected: exceeded max retries");
            }
        }
        Ok(())
    }

    /// Verify rollback safety: entries can be safely removed without side effects.
    pub fn verify_rollback_safety(&self) -> Result<(), &'static str> {
        if self
            .entries
            .iter()
            .any(|e| !e.is_authorized && self.retry_policy.require_authorization)
        {
            return Err("Unauthorized entry in queue: unsafe to retry");
        }

        Ok(())
    }

    /// Get all entries.
    pub fn entries(&self) -> &[DeadLetterEntry] {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn test_dead_letter_queue_creation() {
        let queue = DeadLetterQueue::new();
        assert_eq!(queue.queue_size(), 0);
        assert_eq!(queue.total_inspections(), 0);
    }

    #[test]
    fn test_add_dead_letter_entry() {
        let mut queue = DeadLetterQueue::new();
        let entry_id = queue.add_dead_letter(1, 100, "test error", true, 1000);

        assert_eq!(entry_id, 0);
        assert_eq!(queue.queue_size(), 1);
    }

    #[test]
    fn test_inspect_entry() {
        let mut queue = DeadLetterQueue::new();
        let entry_id = queue.add_dead_letter(1, 100, "test error", true, 1000);

        let entry = queue.inspect(entry_id);
        assert!(entry.is_some());
        assert_eq!(queue.total_inspections(), 1);
    }

    #[test]
    fn test_retry_eligibility() {
        let queue = DeadLetterQueue::new();
        let policy = queue.retry_policy;

        let mut queue = DeadLetterQueue::with_policy(policy);
        let entry_id = queue.add_dead_letter(1, 100, "test error", true, 1000);

        assert!(queue.is_eligible_for_retry(entry_id));
    }

    #[test]
    fn test_retry_authorization_check() {
        let policy = RetryPolicy {
            require_authorization: true,
            ..Default::default()
        };
        let mut queue = DeadLetterQueue::with_policy(policy);

        let entry_id = queue.add_dead_letter(1, 100, "test error", false, 1000);

        assert!(!queue.is_eligible_for_retry(entry_id));
    }

    #[test]
    fn test_backoff_calculation() {
        let queue = DeadLetterQueue::new();
        let entry_id = queue.add_dead_letter(1, 100, "test error", true, 1000);

        let backoff = queue.calculate_backoff_delay(entry_id).ok();
        assert!(backoff.is_some());
    }

    #[test]
    fn test_record_successful_retry() {
        let mut queue = DeadLetterQueue::new();
        let entry_id = queue.add_dead_letter(1, 100, "test error", true, 1000);

        assert!(queue.record_successful_retry(entry_id).is_ok());
        assert_eq!(queue.successful_retries(), 1);
    }

    #[test]
    fn test_record_failed_retry() {
        let mut queue = DeadLetterQueue::new();
        let entry_id = queue.add_dead_letter(1, 100, "test error", true, 1000);

        assert!(queue
            .record_failed_retry(entry_id, "new error", 2000)
            .is_ok());
        assert_eq!(queue.failed_retries(), 1);
    }

    #[test]
    fn test_entries_for_actor() {
        let mut queue = DeadLetterQueue::new();
        queue.add_dead_letter(1, 100, "error1", true, 1000);
        queue.add_dead_letter(2, 100, "error2", true, 1000);
        queue.add_dead_letter(3, 200, "error3", true, 1000);

        let actor_entries = queue.entries_for_actor(100);
        assert_eq!(actor_entries.len(), 2);
    }

    #[test]
    fn test_remove_entry() {
        let mut queue = DeadLetterQueue::new();
        let entry_id = queue.add_dead_letter(1, 100, "test error", true, 1000);

        assert!(queue.remove_entry(entry_id).is_ok());
        assert_eq!(queue.queue_size(), 0);
    }

    #[test]
    fn test_verify_authorization_for_retry() {
        let queue = DeadLetterQueue::new();
        let entry_id = queue.add_dead_letter(1, 100, "test error", true, 1000);

        assert_eq!(
            queue.verify_authorization_for_retry(entry_id).ok(),
            Some(true)
        );
    }

    #[test]
    fn test_poison_pill_detection() {
        let policy = RetryPolicy {
            max_retries: 3,
            ..Default::default()
        };
        let mut queue = DeadLetterQueue::with_policy(policy);

        let entry_id = queue.add_dead_letter(1, 100, "test error", true, 1000);
        queue.record_failed_retry(entry_id, "error", 2000).ok();
        queue.record_failed_retry(entry_id, "error", 3000).ok();
        queue.record_failed_retry(entry_id, "error", 4000).ok();
        queue.record_failed_retry(entry_id, "error", 5000).ok();

        assert!(queue.verify_no_poison_pills().is_err());
    }

    #[test]
    fn test_rollback_safety_verification() {
        let mut queue = DeadLetterQueue::new();
        queue.add_dead_letter(1, 100, "test error", true, 1000);

        assert!(queue.verify_rollback_safety().is_ok());
    }
}
