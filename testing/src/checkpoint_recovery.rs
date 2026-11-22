//! Resumable orphan-repair command with checkpoints.
//!
//! Provides checkpoint and recovery mechanisms that allow repair operations
//! to be interrupted and resumed safely without data loss or duplication.

use alloc::vec::Vec;

/// RepairCheckpoint captures the state of a repair operation at a point in time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairCheckpoint {
    pub checkpoint_id: u64,
    pub last_processed_id: u64,
    pub items_repaired: u32,
    pub items_failed: u32,
    pub timestamp: u64,
}

/// RepairOperation tracks the status and progress of a repair task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepairStatus {
    Pending,
    InProgress,
    Paused,
    Completed,
    Failed,
}

/// OrphanRepairTracker manages resumable repair operations with checkpoints.
#[derive(Clone, Debug)]
pub struct OrphanRepairTracker {
    operation_id: u64,
    status: RepairStatus,
    total_orphans: u32,
    checkpoints: Vec<RepairCheckpoint>,
    current_checkpoint: Option<RepairCheckpoint>,
    items_repaired: u32,
    items_failed: u32,
    last_error: Option<&'static str>,
}

impl OrphanRepairTracker {
    /// Create a new orphan repair tracker.
    pub fn new(operation_id: u64, total_orphans: u32) -> Self {
        Self {
            operation_id,
            status: RepairStatus::Pending,
            total_orphans,
            checkpoints: Vec::new(),
            current_checkpoint: None,
            items_repaired: 0,
            items_failed: 0,
            last_error: None,
        }
    }

    /// Start the repair operation.
    pub fn start(&mut self) {
        self.status = RepairStatus::InProgress;
    }

    /// Pause the repair operation and create a checkpoint.
    pub fn pause(&mut self, timestamp: u64) -> Result<RepairCheckpoint, &'static str> {
        if self.status != RepairStatus::InProgress {
            return Err("Operation not in progress");
        }

        let checkpoint = RepairCheckpoint {
            checkpoint_id: self.checkpoints.len() as u64,
            last_processed_id: self.items_repaired as u64,
            items_repaired: self.items_repaired,
            items_failed: self.items_failed,
            timestamp,
        };

        self.checkpoints.push(checkpoint.clone());
        self.current_checkpoint = Some(checkpoint.clone());
        self.status = RepairStatus::Paused;

        Ok(checkpoint)
    }

    /// Resume the repair operation from the last checkpoint.
    pub fn resume(&mut self) -> Result<RepairCheckpoint, &'static str> {
        if self.status != RepairStatus::Paused {
            return Err("Operation not paused");
        }

        let checkpoint = self
            .current_checkpoint
            .as_ref()
            .cloned()
            .ok_or("No checkpoint available")?;

        self.status = RepairStatus::InProgress;
        Ok(checkpoint)
    }

    /// Record a successful repair.
    pub fn record_repair(&mut self) -> Result<(), &'static str> {
        if self.status != RepairStatus::InProgress {
            return Err("Operation not in progress");
        }

        if self.items_repaired >= self.total_orphans {
            return Err("All items already repaired");
        }

        self.items_repaired = self.items_repaired.saturating_add(1);
        Ok(())
    }

    /// Record a failed repair.
    pub fn record_failure(&mut self, error: &'static str) -> Result<(), &'static str> {
        if self.status != RepairStatus::InProgress {
            return Err("Operation not in progress");
        }

        self.items_failed = self.items_failed.saturating_add(1);
        self.last_error = Some(error);

        if self.items_failed > self.total_orphans / 2 {
            self.status = RepairStatus::Failed;
            return Err("Too many failures, operation failed");
        }

        Ok(())
    }

    /// Complete the repair operation.
    pub fn complete(&mut self) -> Result<(), &'static str> {
        if self.status != RepairStatus::InProgress {
            return Err("Operation not in progress");
        }

        if self.items_repaired + self.items_failed < self.total_orphans {
            return Err("Not all items processed");
        }

        self.status = RepairStatus::Completed;
        Ok(())
    }

    /// Get the current operation status.
    pub fn status(&self) -> &RepairStatus {
        &self.status
    }

    /// Get progress percentage.
    pub fn progress_percent(&self) -> u32 {
        if self.total_orphans == 0 {
            return 100;
        }
        ((self.items_repaired + self.items_failed) * 100) / self.total_orphans
    }

    /// Verify checkpoint safety (no duplication).
    pub fn verify_checkpoint_safety(&self) -> Result<(), &'static str> {
        let mut seen_ids = Vec::new();

        for checkpoint in &self.checkpoints {
            if seen_ids.contains(&checkpoint.last_processed_id) {
                return Err("Duplicate processing detected in checkpoint");
            }
            seen_ids.push(checkpoint.last_processed_id);
        }

        Ok(())
    }

    /// Verify recovery consistency (no data loss).
    pub fn verify_recovery_consistency(&self) -> Result<(), &'static str> {
        let mut total_processed = 0;

        for checkpoint in &self.checkpoints {
            if checkpoint.items_repaired + checkpoint.items_failed < total_processed {
                return Err("Checkpoint shows fewer items than previous checkpoint");
            }
            total_processed = checkpoint.items_repaired + checkpoint.items_failed;
        }

        Ok(())
    }

    /// Get all checkpoints.
    pub fn checkpoints(&self) -> &[RepairCheckpoint] {
        &self.checkpoints
    }

    /// Get items repaired count.
    pub fn items_repaired(&self) -> u32 {
        self.items_repaired
    }

    /// Get items failed count.
    pub fn items_failed(&self) -> u32 {
        self.items_failed
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn test_repair_tracker_creation() {
        let tracker = OrphanRepairTracker::new(1, 100);
        assert_eq!(tracker.operation_id, 1);
        assert_eq!(tracker.total_orphans, 100);
        assert_eq!(tracker.status, RepairStatus::Pending);
    }

    #[test]
    fn test_repair_lifecycle() {
        let mut tracker = OrphanRepairTracker::new(1, 100);

        tracker.start();
        assert_eq!(tracker.status, RepairStatus::InProgress);

        tracker.record_repair().ok();
        assert_eq!(tracker.items_repaired(), 1);

        let checkpoint = tracker.pause(1000).ok();
        assert!(checkpoint.is_some());
        assert_eq!(tracker.status, RepairStatus::Paused);
    }

    #[test]
    fn test_checkpoint_creation_and_resume() {
        let mut tracker = OrphanRepairTracker::new(1, 100);
        tracker.start();

        for _ in 0..10 {
            tracker.record_repair().ok();
        }

        let checkpoint = tracker.pause(1000).ok().flatten();
        assert_eq!(checkpoint.map(|c| c.items_repaired), Some(10));

        let resume_result = tracker.resume();
        assert!(resume_result.is_ok());
        assert_eq!(tracker.status, RepairStatus::InProgress);
    }

    #[test]
    fn test_repair_tracking() {
        let mut tracker = OrphanRepairTracker::new(1, 100);
        tracker.start();

        for _ in 0..50 {
            tracker.record_repair().ok();
        }

        for _ in 0..10 {
            tracker.record_failure("test error").ok();
        }

        assert_eq!(tracker.items_repaired(), 50);
        assert_eq!(tracker.items_failed(), 10);
    }

    #[test]
    fn test_progress_tracking() {
        let mut tracker = OrphanRepairTracker::new(1, 100);
        tracker.start();

        for _ in 0..50 {
            tracker.record_repair().ok();
        }

        assert_eq!(tracker.progress_percent(), 50);
    }

    #[test]
    fn test_checkpoint_safety_verification() {
        let mut tracker = OrphanRepairTracker::new(1, 100);
        tracker.start();

        for _ in 0..10 {
            tracker.record_repair().ok();
        }

        tracker.pause(1000).ok();

        assert!(tracker.verify_checkpoint_safety().is_ok());
    }

    #[test]
    fn test_recovery_consistency() {
        let mut tracker = OrphanRepairTracker::new(1, 100);
        tracker.start();

        for _ in 0..10 {
            tracker.record_repair().ok();
        }

        tracker.pause(1000).ok();
        tracker.resume().ok();

        for _ in 0..10 {
            tracker.record_repair().ok();
        }

        tracker.pause(2000).ok();

        assert!(tracker.verify_recovery_consistency().is_ok());
    }

    #[test]
    fn test_completion() {
        let mut tracker = OrphanRepairTracker::new(1, 10);
        tracker.start();

        for _ in 0..10 {
            tracker.record_repair().ok();
        }

        let result = tracker.complete();
        assert!(result.is_ok());
        assert_eq!(tracker.status, RepairStatus::Completed);
    }
}
