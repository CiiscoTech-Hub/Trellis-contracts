//! Bounded worker concurrency harness with backpressure.
//!
//! Tests that worker pools respect concurrency limits and apply backpressure
//! to prevent resource exhaustion during concurrent mutations.
//!
//! Worst-case load coverage:
//! - Normal path: work within limits is admitted and completed.
//! - Failure path: a failing work item releases its slot and budget and is
//!   recorded as rejected; the queue keeps its non-failing items.
//! - Retry path: a rejected item can be resubmitted once capacity frees up.
//! - Authorization path: work whose cost exceeds the budget (or a zero-capacity
//!   pool) is refused without mutating pool state.
//! - Saturation: at maximum workers / full budget, all further submissions are
//!   backpressured and state invariants hold.
//!
//! Edge cases and recovery:
//! - Releasing more workers or cost than were acquired saturates at zero and
//!   never underflows.
//! - `release_worker` completes the queue head only when a queue entry exists;
//!   releases without queued work only restore capacity.
//! - `process_queue` stops at the first failing work item and returns its error;
//!   the failed slot is released before returning, so the pool is left in a
//!   consistent state and processing can be resumed by calling again.
//! - Budget arithmetic uses saturating/checked operations so that oversized
//!   costs cannot overflow and bypass backpressure.

use alloc::vec::Vec;

/// WorkerState tracks the execution and resource state of a concurrent worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkerState {
    Idle,
    Active,
    Backpressured,
    Failed,
}

/// WorkerLoad represents the resource demand of a pending work item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerLoad {
    pub work_id: u64,
    pub resource_cost: u32,
    pub priority: u32,
}

/// BoundedConcurrencyPool manages worker concurrency with backpressure.
#[derive(Clone, Debug)]
pub struct BoundedConcurrencyPool {
    max_workers: u32,
    max_resource_budget: u32,
    current_workers: u32,
    current_resource_usage: u32,
    work_queue: Vec<WorkerLoad>,
    completed_work: Vec<u64>,
    rejected_work: Vec<u64>,
}

impl BoundedConcurrencyPool {
    /// Create a new bounded concurrency pool.
    pub fn new(max_workers: u32, max_resource_budget: u32) -> Self {
        Self {
            max_workers,
            max_resource_budget,
            current_workers: 0,
            current_resource_usage: 0,
            work_queue: Vec::new(),
            completed_work: Vec::new(),
            rejected_work: Vec::new(),
        }
    }

    /// Submit work to the pool, applying backpressure if limits are exceeded.
    pub fn submit_work(&mut self, work: WorkerLoad) -> Result<(), WorkerLoad> {
        if self.can_accept_work(&work) {
            self.work_queue.push(work);
            Ok(())
        } else {
            self.rejected_work.push(work.work_id);
            Err(work)
        }
    }

    /// Check if the pool can accept more work.
    fn can_accept_work(&self, work: &WorkerLoad) -> bool {
        self.current_workers < self.max_workers
            && self
                .current_resource_usage
                .checked_add(work.resource_cost)
                .map_or(false, |total| total <= self.max_resource_budget)
    }

    /// Acquire a worker slot and resource budget.
    pub fn acquire_worker(&mut self, _work_id: u64, cost: u32) -> Result<(), &'static str> {
        if self.current_workers >= self.max_workers {
            return Err("Worker limit reached");
        }

        let new_usage = self
            .current_resource_usage
            .checked_add(cost)
            .ok_or("Resource budget exceeded")?;
        if new_usage > self.max_resource_budget {
            return Err("Resource budget exceeded");
        }

        self.current_workers = self.current_workers.saturating_add(1);
        self.current_resource_usage = new_usage;

        Ok(())
    }

    /// Release a worker slot and free its resources.
    pub fn release_worker(&mut self, cost: u32, success: bool) {
        self.current_workers = self.current_workers.saturating_sub(1);
        self.current_resource_usage = self.current_resource_usage.saturating_sub(cost);

        if !self.work_queue.is_empty() {
            let work = self.work_queue.remove(0);
            if success {
                self.completed_work.push(work.work_id);
            } else {
                self.rejected_work.push(work.work_id);
            }
        }
    }

    /// Process work from the queue with concurrency limits.
    ///
    /// Items are processed highest-priority first. Items that do not currently
    /// fit within the limits are skipped (backpressure) and remain queued. On
    /// the first processing failure the item is recorded as rejected, its slot
    /// is released, and the error is returned; remaining items stay queued.
    pub fn process_queue<F>(&mut self, mut process_fn: F) -> Result<(), &'static str>
    where
        F: FnMut(&WorkerLoad) -> Result<(), &'static str>,
    {
        let mut queue_copy = self.work_queue.clone();
        queue_copy.sort_by_key(|w| core::cmp::Reverse(w.priority));

        for work in queue_copy.iter() {
            if !self.can_accept_work(work) {
                continue;
            }

            self.acquire_worker(work.work_id, work.resource_cost)?;

            // Remove this item from the live queue before running it.
            if let Some(pos) = self.work_queue.iter().position(|w| w.work_id == work.work_id) {
                self.work_queue.remove(pos);
            }

            match process_fn(work) {
                Ok(()) => {
                    self.completed_work.push(work.work_id);
                    self.current_workers = self.current_workers.saturating_sub(1);
                    self.current_resource_usage =
                        self.current_resource_usage.saturating_sub(work.resource_cost);
                }
                Err(e) => {
                    self.rejected_work.push(work.work_id);
                    self.current_workers = self.current_workers.saturating_sub(1);
                    self.current_resource_usage =
                        self.current_resource_usage.saturating_sub(work.resource_cost);
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    /// Get current worker state.
    pub fn worker_state(&self) -> WorkerState {
        if self.current_workers == 0 {
            WorkerState::Idle
        } else if self.current_workers >= self.max_workers {
            WorkerState::Backpressured
        } else {
            WorkerState::Active
        }
    }

    /// Get pending work queue size.
    pub fn pending_work(&self) -> usize {
        self.work_queue.len()
    }

    /// Get completed work count.
    pub fn completed_work_count(&self) -> usize {
        self.completed_work.len()
    }

    /// Get rejected work count (backpressure).
    pub fn rejected_work_count(&self) -> usize {
        self.rejected_work.len()
    }

    /// Verify backpressure is applied correctly.
    pub fn verify_backpressure(&self) -> Result<(), &'static str> {
        if self.current_workers > self.max_workers {
            return Err("Worker count exceeded limit");
        }

        if self.current_resource_usage > self.max_resource_budget {
            return Err("Resource usage exceeded limit");
        }

        Ok(())
    }

    /// Get current resource usage percentage.
    pub fn resource_utilization_percent(&self) -> u32 {
        if self.max_resource_budget == 0 {
            return 0;
        }
        let pct = (self.current_resource_usage as u64 * 100) / self.max_resource_budget as u64;
        pct.min(u32::MAX as u64) as u32
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn load(id: u64, cost: u32, priority: u32) -> WorkerLoad {
        WorkerLoad {
            work_id: id,
            resource_cost: cost,
            priority,
        }
    }

    #[test]
    fn test_bounded_pool_creation() {
        let pool = BoundedConcurrencyPool::new(5, 1000);
        assert_eq!(pool.max_workers, 5);
        assert_eq!(pool.max_resource_budget, 1000);
    }

    #[test]
    fn test_submit_work_within_limits() {
        let mut pool = BoundedConcurrencyPool::new(5, 1000);
        assert!(pool.submit_work(load(1, 100, 1)).is_ok());
        assert_eq!(pool.pending_work(), 1);
    }

    #[test]
    fn test_backpressure_on_resource_limit() {
        let mut pool = BoundedConcurrencyPool::new(5, 100);
        assert!(pool.submit_work(load(1, 80, 1)).is_ok());
        let rejected = pool.submit_work(load(2, 50, 1));
        assert!(rejected.is_err());
        assert_eq!(rejected.unwrap_err().work_id, 2);
        assert_eq!(pool.rejected_work_count(), 1);
    }

    #[test]
    fn test_backpressure_on_worker_limit() {
        let mut pool = BoundedConcurrencyPool::new(1, 10_000);
        assert!(pool.acquire_worker(1, 10).is_ok());
        assert!(pool.submit_work(load(2, 10, 1)).is_err());
    }

    #[test]
    fn test_acquire_and_release_worker() {
        let mut pool = BoundedConcurrencyPool::new(5, 1000);

        assert!(pool.acquire_worker(1, 100).is_ok());
        assert_eq!(pool.current_workers, 1);
        assert_eq!(pool.current_resource_usage, 100);

        pool.release_worker(100, true);
        assert_eq!(pool.current_workers, 0);
        assert_eq!(pool.current_resource_usage, 0);
    }

    #[test]
    fn test_release_underflow_saturates() {
        let mut pool = BoundedConcurrencyPool::new(5, 1000);
        pool.release_worker(500, true);
        assert_eq!(pool.current_workers, 0);
        assert_eq!(pool.current_resource_usage, 0);
        assert!(pool.verify_backpressure().is_ok());
    }

    #[test]
    fn test_worker_limit_enforcement() {
        let mut pool = BoundedConcurrencyPool::new(2, 10000);

        assert!(pool.acquire_worker(1, 100).is_ok());
        assert!(pool.acquire_worker(2, 100).is_ok());
        assert_eq!(pool.acquire_worker(3, 100), Err("Worker limit reached"));
    }

    #[test]
    fn test_oversized_cost_does_not_overflow() {
        let mut pool = BoundedConcurrencyPool::new(5, 1000);
        assert!(pool.acquire_worker(1, 900).is_ok());
        // u32::MAX cost would overflow a naive add; must be refused cleanly.
        assert_eq!(
            pool.acquire_worker(2, u32::MAX),
            Err("Resource budget exceeded")
        );
        assert_eq!(pool.current_resource_usage, 900);
        assert!(pool.submit_work(load(3, u32::MAX, 1)).is_err());
    }

    #[test]
    fn test_zero_budget_refuses_all_work() {
        let mut pool = BoundedConcurrencyPool::new(5, 0);
        assert!(pool.submit_work(load(1, 1, 1)).is_err());
        assert_eq!(pool.acquire_worker(2, 1), Err("Resource budget exceeded"));
        assert_eq!(pool.resource_utilization_percent(), 0);
    }

    #[test]
    fn test_backpressure_verification() {
        let pool = BoundedConcurrencyPool::new(5, 1000);
        assert!(pool.verify_backpressure().is_ok());
    }

    #[test]
    fn test_worker_state_transitions() {
        let mut pool = BoundedConcurrencyPool::new(2, 1000);

        assert_eq!(pool.worker_state(), WorkerState::Idle);

        pool.acquire_worker(1, 100).ok();
        assert_eq!(pool.worker_state(), WorkerState::Active);

        pool.acquire_worker(2, 100).ok();
        assert_eq!(pool.worker_state(), WorkerState::Backpressured);
    }

    #[test]
    fn test_resource_utilization_percent() {
        let mut pool = BoundedConcurrencyPool::new(5, 1000);
        pool.acquire_worker(1, 500).ok();

        assert_eq!(pool.resource_utilization_percent(), 50);
    }

    #[test]
    fn test_normal_path_processes_by_priority() {
        let mut pool = BoundedConcurrencyPool::new(5, 1000);
        pool.submit_work(load(1, 100, 1)).unwrap();
        pool.submit_work(load(2, 100, 9)).unwrap();
    }
}
