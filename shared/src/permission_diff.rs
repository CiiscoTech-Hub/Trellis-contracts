//! Permission-diff report built before role and policy changes.
//!
//! A [`PermissionSnapshot`] captures the grants a principal holds at a point in
//! time. [`diff`] compares a `before` and `after` snapshot and produces a
//! [`PermissionDiff`] listing every grant added, removed, or unchanged. The
//! diff is pure: it never mutates state, so it can be computed as a preview
//! before a role or policy change is applied, and re-computed on retry without
//! side effects.
//!
//! Operational notes:
//! - Duplicate grants in an input list are collapsed; the diff is set-based.
//! - Snapshots are sorted canonically so diffs are deterministic across runs.
//! - Authorization: only a caller holding the maintainer capability may request
//!   a report. Unauthorized callers receive [`DiffError::Unauthorized`] and no
//!   report is produced.
//! - Rollback: because the diff is read-only, rolling back a change means
//!   re-applying the `before` snapshot. [`PermissionDiff::rollback_plan`]
//!   returns the grants to restore and the grants to strip.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

/// Errors produced while building a permission-diff report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffError {
    /// The caller is not authorized to request a permission-diff report.
    Unauthorized,
    /// The snapshot subject does not match the other snapshot's subject.
    SubjectMismatch,
}

/// A single grant, identified by its scope and role name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Grant {
    pub scope: String,
    pub role: String,
}

impl Grant {
    pub fn new(scope: impl Into<String>, role: impl Into<String>) -> Self {
        Self {
            scope: scope.into(),
            role: role.into(),
        }
    }
}

/// The set of grants a subject holds at one point in time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionSnapshot {
    subject: String,
    grants: BTreeSet<Grant>,
}

impl PermissionSnapshot {
    /// Builds a snapshot. Duplicate grants are collapsed.
    pub fn new(subject: impl Into<String>, grants: impl IntoIterator<Item = Grant>) -> Self {
        Self {
            subject: subject.into(),
            grants: grants.into_iter().collect(),
        }
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }

    pub fn grants(&self) -> &BTreeSet<Grant> {
        &self.grants
    }
}

/// The result of comparing two snapshots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionDiff {
    subject: String,
    added: Vec<Grant>,
    removed: Vec<Grant>,
    unchanged: Vec<Grant>,
}

impl PermissionDiff {
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Grants present after the change but not before.
    pub fn added(&self) -> &[Grant] {
        &self.added
    }

    /// Grants present before the change but not after.
    pub fn removed(&self) -> &[Grant] {
        &self.removed
    }

    /// Grants present in both snapshots.
    pub fn unchanged(&self) -> &[Grant] {
        &self.unchanged
    }

    /// True when the change would alter no grants.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }

    /// Returns the rollback plan: grants to restore (previously removed) and
    /// grants to strip (previously added). Applying the plan to the post-change
    /// state yields the pre-change state.
    pub fn rollback_plan(&self) -> RollbackPlan {
        RollbackPlan {
            restore: self.removed.clone(),
            strip: self.added.clone(),
        }
    }
}

/// Inverse of a permission change, used for recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackPlan {
    pub restore: Vec<Grant>,
    pub strip: Vec<Grant>,
}

/// Builds a permission-diff report between `before` and `after`.
///
/// `caller_is_maintainer` must be true for the report to be produced. The
/// function is pure and idempotent, so a failed or retried call has no side
/// effects on the underlying permission state.
pub fn diff(
    caller_is_maintainer: bool,
    before: &PermissionSnapshot,
    after: &PermissionSnapshot,
) -> Result<PermissionDiff, DiffError> {
    if !caller_is_maintainer {
        return Err(DiffError::Unauthorized);
    }
    if before.subject != after.subject {
        return Err(DiffError::SubjectMismatch);
    }

    let added = after
        .grants
        .difference(&before.grants)
        .cloned()
        .collect::<Vec<_>>();
    let removed = before
        .grants
        .difference(&after.grants)
        .cloned()
        .collect::<Vec<_>>();
    let unchanged = before
        .grants
        .intersection(&after.grants)
        .cloned()
        .collect::<Vec<_>>();

    Ok(PermissionDiff {
        subject: before.subject.clone(),
        added,
        removed,
        unchanged,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(subject: &str, grants: &[(&str, &str)]) -> PermissionSnapshot {
        PermissionSnapshot::new(
            subject,
            grants.iter().map(|(s, r)| Grant::new(*s, *r)),
        )
    }

    #[test]
    fn normal_path_reports_added_removed_and_unchanged() {
        let before = snap("alice", &[("pool", "reader"), ("pool", "writer")]);
        let after = snap("alice", &[("pool", "reader"), ("pool", "admin")]);
        let report = diff(true, &before, &after).unwrap();

        assert_eq!(report.subject(), "alice");
        assert_eq!(report.added(), &[Grant::new("pool", "admin")]);
        assert_eq!(report.removed(), &[Grant::new("pool", "writer")]);
        assert_eq!(report.unchanged(), &[Grant::new("pool", "reader")]);
        assert!(!report.is_empty());
    }

    #[test]
    fn identical_snapshots_produce_empty_diff() {
        let s = snap("alice", &[("pool", "reader")]);
        let report = diff(true, &s, &s.clone()).unwrap();
        assert!(report.is_empty());
        assert_eq!(report.unchanged().len(), 1);
    }

    #[test]
    fn unauthorized_caller_is_rejected_without_report() {
        let before = snap("alice", &[]);
        let after = snap("alice", &[("pool", "admin")]);
        assert_eq!(
            diff(false, &before, &after),
            Err(DiffError::Unauthorized)
        );
    }

    #[test]
    fn subject_mismatch_is_rejected() {
        let before = snap("alice", &[]);
        let after = snap("bob", &[]);
        assert_eq!(
            diff(true, &before, &after),
            Err(DiffError::SubjectMismatch)
        );
    }

    #[test]
    fn retry_is_idempotent() {
        let before = snap("alice", &[("pool", "reader")]);
        let after = snap("alice", &[]);
        let first = diff(true, &before, &after).unwrap();
        let second = diff(true, &before, &after).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn duplicate_grants_are_collapsed() {
        let before = PermissionSnapshot::new(
            "alice",
            [Grant::new("pool", "reader"), Grant::new("pool", "reader")],
        );
        let after = snap("alice", &[("pool", "reader")]);
        assert!(diff(true, &before, &after).unwrap().is_empty());
    }

    #[test]
    fn rollback_plan_inverts_the_change() {
        let before = snap("alice", &[("pool", "reader")]);
        let after = snap("alice", &[("pool", "admin")]);
        let plan = diff(true, &before, &after).unwrap().rollback_plan();
        assert_eq!(plan.restore, vec![Grant::new("pool", "reader")]);
        assert_eq!(plan.strip, vec![Grant::new("pool", "admin")]);
    }
}
