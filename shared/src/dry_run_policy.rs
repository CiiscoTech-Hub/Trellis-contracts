//! Dry-run policy evaluator with affected-record previews (Issue #282).
//!
//! Evaluates a proposed [`PolicyConfig`] change against a set of record
//! snapshots *without* committing any state, returning a deterministic
//! preview of which records would be affected and how.
//!
//! ## Design
//!
//! The evaluator is **pure**: it takes the current config, the proposed
//! config, and a bounded slice of record snapshots, then returns an
//! [`DryRunReport`] with per-record verdicts. No storage writes, no
//! events, no auth checks — callers compose those around it.
//!
//! Time complexity: O(n) where n = number of record snapshots.
//! Space complexity: O(n) for the per-record verdict vector.

use soroban_sdk::{contracttype, symbol_short, Env, Symbol, Vec};

use crate::policy::{evaluate, PolicyConfig, PolicyDecision, PolicyInput};

pub const MAX_DRY_RUN_RECORDS: u32 = 500;

pub const TOPIC_DRY_RUN: Symbol = symbol_short!("pol_dry");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordSnapshot {
    pub record_id: u64,
    pub amount: i128,
    pub actor_tier: u32,
    pub daily_ops: u32,
    pub region_allowed: bool,
}

impl RecordSnapshot {
    pub fn to_policy_input(&self) -> PolicyInput {
        PolicyInput {
            amount: self.amount,
            actor_tier: self.actor_tier,
            daily_ops: self.daily_ops,
            region_allowed: self.region_allowed,
        }
    }
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImpactKind {
    NoChange,
    NewlyAllowed,
    NewlyDenied,
    ReasonChanged,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordVerdict {
    pub record_id: u64,
    pub current_decision: PolicyDecision,
    pub proposed_decision: PolicyDecision,
    pub impact: ImpactKind,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DryRunSummary {
    pub total_records: u32,
    pub unchanged: u32,
    pub newly_allowed: u32,
    pub newly_denied: u32,
    pub reason_changed: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DryRunReport {
    pub summary: DryRunSummary,
    pub verdicts: Vec<RecordVerdict>,
    pub current_config_valid: bool,
    pub proposed_config_valid: bool,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DryRunError {
    TooManyRecords = 1,
    InvalidProposedConfig = 2,
}

// ---------------------------------------------------------------------------
// Core evaluator — pure, no storage
// ---------------------------------------------------------------------------

fn classify_impact(current: &PolicyDecision, proposed: &PolicyDecision) -> ImpactKind {
    if current.allowed == proposed.allowed && current.reason == proposed.reason {
        ImpactKind::NoChange
    } else if !current.allowed && proposed.allowed {
        ImpactKind::NewlyAllowed
    } else if current.allowed && !proposed.allowed {
        ImpactKind::NewlyDenied
    } else {
        ImpactKind::ReasonChanged
    }
}

pub fn dry_run_evaluate(
    env: &Env,
    current_config: &PolicyConfig,
    proposed_config: &PolicyConfig,
    records: &Vec<RecordSnapshot>,
) -> Result<DryRunReport, DryRunError> {
    let count = records.len();
    if count > MAX_DRY_RUN_RECORDS {
        return Err(DryRunError::TooManyRecords);
    }

    let current_valid = crate::policy::validate_policy(current_config).is_ok();
    let proposed_valid = crate::policy::validate_policy(proposed_config).is_ok();

    if !proposed_valid {
        return Err(DryRunError::InvalidProposedConfig);
    }

    let mut verdicts = Vec::new(env);
    let mut unchanged = 0u32;
    let mut newly_allowed = 0u32;
    let mut newly_denied = 0u32;
    let mut reason_changed = 0u32;

    for snapshot in records.iter() {
        let input = snapshot.to_policy_input();
        let current_decision = evaluate(current_config, &input);
        let proposed_decision = evaluate(proposed_config, &input);
        let impact = classify_impact(&current_decision, &proposed_decision);

        match impact {
            ImpactKind::NoChange => unchanged += 1,
            ImpactKind::NewlyAllowed => newly_allowed += 1,
            ImpactKind::NewlyDenied => newly_denied += 1,
            ImpactKind::ReasonChanged => reason_changed += 1,
        }

        verdicts.push_back(RecordVerdict {
            record_id: snapshot.record_id,
            current_decision,
            proposed_decision,
            impact,
        });
    }

    Ok(DryRunReport {
        summary: DryRunSummary {
            total_records: count,
            unchanged,
            newly_allowed,
            newly_denied,
            reason_changed,
        },
        verdicts,
        current_config_valid: current_valid,
        proposed_config_valid: proposed_valid,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{PolicyConfig, PolicyReason};
    use soroban_sdk::Env;

    fn snapshot(id: u64, amount: i128, tier: u32, ops: u32) -> RecordSnapshot {
        RecordSnapshot {
            record_id: id,
            amount,
            actor_tier: tier,
            daily_ops: ops,
            region_allowed: true,
        }
    }

    #[test]
    fn normal_path_no_change_when_configs_identical() {
        let env = Env::default();
        let cfg = PolicyConfig::default();
        let records = Vec::from_array(&env, [snapshot(1, 100, 1, 0), snapshot(2, 500, 2, 10)]);

        let report = dry_run_evaluate(&env, &cfg, &cfg, &records).unwrap();
        assert_eq!(report.summary.total_records, 2);
        assert_eq!(report.summary.unchanged, 2);
        assert_eq!(report.summary.newly_denied, 0);
        assert_eq!(report.summary.newly_allowed, 0);
        assert!(report.current_config_valid);
        assert!(report.proposed_config_valid);
    }

    #[test]
    fn normal_path_tightening_denies_affected_records() {
        let env = Env::default();
        let current = PolicyConfig::default();
        let proposed = PolicyConfig {
            max_amount: 200,
            ..PolicyConfig::default()
        };
        let records = Vec::from_array(
            &env,
            [
                snapshot(1, 100, 1, 0),
                snapshot(2, 300, 1, 0),
                snapshot(3, 200, 1, 0),
            ],
        );

        let report = dry_run_evaluate(&env, &current, &proposed, &records).unwrap();
        assert_eq!(report.summary.newly_denied, 1);
        assert_eq!(report.summary.unchanged, 2);

        let denied = report.verdicts.get_unchecked(1);
        assert_eq!(denied.record_id, 2);
        assert_eq!(denied.impact, ImpactKind::NewlyDenied);
        assert_eq!(
            denied.proposed_decision.reason,
            PolicyReason::AmountAboveMaximum
        );
    }

    #[test]
    fn normal_path_relaxing_allows_previously_denied_records() {
        let env = Env::default();
        let current = PolicyConfig {
            max_amount: 100,
            ..PolicyConfig::default()
        };
        let proposed = PolicyConfig::default();
        let records = Vec::from_array(&env, [snapshot(1, 500, 1, 0)]);

        let report = dry_run_evaluate(&env, &current, &proposed, &records).unwrap();
        assert_eq!(report.summary.newly_allowed, 1);
    }

    #[test]
    fn failure_path_too_many_records_rejected() {
        let env = Env::default();
        let cfg = PolicyConfig::default();
        let mut records = Vec::new(&env);
        for i in 0..=MAX_DRY_RUN_RECORDS {
            records.push_back(snapshot(i as u64, 100, 1, 0));
        }

        let err = dry_run_evaluate(&env, &cfg, &cfg, &records).unwrap_err();
        assert_eq!(err, DryRunError::TooManyRecords);
    }

    #[test]
    fn failure_path_invalid_proposed_config_rejected() {
        let env = Env::default();
        let current = PolicyConfig::default();
        let invalid = PolicyConfig {
            min_amount: 0,
            ..PolicyConfig::default()
        };
        let records = Vec::from_array(&env, [snapshot(1, 100, 1, 0)]);

        let err = dry_run_evaluate(&env, &current, &invalid, &records).unwrap_err();
        assert_eq!(err, DryRunError::InvalidProposedConfig);
    }

    #[test]
    fn authorization_path_tier_restriction_newly_denies_high_tier_actors() {
        let env = Env::default();
        let current = PolicyConfig {
            allowed_max_tier: 3,
            ..PolicyConfig::default()
        };
        let proposed = PolicyConfig {
            allowed_max_tier: 1,
            ..PolicyConfig::default()
        };
        let records = Vec::from_array(
            &env,
            [
                snapshot(1, 100, 1, 0),
                snapshot(2, 100, 2, 0),
                snapshot(3, 100, 3, 0),
            ],
        );

        let report = dry_run_evaluate(&env, &current, &proposed, &records).unwrap();
        assert_eq!(report.summary.newly_denied, 2);
        assert_eq!(report.summary.unchanged, 1);
    }

    #[test]
    fn retry_path_deterministic_across_repeated_calls() {
        let env = Env::default();
        let current = PolicyConfig::default();
        let proposed = PolicyConfig {
            max_daily_ops: 5,
            ..PolicyConfig::default()
        };
        let records = Vec::from_array(&env, [snapshot(1, 100, 1, 6)]);

        let r1 = dry_run_evaluate(&env, &current, &proposed, &records).unwrap();
        let r2 = dry_run_evaluate(&env, &current, &proposed, &records).unwrap();
        assert_eq!(r1.summary, r2.summary);
        assert_eq!(
            r1.verdicts.get_unchecked(0).impact,
            r2.verdicts.get_unchecked(0).impact
        );
    }

    #[test]
    fn empty_record_set_returns_clean_report() {
        let env = Env::default();
        let cfg = PolicyConfig::default();
        let records = Vec::new(&env);

        let report = dry_run_evaluate(&env, &cfg, &cfg, &records).unwrap();
        assert_eq!(report.summary.total_records, 0);
        assert_eq!(report.verdicts.len(), 0);
    }

    #[test]
    fn region_restriction_change_correctly_previewed() {
        let env = Env::default();
        let current = PolicyConfig {
            region_allowed: true,
            ..PolicyConfig::default()
        };
        let proposed = PolicyConfig {
            region_allowed: false,
            ..PolicyConfig::default()
        };
        let mut record = snapshot(1, 100, 1, 0);
        record.region_allowed = false;
        let records = Vec::from_array(&env, [record]);

        let report = dry_run_evaluate(&env, &current, &proposed, &records).unwrap();
        assert_eq!(report.summary.newly_denied, 1);
    }
}
