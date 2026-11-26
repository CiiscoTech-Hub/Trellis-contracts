//! Incident runbook with executable recovery checks (Issue #452).
//!
//! `docs/INCIDENT_RUNBOOK.md` describes what to do for each incident below.
//! This module runs the same steps against a local deployment of the real
//! aid contract and records every check as a [`shared::operator_runbook`]
//! [`RunbookCheck`], so "is the incident recovered?" is answered by
//! [`evaluate_runbook`] instead of by reading a checklist.
//!
//! Every incident runs in three phases:
//!
//! 1. **contain**: confirm the incident is real and its blast radius is
//!    bounded (claims blocked, strangers refused);
//! 2. **recover**: perform the recovery action (resume, refund);
//! 3. **verify**: prove the system is healthy again. Escrow must equal the
//!    sum of pending aid, the user who was blocked must get their funds, and
//!    the [[`crate::high_value_journeys`]] monitor must pass on the recovered
//!    deployment.
//!
//! Every phase can be run again. A rerun replaces that phase's check
//! outcomes and bumps their `attempts`, so the retry path for a failed
//! recovery is: fix the cause, run [`IncidentDrill::recover`] again, then
//! [`IncidentDrill::verify`].
//!
//! A mandatory check that is skipped (e.g. the operator never resumed the
//! contract) fails the runbook; it is never treated as passed.

use std::vec::Vec as StdVec;

use soroban_sdk::Vec;

use aid_contract::{AidError, AidStatus};
pub use shared::operator_runbook::CheckStatus;
use shared::operator_runbook::{
    create_check, evaluate_runbook, update_check_status, IncidentSeverity, RunbookCheck,
    RunbookResult,
};

use crate::high_value_journeys::{
    run_on, AidFixture, HighValueJourney, HvOptions, HV_DONOR_FUNDING, HV_JOURNEY_AMOUNT,
};

/// An incident the runbook knows how to recover from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Incident {
    /// The aid contract was paused in an emergency and must be resumed safely.
    EmergencyPause,
    /// An aid expired unclaimed and its funds are stuck in escrow.
    ExpiredEscrow,
}

impl Incident {
    pub const ALL: [Incident; 2] = [Incident::EmergencyPause, Incident::ExpiredEscrow];

    pub fn as_str(self) -> &'static str {
        match self {
            Incident::EmergencyPause => "emergency_pause",
            Incident::ExpiredEscrow => "expired_escrow",
        }
    }

    pub fn parse(value: &str) -> Option<Incident> {
        Incident::ALL.into_iter().find(|i| i.as_str() == value)
    }
}

/// Mistakes an operator can make, for rehearsing failed recoveries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryFault {
    None,
    /// The recovery action (resume / refund) is not performed.
    SkipRecovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Contain,
    Recover,
    Verify,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Contain => "contain",
            Phase::Recover => "recover",
            Phase::Verify => "verify",
        }
    }
}

/// One executed check, in a form the binary can print.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckOutcome {
    pub id: &'static str,
    pub phase: Phase,
    pub status: CheckStatus,
    pub mandatory: bool,
    /// Why the check failed or was skipped; empty when it passed.
    pub detail: &'static str,
    /// What the operator should do if this check is not `Passed`.
    pub remediation: &'static str,
    /// How many times this check has been run.
    pub attempts: u32,
    /// The record evaluated by [`evaluate_runbook`].
    pub record: RunbookCheck,
}

struct CheckSpec {
    id: &'static str,
    description: &'static str,
    severity: IncidentSeverity,
    remediation: &'static str,
    mandatory: bool,
}

const fn spec(
    id: &'static str,
    description: &'static str,
    severity: IncidentSeverity,
    remediation: &'static str,
) -> CheckSpec {
    CheckSpec {
        id,
        description,
        severity,
        remediation,
        mandatory: true,
    }
}

// ── Check catalogue (mirrors docs/INCIDENT_RUNBOOK.md) ──────────────────

const PAUSE_APPLIED: CheckSpec = spec(
    "pause_applied",
    "A pauser can pause the aid contract",
    IncidentSeverity::Critical,
    "Confirm the pauser key holds Role::Pauser (set_pauser); if not, pause with the admin.",
);
const CLAIMS_BLOCKED: CheckSpec = spec(
    "claims_blocked_while_paused",
    "Claims are refused with Paused and escrow does not move",
    IncidentSeverity::Critical,
    "Pause is not effective: stop and escalate; consider an emergency upgrade.",
);
const UNAUTHORIZED_RESUME_REFUSED: CheckSpec = spec(
    "unauthorized_resume_refused",
    "A non-pauser cannot resume the contract",
    IncidentSeverity::Critical,
    "Authorization regression: keep paused, rotate roles, and audit set_pauser history.",
);
const RESUMED_BY_PAUSER: CheckSpec = spec(
    "resumed_by_pauser",
    "The pauser resumes the contract after the cause is fixed",
    IncidentSeverity::High,
    "Call set_paused(pauser, false) once the root cause is fixed, then rerun verify.",
);
const STORAGE_SCHEMA_VALID: CheckSpec = spec(
    "storage_schema_valid",
    "Storage schema version is supported by the running build",
    IncidentSeverity::High,
    "Run the schema migration in docs/MIGRATION_SAFETY.md before resuming traffic.",
);
const ESCROW_CONSERVED: CheckSpec = spec(
    "escrow_conserved",
    "Contract token balance equals the sum of pending aid",
    IncidentSeverity::Critical,
    "Escrow drift: keep paused and reconcile with docs/RECONCILIATION_JOB.md.",
);
const BLOCKED_CLAIM_COMPLETES: CheckSpec = spec(
    "blocked_claim_completes",
    "The claim blocked by the incident now pays the recipient exactly once",
    IncidentSeverity::Critical,
    "Contract is still paused or the aid changed state; inspect get_aid and the pause flag.",
);
const POST_RECOVERY_JOURNEY: CheckSpec = spec(
    "post_recovery_journey",
    "The high-value journey monitor passes on the recovered deployment",
    IncidentSeverity::High,
    "Run high-value-journey-monitor and follow the failing dependency's recovery row.",
);
const CLAIM_REFUSED_AFTER_EXPIRY: CheckSpec = spec(
    "claim_refused_after_expiry",
    "The recipient can no longer claim the expired aid",
    IncidentSeverity::Critical,
    "Expiry is not enforced: pause the contract and escalate.",
);
const STRANGER_REFUND_REFUSED: CheckSpec = spec(
    "stranger_refund_refused",
    "Only the donor or admin can refund",
    IncidentSeverity::Critical,
    "Authorization regression: pause the contract and escalate.",
);
const REFUND_TO_DONOR: CheckSpec = spec(
    "refund_to_donor",
    "The donor (or admin) refunds the expired aid",
    IncidentSeverity::High,
    "Call refund_aid(aid_id, donor) or refund_aid(aid_id, admin), then rerun verify.",
);
const REFUND_RETRY_IDEMPOTENT: CheckSpec = spec(
    "refund_retry_idempotent",
    "Retrying the refund is refused with AlreadyRefunded and pays nothing",
    IncidentSeverity::Critical,
    "If the refund has not landed, complete refund_to_donor first; if a repeated refund paid out, pause the contract and escalate.",
);
const DONOR_MADE_WHOLE: CheckSpec = spec(
    "donor_made_whole",
    "The donor's balance is back to its pre-donation value",
    IncidentSeverity::Critical,
    "The refund did not land: check the refund step and the token contract.",
);

/// One incident, run against its own local deployment.
pub struct IncidentDrill {
    pub incident: Incident,
    pub fixture: AidFixture,
    /// The aid that the incident affected.
    pub aid_id: u64,
    outcomes: StdVec<CheckOutcome>,
}

impl IncidentDrill {
    /// Deploy, escrow one aid, and put the deployment into the incident state.
    /// For `EmergencyPause` the incident state is produced by [`Self::contain`].
    pub fn start(incident: Incident) -> Option<Self> {
        let fixture = AidFixture::new(HV_DONOR_FUNDING);
        let aid_id = fixture.donate(HV_JOURNEY_AMOUNT)?;
        if incident == Incident::ExpiredEscrow {
            fixture.expire_all();
        }
        Some(Self {
            incident,
            fixture,
            aid_id,
            outcomes: StdVec::new(),
        })
    }

    pub fn outcomes(&self) -> &[CheckOutcome] {
        &self.outcomes
    }

    /// Records a check, replacing an earlier outcome with the same id.
    fn record(&mut self, phase: Phase, spec: &CheckSpec, result: Result<(), &'static str>) {
        let env = &self.fixture.env;
        let mut record = create_check(
            env,
            spec.id,
            spec.description,
            spec.severity,
            spec.remediation,
            spec.mandatory,
        );
        let (status, detail) = match result {
            Ok(()) => (CheckStatus::Passed, ""),
            Err(SKIPPED) => (CheckStatus::Skipped, SKIPPED),
            Err(detail) => (CheckStatus::Failed, detail),
        };
        // InProgress -> Passed/Failed/Skipped is always a valid transition.
        let _ = update_check_status(env, &mut record, status);
        let attempts = match self.outcomes.iter().position(|o| o.id == spec.id) {
            Some(index) => self.outcomes.remove(index).attempts + 1,
            None => 1,
        };
        self.outcomes.push(CheckOutcome {
            id: spec.id,
            phase,
            status,
            mandatory: spec.mandatory,
            detail,
            remediation: spec.remediation,
            attempts,
            record,
        });
    }

    /// Phase 1: bound the blast radius.
    pub fn contain(&mut self) {
        let f = &self.fixture;
        let aid = self.aid_id;
        match self.incident {
            Incident::EmergencyPause => {
                let paused = check(f.set_paused(&f.pauser, true), "pauser could not pause");
                self.record(Phase::Contain, &PAUSE_APPLIED, paused);

                let f = &self.fixture;
                let escrow = f.escrow_balance();
                let blocked = check(
                    f.claim(aid, &f.recipient) == Err(Some(AidError::Paused))
                        && f.escrow_balance() == escrow,
                    "claim was not refused with Paused",
                );
                self.record(Phase::Contain, &CLAIMS_BLOCKED, blocked);

                let f = &self.fixture;
                let refused = check(
                    !f.set_paused(&f.stranger, false)
                        && f.claim(aid, &f.recipient) == Err(Some(AidError::Paused)),
                    "a non-pauser resumed the contract",
                );
                self.record(Phase::Contain, &UNAUTHORIZED_RESUME_REFUSED, refused);
            }
            Incident::ExpiredEscrow => {
                let refused = check(
                    f.claim(aid, &f.recipient) == Err(Some(AidError::Expired)),
                    "expired aid was claimable",
                );
                self.record(Phase::Contain, &CLAIM_REFUSED_AFTER_EXPIRY, refused);

                let f = &self.fixture;
                let stranger = check(
                    f.refund(aid, &f.stranger) == Err(Some(AidError::Unauthorized)),
                    "a stranger was allowed to refund",
                );
                self.record(Phase::Contain, &STRANGER_REFUND_REFUSED, stranger);
            }
        }
    }

    /// Phase 2: perform the recovery action. Safe to call again after a
    /// failed or skipped attempt.
    pub fn recover(&mut self, fault: RecoveryFault) {
        let f = &self.fixture;
        let skip = fault == RecoveryFault::SkipRecovery;
        match self.incident {
            Incident::EmergencyPause => {
                let resumed = if skip {
                    Err(SKIPPED)
                } else {
                    check(f.set_paused(&f.pauser, false), "pauser could not resume")
                };
                self.record(Phase::Recover, &RESUMED_BY_PAUSER, resumed);
            }
            Incident::ExpiredEscrow => {
                let refunded = if skip {
                    Err(SKIPPED)
                } else {
                    match f.refund(self.aid_id, &f.donor) {
                        Ok(()) => Ok(()),
                        // A retried recovery whose first refund landed.
                        Err(Some(AidError::AlreadyRefunded))
                            if f.status(self.aid_id) == Some(AidStatus::Refunded) =>
                        {
                            Ok(())
                        }
                        Err(_) => Err("refund_aid was refused"),
                    }
                };
                self.record(Phase::Recover, &REFUND_TO_DONOR, refunded);
            }
        }
    }

    /// Phase 3: prove the deployment is healthy. Safe to call again.
    pub fn verify(&mut self) {
        let schema = check(
            matches!(
                self.fixture.client().try_validate_storage_schema(),
                Ok(Ok(_))
            ),
            "unsupported storage schema version",
        );
        self.record(Phase::Verify, &STORAGE_SCHEMA_VALID, schema);

        let conserved = check(self.escrow_conserved(), "escrow != sum of pending aid");
        self.record(Phase::Verify, &ESCROW_CONSERVED, conserved);

        let f = &self.fixture;
        let journey = match self.incident {
            Incident::EmergencyPause => {
                let before = f.balance(&f.recipient);
                let settled = match f.claim(self.aid_id, &f.recipient) {
                    Ok(()) => f.balance(&f.recipient) == before + HV_JOURNEY_AMOUNT,
                    // Already claimed by an earlier verify run: confirm, don't pay again.
                    Err(Some(AidError::AlreadyClaimed)) => {
                        f.status(self.aid_id) == Some(AidStatus::Settled)
                    }
                    Err(_) => false,
                };
                let completed = check(settled, "the blocked claim did not settle");
                self.record(Phase::Verify, &BLOCKED_CLAIM_COMPLETES, completed);
                HighValueJourney::DonateClaim
            }
            Incident::ExpiredEscrow => {
                // Only retry a refund that has landed. Calling refund_aid on a
                // still-pending aid would perform the skipped recovery step
                // here and hide it.
                let idempotent = if f.status(self.aid_id) != Some(AidStatus::Refunded) {
                    Err("refund has not landed; nothing to retry")
                } else {
                    let before = f.balance(&f.donor);
                    check(
                        f.refund(self.aid_id, &f.donor) == Err(Some(AidError::AlreadyRefunded))
                            && f.balance(&f.donor) == before,
                        "a repeated refund was not refused",
                    )
                };
                self.record(Phase::Verify, &REFUND_RETRY_IDEMPOTENT, idempotent);

                let f = &self.fixture;
                let whole = check(
                    f.balance(&f.donor) == HV_DONOR_FUNDING,
                    "donor balance is below its pre-donation value",
                );
                self.record(Phase::Verify, &DONOR_MADE_WHOLE, whole);
                HighValueJourney::DonateRefund
            }
        };

        let f = &self.fixture;
        let monitor = check(
            run_on(f, journey, &HvOptions::new()).is_ok(),
            "the journey monitor failed on the recovered deployment",
        );
        self.record(Phase::Verify, &POST_RECOVERY_JOURNEY, monitor);
    }

    /// The contract must hold exactly the funds of aid that is still pending.
    fn escrow_conserved(&self) -> bool {
        let f = &self.fixture;
        f.status(self.aid_id).is_some() && f.escrow_balance() == f.pending_escrow_total()
    }

    /// The runbook record, evaluated by the shared fail-closed rule.
    pub fn result(&self) -> RunbookResult {
        let env = &self.fixture.env;
        let mut checks = Vec::new(env);
        for outcome in &self.outcomes {
            checks.push_back(outcome.record.clone());
        }
        evaluate_runbook(env, self.incident.as_str(), &checks)
    }

    pub fn passed(&self) -> bool {
        self.result().all_passed
    }
}

const SKIPPED: &str = "recovery step not performed";

fn check(ok: bool, detail: &'static str) -> Result<(), &'static str> {
    if ok {
        Ok(())
    } else {
        Err(detail)
    }
}

/// Run every phase of one incident. `None` if the fixture could not even
/// escrow the aid the incident is about.
pub fn run_incident(incident: Incident, fault: RecoveryFault) -> Option<IncidentDrill> {
    let mut drill = IncidentDrill::start(incident)?;
    drill.contain();
    drill.recover(fault);
    drill.verify();
    Some(drill)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status_of(drill: &IncidentDrill, id: &str) -> CheckStatus {
        drill.outcomes().iter().find(|o| o.id == id).unwrap().status
    }

    fn failing(drill: &IncidentDrill) -> StdVec<&'static str> {
        drill
            .outcomes()
            .iter()
            .filter(|o| o.status != CheckStatus::Passed)
            .map(|o| o.id)
            .collect()
    }

    // ── normal ──────────────────────────────────────────────────────────

    #[test]
    fn every_incident_recovers_and_every_check_passes() {
        for incident in Incident::ALL {
            let drill = run_incident(incident, RecoveryFault::None).unwrap();
            assert!(drill.passed(), "{incident:?}: {:?}", failing(&drill));
            assert!(drill
                .outcomes()
                .iter()
                .all(|o| o.mandatory && o.attempts == 1));
            assert_eq!(drill.result().checks.len(), drill.outcomes().len() as u32);
        }
    }

    #[test]
    fn emergency_pause_pays_the_blocked_recipient_once() {
        let drill = run_incident(Incident::EmergencyPause, RecoveryFault::None).unwrap();
        let f = &drill.fixture;
        // Blocked claim + one post-recovery journey claim.
        assert_eq!(f.balance(&f.recipient), 2 * HV_JOURNEY_AMOUNT);
        assert_eq!(f.escrow_balance(), 0);
    }

    #[test]
    fn expired_escrow_returns_funds_to_the_donor() {
        let drill = run_incident(Incident::ExpiredEscrow, RecoveryFault::None).unwrap();
        let f = &drill.fixture;
        assert_eq!(f.status(drill.aid_id), Some(AidStatus::Refunded));
        assert_eq!(f.balance(&f.donor), HV_DONOR_FUNDING);
        assert_eq!(f.balance(&f.recipient), 0);
    }

    #[test]
    fn incident_names_round_trip() {
        for incident in Incident::ALL {
            assert_eq!(Incident::parse(incident.as_str()), Some(incident));
        }
        assert_eq!(Incident::parse("unknown"), None);
    }

    // ── failure ─────────────────────────────────────────────────────────

    #[test]
    fn skipped_resume_fails_the_runbook_and_names_the_checks() {
        let drill = run_incident(Incident::EmergencyPause, RecoveryFault::SkipRecovery).unwrap();
        assert!(!drill.passed());
        assert_eq!(status_of(&drill, "resumed_by_pauser"), CheckStatus::Skipped);
        assert_eq!(
            status_of(&drill, "blocked_claim_completes"),
            CheckStatus::Failed
        );
        assert_eq!(
            status_of(&drill, "post_recovery_journey"),
            CheckStatus::Failed
        );
        // Funds stayed safely in escrow the whole time: the incident aid plus
        // the aid the failed post-recovery journey escrowed while paused.
        assert_eq!(status_of(&drill, "escrow_conserved"), CheckStatus::Passed);
        let f = &drill.fixture;
        assert_eq!(f.escrow_balance(), 2 * HV_JOURNEY_AMOUNT);
        assert_eq!(f.escrow_balance(), f.pending_escrow_total());
    }

    #[test]
    fn skipped_refund_fails_the_runbook_with_funds_still_escrowed() {
        let drill = run_incident(Incident::ExpiredEscrow, RecoveryFault::SkipRecovery).unwrap();
        assert!(!drill.passed());
        assert_eq!(status_of(&drill, "refund_to_donor"), CheckStatus::Skipped);
        assert_eq!(status_of(&drill, "donor_made_whole"), CheckStatus::Failed);
        // Verify must not perform the skipped refund itself.
        assert_eq!(
            status_of(&drill, "refund_retry_idempotent"),
            CheckStatus::Failed
        );
        assert_eq!(drill.fixture.status(drill.aid_id), Some(AidStatus::Pending));
        assert_eq!(status_of(&drill, "escrow_conserved"), CheckStatus::Passed);
        assert_eq!(drill.fixture.escrow_balance(), HV_JOURNEY_AMOUNT);
    }

    #[test]
    fn failed_check_carries_remediation_for_the_operator() {
        let drill = run_incident(Incident::EmergencyPause, RecoveryFault::SkipRecovery).unwrap();
        for outcome in drill
            .outcomes()
            .iter()
            .filter(|o| o.status != CheckStatus::Passed)
        {
            assert!(!outcome.detail.is_empty(), "{}", outcome.id);
            assert!(!outcome.remediation.is_empty(), "{}", outcome.id);
        }
    }

    // ── retry ───────────────────────────────────────────────────────────

    #[test]
    fn rerunning_recovery_after_a_skipped_step_passes() {
        for incident in Incident::ALL {
            let mut drill = run_incident(incident, RecoveryFault::SkipRecovery).unwrap();
            assert!(!drill.passed());
            drill.recover(RecoveryFault::None);
            drill.verify();
            assert!(drill.passed(), "{incident:?}: {:?}", failing(&drill));
            assert!(drill.outcomes().iter().any(|o| o.attempts == 2));
        }
    }

    #[test]
    fn rerunning_a_completed_recovery_is_idempotent() {
        for incident in Incident::ALL {
            let mut drill = run_incident(incident, RecoveryFault::None).unwrap();
            let f = &drill.fixture;
            let donor = f.balance(&f.donor);
            let recipient = f.balance(&f.recipient);
            drill.recover(RecoveryFault::None);
            drill.verify();
            assert!(drill.passed(), "{incident:?}: {:?}", failing(&drill));
            let f = &drill.fixture;
            // Each verify run pays out its own journey but never the incident aid twice.
            match incident {
                Incident::EmergencyPause => {
                    assert_eq!(f.balance(&f.recipient), recipient + HV_JOURNEY_AMOUNT)
                }
                Incident::ExpiredEscrow => assert_eq!(f.balance(&f.donor), donor),
            }
            assert_eq!(f.escrow_balance(), 0);
        }
    }

    // ── authorization ───────────────────────────────────────────────────

    #[test]
    fn strangers_cannot_resume_or_refund() {
        let pause = run_incident(Incident::EmergencyPause, RecoveryFault::None).unwrap();
        assert_eq!(
            status_of(&pause, "unauthorized_resume_refused"),
            CheckStatus::Passed
        );
        let expired = run_incident(Incident::ExpiredEscrow, RecoveryFault::None).unwrap();
        assert_eq!(
            status_of(&expired, "stranger_refund_refused"),
            CheckStatus::Passed
        );
    }

    #[test]
    fn admin_can_refund_on_behalf_of_an_unavailable_donor() {
        let mut drill = IncidentDrill::start(Incident::ExpiredEscrow).unwrap();
        drill.contain();
        let f = &drill.fixture;
        assert_eq!(f.refund(drill.aid_id, &f.admin), Ok(()));
        // The runbook's recover step accepts the refund that already landed.
        drill.recover(RecoveryFault::None);
        drill.verify();
        assert!(drill.passed(), "{:?}", failing(&drill));
    }
}
