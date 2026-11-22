//! Operational checks for Trellis contracts.
//!
//! - [`high_value_journeys`]: synthetic monitoring for the journeys that move
//!   donor funds, run against the real aid contract (Issue #451).
//! - [`incident_runbook`]: executable contain/recover/verify checks for the
//!   incidents in `docs/INCIDENT_RUNBOOK.md` (Issue #452).
//!
//! Everything runs in a local, in-process soroban `Env`. Nothing here talks to
//! a network or holds key material.

pub mod high_value_journeys;
pub mod incident_runbook;
