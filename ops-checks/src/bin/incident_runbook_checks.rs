//! Executable recovery checks for the incident runbook (Issue #452).
//!
//! Runs each incident in `docs/INCIDENT_RUNBOOK.md` (contain -> recover ->
//! verify) against a local, in-process deployment of the real aid contract
//! and prints one JSON object with every check's outcome. No network access.
//!
//! Environment:
//! - `INCIDENT_RUNBOOK_SCENARIO`: `all` (default), `emergency_pause`, `expired_escrow`
//! - `INCIDENT_RUNBOOK_FAULT`: `skip_recovery` rehearses a recovery step that
//!   was never performed; the run must then fail.
//!
//! Exit codes: 0 every incident recovered, 1 a mandatory check did not pass,
//! 2 invalid configuration.

use ops_checks::incident_runbook::{run_incident, CheckStatus, Incident, RecoveryFault};

fn main() {
    let scenario = std::env::var("INCIDENT_RUNBOOK_SCENARIO").unwrap_or_default();
    let incidents: Vec<Incident> = match scenario.as_str() {
        "" | "all" => Incident::ALL.to_vec(),
        name => match Incident::parse(name) {
            Some(incident) => vec![incident],
            None => usage(&format!("unknown INCIDENT_RUNBOOK_SCENARIO {name:?}")),
        },
    };
    let fault = match std::env::var("INCIDENT_RUNBOOK_FAULT").as_deref() {
        Err(_) | Ok("") | Ok("none") => RecoveryFault::None,
        Ok("skip_recovery") => RecoveryFault::SkipRecovery,
        Ok(other) => usage(&format!("unknown INCIDENT_RUNBOOK_FAULT {other:?}")),
    };

    let mut all_recovered = true;
    let mut reports = Vec::new();
    for incident in incidents {
        let Some(drill) = run_incident(incident, fault) else {
            all_recovered = false;
            reports.push(format!(
                "{{\"incident\":\"{}\",\"recovered\":false,\"error\":\"fixture could not escrow the incident aid\",\"checks\":[]}}",
                incident.as_str()
            ));
            continue;
        };
        let recovered = drill.passed();
        all_recovered &= recovered;
        let checks: Vec<String> = drill
            .outcomes()
            .iter()
            .map(|o| {
                let mut json = format!(
                    "{{\"id\":\"{}\",\"phase\":\"{}\",\"status\":\"{}\",\"mandatory\":{},\"attempts\":{}",
                    o.id,
                    o.phase.as_str(),
                    status(o.status),
                    o.mandatory,
                    o.attempts,
                );
                if o.status != CheckStatus::Passed {
                    json.push_str(&format!(
                        ",\"detail\":\"{}\",\"remediation\":\"{}\"",
                        o.detail, o.remediation
                    ));
                }
                json.push('}');
                json
            })
            .collect();
        reports.push(format!(
            "{{\"incident\":\"{}\",\"recovered\":{},\"checks\":[{}]}}",
            incident.as_str(),
            recovered,
            checks.join(","),
        ));
    }

    println!(
        "{{\"status\":\"{}\",\"incidents\":[{}]}}",
        if all_recovered { "pass" } else { "fail" },
        reports.join(","),
    );
    if !all_recovered {
        std::process::exit(1);
    }
}

fn status(status: CheckStatus) -> &'static str {
    match status {
        CheckStatus::Passed => "passed",
        CheckStatus::Failed => "failed",
        CheckStatus::InProgress => "in_progress",
        CheckStatus::Skipped => "skipped",
    }
}

fn usage(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(2);
}
