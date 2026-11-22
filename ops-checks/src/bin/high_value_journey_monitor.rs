//! Runnable synthetic monitor for high-value aid journeys (Issue #451).
//!
//! Runs every journey in `ops_checks::high_value_journeys` against a local,
//! in-process deployment of the real aid contract. It never contacts Soroban
//! RPC or submits a transaction to a network.
//!
//! Prints one JSON object to stdout. Exit codes: 0 all journeys passed,
//! 1 at least one failed (each failure carries `severity` and `retryable`).

use std::time::Instant;

use ops_checks::high_value_journeys::{
    run, HighValueJourney, HvDependency, HvFault, HvOptions, MonitorGuard,
    DEFAULT_MAX_CLAIM_ATTEMPTS,
};

fn main() {
    // Presented only so the monitor can refuse it; never used.
    let secret = std::env::var("HV_MONITOR_SECRET").ok();
    let endpoint = std::env::var("HV_MONITOR_RPC_URL").ok();
    let max_claim_attempts = std::env::var("HV_MONITOR_MAX_CLAIM_ATTEMPTS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_MAX_CLAIM_ATTEMPTS);
    let fault_name = std::env::var("HV_MONITOR_FAULT").unwrap_or_default();
    let Some(fault) = parse_fault(&fault_name) else {
        eprintln!(
            "unknown HV_MONITOR_FAULT {fault_name:?}; expected one of: underfunded_donor, \
             claim_paused:<n>, lost_claim_ack, claim_after_expiry, auth_probe_bypass"
        );
        std::process::exit(2);
    };

    let options = HvOptions {
        guard: MonitorGuard {
            secret: secret.as_deref(),
            endpoint: endpoint.as_deref(),
        },
        max_claim_attempts,
        fault,
    };

    let mut all_passed = true;
    let mut journeys = Vec::new();
    for journey in HighValueJourney::ALL {
        let started = Instant::now();
        let outcome = run(journey, &options);
        let latency_ms = started.elapsed().as_millis();
        journeys.push(match outcome {
            Ok(pass) => format!(
                "{{\"journey\":\"{}\",\"status\":\"pass\",\"latency_ms\":{},\"attempts\":{},\"reconciled\":{},\"auth_probes_refused\":{},\"escrow_balance\":{}}}",
                journey.as_str(),
                latency_ms,
                pass.attempts,
                pass.reconciled,
                pass.auth_probes_refused,
                pass.escrow_balance,
            ),
            Err(failure) => {
                all_passed = false;
                let detail = match failure.error {
                    Some(error) => format!("{error:?}"),
                    None => describe(failure.dependency).to_string(),
                };
                format!(
                    "{{\"journey\":\"{}\",\"status\":\"fail\",\"latency_ms\":{},\"failed_step\":\"{}\",\"dependency\":\"{}\",\"detail\":\"{}\",\"severity\":\"{}\",\"retryable\":{},\"funds_escrowed\":{},\"attempts\":{}}}",
                    journey.as_str(),
                    latency_ms,
                    failure.step,
                    failure.dependency.as_str(),
                    detail,
                    failure.severity.as_str(),
                    failure.retryable,
                    failure.funds_escrowed,
                    failure.attempts,
                )
            }
        });
    }

    println!(
        "{{\"status\":\"{}\",\"journeys\":[{}]}}",
        if all_passed { "pass" } else { "fail" },
        journeys.join(","),
    );
    if !all_passed {
        std::process::exit(1);
    }
}

/// Explains a failure that did not carry an aid-contract error code.
fn describe(dependency: HvDependency) -> &'static str {
    match dependency {
        HvDependency::Credentials => "refused unsafe monitor configuration before deploying",
        HvDependency::Token => "token transfer for the escrow was refused",
        HvDependency::Contract => "aid contract refused the call",
        HvDependency::Authorization => "a call that must be refused for a stranger was accepted",
        HvDependency::Accounting => "balances or aid status differ from the expected outcome",
    }
}

fn parse_fault(value: &str) -> Option<HvFault> {
    Some(match value {
        "" | "none" => HvFault::None,
        "underfunded_donor" => HvFault::UnderfundedDonor,
        "lost_claim_ack" => HvFault::LostClaimAck,
        "claim_after_expiry" => HvFault::ClaimAfterExpiry,
        "auth_probe_bypass" => HvFault::AuthProbeBypass,
        other => HvFault::ClaimPaused(other.strip_prefix("claim_paused:")?.parse().ok()?),
    })
}
