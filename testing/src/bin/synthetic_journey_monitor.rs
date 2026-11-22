//! Runnable synthetic monitor for the fund -> quote -> settle journey.
//!
//! This uses the repository's credential-free, in-process sandbox adapters. It
//! never contacts Soroban RPC or submits a transaction to a network. The
//! journey itself (failure attribution, bounded settlement retry, credential
//! refusal) lives in `testing::synthetic_monitor` so it is unit tested.
//!
//! Exit codes: 0 pass, 1 fail (the JSON `retryable` field says whether a rerun can help).

use std::time::Instant;

use soroban_sdk::Env;
use testing::synthetic_monitor::{
    run_journey, JourneyFault, JourneyOptions, DEFAULT_MAX_SETTLEMENT_ATTEMPTS, JOURNEY_NAME,
};

fn main() {
    let started = Instant::now();
    let env = Env::default();

    // Presented only so the monitor can refuse it; never used.
    let secret = std::env::var("SYNTHETIC_MONITOR_SECRET").ok();
    let endpoint = std::env::var("SYNTHETIC_MONITOR_RPC_URL").ok();
    let max_settlement_attempts = std::env::var("SYNTHETIC_MONITOR_MAX_SETTLEMENT_ATTEMPTS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_MAX_SETTLEMENT_ATTEMPTS);
    let fault = match std::env::var("SYNTHETIC_MONITOR_FAULT").as_deref() {
        Ok("oracle_unavailable") => JourneyFault::OracleUnavailable,
        Ok("oracle_stale") => JourneyFault::OracleStale,
        Ok("underfunded_payer") => JourneyFault::UnderfundedPayer,
        Ok(value) if value.starts_with("rpc_timeouts:") => JourneyFault::RpcTimeouts(
            value["rpc_timeouts:".len()..].parse().unwrap_or(1),
        ),
        _ => JourneyFault::None,
    };

    let options = JourneyOptions {
        secret: secret.as_deref(),
        endpoint: endpoint.as_deref(),
        max_settlement_attempts,
        fault,
        ..JourneyOptions::new()
    };

    match run_journey(&env, &options) {
        Ok(pass) => {
            println!(
                "{{\"status\":\"pass\",\"journey\":\"{}\",\"latency_ms\":{},\"steps\":{},\"settled_ledger\":{},\"settlement_attempts\":{},\"dependency\":null}}",
                JOURNEY_NAME,
                started.elapsed().as_millis(),
                pass.report.steps,
                pass.report.settled_ledger,
                pass.settlement_attempts,
            );
        }
        Err(failure) => {
            let detail = match failure.error {
                Some(error) => format!("{error:?}"),
                None => "unexpected settlement report".to_string(),
            };
            println!(
                "{{\"status\":\"fail\",\"journey\":\"{}\",\"latency_ms\":{},\"failed_step\":{},\"dependency\":{},\"detail\":{},\"retryable\":{},\"settlement_pending\":{},\"settlement_attempts\":{}}}",
                JOURNEY_NAME,
                started.elapsed().as_millis(),
                json_string(failure.step),
                json_string(failure.dependency.as_str()),
                json_string(&detail),
                failure.retryable,
                failure.settlement_pending,
                failure.settlement_attempts,
            );
            std::process::exit(1);
        }
    }
}

fn json_string(value: &str) -> String {
    let mut encoded = String::from("\"");
    for character in value.chars() {
        match character {
            '"' => encoded.push_str("\\\""),
            '\\' => encoded.push_str("\\\\"),
            '\n' => encoded.push_str("\\n"),
            '\r' => encoded.push_str("\\r"),
            '\t' => encoded.push_str("\\t"),
            c if c.is_control() => encoded.push(' '),
            c => encoded.push(c),
        }
    }
    encoded.push('"');
    encoded
}
