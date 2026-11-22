//! Synthetic monitoring for the critical `fund -> oracle quote -> settle`
//! journey (Issue #291).
//!
//! The journey logic lives here, not in the binary, so every path is covered
//! by unit tests:
//!
//! - **normal**: the journey settles with the expected fee and balances;
//! - **failure**: each dependency (sandbox, credentials, token, oracle, rpc)
//!   is blamed precisely, and assertion drift is reported as a regression;
//! - **retry**: an RPC settlement timeout is retried a bounded number of
//!   times through [`Sandbox::retry_pending_settlement`], which never repeats
//!   the token transfer, and the monitor asserts exactly one transfer happened;
//! - **authorization**: the monitor refuses to run with key material or a
//!   non-loopback/mainnet endpoint, before any adapter is touched.
//!
//! The `synthetic-journey-monitor` binary renders a [`JourneyOutcome`] as one
//! JSON line. See `docs/SYNTHETIC_JOURNEY_MONITOR.md`.

use soroban_sdk::{symbol_short, testutils::Address as _, Address, Env, Symbol};

use crate::sandbox::{estimate_fee, Sandbox, SandboxConfig, WorkflowReport};
use shared::Error;

pub const JOURNEY_NAME: &str = "fund_quote_settle";
pub const JOURNEY_SEED: u64 = 0x247;
pub const JOURNEY_AMOUNT: i128 = 100_000;
pub const JOURNEY_ORACLE_PRICE: i128 = 1_000_000;
/// Upper bound on settlement submissions (first attempt + retries).
pub const DEFAULT_MAX_SETTLEMENT_ATTEMPTS: u32 = 3;
/// Hard cap so a misconfigured monitor cannot spin.
pub const MAX_SETTLEMENT_ATTEMPTS_CAP: u32 = 10;

/// The dependency a failed journey is attributed to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JourneyDependency {
    Sandbox,
    Credentials,
    Token,
    Oracle,
    Rpc,
    WorkflowAssertion,
    Workflow,
}

impl JourneyDependency {
    pub fn as_str(self) -> &'static str {
        match self {
            JourneyDependency::Sandbox => "sandbox",
            JourneyDependency::Credentials => "credentials",
            JourneyDependency::Token => "token",
            JourneyDependency::Oracle => "oracle",
            JourneyDependency::Rpc => "rpc",
            JourneyDependency::WorkflowAssertion => "workflow_assertion",
            JourneyDependency::Workflow => "workflow",
        }
    }
}

/// Faults injected into the synthetic fixture, for drills and tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JourneyFault {
    None,
    OracleUnavailable,
    OracleStale,
    UnderfundedPayer,
    /// The first `n` settlement submissions time out.
    RpcTimeouts(u32),
}

#[derive(Clone, Debug)]
pub struct JourneyOptions<'a> {
    pub config: SandboxConfig,
    /// Key material presented to the monitor. Must be absent.
    pub secret: Option<&'a str>,
    /// RPC endpoint the monitor would target. Must pass the sandbox allow-list.
    pub endpoint: Option<&'a str>,
    pub max_settlement_attempts: u32,
    pub fault: JourneyFault,
}

impl<'a> JourneyOptions<'a> {
    pub fn new() -> Self {
        Self {
            config: SandboxConfig::new(JOURNEY_SEED),
            secret: None,
            endpoint: None,
            max_settlement_attempts: DEFAULT_MAX_SETTLEMENT_ATTEMPTS,
            fault: JourneyFault::None,
        }
    }
}

impl<'a> Default for JourneyOptions<'a> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JourneyPass {
    pub report: WorkflowReport,
    /// Settlement submissions made; `> 1` means the journey recovered by retrying.
    pub settlement_attempts: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JourneyFailure {
    pub dependency: JourneyDependency,
    pub step: &'static str,
    pub error: Option<Error>,
    pub settlement_attempts: u32,
    /// Whether rerunning the monitor unchanged can reasonably succeed.
    pub retryable: bool,
    /// True when the token leg completed but settlement did not: operators
    /// must retry the settlement, never the transfer.
    pub settlement_pending: bool,
}

pub type JourneyOutcome = Result<JourneyPass, JourneyFailure>;

fn fail(
    dependency: JourneyDependency,
    step: &'static str,
    error: Option<Error>,
    settlement_attempts: u32,
    settlement_pending: bool,
) -> JourneyFailure {
    let retryable = matches!(
        dependency,
        JourneyDependency::Oracle | JourneyDependency::Rpc
    );
    JourneyFailure {
        dependency,
        step,
        error,
        settlement_attempts,
        retryable,
        settlement_pending,
    }
}

fn blame(sandbox: &Sandbox) -> JourneyDependency {
    let refused = sandbox.calls().iter().find(|call| !call.allowed);
    match refused {
        Some(call) if call.adapter == symbol_short!("oracle") => JourneyDependency::Oracle,
        Some(call) if call.adapter == symbol_short!("token") => JourneyDependency::Token,
        Some(call) if call.adapter == symbol_short!("rpc") => JourneyDependency::Rpc,
        _ => JourneyDependency::Workflow,
    }
}

/// Run the critical journey once against the in-process sandbox.
pub fn run_journey(env: &Env, options: &JourneyOptions) -> JourneyOutcome {
    // Authorization path: refuse credentials and unsafe endpoints before any
    // adapter call, so a misconfigured monitor can never act on a real network.
    let mut sandbox = Sandbox::new(env, options.config.clone())
        .map_err(|e| fail(JourneyDependency::Sandbox, "initialize", Some(e), 0, false))?;
    sandbox
        .assert_credential_free(options.secret)
        .map_err(|e| fail(JourneyDependency::Credentials, "credential check", Some(e), 0, false))?;
    if let Some(endpoint) = options.endpoint {
        sandbox
            .assert_endpoint_allowed(endpoint)
            .map_err(|e| fail(JourneyDependency::Credentials, "endpoint check", Some(e), 0, false))?;
    }

    let max_attempts = options
        .max_settlement_attempts
        .clamp(1, MAX_SETTLEMENT_ATTEMPTS_CAP);
    let payer = Address::generate(env);
    let payee = Address::generate(env);
    let asset = Symbol::new(env, "synthetic_asset");

    let funding = if options.fault == JourneyFault::UnderfundedPayer {
        JOURNEY_AMOUNT / 10
    } else {
        JOURNEY_AMOUNT
    };
    sandbox
        .token_mut()
        .mint(&payer, funding)
        .map_err(|e| fail(JourneyDependency::Token, "fund payer", Some(e), 0, false))?;
    sandbox
        .oracle_mut()
        .set_price(&asset, JOURNEY_ORACLE_PRICE)
        .map_err(|e| fail(JourneyDependency::Oracle, "configure quote", Some(e), 0, false))?;
    match options.fault {
        JourneyFault::OracleUnavailable => sandbox.oracle_mut().fail_for(&asset),
        JourneyFault::OracleStale => sandbox.oracle_mut().mark_stale(&asset),
        _ => {}
    }

    let timeouts = match options.fault {
        JourneyFault::RpcTimeouts(n) => n,
        _ => 0,
    };

    let mut attempts = 1u32;
    sandbox.rpc_mut().set_fail_next(timeouts >= attempts);
    let mut result = sandbox.run_primary_workflow(env, &payer, &payee, &asset, JOURNEY_AMOUNT);

    // Retry path: only the settlement leg, only while it is pending.
    while result.is_err() && sandbox.has_pending_settlement() && attempts < max_attempts {
        attempts += 1;
        sandbox.rpc_mut().set_fail_next(timeouts >= attempts);
        result = sandbox.retry_pending_settlement();
    }

    let report = match result {
        Ok(report) => report,
        Err(error) => {
            let pending = sandbox.has_pending_settlement();
            let dependency = if pending { JourneyDependency::Rpc } else { blame(&sandbox) };
            let step = if pending { "settle" } else { "run primary workflow" };
            return Err(fail(dependency, step, Some(error), if pending { attempts } else { 0 }, pending));
        }
    };

    let expected_fee = estimate_fee(JOURNEY_AMOUNT).unwrap_or(-1);
    let expected_net = JOURNEY_AMOUNT - expected_fee;
    let consistent = report.fee == expected_fee
        && report.oracle_price == JOURNEY_ORACLE_PRICE
        && report.payer_balance == funding - expected_net
        && report.payee_balance == expected_net
        && report.credential_free
        // Retrying settlement must never pay the recipient twice.
        && sandbox.token().transfers() == 1;
    if !consistent {
        return Err(fail(
            JourneyDependency::WorkflowAssertion,
            "verify settlement",
            None,
            attempts,
            false,
        ));
    }

    Ok(JourneyPass {
        report,
        settlement_attempts: attempts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::SandboxNetwork;

    fn run(options: JourneyOptions) -> JourneyOutcome {
        let env = Env::default();
        run_journey(&env, &options)
    }

    fn with_fault(fault: JourneyFault) -> JourneyOptions<'static> {
        JourneyOptions {
            fault,
            ..JourneyOptions::new()
        }
    }

    #[test]
    fn normal_journey_settles_with_expected_accounting() {
        let pass = run(JourneyOptions::new()).unwrap();
        assert_eq!(pass.settlement_attempts, 1);
        assert_eq!(pass.report.fee, 500);
        assert_eq!(pass.report.payee_balance, JOURNEY_AMOUNT - 500);
        assert_eq!(pass.report.payer_balance, 500);
        assert!(pass.report.credential_free);
    }

    #[test]
    fn journey_is_deterministic_for_a_fixed_seed() {
        let a = run(JourneyOptions::new()).unwrap();
        let b = run(JourneyOptions::new()).unwrap();
        assert_eq!(a.report, b.report);
    }

    #[test]
    fn oracle_outage_and_staleness_are_blamed_on_the_oracle() {
        let outage = run(with_fault(JourneyFault::OracleUnavailable)).unwrap_err();
        assert_eq!(outage.dependency, JourneyDependency::Oracle);
        assert_eq!(outage.error, Some(Error::NotFound));
        assert!(outage.retryable);
        assert!(!outage.settlement_pending);

        let stale = run(with_fault(JourneyFault::OracleStale)).unwrap_err();
        assert_eq!(stale.dependency, JourneyDependency::Oracle);
        assert_eq!(stale.error, Some(Error::StaleData));
    }

    #[test]
    fn underfunded_payer_is_blamed_on_the_token_and_not_retryable() {
        let failure = run(with_fault(JourneyFault::UnderfundedPayer)).unwrap_err();
        assert_eq!(failure.dependency, JourneyDependency::Token);
        assert_eq!(failure.error, Some(Error::InsufficientBalance));
        assert!(!failure.retryable);
    }

    #[test]
    fn transient_rpc_timeouts_recover_by_retrying_settlement_only() {
        let pass = run(with_fault(JourneyFault::RpcTimeouts(2))).unwrap();
        assert_eq!(pass.settlement_attempts, 3);
        // The transfer ran once; balances match a single payment.
        assert_eq!(pass.report.payee_balance, JOURNEY_AMOUNT - 500);
    }

    #[test]
    fn persistent_rpc_timeouts_exhaust_the_bounded_retry_budget() {
        let failure = run(with_fault(JourneyFault::RpcTimeouts(5))).unwrap_err();
        assert_eq!(failure.dependency, JourneyDependency::Rpc);
        assert_eq!(failure.step, "settle");
        assert_eq!(failure.error, Some(Error::Expired));
        assert_eq!(failure.settlement_attempts, DEFAULT_MAX_SETTLEMENT_ATTEMPTS);
        assert!(failure.retryable);
        assert!(failure.settlement_pending);
    }

    #[test]
    fn retry_budget_is_clamped() {
        let no_retry = run(JourneyOptions {
            max_settlement_attempts: 0,
            ..with_fault(JourneyFault::RpcTimeouts(1))
        })
        .unwrap_err();
        assert_eq!(no_retry.settlement_attempts, 1);

        let capped = run(JourneyOptions {
            max_settlement_attempts: u32::MAX,
            ..with_fault(JourneyFault::RpcTimeouts(u32::MAX))
        })
        .unwrap_err();
        assert_eq!(capped.settlement_attempts, MAX_SETTLEMENT_ATTEMPTS_CAP);
    }

    #[test]
    fn key_material_is_refused_before_any_adapter_call() {
        let failure = run(JourneyOptions {
            secret: Some("SDUMMYSECRETVALUE"),
            ..JourneyOptions::new()
        })
        .unwrap_err();
        assert_eq!(failure.dependency, JourneyDependency::Credentials);
        assert_eq!(failure.error, Some(Error::UnsafeSecret));
        assert!(!failure.retryable);
    }

    #[test]
    fn non_loopback_endpoint_and_mainnet_are_refused() {
        let remote = run(JourneyOptions {
            endpoint: Some("https://soroban-mainnet.stellar.org"),
            ..JourneyOptions::new()
        })
        .unwrap_err();
        assert_eq!(remote.dependency, JourneyDependency::Credentials);
        assert_eq!(remote.step, "endpoint check");

        let mut mainnet = JourneyOptions::new();
        mainnet.config.network = SandboxNetwork::Mainnet;
        let refused = run(mainnet).unwrap_err();
        assert_eq!(refused.dependency, JourneyDependency::Sandbox);
        assert_eq!(refused.error, Some(Error::ConfigInvalid));

        let local = run(JourneyOptions {
            endpoint: Some("http://localhost:8000/soroban/rpc"),
            ..JourneyOptions::new()
        });
        assert!(local.is_ok());
    }
}
