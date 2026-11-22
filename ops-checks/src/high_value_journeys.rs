//! Synthetic monitoring for high-value user journeys (Issue #451).
//!
//! `testing::synthetic_monitor` checks the `fund -> quote -> settle` path
//! against in-process *fakes*. This module checks the journeys that move donor
//! funds against the *real* `aid-contract` code and a real Stellar Asset
//! Contract token, all inside a local `Env`:
//!
//! | Journey          | Steps                                                       |
//! |------------------|-------------------------------------------------------------|
//! | `donate_claim`   | donor escrows aid -> recipient claims -> funds reach recipient |
//! | `donate_refund`  | donor escrows aid -> aid expires -> donor is refunded       |
//!
//! Every run covers four paths:
//!
//! - **normal**: the journey completes and the monitor checks every balance
//!   (donor, recipient, contract escrow) and the final aid status;
//! - **failure**: each failure is attributed to a step and a dependency
//!   (`token`, `contract`, `authorization`, `accounting`), with a
//!   [`JourneySeverity`] that says whether to page or file a ticket and
//!   whether funds are still held in escrow;
//! - **retry**: a claim refused because the contract is paused is retried a
//!   bounded number of times, and a claim whose acknowledgement was lost is
//!   reconciled from on-chain state instead of being paid twice;
//! - **authorization**: before the real claim/refund, a stranger tries the
//!   same call and must be refused. If the stranger is accepted, the monitor
//!   reports an `authorization` failure and pages.
//!
//! The monitor never touches a network: [`MonitorGuard`] refuses key material
//! and non-loopback endpoints before any contract is registered.
//! See `docs/SYNTHETIC_JOURNEY_MONITOR.md`.

use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    token, Address, Env,
};

use aid_contract::{AidContract, AidContractClient, AidError, AidStatus};

/// Amount escrowed by every synthetic donation.
pub const HV_JOURNEY_AMOUNT: i128 = 250_000;
/// Balance minted to the synthetic donor (enough for one donation).
pub const HV_DONOR_FUNDING: i128 = 1_000_000;
/// Ledger the fixture starts at.
pub const HV_START_LEDGER: u32 = 1_000;
/// Ledgers between donation and expiry.
pub const HV_EXPIRY_LEDGERS: u32 = 500;
/// Default upper bound on claim submissions (first attempt + retries).
pub const DEFAULT_MAX_CLAIM_ATTEMPTS: u32 = 3;
/// Hard cap so a misconfigured monitor cannot spin.
pub const MAX_CLAIM_ATTEMPTS_CAP: u32 = 10;

/// Loopback prefixes an endpoint may use; anything else is refused.
const LOOPBACK_PREFIXES: [&str; 4] = [
    "http://localhost",
    "http://127.0.0.1",
    "http://[::1]",
    "http://0.0.0.0",
];

/// A high-value journey the monitor can run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HighValueJourney {
    /// Donor escrows aid, recipient claims it.
    DonateClaim,
    /// Donor escrows aid, it expires unclaimed, donor is refunded.
    DonateRefund,
}

impl HighValueJourney {
    /// Every journey, in the order the monitor runs them.
    pub const ALL: [HighValueJourney; 2] = [
        HighValueJourney::DonateClaim,
        HighValueJourney::DonateRefund,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            HighValueJourney::DonateClaim => "donate_claim",
            HighValueJourney::DonateRefund => "donate_refund",
        }
    }
}

/// What a failed journey is attributed to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HvDependency {
    /// Monitor configuration refused (key material, unsafe endpoint).
    Credentials,
    /// The token contract refused a transfer (e.g. donor underfunded).
    Token,
    /// The aid contract refused the call (paused, expired, ...).
    Contract,
    /// A stranger was allowed to do something only the owner may do.
    Authorization,
    /// Balances or status differ from what the journey must produce.
    Accounting,
}

impl HvDependency {
    pub fn as_str(self) -> &'static str {
        match self {
            HvDependency::Credentials => "credentials",
            HvDependency::Token => "token",
            HvDependency::Contract => "contract",
            HvDependency::Authorization => "authorization",
            HvDependency::Accounting => "accounting",
        }
    }
}

/// How urgently a failure needs a human.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JourneySeverity {
    /// Wake someone up: funds at risk or a security control failed.
    Page,
    /// Needs a fix, but no funds are at risk right now.
    Ticket,
}

impl JourneySeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            JourneySeverity::Page => "page",
            JourneySeverity::Ticket => "ticket",
        }
    }
}

/// Faults injected into the fixture, for drills and tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HvFault {
    None,
    /// Donor is minted less than the donation; escrow fails at the token.
    UnderfundedDonor,
    /// The contract is paused before the claim and an operator resumes it
    /// after `n` refused claim attempts (`u32::MAX`: never).
    ClaimPaused(u32),
    /// The first claim succeeds but its acknowledgement is lost, so the
    /// monitor retries a claim that already settled.
    LostClaimAck,
    /// The ledger passes the expiry before the recipient claims.
    ClaimAfterExpiry,
    /// Drill for an authorization regression: the authorization probe is
    /// sent from the real recipient, so the call it expects to be refused is
    /// accepted. The monitor must report `authorization` and page.
    AuthProbeBypass,
}

/// Refuses to run the monitor with key material or a remote endpoint.
#[derive(Clone, Copy, Debug, Default)]
pub struct MonitorGuard<'a> {
    /// Key material presented to the monitor. Must be absent.
    pub secret: Option<&'a str>,
    /// RPC endpoint the monitor would target. Must be loopback.
    pub endpoint: Option<&'a str>,
}

impl MonitorGuard<'_> {
    /// `Err(step)` names the check that refused.
    pub fn check(&self) -> Result<(), &'static str> {
        if self.secret.map(str::trim).is_some_and(|s| !s.is_empty()) {
            return Err("credential check");
        }
        if let Some(url) = self.endpoint {
            let url = url.trim();
            // The loopback host must end right after the prefix, so
            // `http://localhost.evil.example` is not mistaken for loopback.
            let loopback = LOOPBACK_PREFIXES.iter().any(|prefix| {
                url.strip_prefix(prefix)
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with([':', '/']))
            });
            if url.contains(char::is_whitespace) || !loopback {
                return Err("endpoint check");
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct HvOptions<'a> {
    pub guard: MonitorGuard<'a>,
    pub max_claim_attempts: u32,
    pub fault: HvFault,
}

impl HvOptions<'_> {
    pub fn new() -> Self {
        Self {
            guard: MonitorGuard::default(),
            max_claim_attempts: DEFAULT_MAX_CLAIM_ATTEMPTS,
            fault: HvFault::None,
        }
    }
}

impl Default for HvOptions<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// A completed journey.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HvPass {
    pub journey: HighValueJourney,
    pub aid_id: u64,
    /// Claim or refund submissions made; `> 1` means the journey retried.
    pub attempts: u32,
    /// The journey retried a call that had already succeeded and confirmed
    /// the outcome from contract state instead of paying again.
    pub reconciled: bool,
    /// Authorization probes that were correctly refused.
    pub auth_probes_refused: u32,
    pub donor_balance: i128,
    pub recipient_balance: i128,
    pub escrow_balance: i128,
}

/// A failed journey.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HvFailure {
    pub journey: HighValueJourney,
    pub step: &'static str,
    pub dependency: HvDependency,
    /// The aid contract's error, when it returned one.
    pub error: Option<AidError>,
    pub attempts: u32,
    /// Whether rerunning the journey unchanged can reasonably succeed.
    pub retryable: bool,
    /// Donor funds are still held by the contract. They are safe, but the
    /// claim or refund has not happened yet.
    pub funds_escrowed: bool,
    pub severity: JourneySeverity,
}

pub type HvOutcome = Result<HvPass, HvFailure>;

/// A local deployment of the aid contract with funded synthetic actors.
///
/// Also used by [`crate::incident_runbook`] so recovery checks and the
/// monitor exercise the same deployment shape.
pub struct AidFixture {
    pub env: Env,
    pub contract: Address,
    pub token: Address,
    pub admin: Address,
    pub pauser: Address,
    pub donor: Address,
    pub recipient: Address,
    pub stranger: Address,
}

impl AidFixture {
    /// Register a token and an initialized aid contract, fund the donor with
    /// `donor_funding`, and grant a dedicated pauser.
    pub fn new(donor_funding: i128) -> Self {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_sequence_number(HV_START_LEDGER);

        let admin = Address::generate(&env);
        let pauser = Address::generate(&env);
        let donor = Address::generate(&env);
        let recipient = Address::generate(&env);
        let stranger = Address::generate(&env);
        let treasury = Address::generate(&env);

        let token = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        if donor_funding > 0 {
            token::StellarAssetClient::new(&env, &token).mint(&donor, &donor_funding);
        }

        let contract = env.register_contract(None, AidContract);
        let client = AidContractClient::new(&env, &contract);
        client.initialize(&admin, &treasury, &token, &(30 * 24 * 60 * 60));
        client.set_pauser(&admin, &pauser, &true);

        Self {
            env,
            contract,
            token,
            admin,
            pauser,
            donor,
            recipient,
            stranger,
        }
    }

    pub fn client(&self) -> AidContractClient<'_> {
        AidContractClient::new(&self.env, &self.contract)
    }

    pub fn balance(&self, who: &Address) -> i128 {
        token::Client::new(&self.env, &self.token).balance(who)
    }

    pub fn escrow_balance(&self) -> i128 {
        self.balance(&self.contract)
    }

    /// Escrow `amount` from the donor to the recipient. `None` if refused.
    pub fn donate(&self, amount: i128) -> Option<u64> {
        let expiry = self.env.ledger().sequence() + HV_EXPIRY_LEDGERS;
        match self
            .client()
            .try_create_aid(&self.donor, &self.recipient, &amount, &expiry, &None)
        {
            Ok(Ok(id)) => Some(id),
            _ => None,
        }
    }

    /// Move the ledger past the expiry of every aid created so far.
    pub fn expire_all(&self) {
        let next = self.env.ledger().sequence() + HV_EXPIRY_LEDGERS + 1;
        self.env.ledger().set_sequence_number(next);
    }

    /// `Ok(())` if the claim succeeded, otherwise the contract's error
    /// (`None` when the failure was not an `AidError`).
    pub fn claim(&self, aid_id: u64, claimant: &Address) -> Result<(), Option<AidError>> {
        flatten(self.client().try_claim_aid(&aid_id, claimant))
    }

    pub fn refund(&self, aid_id: u64, caller: &Address) -> Result<(), Option<AidError>> {
        flatten(self.client().try_refund_aid(&aid_id, caller))
    }

    /// Pause or resume as `caller`. `false` if the contract refused.
    pub fn set_paused(&self, caller: &Address, paused: bool) -> bool {
        matches!(self.client().try_set_paused(caller, &paused), Ok(Ok(())))
    }

    /// Sum of every aid still `Pending`, i.e. what the contract must hold.
    /// Fixture ids are sequential from 0, so the scan stops at the first gap.
    pub fn pending_escrow_total(&self) -> i128 {
        let client = self.client();
        let mut total = 0;
        let mut id = 0u64;
        while let Some(aid) = client.get_aid(&id) {
            if aid.status == AidStatus::Pending {
                total += aid.amount;
            }
            id += 1;
        }
        total
    }

    pub fn status(&self, aid_id: u64) -> Option<AidStatus> {
        self.client().get_aid(&aid_id).map(|record| record.status)
    }
}

fn flatten<E>(
    result: Result<Result<(), E>, Result<AidError, soroban_sdk::InvokeError>>,
) -> Result<(), Option<AidError>> {
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(None),
        Err(Ok(error)) => Err(Some(error)),
        Err(Err(_)) => Err(None),
    }
}

/// Run every high-value journey, each against a fresh local deployment.
pub fn run_all(options: &HvOptions) -> [(HighValueJourney, HvOutcome); 2] {
    HighValueJourney::ALL.map(|journey| (journey, run(journey, options)))
}

/// Run one journey against a fresh local deployment.
pub fn run(journey: HighValueJourney, options: &HvOptions) -> HvOutcome {
    // Authorization path: refuse unsafe configuration before deploying anything.
    if let Err(step) = options.guard.check() {
        return Err(HvFailure {
            journey,
            step,
            dependency: HvDependency::Credentials,
            error: None,
            attempts: 0,
            retryable: false,
            funds_escrowed: false,
            severity: JourneySeverity::Ticket,
        });
    }
    let funding = if options.fault == HvFault::UnderfundedDonor {
        HV_JOURNEY_AMOUNT / 10
    } else {
        HV_DONOR_FUNDING
    };
    let fixture = AidFixture::new(funding);
    run_on(&fixture, journey, options)
}

/// Run one journey against an existing deployment, e.g. to verify a
/// deployment after incident recovery. Balances are checked relative to the
/// deployment's state when the journey starts.
pub fn run_on(fixture: &AidFixture, journey: HighValueJourney, options: &HvOptions) -> HvOutcome {
    if let Err(step) = options.guard.check() {
        return Err(HvFailure {
            journey,
            step,
            dependency: HvDependency::Credentials,
            error: None,
            attempts: 0,
            retryable: false,
            funds_escrowed: false,
            severity: JourneySeverity::Ticket,
        });
    }
    let mut run = JourneyRun {
        fixture,
        journey,
        options,
        attempts: 0,
        funds_escrowed: false,
    };
    match journey {
        HighValueJourney::DonateClaim => run.donate_claim(),
        HighValueJourney::DonateRefund => run.donate_refund(),
    }
}

struct JourneyRun<'f, 'o, 'a> {
    fixture: &'f AidFixture,
    journey: HighValueJourney,
    options: &'o HvOptions<'a>,
    attempts: u32,
    funds_escrowed: bool,
}

/// Balances at the start of a journey, so it can run on a used deployment.
struct Baseline {
    donor: i128,
    recipient: i128,
    escrow: i128,
}

impl JourneyRun<'_, '_, '_> {
    fn fail(
        &self,
        step: &'static str,
        dependency: HvDependency,
        error: Option<AidError>,
    ) -> HvFailure {
        // A paused contract clears once an operator resumes it; everything
        // else needs a fix before a rerun can help.
        let retryable = error == Some(AidError::Paused);
        let severity = match dependency {
            HvDependency::Authorization | HvDependency::Accounting => JourneySeverity::Page,
            // Funds held but the user cannot get them out.
            _ if self.funds_escrowed && !retryable => JourneySeverity::Page,
            _ => JourneySeverity::Ticket,
        };
        HvFailure {
            journey: self.journey,
            step,
            dependency,
            error,
            attempts: self.attempts,
            retryable,
            funds_escrowed: self.funds_escrowed,
            severity,
        }
    }

    fn baseline(&self) -> Baseline {
        let f = self.fixture;
        Baseline {
            donor: f.balance(&f.donor),
            recipient: f.balance(&f.recipient),
            escrow: f.escrow_balance(),
        }
    }

    fn escrow(&mut self, base: &Baseline) -> Result<u64, HvFailure> {
        let f = self.fixture;
        let aid_id = f
            .donate(HV_JOURNEY_AMOUNT)
            .ok_or_else(|| self.fail("escrow donation", HvDependency::Token, None))?;
        self.funds_escrowed = true;
        if f.escrow_balance() != base.escrow + HV_JOURNEY_AMOUNT
            || f.balance(&f.donor) != base.donor - HV_JOURNEY_AMOUNT
            || f.status(aid_id) != Some(AidStatus::Pending)
        {
            return Err(self.fail("verify escrow", HvDependency::Accounting, None));
        }
        Ok(aid_id)
    }

    /// The probe address: a stranger, unless the bypass drill swaps in the
    /// real owner to simulate a broken authorization check.
    fn probe(&self, owner: &Address) -> Address {
        if self.options.fault == HvFault::AuthProbeBypass {
            owner.clone()
        } else {
            self.fixture.stranger.clone()
        }
    }

    fn donate_claim(&mut self) -> HvOutcome {
        let f = self.fixture;
        let base = self.baseline();
        let aid_id = self.escrow(&base)?;

        // Authorization probe: a stranger must not be able to claim.
        let probe = self.probe(&f.recipient);
        match f.claim(aid_id, &probe) {
            Err(Some(AidError::Unauthorized)) => {}
            _ => return Err(self.fail("authorization probe", HvDependency::Authorization, None)),
        }

        match self.options.fault {
            HvFault::ClaimAfterExpiry => f.expire_all(),
            HvFault::ClaimPaused(_) => {
                if !f.set_paused(&f.pauser, true) {
                    return Err(self.fail("pause drill", HvDependency::Contract, None));
                }
            }
            _ => {}
        }

        let max_attempts = self
            .options
            .max_claim_attempts
            .clamp(1, MAX_CLAIM_ATTEMPTS_CAP);
        let mut reconciled = false;
        loop {
            self.attempts += 1;
            let mut result = f.claim(aid_id, &f.recipient);
            if self.options.fault == HvFault::LostClaimAck && self.attempts == 1 && result.is_ok() {
                // The call landed but the monitor never saw the response.
                result = Err(None);
            }
            match result {
                Ok(()) => break,
                // Retry path 1: a claim that already landed is reconciled from
                // state, never resubmitted as a new payment.
                Err(Some(AidError::AlreadyClaimed)) if self.attempts > 1 => {
                    reconciled = true;
                    break;
                }
                // Retry path 2: paused is transient; wait for an operator.
                Err(Some(AidError::Paused)) if self.attempts < max_attempts => {
                    if let HvFault::ClaimPaused(resume_after) = self.options.fault {
                        if self.attempts >= resume_after {
                            f.set_paused(&f.pauser, false);
                        }
                    }
                }
                Err(None) if self.attempts < max_attempts => {}
                Err(error) => {
                    return Err(self.fail("claim", HvDependency::Contract, error));
                }
            }
        }

        self.funds_escrowed = false;
        // Exactly one payment, regardless of how many attempts it took.
        if f.status(aid_id) != Some(AidStatus::Settled)
            || f.balance(&f.recipient) != base.recipient + HV_JOURNEY_AMOUNT
            || f.balance(&f.donor) != base.donor - HV_JOURNEY_AMOUNT
            || f.escrow_balance() != base.escrow
        {
            return Err(self.fail("verify settlement", HvDependency::Accounting, None));
        }
        Ok(self.pass(aid_id, reconciled))
    }

    fn donate_refund(&mut self) -> HvOutcome {
        let f = self.fixture;
        let base = self.baseline();
        let aid_id = self.escrow(&base)?;

        // Refunding before expiry must be refused, or donors could pull
        // funds out from under a recipient.
        if f.refund(aid_id, &f.donor) != Err(Some(AidError::NotExpiredYet)) {
            return Err(self.fail("early refund guard", HvDependency::Contract, None));
        }
        f.expire_all();

        // Authorization probe: a stranger must not be able to trigger the refund.
        let probe = self.probe(&f.donor);
        match f.refund(aid_id, &probe) {
            Err(Some(AidError::Unauthorized)) => {}
            _ => return Err(self.fail("authorization probe", HvDependency::Authorization, None)),
        }
        // Once expired, the recipient can no longer claim.
        if f.claim(aid_id, &f.recipient) != Err(Some(AidError::Expired)) {
            return Err(self.fail("expired claim guard", HvDependency::Contract, None));
        }

        self.attempts = 1;
        if let Err(error) = f.refund(aid_id, &f.donor) {
            return Err(self.fail("refund", HvDependency::Contract, error));
        }
        // Retrying a refund that landed must be refused, not paid again.
        self.attempts = 2;
        if f.refund(aid_id, &f.donor) != Err(Some(AidError::AlreadyRefunded)) {
            return Err(self.fail("refund retry guard", HvDependency::Accounting, None));
        }

        self.funds_escrowed = false;
        if f.status(aid_id) != Some(AidStatus::Refunded)
            || f.balance(&f.donor) != base.donor
            || f.balance(&f.recipient) != base.recipient
            || f.escrow_balance() != base.escrow
        {
            return Err(self.fail("verify refund", HvDependency::Accounting, None));
        }
        Ok(self.pass(aid_id, false))
    }

    fn pass(&self, aid_id: u64, reconciled: bool) -> HvPass {
        let f = self.fixture;
        HvPass {
            journey: self.journey,
            aid_id,
            attempts: self.attempts,
            reconciled,
            // Each journey sends one probe; reaching here means it was refused.
            auth_probes_refused: 1,
            donor_balance: f.balance(&f.donor),
            recipient_balance: f.balance(&f.recipient),
            escrow_balance: f.escrow_balance(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(fault: HvFault) -> HvOptions<'static> {
        HvOptions {
            fault,
            ..HvOptions::new()
        }
    }

    // ── normal ──────────────────────────────────────────────────────────

    #[test]
    fn donate_claim_pays_recipient_exactly_once() {
        let pass = run(HighValueJourney::DonateClaim, &HvOptions::new()).unwrap();
        assert_eq!(pass.attempts, 1);
        assert!(!pass.reconciled);
        assert_eq!(pass.auth_probes_refused, 1);
        assert_eq!(pass.recipient_balance, HV_JOURNEY_AMOUNT);
        assert_eq!(pass.donor_balance, HV_DONOR_FUNDING - HV_JOURNEY_AMOUNT);
        assert_eq!(pass.escrow_balance, 0);
    }

    #[test]
    fn donate_refund_makes_donor_whole() {
        let pass = run(HighValueJourney::DonateRefund, &HvOptions::new()).unwrap();
        assert_eq!(pass.donor_balance, HV_DONOR_FUNDING);
        assert_eq!(pass.recipient_balance, 0);
        assert_eq!(pass.escrow_balance, 0);
        // Second refund attempt was the retry guard, and it was refused.
        assert_eq!(pass.attempts, 2);
    }

    #[test]
    fn run_all_covers_every_journey_and_passes() {
        let results = run_all(&HvOptions::new());
        assert_eq!(results.len(), HighValueJourney::ALL.len());
        for (journey, outcome) in results {
            assert_eq!(outcome.unwrap().journey, journey);
        }
    }

    #[test]
    fn journeys_can_run_on_a_used_deployment() {
        let fixture = AidFixture::new(HV_DONOR_FUNDING);
        let options = HvOptions::new();
        run_on(&fixture, HighValueJourney::DonateClaim, &options).unwrap();
        run_on(&fixture, HighValueJourney::DonateRefund, &options).unwrap();
        let again = run_on(&fixture, HighValueJourney::DonateClaim, &options).unwrap();
        assert_eq!(again.recipient_balance, 2 * HV_JOURNEY_AMOUNT);
    }

    // ── failure ─────────────────────────────────────────────────────────

    #[test]
    fn underfunded_donor_is_blamed_on_the_token_with_no_funds_held() {
        let failure = run(
            HighValueJourney::DonateClaim,
            &opts(HvFault::UnderfundedDonor),
        )
        .unwrap_err();
        assert_eq!(failure.dependency, HvDependency::Token);
        assert_eq!(failure.step, "escrow donation");
        assert!(!failure.funds_escrowed);
        assert!(!failure.retryable);
        assert_eq!(failure.severity, JourneySeverity::Ticket);
    }

    #[test]
    fn claim_after_expiry_pages_because_funds_are_stuck_in_escrow() {
        let failure = run(
            HighValueJourney::DonateClaim,
            &opts(HvFault::ClaimAfterExpiry),
        )
        .unwrap_err();
        assert_eq!(failure.dependency, HvDependency::Contract);
        assert_eq!(failure.error, Some(AidError::Expired));
        assert!(failure.funds_escrowed);
        assert!(!failure.retryable);
        assert_eq!(failure.severity, JourneySeverity::Page);
    }

    // ── retry ───────────────────────────────────────────────────────────

    #[test]
    fn paused_claim_recovers_once_an_operator_resumes() {
        let pass = run(
            HighValueJourney::DonateClaim,
            &opts(HvFault::ClaimPaused(2)),
        )
        .unwrap();
        assert_eq!(pass.attempts, 3);
        assert_eq!(pass.recipient_balance, HV_JOURNEY_AMOUNT);
    }

    #[test]
    fn paused_claim_exhausts_bounded_budget_and_keeps_funds_escrowed() {
        let failure = run(
            HighValueJourney::DonateClaim,
            &opts(HvFault::ClaimPaused(u32::MAX)),
        )
        .unwrap_err();
        assert_eq!(failure.error, Some(AidError::Paused));
        assert_eq!(failure.attempts, DEFAULT_MAX_CLAIM_ATTEMPTS);
        assert!(failure.retryable);
        assert!(failure.funds_escrowed);
        assert_eq!(failure.severity, JourneySeverity::Ticket);
    }

    #[test]
    fn claim_retry_budget_is_clamped() {
        let none = run(
            HighValueJourney::DonateClaim,
            &HvOptions {
                max_claim_attempts: 0,
                ..opts(HvFault::ClaimPaused(u32::MAX))
            },
        )
        .unwrap_err();
        assert_eq!(none.attempts, 1);

        let capped = run(
            HighValueJourney::DonateClaim,
            &HvOptions {
                max_claim_attempts: u32::MAX,
                ..opts(HvFault::ClaimPaused(u32::MAX))
            },
        )
        .unwrap_err();
        assert_eq!(capped.attempts, MAX_CLAIM_ATTEMPTS_CAP);
    }

    #[test]
    fn lost_claim_ack_is_reconciled_without_a_second_payment() {
        let pass = run(HighValueJourney::DonateClaim, &opts(HvFault::LostClaimAck)).unwrap();
        assert!(pass.reconciled);
        assert_eq!(pass.attempts, 2);
        assert_eq!(pass.recipient_balance, HV_JOURNEY_AMOUNT);
        assert_eq!(pass.escrow_balance, 0);
    }

    // ── authorization ───────────────────────────────────────────────────

    #[test]
    fn auth_bypass_drill_pages_on_both_journeys() {
        for journey in HighValueJourney::ALL {
            let failure = run(journey, &opts(HvFault::AuthProbeBypass)).unwrap_err();
            assert_eq!(
                failure.dependency,
                HvDependency::Authorization,
                "{journey:?}"
            );
            assert_eq!(failure.step, "authorization probe");
            assert_eq!(failure.severity, JourneySeverity::Page);
        }
    }

    #[test]
    fn key_material_and_remote_endpoints_are_refused_before_deploying() {
        let secret = run(
            HighValueJourney::DonateClaim,
            &HvOptions {
                guard: MonitorGuard {
                    secret: Some("SDUMMYSECRETVALUE"),
                    endpoint: None,
                },
                ..HvOptions::new()
            },
        )
        .unwrap_err();
        assert_eq!(secret.dependency, HvDependency::Credentials);
        assert_eq!(secret.step, "credential check");

        let endpoint = |url| MonitorGuard {
            secret: None,
            endpoint: Some(url),
        };
        for refused in [
            "https://soroban-mainnet.stellar.org",
            "http://localhost.evil.example:8000",
            "http://127.0.0.1.nip.io/rpc",
            "http://localhost :8000",
            "",
        ] {
            assert_eq!(
                endpoint(refused).check(),
                Err("endpoint check"),
                "{refused}"
            );
        }
        for allowed in [
            "http://localhost",
            "http://127.0.0.1:8000/rpc",
            "http://[::1]:8000",
        ] {
            assert!(endpoint(allowed).check().is_ok(), "{allowed}");
        }
        // Blank secrets are treated as absent.
        assert!(MonitorGuard {
            secret: Some("   "),
            endpoint: None,
        }
        .check()
        .is_ok());

        let remote = run(
            HighValueJourney::DonateRefund,
            &HvOptions {
                guard: endpoint("https://soroban-mainnet.stellar.org"),
                ..HvOptions::new()
            },
        )
        .unwrap_err();
        assert_eq!(remote.dependency, HvDependency::Credentials);
        assert_eq!(remote.attempts, 0);
    }
}
