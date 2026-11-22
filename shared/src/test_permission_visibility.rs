//! Contract tests for permission changes and hidden records (Issue #445).
//!
//! Visibility on the timeline is derived from on-chain roles at read time.
//! These tests pin down what happens to hidden records (participant-only,
//! redacted, deleted) when those roles change: grants, revocations and admin
//! ownership transfers.

#![cfg(test)]

extern crate std;

use soroban_sdk::{
    contract, contractimpl, symbol_short,
    testutils::{Address as _, Ledger as _},
    Address, Bytes, Env,
};

use crate::{
    auth::{
        accept_ownership_transfer, grant_role, propose_ownership_transfer, revoke_role, set_admin,
        Role,
    },
    errors::Error,
    timeline::{
        anonymous_viewer, append_user_event, can_view, delete_entry, entry_exists, is_maintainer,
        redact_entry, timeline_page, viewer_for, ResourceLink, TimelineEntry, TimelineEventType,
        Visibility,
    },
};

#[contract]
pub struct DummyVisibilityContract;

#[contractimpl]
impl DummyVisibilityContract {
    pub fn noop(_env: Env) {}
}

struct Ctx {
    env: Env,
    id: Address,
    admin: Address,
    alice: Address,
    bob: Address,
    carol: Address,
}

impl Ctx {
    /// One contract frame per operation: the test host refuses a second
    /// `require_auth` for the same address inside one frame.
    fn run<T>(&self, f: impl FnOnce() -> T) -> T {
        self.env.as_contract(&self.id, f)
    }
}

fn setup() -> Ctx {
    let env = Env::default();
    env.mock_all_auths_allowing_non_root_auth();
    env.ledger().set_timestamp(100);
    let admin = Address::generate(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let carol = Address::generate(&env);
    let id = env.register_contract(None, DummyVisibilityContract);
    env.as_contract(&id, || {
        set_admin(&env, &admin);
        grant_role(&env, &admin, &admin, Role::Admin).unwrap();
    });
    Ctx {
        env,
        id,
        admin,
        alice,
        bob,
        carol,
    }
}

fn link(env: &Env, id: u64) -> ResourceLink {
    ResourceLink {
        kind: Bytes::from_slice(env, b"aid"),
        id,
        revision: 0,
    }
}

/// Alice pays Bob: visible to Alice, Bob and maintainers only.
fn participant_entry(ctx: &Ctx, id: u64) -> TimelineEntry {
    ctx.run(|| {
        append_user_event(
            &ctx.env,
            Some(ctx.alice.clone()),
            TimelineEventType::PaymentSent,
            Visibility::Participant,
            link(&ctx.env, id),
            Some(ctx.bob.clone()),
            symbol_short!("paid"),
        )
        .unwrap()
    })
}

fn public_entry(ctx: &Ctx, id: u64) -> TimelineEntry {
    ctx.run(|| {
        append_user_event(
            &ctx.env,
            Some(ctx.alice.clone()),
            TimelineEventType::RecordCreated,
            Visibility::Public,
            link(&ctx.env, id),
            None,
            symbol_short!("created"),
        )
        .unwrap()
    })
}

fn visible_to(ctx: &Ctx, who: &Address) -> std::vec::Vec<u64> {
    ctx.run(|| {
        let page = timeline_page(&ctx.env, &viewer_for(&ctx.env, who), None, 0).unwrap();
        let mut out = std::vec::Vec::new();
        for e in page.entries.iter() {
            out.push(e.seq);
        }
        out
    })
}

#[test]
fn granting_and_revoking_a_maintainer_role_toggles_access_to_participant_records() {
    let ctx = setup();
    let entry = participant_entry(&ctx, 1);

    assert!(visible_to(&ctx, &ctx.carol).is_empty());

    ctx.run(|| grant_role(&ctx.env, &ctx.admin, &ctx.carol, Role::Upgrader).unwrap());
    assert_eq!(visible_to(&ctx, &ctx.carol), std::vec![entry.seq]);

    ctx.run(|| revoke_role(&ctx.env, &ctx.admin, &ctx.carol, Role::Upgrader).unwrap());
    assert!(visible_to(&ctx, &ctx.carol).is_empty());
    // The participants themselves are unaffected by someone else's role change.
    assert_eq!(visible_to(&ctx, &ctx.bob), std::vec![entry.seq]);
}

#[test]
fn a_non_maintainer_role_grants_no_extra_visibility() {
    let ctx = setup();
    participant_entry(&ctx, 1);

    ctx.run(|| grant_role(&ctx.env, &ctx.admin, &ctx.carol, Role::TreasuryManager).unwrap());
    ctx.run(|| {
        assert!(!is_maintainer(&ctx.env, &ctx.carol));
    });
    assert!(visible_to(&ctx, &ctx.carol).is_empty());
}

#[test]
fn redacted_records_stay_hidden_after_a_maintainer_is_revoked() {
    let ctx = setup();
    let entry = public_entry(&ctx, 1);
    ctx.run(|| redact_entry(&ctx.env, &ctx.admin, entry.seq, symbol_short!("pii")).unwrap());

    ctx.run(|| grant_role(&ctx.env, &ctx.admin, &ctx.carol, Role::Upgrader).unwrap());
    assert_eq!(visible_to(&ctx, &ctx.carol), std::vec![entry.seq]);
    // The author of a redacted public entry no longer sees it either.
    assert!(visible_to(&ctx, &ctx.alice).is_empty());
    ctx.run(|| {
        let page = timeline_page(&ctx.env, &anonymous_viewer(), None, 0).unwrap();
        assert_eq!(page.entries.len(), 0);
    });

    ctx.run(|| revoke_role(&ctx.env, &ctx.admin, &ctx.carol, Role::Upgrader).unwrap());
    assert!(visible_to(&ctx, &ctx.carol).is_empty());
}

#[test]
fn a_viewer_must_be_rebuilt_after_a_role_change() {
    let ctx = setup();
    let entry = participant_entry(&ctx, 1);
    ctx.run(|| grant_role(&ctx.env, &ctx.admin, &ctx.carol, Role::Upgrader).unwrap());

    let stale = ctx.run(|| viewer_for(&ctx.env, &ctx.carol));
    ctx.run(|| revoke_role(&ctx.env, &ctx.admin, &ctx.carol, Role::Upgrader).unwrap());

    // `Viewer` is a value snapshot: a copy held across a revocation still
    // claims maintainer status. Reads must build the viewer in the same
    // invocation, which `viewer_for` does from current role storage.
    assert!(stale.is_maintainer);
    assert!(can_view(&entry, &stale));
    ctx.run(|| {
        let fresh = viewer_for(&ctx.env, &ctx.carol);
        assert!(!fresh.is_maintainer);
        assert!(!can_view(&entry, &fresh));
    });
}

#[test]
fn ownership_transfer_moves_maintainer_visibility() {
    let ctx = setup();
    let entry = participant_entry(&ctx, 1);
    assert_eq!(visible_to(&ctx, &ctx.admin), std::vec![entry.seq]);

    ctx.run(|| propose_ownership_transfer(&ctx.env, &ctx.admin, &ctx.carol, 200).unwrap());
    // Proposing alone changes nothing.
    assert!(visible_to(&ctx, &ctx.carol).is_empty());

    ctx.run(|| accept_ownership_transfer(&ctx.env, &ctx.carol).unwrap());
    assert_eq!(visible_to(&ctx, &ctx.carol), std::vec![entry.seq]);
    assert!(visible_to(&ctx, &ctx.admin).is_empty());
}

#[test]
fn a_revoked_admin_role_cannot_redact() {
    let ctx = setup();
    let entry = public_entry(&ctx, 1);

    ctx.run(|| grant_role(&ctx.env, &ctx.admin, &ctx.carol, Role::Admin).unwrap());
    ctx.run(|| redact_entry(&ctx.env, &ctx.carol, entry.seq, symbol_short!("spam")).unwrap());

    ctx.run(|| revoke_role(&ctx.env, &ctx.admin, &ctx.carol, Role::Admin).unwrap());
    ctx.run(|| {
        assert_eq!(
            redact_entry(&ctx.env, &ctx.carol, entry.seq, symbol_short!("spam")),
            Err(Error::Unauthorized)
        );
    });
}

#[test]
fn hidden_records_do_not_shift_pagination_for_other_viewers() {
    let ctx = setup();
    let hidden = participant_entry(&ctx, 1);
    let redacted = public_entry(&ctx, 2);
    let visible = public_entry(&ctx, 3);
    ctx.run(|| redact_entry(&ctx.env, &ctx.admin, redacted.seq, symbol_short!("pii")).unwrap());

    ctx.run(|| {
        let viewer = viewer_for(&ctx.env, &ctx.carol);
        let page = timeline_page(&ctx.env, &viewer, None, 1).unwrap();
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries.get(0).unwrap().seq, visible.seq);
        assert!(!page.has_more);
        assert_eq!(page.next_cursor, None);
    });
    assert_eq!(
        visible_to(&ctx, &ctx.admin),
        std::vec![hidden.seq, redacted.seq, visible.seq]
    );
}

#[test]
fn deleted_records_are_gone_even_for_maintainers() {
    let ctx = setup();
    let entry = participant_entry(&ctx, 1);
    ctx.run(|| delete_entry(&ctx.env, &ctx.admin, entry.seq, symbol_short!("gdpr")).unwrap());

    ctx.run(|| assert!(!entry_exists(&ctx.env, entry.seq)));
    assert!(visible_to(&ctx, &ctx.admin).is_empty());
    assert!(visible_to(&ctx, &ctx.bob).is_empty());
}
