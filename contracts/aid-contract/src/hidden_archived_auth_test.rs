//! Authorization tests for hidden and archived aid records (Issue #480).
//!
//! Vocabulary used throughout (see `docs/HIDDEN_ARCHIVED_RECORDS.md`):
//!
//! - **Hidden** — a record whose admin-controlled `SearchHidden` flag is set
//!   via [`AidContract::set_aid_search_visibility`]. Hiding is a *discovery*
//!   control: the record leaves `search_aids` / `search_aids_cursor` for every
//!   viewer, but owners keep it in their own listings and it stays claimable /
//!   refundable so escrowed funds are never locked by a visibility toggle.
//! - **Archived** — a terminal record (`Settled` or `Refunded`) that is kept
//!   in canonical storage for owners and audit but is no longer discoverable.
//! - **Purged** — an archived record removed by [`AidContract::delete_aid`].
//! - **Evicted** — a record whose canonical entry disappeared (TTL expiry,
//!   simulated here by removing the key), leaving a dangling index entry.
//!
//! Each section covers one of the acceptance-criteria paths: normal, failure,
//! authorization (both the role check and the signature check), retry, and
//! recovery / rollback.

extern crate std;

use super::*;
use soroban_sdk::{
    testutils::{Address as _, AuthorizedFunction, Ledger},
    token, Env, IntoVal,
};

const MINT_AMOUNT: i128 = 1_000_000;
const AMOUNT: i128 = 100;

struct Fx {
    env: Env,
    admin: Address,
    donor: Address,
    recipient: Address,
    delegate: Address,
    outsider: Address,
    token: Address,
    contract_id: Address,
}

impl Fx {
    fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let donor = Address::generate(&env);
        let recipient = Address::generate(&env);
        let delegate = Address::generate(&env);
        let outsider = Address::generate(&env);

        let token = env
            .register_stellar_asset_contract_v2(admin.clone())
            .address();
        token::StellarAssetClient::new(&env, &token).mint(&donor, &MINT_AMOUNT);

        let contract_id = env.register_contract(None, AidContract);
        let treasury = Address::generate(&env);
        AidContractClient::new(&env, &contract_id).initialize(&admin, &treasury, &token, &3600);

        Fx {
            env,
            admin,
            donor,
            recipient,
            delegate,
            outsider,
            token,
            contract_id,
        }
    }

    fn client(&self) -> AidContractClient<'_> {
        AidContractClient::new(&self.env, &self.contract_id)
    }

    fn create(&self) -> u64 {
        let expiry = self.env.ledger().sequence() + 100;
        self.client()
            .create_aid(&self.donor, &self.recipient, &AMOUNT, &expiry, &None)
    }

    fn create_n(&self, n: u32) -> std::vec::Vec<u64> {
        (0..n).map(|_| self.create()).collect()
    }

    fn advance_past_expiry(&self) {
        self.env.ledger().with_mut(|l| l.sequence_number += 101);
    }

    /// Raw derived discovery index, bypassing every read-time filter.
    fn index(&self) -> std::vec::Vec<u64> {
        self.env.as_contract(&self.contract_id, || {
            storage::get_search_index(&self.env).iter().collect()
        })
    }

    fn is_hidden(&self, aid_id: u64) -> bool {
        self.env.as_contract(&self.contract_id, || {
            storage::is_search_hidden(&self.env, aid_id)
        })
    }

    fn balance(&self, who: &Address) -> i128 {
        token::Client::new(&self.env, &self.token).balance(who)
    }

    /// IDs returned by the legacy offset search for `viewer`.
    fn search_ids(&self, viewer: &Address) -> std::vec::Vec<u64> {
        self.client()
            .search_aids(viewer, &0, &50)
            .records
            .iter()
            .map(|r| r.id)
            .collect()
    }

    /// IDs returned by walking every page of the keyset cursor search.
    fn cursor_search_ids(&self, viewer: &Address, page_size: u32) -> std::vec::Vec<u64> {
        let mut out = std::vec::Vec::new();
        let mut cursor: Option<u64> = None;
        loop {
            let page = self
                .client()
                .search_aids_cursor(viewer, &cursor, &page_size);
            out.extend(page.records.iter().map(|r| r.id));
            if !page.has_more {
                break;
            }
            cursor = page.next_cursor;
        }
        out
    }

    fn donor_ids(&self) -> std::vec::Vec<u64> {
        self.client()
            .list_aids_by_donor_cursor(&self.donor, &None, &50)
            .records
            .iter()
            .map(|r| r.id)
            .collect()
    }

    fn recipient_ids(&self) -> std::vec::Vec<u64> {
        self.client()
            .list_aids_by_recipient_cursor(&self.recipient, &None, &50)
            .records
            .iter()
            .map(|r| r.id)
            .collect()
    }

    /// Every privileged or participant viewer that could plausibly see a record.
    fn all_viewers(&self) -> [Address; 5] {
        [
            self.admin.clone(),
            self.donor.clone(),
            self.recipient.clone(),
            self.delegate.clone(),
            self.outsider.clone(),
        ]
    }

    fn assert_undiscoverable_by_anyone(&self, aid_id: u64) {
        for viewer in self.all_viewers().iter() {
            assert!(
                !self.search_ids(viewer).contains(&aid_id),
                "aid {aid_id} leaked through search_aids to {viewer:?}"
            );
            assert!(
                !self.cursor_search_ids(viewer, 2).contains(&aid_id),
                "aid {aid_id} leaked through search_aids_cursor to {viewer:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Normal paths
// ---------------------------------------------------------------------------

#[test]
fn hidden_pending_record_is_undiscoverable_by_every_viewer_including_admin() {
    let fx = Fx::new();
    let ids = fx.create_n(3);
    fx.client()
        .grant_search_access(&fx.donor, &ids[1], &fx.delegate);

    fx.client()
        .set_aid_search_visibility(&fx.admin, &ids[1], &false);

    assert!(fx.is_hidden(ids[1]));
    assert_eq!(fx.index(), std::vec![ids[0], ids[2]]);
    fx.assert_undiscoverable_by_anyone(ids[1]);
    // Neighbouring visible records are unaffected.
    assert_eq!(fx.search_ids(&fx.donor), std::vec![ids[0], ids[2]]);
    // An explicit discovery grant does not override the hidden flag.
    assert!(fx
        .client()
        .search_aids(&fx.delegate, &0, &50)
        .records
        .is_empty());
}

#[test]
fn hidden_record_stays_in_owner_listings_and_canonical_reads() {
    let fx = Fx::new();
    let id = fx.create();
    fx.client()
        .set_aid_search_visibility(&fx.admin, &id, &false);

    // Hiding is a discovery control, not a deletion: owners still see it.
    assert_eq!(fx.donor_ids(), std::vec![id]);
    assert_eq!(fx.recipient_ids(), std::vec![id]);
    let legacy = fx.client().list_aids_by_donor(&fx.donor, &0, &50);
    assert_eq!(legacy.records.len(), 1);
    let record = fx.client().get_aid(&id).expect("canonical record retained");
    assert_eq!(record.status, AidStatus::Pending);
}

#[test]
fn archived_records_leave_discovery_but_stay_with_owners() {
    let fx = Fx::new();
    let settled = fx.create();
    let refunded = fx.create();
    let live = fx.create();
    fx.client()
        .grant_search_access(&fx.donor, &settled, &fx.delegate);
    fx.client()
        .grant_search_access(&fx.donor, &refunded, &fx.delegate);

    fx.client().claim_aid(&settled, &fx.recipient);
    fx.advance_past_expiry();
    fx.client().refund_aid(&refunded, &fx.donor);

    assert_eq!(fx.index(), std::vec![live]);
    fx.assert_undiscoverable_by_anyone(settled);
    fx.assert_undiscoverable_by_anyone(refunded);

    assert_eq!(fx.donor_ids(), std::vec![settled, refunded, live]);
    assert_eq!(fx.recipient_ids(), std::vec![settled, refunded, live]);
    assert_eq!(
        fx.client().get_aid(&settled).unwrap().status,
        AidStatus::Settled
    );
    assert_eq!(
        fx.client().get_aid(&refunded).unwrap().status,
        AidStatus::Refunded
    );
}

#[test]
fn hiding_never_locks_escrowed_funds() {
    let fx = Fx::new();
    let claimable = fx.create();
    let refundable = fx.create();
    fx.client()
        .set_aid_search_visibility(&fx.admin, &claimable, &false);
    fx.client()
        .set_aid_search_visibility(&fx.admin, &refundable, &false);

    let escrow_before = fx.balance(&fx.contract_id);
    fx.client().claim_aid(&claimable, &fx.recipient);
    assert_eq!(fx.balance(&fx.recipient), AMOUNT);

    fx.advance_past_expiry();
    let donor_before = fx.balance(&fx.donor);
    fx.client().refund_aid(&refundable, &fx.donor);
    assert_eq!(fx.balance(&fx.donor), donor_before + AMOUNT);
    assert_eq!(fx.balance(&fx.contract_id), escrow_before - 2 * AMOUNT);

    // Archived while hidden: still not discoverable, hidden flag persists.
    assert!(fx.is_hidden(claimable));
    assert!(fx.index().is_empty());
}

#[test]
fn hidden_milestone_program_stays_claimable_and_cannot_be_purged_mid_flight() {
    let fx = Fx::new();
    let mut milestones = Vec::new(&fx.env);
    for _ in 0..2 {
        milestones.push_back(AidMilestone {
            description: symbol_short!("phase"),
            amount: AMOUNT,
            verified: false,
            claimed: false,
        });
    }
    let expiry = fx.env.ledger().sequence() + 100;
    let id = fx
        .client()
        .create_milestone_aid(&fx.donor, &fx.recipient, &milestones, &expiry);
    fx.client()
        .set_aid_search_visibility(&fx.admin, &id, &false);

    fx.client().verify_milestone(&fx.admin, &id, &0);
    fx.client().claim_aid_milestone(&fx.recipient, &id, &0);
    assert_eq!(
        fx.client().get_aid(&id).unwrap().status,
        AidStatus::PartiallyClaimed
    );

    // Still escrowing the second tranche, so even the admin cannot purge it.
    assert_eq!(
        fx.client().try_delete_aid(&fx.admin, &id),
        Err(Ok(AidError::CannotDeletePending))
    );
    fx.assert_undiscoverable_by_anyone(id);
}

// ---------------------------------------------------------------------------
// Authorization (role) paths — every rejection must leave state untouched
// ---------------------------------------------------------------------------

#[test]
fn only_admin_can_hide_or_unhide_a_record() {
    let fx = Fx::new();
    let visible = fx.create();
    let hidden = fx.create();
    fx.client()
        .set_aid_search_visibility(&fx.admin, &hidden, &false);
    let index_before = fx.index();

    for caller in [&fx.donor, &fx.recipient, &fx.delegate, &fx.outsider] {
        assert_eq!(
            fx.client()
                .try_set_aid_search_visibility(caller, &visible, &false),
            Err(Ok(AidError::Unauthorized)),
            "{caller:?} must not hide a record"
        );
        assert_eq!(
            fx.client()
                .try_set_aid_search_visibility(caller, &hidden, &true),
            Err(Ok(AidError::Unauthorized)),
            "{caller:?} must not unhide a record"
        );
    }

    assert!(!fx.is_hidden(visible));
    assert!(fx.is_hidden(hidden));
    assert_eq!(fx.index(), index_before);
}

#[test]
fn only_admin_can_purge_archived_records() {
    let fx = Fx::new();
    let id = fx.create();
    fx.client().claim_aid(&id, &fx.recipient);

    for caller in [&fx.donor, &fx.recipient, &fx.delegate, &fx.outsider] {
        assert_eq!(
            fx.client().try_delete_aid(caller, &id),
            Err(Ok(AidError::Unauthorized)),
            "{caller:?} must not purge an archived record"
        );
    }
    assert_eq!(fx.client().get_aid(&id).unwrap().status, AidStatus::Settled);

    fx.client().delete_aid(&fx.admin, &id);
    assert_eq!(fx.client().get_aid(&id), None);
    assert!(fx.donor_ids().is_empty());
}

#[test]
fn hidden_pending_record_cannot_be_purged_even_by_admin() {
    let fx = Fx::new();
    let id = fx.create();
    fx.client()
        .set_aid_search_visibility(&fx.admin, &id, &false);

    assert_eq!(
        fx.client().try_delete_aid(&fx.admin, &id),
        Err(Ok(AidError::CannotDeletePending))
    );
    assert!(fx.client().get_aid(&id).is_some());
    assert_eq!(fx.balance(&fx.contract_id), AMOUNT);
}

#[test]
fn only_donor_can_grant_or_revoke_discovery_on_hidden_and_archived_records() {
    let fx = Fx::new();
    let hidden = fx.create();
    let archived = fx.create();
    fx.client()
        .set_aid_search_visibility(&fx.admin, &hidden, &false);
    fx.client().claim_aid(&archived, &fx.recipient);

    for id in [hidden, archived] {
        // The admin moderates visibility but does not own discovery grants.
        for caller in [&fx.admin, &fx.recipient, &fx.outsider] {
            assert_eq!(
                fx.client()
                    .try_grant_search_access(caller, &id, &fx.delegate),
                Err(Ok(AidError::Unauthorized))
            );
            assert_eq!(
                fx.client()
                    .try_revoke_search_access(caller, &id, &fx.delegate),
                Err(Ok(AidError::Unauthorized))
            );
        }
    }
}

#[test]
fn donor_grant_cannot_reveal_hidden_or_archived_records() {
    let fx = Fx::new();
    let hidden = fx.create();
    let archived = fx.create();
    fx.client()
        .set_aid_search_visibility(&fx.admin, &hidden, &false);
    fx.client().claim_aid(&archived, &fx.recipient);

    // Granting is allowed (the donor owns the record) but is inert while the
    // record is hidden or archived: the read-time filter wins.
    fx.client()
        .grant_search_access(&fx.donor, &hidden, &fx.delegate);
    fx.client()
        .grant_search_access(&fx.donor, &archived, &fx.delegate);
    assert!(fx.search_ids(&fx.delegate).is_empty());
    assert!(fx.cursor_search_ids(&fx.delegate, 1).is_empty());

    // Once the admin restores the hidden record, the pre-existing grant applies.
    fx.client()
        .set_aid_search_visibility(&fx.admin, &hidden, &true);
    assert_eq!(fx.search_ids(&fx.delegate), std::vec![hidden]);
}

#[test]
fn rotated_admin_loses_moderation_rights_over_hidden_records() {
    let fx = Fx::new();
    let id = fx.create();
    fx.client()
        .set_aid_search_visibility(&fx.admin, &id, &false);

    let new_admin = Address::generate(&fx.env);
    fx.env.as_contract(&fx.contract_id, || {
        shared::auth::set_admin(&fx.env, &new_admin);
    });

    assert_eq!(
        fx.client()
            .try_set_aid_search_visibility(&fx.admin, &id, &true),
        Err(Ok(AidError::Unauthorized))
    );
    assert!(fx.is_hidden(id));
    // The former admin also no longer receives the admin discovery bypass.
    fx.client()
        .set_aid_search_visibility(&new_admin, &id, &true);
    assert!(!fx.search_ids(&fx.admin).contains(&id));
    assert_eq!(fx.search_ids(&new_admin), std::vec![id]);
}

// ---------------------------------------------------------------------------
// Authorization (signature) paths — passing a privileged address is not
// enough; the address must actually sign.
// ---------------------------------------------------------------------------

#[test]
fn visibility_change_requires_admin_signature_not_just_admin_address() {
    let fx = Fx::new();
    let id = fx.create();

    fx.env.set_auths(&[]);
    assert!(fx
        .client()
        .try_set_aid_search_visibility(&fx.admin, &id, &false)
        .is_err());
    assert!(!fx.is_hidden(id));

    fx.env.mock_all_auths();
    fx.client()
        .set_aid_search_visibility(&fx.admin, &id, &false);
    let auths = fx.env.auths();
    assert_eq!(auths.len(), 1);
    let (signer, invocation) = &auths[0];
    assert_eq!(signer, &fx.admin);
    assert_eq!(
        invocation.function,
        AuthorizedFunction::Contract((
            fx.contract_id.clone(),
            Symbol::new(&fx.env, "set_aid_search_visibility"),
            (fx.admin.clone(), id, false).into_val(&fx.env),
        ))
    );
}

#[test]
fn purge_requires_admin_signature() {
    let fx = Fx::new();
    let id = fx.create();
    fx.client().claim_aid(&id, &fx.recipient);

    fx.env.set_auths(&[]);
    assert!(fx.client().try_delete_aid(&fx.admin, &id).is_err());
    fx.env.mock_all_auths();
    assert!(fx.client().get_aid(&id).is_some());
}

#[test]
fn spoofed_viewer_cannot_search_or_list_as_a_participant() {
    let fx = Fx::new();
    let id = fx.create();
    fx.client()
        .set_aid_search_visibility(&fx.admin, &id, &false);

    // Without the donor's / recipient's signature, an outsider cannot borrow
    // their identity to enumerate hidden or archived records.
    fx.env.set_auths(&[]);
    assert!(fx.client().try_search_aids(&fx.admin, &0, &10).is_err());
    assert!(fx
        .client()
        .try_search_aids_cursor(&fx.donor, &None, &10)
        .is_err());
    assert!(fx
        .client()
        .try_list_aids_by_donor_cursor(&fx.donor, &None, &10)
        .is_err());
    assert!(fx
        .client()
        .try_list_aids_by_recipient(&fx.recipient, &0, &10)
        .is_err());
    assert!(fx
        .client()
        .try_grant_search_access(&fx.donor, &id, &fx.outsider)
        .is_err());
    fx.env.mock_all_auths();
    assert!(fx.search_ids(&fx.outsider).is_empty());
}

// ---------------------------------------------------------------------------
// Failure + retry paths
// ---------------------------------------------------------------------------

#[test]
fn retrying_settlement_of_archived_records_is_rejected_without_side_effects() {
    let fx = Fx::new();
    let settled = fx.create();
    let refunded = fx.create();
    fx.client().claim_aid(&settled, &fx.recipient);
    fx.advance_past_expiry();
    fx.client().refund_aid(&refunded, &fx.donor);

    let balances = (
        fx.balance(&fx.contract_id),
        fx.balance(&fx.donor),
        fx.balance(&fx.recipient),
    );

    assert_eq!(
        fx.client().try_claim_aid(&settled, &fx.recipient),
        Err(Ok(AidError::AlreadyClaimed))
    );
    assert_eq!(
        fx.client().try_refund_aid(&settled, &fx.donor),
        Err(Ok(AidError::AlreadyClaimed))
    );
    assert_eq!(
        fx.client().try_refund_aid(&refunded, &fx.admin),
        Err(Ok(AidError::AlreadyRefunded))
    );
    assert_eq!(
        fx.client().try_claim_aid(&refunded, &fx.recipient),
        Err(Ok(AidError::AlreadyClaimed))
    );

    assert_eq!(
        balances,
        (
            fx.balance(&fx.contract_id),
            fx.balance(&fx.donor),
            fx.balance(&fx.recipient),
        )
    );
    assert!(fx.index().is_empty());
}

#[test]
fn visibility_toggle_is_idempotent_under_retry() {
    let fx = Fx::new();
    let ids = fx.create_n(3);

    for _ in 0..3 {
        fx.client()
            .set_aid_search_visibility(&fx.admin, &ids[1], &false);
    }
    assert_eq!(fx.index(), std::vec![ids[0], ids[2]]);

    for _ in 0..3 {
        fx.client()
            .set_aid_search_visibility(&fx.admin, &ids[1], &true);
    }
    assert_eq!(fx.index(), ids, "retried unhide must not duplicate entries");
}

#[test]
fn retry_after_purge_fails_closed_with_not_found() {
    let fx = Fx::new();
    let id = fx.create();
    fx.client().claim_aid(&id, &fx.recipient);
    fx.client().delete_aid(&fx.admin, &id);

    assert_eq!(
        fx.client().try_delete_aid(&fx.admin, &id),
        Err(Ok(AidError::NotFound))
    );
    assert_eq!(
        fx.client()
            .try_set_aid_search_visibility(&fx.admin, &id, &true),
        Err(Ok(AidError::NotFound))
    );
    assert_eq!(
        fx.client()
            .try_grant_search_access(&fx.donor, &id, &fx.delegate),
        Err(Ok(AidError::NotFound))
    );
    assert_eq!(
        fx.client().try_claim_aid(&id, &fx.recipient),
        Err(Ok(AidError::NotFound))
    );
    assert!(fx.index().is_empty());
    fx.assert_undiscoverable_by_anyone(id);
}

#[test]
fn rejected_caller_then_authorized_retry_succeeds() {
    let fx = Fx::new();
    let id = fx.create();

    assert_eq!(
        fx.client()
            .try_set_aid_search_visibility(&fx.donor, &id, &false),
        Err(Ok(AidError::Unauthorized))
    );
    // The failed attempt left nothing behind that would block the real retry.
    assert!(!fx.is_hidden(id));
    fx.client()
        .set_aid_search_visibility(&fx.admin, &id, &false);
    assert!(fx.is_hidden(id));
}

#[test]
fn claim_on_hidden_record_while_paused_can_be_retried_after_unpause() {
    let fx = Fx::new();
    let id = fx.create();
    fx.client()
        .set_aid_search_visibility(&fx.admin, &id, &false);
    fx.client().set_paused(&fx.admin, &true);

    assert_eq!(
        fx.client().try_claim_aid(&id, &fx.recipient),
        Err(Ok(AidError::Paused))
    );
    assert_eq!(fx.client().get_aid(&id).unwrap().status, AidStatus::Pending);

    fx.client().set_paused(&fx.admin, &false);
    fx.client().claim_aid(&id, &fx.recipient);
    assert_eq!(fx.client().get_aid(&id).unwrap().status, AidStatus::Settled);
    assert_eq!(fx.balance(&fx.recipient), AMOUNT);
}

// ---------------------------------------------------------------------------
// Recovery / rollback paths
// ---------------------------------------------------------------------------

#[test]
fn unhide_restores_cursor_reachability_for_older_records() {
    // Regression for #480: un-hiding an older record appended it behind newer
    // IDs, leaving the index unsorted so the binary-searched keyset cursor
    // silently skipped it.
    let fx = Fx::new();
    let ids = fx.create_n(5);

    fx.client()
        .set_aid_search_visibility(&fx.admin, &ids[0], &false);
    fx.client()
        .set_aid_search_visibility(&fx.admin, &ids[0], &true);

    assert_eq!(fx.index(), ids, "index must stay sorted after rollback");
    for page_size in 1..=5 {
        assert_eq!(
            fx.cursor_search_ids(&fx.donor, page_size),
            ids,
            "page size {page_size} must reach every visible record"
        );
    }
}

#[test]
fn unhiding_an_archived_record_does_not_resurrect_it() {
    let fx = Fx::new();
    let id = fx.create();
    fx.client()
        .set_aid_search_visibility(&fx.admin, &id, &false);
    fx.client().claim_aid(&id, &fx.recipient);

    // Rolling back the hide on a record that has since been archived clears
    // the flag but must not put a settled record back into discovery.
    fx.client().set_aid_search_visibility(&fx.admin, &id, &true);
    assert!(!fx.is_hidden(id));
    assert!(fx.index().is_empty());
    fx.assert_undiscoverable_by_anyone(id);
}

#[test]
fn stale_index_entries_for_hidden_archived_and_purged_records_never_leak() {
    let fx = Fx::new();
    let live = fx.create();
    let hidden = fx.create();
    let archived = fx.create();
    let purged = fx.create();
    fx.client()
        .grant_search_access(&fx.donor, &hidden, &fx.delegate);
    fx.client()
        .grant_search_access(&fx.donor, &archived, &fx.delegate);
    fx.client()
        .set_aid_search_visibility(&fx.admin, &hidden, &false);
    fx.client().claim_aid(&archived, &fx.recipient);
    fx.client().claim_aid(&purged, &fx.recipient);
    fx.client().delete_aid(&fx.admin, &purged);

    // Simulate a corrupted / partially-written derived index that still lists
    // every record (e.g. an interrupted migration or a buggy indexer).
    fx.env.as_contract(&fx.contract_id, || {
        let mut corrupt = Vec::new(&fx.env);
        for id in [live, hidden, archived, purged] {
            corrupt.push_back(id);
        }
        storage::set_search_index(&fx.env, &corrupt);
    });

    // Defence in depth: the read-time filter still hides everything but `live`.
    for viewer in fx.all_viewers().iter() {
        let expected: std::vec::Vec<u64> = if *viewer == fx.outsider || *viewer == fx.delegate {
            std::vec![]
        } else {
            std::vec![live]
        };
        assert_eq!(
            fx.search_ids(viewer),
            expected,
            "search_aids for {viewer:?}"
        );
        assert_eq!(
            fx.cursor_search_ids(viewer, 1),
            expected,
            "search_aids_cursor for {viewer:?}"
        );
    }

    // Recovery: the admin rebuild drops all three stale entries.
    let report = fx.client().repair_search_index(&fx.admin);
    assert_eq!((report.indexed, report.added, report.removed), (1, 0, 3));
    assert_eq!(fx.index(), std::vec![live]);
}

#[test]
fn repair_is_admin_only_idempotent_and_never_reindexes_hidden_records() {
    let fx = Fx::new();
    let ids = fx.create_n(3);
    fx.client()
        .set_aid_search_visibility(&fx.admin, &ids[1], &false);
    fx.client().claim_aid(&ids[2], &fx.recipient);

    for caller in [&fx.donor, &fx.recipient, &fx.outsider] {
        assert_eq!(
            fx.client().try_repair_search_index(caller),
            Err(Ok(AidError::Unauthorized))
        );
    }

    // Wipe the index entirely, then recover.
    fx.env.as_contract(&fx.contract_id, || {
        storage::set_search_index(&fx.env, &Vec::new(&fx.env));
    });
    let first = fx.client().repair_search_index(&fx.admin);
    assert_eq!((first.indexed, first.added, first.removed), (1, 1, 0));
    assert_eq!(fx.index(), std::vec![ids[0]]);

    // A retried repair is a no-op.
    let second = fx.client().repair_search_index(&fx.admin);
    assert_eq!((second.indexed, second.added, second.removed), (1, 0, 0));
    assert!(fx.is_hidden(ids[1]));
}

#[test]
fn evicted_record_with_dangling_index_entry_is_skipped_and_repaired() {
    let fx = Fx::new();
    let ids = fx.create_n(3);

    // Simulate TTL eviction of the middle record's canonical entry.
    fx.env.as_contract(&fx.contract_id, || {
        storage::remove_aid(&fx.env, ids[1]);
    });
    assert_eq!(fx.index(), ids, "index still holds the dangling entry");

    assert_eq!(
        fx.cursor_search_ids(&fx.donor, 1),
        std::vec![ids[0], ids[2]]
    );
    assert_eq!(
        fx.client()
            .try_set_aid_search_visibility(&fx.admin, &ids[1], &false),
        Err(Ok(AidError::NotFound))
    );

    let report = fx.client().repair_search_index(&fx.admin);
    assert_eq!(report.removed, 1);
    assert_eq!(fx.index(), std::vec![ids[0], ids[2]]);
}
