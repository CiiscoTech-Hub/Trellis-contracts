//! Unit tests for permission-aware export with field redaction.
//!
//! Tests cover field preservation and status handling.
//! Note: Full integration tests require contract context (env.as_contract) 
//! but the redaction logic is verified in this module.

#![cfg(test)]
extern crate std;

use crate::types::{AidMilestone, AidRecord, AidStatus};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{symbol_short, Address};

fn create_test_aid(
    donor: &Address,
    recipient: &Address,
    token: &Address,
) -> AidRecord {
    AidRecord {
        id: 1,
        donor: donor.clone(),
        recipient: recipient.clone(),
        token: token.clone(),
        amount: 1000,
        expiry_ledger: 1000,
        status: AidStatus::Pending,
        milestone_count: 0,
    }
}

#[test]
fn test_all_aid_statuses_can_be_created() {
    // Verify that all aid status variants can be constructed
    // This tests that AidStatus enum is properly defined
    let statuses = [
        AidStatus::Pending,
        AidStatus::Settled,
        AidStatus::Refunded,
        AidStatus::PartiallyClaimed,
    ];

    for status in &statuses {
        assert!(matches!(
            status,
            AidStatus::Pending
                | AidStatus::Settled
                | AidStatus::Refunded
                | AidStatus::PartiallyClaimed
        ));
    }
}

#[test]
fn test_milestone_structure_creation() {
    // Verify that milestones can be created with the expected structure
    let milestone = AidMilestone {
        description: symbol_short!("phase1"),
        amount: 500,
        verified: true,
        claimed: false,
    };

    assert_eq!(milestone.amount, 500);
    assert_eq!(milestone.verified, true);
    assert_eq!(milestone.claimed, false);
}

#[test]
fn test_aid_record_field_assignments() {
    // Verify aid record fields can be assigned and retrieved
    let env = soroban_sdk::Env::default();
    let donor = Address::generate(&env);
    let recipient = Address::generate(&env);
    let token = Address::generate(&env);

    let aid = create_test_aid(&donor, &recipient, &token);

    assert_eq!(aid.id, 1);
    assert_eq!(aid.donor, donor);
    assert_eq!(aid.recipient, recipient);
    assert_eq!(aid.token, token);
    assert_eq!(aid.amount, 1000);
    assert_eq!(aid.expiry_ledger, 1000);
    assert_eq!(aid.milestone_count, 0);
}

#[test]
fn test_milestone_field_variations() {
    // Verify milestones with different field combinations
    let m1 = AidMilestone {
        description: symbol_short!("m1"),
        amount: 100,
        verified: true,
        claimed: true,
    };

    let m2 = AidMilestone {
        description: symbol_short!("m2"),
        amount: 200,
        verified: false,
        claimed: false,
    };

    // Milestones should maintain their distinct states
    assert_ne!(m1.verified, m2.verified);
    assert_ne!(m1.claimed, m2.claimed);
    assert_ne!(m1.amount, m2.amount);
}

// ---------------------------------------------------------------------------
// Redaction through the stored-record export path (Issue #477)
// ---------------------------------------------------------------------------

use crate::api::{ExternalApi, ExternalApiClient};
use crate::export::{
    export_aid, export_aid_with_milestones, export_aids_paginated, ExportedAidRecord,
};
use crate::{AidContract, AidContractClient};
use soroban_sdk::testutils::Events as _;
use soroban_sdk::{token, vec, Env, Vec};

struct ExportFixture {
    env: Env,
    contract_id: Address,
    admin: Address,
    donor: Address,
    recipient: Address,
    inspector: Address,
    token: Address,
}

fn export_setup() -> ExportFixture {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let donor = Address::generate(&env);
    let recipient = Address::generate(&env);
    let inspector = Address::generate(&env);
    let token = env.register_stellar_asset_contract(admin.clone());
    token::StellarAssetClient::new(&env, &token).mint(&donor, &10_000);

    let contract_id = env.register_contract(None, AidContract);
    let client = AidContractClient::new(&env, &contract_id);
    client.initialize(&admin, &Address::generate(&env), &token, &3600);
    client.set_inspector(&admin, &inspector, &true);

    ExportFixture {
        env,
        contract_id,
        admin,
        donor,
        recipient,
        inspector,
        token,
    }
}

impl ExportFixture {
    fn client(&self) -> AidContractClient<'_> {
        AidContractClient::new(&self.env, &self.contract_id)
    }

    fn create(&self, recipient: &Address) -> u64 {
        let expiry = self.env.ledger().sequence() + 100;
        self.client()
            .create_aid(&self.donor, recipient, &500, &expiry, &None)
    }

    fn export_as(&self, caller: &Address, aid_id: u64) -> Option<ExportedAidRecord> {
        self.env
            .as_contract(&self.contract_id, || export_aid(&self.env, caller, aid_id))
    }
}

#[test]
fn normal_path_each_role_sees_only_its_allowed_fields() {
    let fx = export_setup();
    let aid_id = fx.create(&fx.recipient);
    let full = ExportedAidRecord {
        id: aid_id,
        donor: Some(fx.donor.clone()),
        recipient: fx.recipient.clone(),
        token: Some(fx.token.clone()),
        amount: 500,
        expiry_ledger: Some(fx.env.ledger().sequence() + 100),
        status: AidStatus::Pending,
        milestone_count: 0,
    };
    let redacted = ExportedAidRecord {
        donor: None,
        token: None,
        expiry_ledger: None,
        ..full.clone()
    };

    assert_eq!(fx.export_as(&fx.admin, aid_id), Some(full.clone()));
    assert_eq!(fx.export_as(&fx.donor, aid_id), Some(full.clone()));
    assert_eq!(fx.export_as(&fx.inspector, aid_id), Some(full));
    assert_eq!(fx.export_as(&fx.recipient, aid_id), Some(redacted.clone()));

    // Redaction does not depend on status: a settled record hides the same fields.
    fx.client().claim_aid(&aid_id, &fx.recipient);
    assert_eq!(
        fx.export_as(&fx.recipient, aid_id),
        Some(ExportedAidRecord {
            status: AidStatus::Settled,
            ..redacted
        })
    );
}

#[test]
fn normal_path_milestone_verification_is_hidden_from_the_recipient() {
    let fx = export_setup();
    let tranche = |description| AidMilestone {
        description,
        amount: 100,
        verified: false,
        claimed: false,
    };
    let milestones = vec![
        &fx.env,
        tranche(symbol_short!("build")),
        tranche(symbol_short!("audit")),
    ];
    let expiry = fx.env.ledger().sequence() + 100;
    let aid_id = fx
        .client()
        .create_milestone_aid(&fx.donor, &fx.recipient, &milestones, &expiry);
    fx.client().verify_milestone(&fx.inspector, &aid_id, &0);

    let as_role = |caller: &Address| {
        fx.env.as_contract(&fx.contract_id, || {
            export_aid_with_milestones(&fx.env, caller, aid_id)
                .unwrap()
                .1
        })
    };
    let seen_by_donor = as_role(&fx.donor);
    assert_eq!(seen_by_donor.get(0).unwrap().verified, Some(true));
    assert_eq!(seen_by_donor.get(1).unwrap().verified, Some(false));

    let seen_by_recipient = as_role(&fx.recipient);
    assert_eq!(seen_by_recipient.len(), 2);
    for m in seen_by_recipient.iter() {
        assert_eq!(m.verified, None);
        assert_eq!(m.amount, 100);
        assert!(!m.claimed);
    }
}

#[test]
fn failure_path_missing_records_and_unrelated_callers_get_nothing() {
    let fx = export_setup();
    let other_recipient = Address::generate(&fx.env);
    let stranger = Address::generate(&fx.env);
    let mine = fx.create(&fx.recipient);
    let theirs = fx.create(&other_recipient);

    assert_eq!(fx.export_as(&fx.admin, 999), None);
    assert_eq!(fx.export_as(&stranger, mine), None);
    assert_eq!(fx.export_as(&fx.recipient, theirs), None);
    assert!(fx.env.as_contract(&fx.contract_id, || {
        export_aid_with_milestones(&fx.env, &stranger, mine).is_none()
    }));
}

#[test]
fn retry_path_repeated_and_resumed_exports_return_the_same_records() {
    let fx = export_setup();
    let other_recipient = Address::generate(&fx.env);
    let first = fx.create(&fx.recipient);
    let unreadable = fx.create(&other_recipient);
    let last = fx.create(&fx.recipient);
    let ids = vec![&fx.env, first, unreadable, 999, last];

    let page = |limit: u32, cursor: Option<u64>| {
        fx.env.as_contract(&fx.contract_id, || {
            export_aids_paginated(&fx.env, &fx.recipient, &ids, limit, cursor)
        })
    };

    let page1 = page(1, None);
    assert_eq!(page1.records.len(), 1);
    assert_eq!(page1.records.get(0).unwrap().id, first);
    assert_eq!(page1.next_cursor, Some(1));

    // Resuming skips the record the caller cannot read and the missing id.
    let page2 = page(1, page1.next_cursor);
    assert_eq!(page2.records.len(), 1);
    assert_eq!(page2.records.get(0).unwrap().id, last);
    assert_eq!(page2.records.get(0).unwrap().donor, None);
    assert_eq!(page2.next_cursor, None);

    // Retrying a page, or a single export, returns exactly the same data.
    assert_eq!(page(1, page1.next_cursor), page2);
    assert_eq!(
        fx.export_as(&fx.recipient, first),
        fx.export_as(&fx.recipient, first)
    );
    let mut all = Vec::new(&fx.env);
    all.push_back(page1.records.get(0).unwrap());
    all.push_back(page2.records.get(0).unwrap());
    assert_eq!(page(10, None).records, all);
}

#[test]
fn authorization_path_role_precedence_and_spoofed_callers() {
    let fx = export_setup();
    let aid_id = fx.create(&fx.recipient);

    // An inspector who is also the recipient gets the recipient's redacted view.
    fx.client().set_inspector(&fx.admin, &fx.recipient, &true);
    let seen = fx.export_as(&fx.recipient, aid_id).unwrap();
    assert_eq!(seen.donor, None);
    assert_eq!(seen.token, None);

    // Naming the admin as `caller` without the admin's signature is rejected.
    let env = Env::default();
    let api = ExternalApiClient::new(&env, &env.register_contract(None, ExternalApi));
    let admin = Address::generate(&env);
    assert!(matches!(
        api.try_export_aid(&admin, &0),
        Err(Ok(e)) if e.is_type(soroban_sdk::xdr::ScErrorType::Auth)
    ));
    env.mock_all_auths();
    assert_eq!(api.export_aid(&admin, &0), None);
}

#[test]
fn exports_publish_no_events_and_change_no_state() {
    let fx = export_setup();
    let aid_id = fx.create(&fx.recipient);
    let ids = vec![&fx.env, aid_id];
    let events_before = fx.env.events().all().len();
    let record_before = fx.client().get_aid(&aid_id);

    for caller in [&fx.admin, &fx.donor, &fx.recipient, &fx.inspector] {
        fx.env.as_contract(&fx.contract_id, || {
            export_aid(&fx.env, caller, aid_id);
            export_aid_with_milestones(&fx.env, caller, aid_id);
            export_aids_paginated(&fx.env, caller, &ids, 10, None);
        });
    }

    assert_eq!(fx.env.events().all().len(), events_before);
    assert_eq!(fx.client().get_aid(&aid_id), record_before);
}

