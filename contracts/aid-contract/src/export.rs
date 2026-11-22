//! Permission-aware export with field redaction.
//!
//! This module provides export APIs that automatically redact sensitive fields
//! based on the caller's permissions. Callers can only view fields they are
//! authorized to access.
//!
//! ## Permission Model
//!
//! - **Admin**: Can see all fields of all records.
//! - **Donor**: Can see all fields of records they created.
//! - **Recipient**: Can see specified fields (amount, status, milestones).
//! - **Inspector**: Can see verification-related fields.
//! - **Other**: Cannot export any records (authorization failure).
//!
//! ## Field Redaction
//!
//! Each field in `AidRecord` and `AidMilestone` is redacted based on the caller's role:
//!
//! | Field | Admin | Donor | Recipient | Inspector |
//! |-------|-------|-------|-----------|-----------|
//! | id | ✓ | ✓ | ✓ | ✓ |
//! | donor | ✓ | ✓ | ✗ | ✓ |
//! | recipient | ✓ | ✓ | ✓ | ✓ |
//! | token | ✓ | ✓ | ✗ | ✓ |
//! | amount | ✓ | ✓ | ✓ | ✓ |
//! | expiry_ledger | ✓ | ✓ | ✗ | ✓ |
//! | status | ✓ | ✓ | ✓ | ✓ |
//! | milestone_count | ✓ | ✓ | ✓ | ✓ |
//! | (milestone.verified) | ✓ | ✓ | ✗ | ✓ |

use crate::storage::{get_aid, get_milestones, is_inspector};
use crate::types::{AidMilestone, AidRecord};
use shared::auth::{has_permission, Permission};
use soroban_sdk::{contracttype, Address, Env, Vec};

// ---------------------------------------------------------------------------
// Export types
// ---------------------------------------------------------------------------

/// A redacted milestone record with sensitive fields removed based on permissions.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportedMilestone {
    /// Short human-readable description of the milestone.
    pub description: soroban_sdk::Symbol,
    /// Amount escrowed for this tranche.
    pub amount: i128,
    /// Whether the recipient has claimed this tranche.
    pub claimed: bool,
    /// Whether this milestone was verified (None if redacted).
    pub verified: Option<bool>,
}

/// A redacted aid record with sensitive fields removed based on permissions.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportedAidRecord {
    pub id: u64,
    pub donor: Option<Address>,
    pub recipient: Address,
    pub token: Option<Address>,
    pub amount: i128,
    pub expiry_ledger: Option<u32>,
    pub status: crate::types::AidStatus,
    pub milestone_count: u32,
}

/// Paginated response for exported aid records.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportedAidPage {
    pub records: Vec<ExportedAidRecord>,
    pub next_cursor: Option<u64>,
}

// ---------------------------------------------------------------------------
// Permission helpers
// ---------------------------------------------------------------------------

/// Determine the caller's role based on their permissions and the record context.
fn get_caller_role(env: &Env, caller: &Address, aid: &AidRecord) -> CallerRole {
    // Check if admin first (deployment-wide permission)
    if has_permission(env, caller, Permission::ManageConfiguration) {
        return CallerRole::Admin;
    }

    // Check if donor (owner of the record)
    if aid.donor == *caller {
        return CallerRole::Donor;
    }

    // Check if recipient (owner of the resource)
    if aid.recipient == *caller {
        return CallerRole::Recipient;
    }

    // Check if inspector (can verify milestones)
    if is_inspector(env, caller) {
        return CallerRole::Inspector;
    }

    CallerRole::Unauthorized
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CallerRole {
    Admin,
    Donor,
    Recipient,
    Inspector,
    Unauthorized,
}

// ---------------------------------------------------------------------------
// Redaction logic
// ---------------------------------------------------------------------------

/// Redact an aid record based on the caller's role.
///
/// Returns `None` if the caller is not authorized to view the record.
pub fn redact_aid_record(
    env: &Env,
    caller: &Address,
    aid: &AidRecord,
) -> Option<ExportedAidRecord> {
    let role = get_caller_role(env, caller, aid);

    match role {
        CallerRole::Unauthorized => None,
        CallerRole::Admin => {
            // Admin sees everything
            Some(ExportedAidRecord {
                id: aid.id,
                donor: Some(aid.donor.clone()),
                recipient: aid.recipient.clone(),
                token: Some(aid.token.clone()),
                amount: aid.amount,
                expiry_ledger: Some(aid.expiry_ledger),
                status: aid.status,
                milestone_count: aid.milestone_count,
            })
        }
        CallerRole::Donor => {
            // Donor sees everything (they created it)
            Some(ExportedAidRecord {
                id: aid.id,
                donor: Some(aid.donor.clone()),
                recipient: aid.recipient.clone(),
                token: Some(aid.token.clone()),
                amount: aid.amount,
                expiry_ledger: Some(aid.expiry_ledger),
                status: aid.status,
                milestone_count: aid.milestone_count,
            })
        }
        CallerRole::Recipient => {
            // Recipient sees: id, recipient, amount, status, milestone_count
            // Redacted: donor, token, expiry_ledger
            Some(ExportedAidRecord {
                id: aid.id,
                donor: None,
                recipient: aid.recipient.clone(),
                token: None,
                amount: aid.amount,
                expiry_ledger: None,
                status: aid.status,
                milestone_count: aid.milestone_count,
            })
        }
        CallerRole::Inspector => {
            // Inspector sees everything (can verify milestones)
            Some(ExportedAidRecord {
                id: aid.id,
                donor: Some(aid.donor.clone()),
                recipient: aid.recipient.clone(),
                token: Some(aid.token.clone()),
                amount: aid.amount,
                expiry_ledger: Some(aid.expiry_ledger),
                status: aid.status,
                milestone_count: aid.milestone_count,
            })
        }
    }
}

/// Redact a milestone based on the caller's role.
pub fn redact_milestone(
    env: &Env,
    caller: &Address,
    aid: &AidRecord,
    milestone: &AidMilestone,
) -> Option<ExportedMilestone> {
    let role = get_caller_role(env, caller, aid);

    match role {
        CallerRole::Unauthorized => None,
        CallerRole::Admin | CallerRole::Donor | CallerRole::Inspector => {
            // These roles see milestone verification status
            Some(ExportedMilestone {
                description: milestone.description.clone(),
                amount: milestone.amount,
                claimed: milestone.claimed,
                verified: Some(milestone.verified),
            })
        }
        CallerRole::Recipient => {
            // Recipients see milestone but not verification status
            Some(ExportedMilestone {
                description: milestone.description.clone(),
                amount: milestone.amount,
                claimed: milestone.claimed,
                verified: None,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Export APIs
// ---------------------------------------------------------------------------

/// Export a single aid record with field redaction.
///
/// # Returns
/// `Some(record)` if the caller has permission to view the record, `None` otherwise.
///
/// # Authorization paths
/// - Admin: Deployment-wide permission (ManageConfiguration)
/// - Donor: Owner of the record (aid.donor == caller)
/// - Recipient: Receiving the aid (aid.recipient == caller) — with redacted fields
/// - Inspector: Registered inspector address
/// - Other: Unauthorized (returns None)
pub fn export_aid(env: &Env, caller: &Address, aid_id: u64) -> Option<ExportedAidRecord> {
    let aid = get_aid(env, aid_id)?;
    redact_aid_record(env, caller, &aid)
}

/// Export a single aid record with milestones.
///
/// # Returns
/// A tuple of (aid_record, milestones) if authorized, `None` otherwise.
pub fn export_aid_with_milestones(
    env: &Env,
    caller: &Address,
    aid_id: u64,
) -> Option<(ExportedAidRecord, Vec<ExportedMilestone>)> {
    let aid = get_aid(env, aid_id)?;
    let exported_aid = redact_aid_record(env, caller, &aid)?;

    let raw_milestones = get_milestones(env, aid_id);
    let mut exported_milestones = Vec::new(env);

    for milestone in raw_milestones.iter() {
        if let Some(redacted) = redact_milestone(env, caller, &aid, &milestone) {
            exported_milestones.push_back(redacted);
        }
    }

    Some((exported_aid, exported_milestones))
}

/// Export multiple aid records with field redaction and pagination.
///
/// # Parameters
/// - `caller`: Address requesting the export
/// - `aid_ids`: Vector of aid IDs to export
/// - `limit`: Maximum number of records to return
///
/// # Returns
/// A paginated response with redacted records and a cursor for continuation.
/// Only records the caller is authorized to view are included.
///
/// # Behavior
/// - Records the caller cannot access are silently skipped (no authorization error).
/// - Returns up to `limit` records that pass authorization.
/// - `next_cursor` is `None` when all records have been returned.
pub fn export_aids_paginated(
    env: &Env,
    caller: &Address,
    aid_ids: &Vec<u64>,
    limit: u32,
    cursor: Option<u64>,
) -> ExportedAidPage {
    let mut records = Vec::new(env);
    let start = cursor.unwrap_or(0) as usize;
    let mut current_index = start;
    let aid_ids_len = aid_ids.len() as usize;

    while (records.len() as u32) < limit && current_index < aid_ids_len {
        let aid_id = aid_ids.get(current_index as u32).unwrap();
        if let Some(aid) = get_aid(env, aid_id) {
            if let Some(exported) = redact_aid_record(env, caller, &aid) {
                records.push_back(exported);
            }
        }
        current_index += 1;
    }

    let next_cursor = if current_index < aid_ids_len {
        Some(current_index as u64)
    } else {
        None
    };

    ExportedAidPage {
        records,
        next_cursor,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
}
