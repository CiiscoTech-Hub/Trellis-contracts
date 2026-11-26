use crate::export::{export_aid, export_aid_with_milestones, export_aids_paginated, ExportedAidPage, ExportedAidRecord};
use crate::storage::{get_aid, get_aid_counter};
use crate::types::AidRecord;
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Vec};

#[contracttype]
#[derive(Clone, Debug)]
pub struct PaginatedAidsResponse {
    pub aids: Vec<AidRecord>,
    pub next_cursor: Option<u64>,
}

#[contract]
pub struct ExternalApi;

#[contractimpl]
impl ExternalApi {
    /// Export a single aid record with permission-aware field redaction.
    ///
    /// # Authorization
    /// - Admin: Sees all fields
    /// - Donor: Sees all fields (owns the record)
    /// - Recipient: Sees redacted fields (amount, status, milestones only)
    /// - Inspector: Sees all fields including verification status
    /// - Other: Returns None (unauthorized)
    ///
    /// # Returns
    /// `Some(record)` if the caller is authorized, `None` otherwise.
    pub fn export_aid(env: Env, caller: Address, aid_id: u64) -> Option<ExportedAidRecord> {
        caller.require_auth();
        export_aid(&env, &caller, aid_id)
    }

    /// Export a single aid record with all its milestones, with field redaction.
    ///
    /// # Authorization
    /// Same as `export_aid`.
    ///
    /// # Returns
    /// A tuple of (aid_record, milestones) if authorized, `None` otherwise.
    /// Milestone verification status is redacted for recipients.
    pub fn export_aid_with_milestones(
        env: Env,
        caller: Address,
        aid_id: u64,
    ) -> Option<(ExportedAidRecord, Vec<crate::export::ExportedMilestone>)> {
        caller.require_auth();
        export_aid_with_milestones(&env, &caller, aid_id)
    }

    /// Export multiple aid records for a donor with pagination and redaction.
    ///
    /// # Authorization
    /// Records the caller cannot access are silently skipped.
    ///
    /// # Returns
    /// A paginated response with redacted records and a cursor for continuation.
    pub fn export_aids_by_donor(
        env: Env,
        caller: Address,
        donor: Address,
        limit: u32,
        cursor: Option<u64>,
    ) -> ExportedAidPage {
        caller.require_auth();
        
        let mut aid_ids = Vec::new(&env);
        let total_aids = get_aid_counter(&env);
        for current_id in 0..total_aids {
            if let Some(aid) = get_aid(&env, current_id) {
                if aid.donor == donor {
                    aid_ids.push_back(current_id);
                }
            }
        }
        
        export_aids_paginated(&env, &caller, &aid_ids, limit, cursor)
    }

    /// Export multiple aid records for a recipient with pagination and redaction.
    ///
    /// # Authorization
    /// Records the caller cannot access are silently skipped.
    ///
    /// # Returns
    /// A paginated response with redacted records and a cursor for continuation.
    pub fn export_aids_by_recipient(
        env: Env,
        caller: Address,
        recipient: Address,
        limit: u32,
        cursor: Option<u64>,
    ) -> ExportedAidPage {
        caller.require_auth();
        
        let mut aid_ids = Vec::new(&env);
        let total_aids = get_aid_counter(&env);
        for current_id in 0..total_aids {
            if let Some(aid) = get_aid(&env, current_id) {
                if aid.recipient == recipient {
                    aid_ids.push_back(current_id);
                }
            }
        }
        
        export_aids_paginated(&env, &caller, &aid_ids, limit, cursor)
    }

    pub fn list_aids(env: Env, limit: u32, cursor: Option<u64>) -> PaginatedAidsResponse {
        if limit == 0 {
            // Or return an error, depending on desired behavior for limit=0
            return PaginatedAidsResponse {
                aids: Vec::new(&env),
                next_cursor: cursor,
            };
        }

        let mut aids = Vec::new(&env);
        let total_aids = get_aid_counter(&env);
        let start = cursor.unwrap_or(0);

        let mut current_id = start;
        while aids.len() < limit && current_id < total_aids {
            if let Some(aid) = get_aid(&env, current_id) {
                aids.push_back(aid);
            }
            current_id += 1;
        }

        let next_cursor = if current_id < total_aids {
            Some(current_id)
        } else {
            None
        };

        PaginatedAidsResponse { aids, next_cursor }
    }

    pub fn list_aids_by_donor(
        env: Env,
        donor: Address,
        limit: u32,
        cursor: Option<u64>,
    ) -> PaginatedAidsResponse {
        if limit == 0 {
            return PaginatedAidsResponse {
                aids: Vec::new(&env),
                next_cursor: cursor,
            };
        }

        let mut aids = Vec::new(&env);
        let total_aids = get_aid_counter(&env);
        let start = cursor.unwrap_or(0);

        let mut current_id = start;
        while aids.len() < limit && current_id < total_aids {
            if let Some(aid) = get_aid(&env, current_id) {
                if aid.donor == donor {
                    aids.push_back(aid);
                }
            }
            current_id += 1;
        }

        let next_cursor = if current_id < total_aids {
            Some(current_id)
        } else {
            None
        };

        PaginatedAidsResponse { aids, next_cursor }
    }
}
