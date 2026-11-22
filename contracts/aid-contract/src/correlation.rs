use shared::events::CORRELATION_ID_MAX_LEN;
use soroban_sdk::{Bytes, BytesN, Env};

use crate::storage;
use crate::AidError;

/// Returns a zero-filled correlation ID for use as a default/placeholder.
pub fn zero_correlation_id(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0; 32])
}

/// Normalizes an optional free-form correlation ID into a deterministic
/// `Option<Bytes>` suitable for event emission and storage.
///
/// When `None` or empty, returns `None` (no correlation). Otherwise the raw
/// bytes are passed through unchanged, so callers can attach any opaque
/// context (a UUID, or a raw request hash) up to `CORRELATION_ID_MAX_LEN`.
///
/// Fails with [`AidError::InvalidCorrelationId`] when the ID is longer than
/// `CORRELATION_ID_MAX_LEN` bytes, because it is stored and re-emitted on
/// every later event for the aid.
pub fn normalize(_env: &Env, raw: Option<Bytes>) -> Result<Option<Bytes>, AidError> {
    match raw {
        Some(b) if b.len() > CORRELATION_ID_MAX_LEN => Err(AidError::InvalidCorrelationId),
        Some(b) if b.len() > 0 => Ok(Some(b)),
        _ => Ok(None),
    }
}

/// Persists the correlation ID for an aid record so it can be loaded during
/// claim/refund without requiring the caller to resupply it.
pub fn store(env: &Env, aid_id: u64, correlation_id: &Option<Bytes>) {
    if let Some(cid) = correlation_id {
        env.storage()
            .persistent()
            .set(&storage::DataKey::CorrelationId(aid_id), cid);
    }
}

/// Loads the stored correlation ID for an aid record, if one was attached
/// at creation time.
pub fn load(env: &Env, aid_id: u64) -> Option<Bytes> {
    env.storage()
        .persistent()
        .get(&storage::DataKey::CorrelationId(aid_id))
}
