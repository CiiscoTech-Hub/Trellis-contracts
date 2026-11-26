//! Bounded event pagination for high-volume histories (Issue #323).
//!
//! An append-only, per-stream event log with three hard bounds:
//!
//! - **Retention**: each stream keeps at most `retention` events. Appending
//!   past the limit prunes exactly one oldest entry, so append cost stays O(1)
//!   and on-chain storage never grows without bound.
//! - **Page size**: [`fetch_page`] returns at most [`MAX_PAGE_SIZE`] events
//!   (one storage read per event), keeping every read within budget.
//! - **Compaction**: [`compact`] physically deletes at most `max_items`
//!   orphaned entries per call after a [`reset_stream`].
//!
//! ## Cursors
//!
//! An [`EventCursor`] is `(stream, epoch, next_seq)`. Sequence numbers are
//! never reused, so a cursor always points at the same event or fails
//! loudly. Re-fetching with the same cursor returns the same page (retries
//! are safe). Failure modes are explicit:
//!
//! | Situation                               | Error                    | Recovery                      |
//! |-----------------------------------------|--------------------------|-------------------------------|
//! | events behind the cursor were pruned    | `CursorExpired`          | [`recover_cursor`] + resync   |
//! | stream was reset since cursor was taken | `CursorEpochMismatch`    | [`recover_cursor`] + resync   |
//! | cursor ahead of head (forged/corrupt)   | `CursorAhead`            | restart from [`first_cursor`] |
//! | cursor for another stream               | `CursorStreamMismatch`   | use the right stream          |

use soroban_sdk::{contracttype, symbol_short, Address, Env, Symbol, Vec};

use crate::storage::{persistent_has, persistent_read, persistent_remove, persistent_set};

pub const DEFAULT_PAGE_SIZE: u32 = 20;
pub const MAX_PAGE_SIZE: u32 = 50;
pub const DEFAULT_RETENTION: u32 = 500;
pub const MAX_RETENTION: u32 = 5_000;
pub const MAX_COMPACT_PER_CALL: u32 = 100;

pub const TOPIC_EVT_PRUNE: Symbol = symbol_short!("evp_prn");
pub const TOPIC_EVT_RESET: Symbol = symbol_short!("evp_rst");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamMeta {
    pub epoch: u32,
    /// Sequence number the next appended event will receive.
    pub head: u64,
    /// Lowest sequence number that is still readable.
    pub oldest: u64,
    /// Lowest sequence number that may still occupy storage (≤ `oldest`).
    pub physical_floor: u64,
    pub retention: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryEvent {
    pub seq: u64,
    pub kind: Symbol,
    pub actor: Address,
    pub amount: i128,
    pub ledger: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventCursor {
    pub stream: Symbol,
    pub epoch: u32,
    pub next_seq: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventPage {
    pub events: Vec<HistoryEvent>,
    /// Always present: when `has_more` is false it points at the head so the
    /// client can poll for new events with it.
    pub next_cursor: EventCursor,
    pub has_more: bool,
    pub oldest_available: u64,
    pub head: u64,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum EventPageError {
    Unauthorized = 1,
    InvalidPageSize = 2,
    InvalidRetention = 3,
    StreamNotFound = 4,
    AlreadyInitialized = 5,
    CursorStreamMismatch = 6,
    CursorEpochMismatch = 7,
    CursorExpired = 8,
    CursorAhead = 9,
    WriterNotAuthorized = 10,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum EvpKey {
    Meta(Symbol),
    Event(Symbol, u64),
    Writer(Symbol, Address),
}

// ---------------------------------------------------------------------------
// Admin / writer management
// ---------------------------------------------------------------------------

fn require_admin(env: &Env, caller: &Address) -> Result<(), EventPageError> {
    crate::auth::require_admin(env, caller).map_err(|_| EventPageError::Unauthorized)
}

fn load_meta(env: &Env, stream: &Symbol) -> Result<StreamMeta, EventPageError> {
    persistent_read(env, &EvpKey::Meta(stream.clone())).ok_or(EventPageError::StreamNotFound)
}

fn save_meta(env: &Env, stream: &Symbol, meta: &StreamMeta) {
    persistent_set(env, &EvpKey::Meta(stream.clone()), meta);
}

pub fn get_stream_meta(env: &Env, stream: &Symbol) -> Option<StreamMeta> {
    persistent_read(env, &EvpKey::Meta(stream.clone()))
}

pub fn init_stream(
    env: &Env,
    caller: &Address,
    stream: &Symbol,
    retention: u32,
) -> Result<StreamMeta, EventPageError> {
    require_admin(env, caller)?;
    if retention == 0 || retention > MAX_RETENTION {
        return Err(EventPageError::InvalidRetention);
    }
    if let Some(existing) = get_stream_meta(env, stream) {
        // Retry of an identical init is a no-op.
        if existing.retention == retention && existing.head == 0 && existing.epoch == 0 {
            return Ok(existing);
        }
        return Err(EventPageError::AlreadyInitialized);
    }
    let meta = StreamMeta { epoch: 0, head: 0, oldest: 0, physical_floor: 0, retention };
    save_meta(env, stream, &meta);
    Ok(meta)
}

pub fn set_writer(
    env: &Env,
    caller: &Address,
    stream: &Symbol,
    writer: &Address,
    allowed: bool,
) -> Result<(), EventPageError> {
    require_admin(env, caller)?;
    load_meta(env, stream)?;
    let key = EvpKey::Writer(stream.clone(), writer.clone());
    if allowed {
        persistent_set(env, &key, &true);
    } else {
        persistent_remove(env, &key);
    }
    Ok(())
}

pub fn is_writer(env: &Env, stream: &Symbol, writer: &Address) -> bool {
    persistent_has(env, &EvpKey::Writer(stream.clone(), writer.clone()))
}

// ---------------------------------------------------------------------------
// Append / prune
// ---------------------------------------------------------------------------

/// Append one event. Prunes at most one entry, so cost is O(1).
pub fn append_event(
    env: &Env,
    writer: &Address,
    stream: &Symbol,
    kind: Symbol,
    amount: i128,
) -> Result<u64, EventPageError> {
    let mut meta = load_meta(env, stream)?;
    if !is_writer(env, stream, writer) {
        return Err(EventPageError::WriterNotAuthorized);
    }
    writer.require_auth();

    let seq = meta.head;
    let event = HistoryEvent {
        seq,
        kind,
        actor: writer.clone(),
        amount,
        ledger: env.ledger().sequence(),
    };
    persistent_set(env, &EvpKey::Event(stream.clone(), seq), &event);
    meta.head = seq + 1;

    if meta.head - meta.oldest > meta.retention as u64 {
        // Drop the oldest logical entry. After a reset `physical_floor` may
        // lag behind; only delete when the slot is the floor itself.
        if meta.physical_floor == meta.oldest {
            persistent_remove(env, &EvpKey::Event(stream.clone(), meta.oldest));
            meta.physical_floor += 1;
        }
        meta.oldest += 1;
        env.events().publish((TOPIC_EVT_PRUNE, stream.clone()), meta.oldest);
    }
    save_meta(env, stream, &meta);
    Ok(seq)
}

/// Logically drop every event and invalidate all outstanding cursors by
/// bumping the epoch. Sequence numbers keep increasing. Physical deletion is
/// deferred to [`compact`] so this call is O(1).
pub fn reset_stream(env: &Env, caller: &Address, stream: &Symbol) -> Result<StreamMeta, EventPageError> {
    require_admin(env, caller)?;
    let mut meta = load_meta(env, stream)?;
    meta.epoch += 1;
    meta.oldest = meta.head;
    save_meta(env, stream, &meta);
    env.events().publish((TOPIC_EVT_RESET, stream.clone()), (meta.epoch, meta.head));
    Ok(meta)
}

/// Physically delete up to `max_items` orphaned entries below `oldest`.
/// Returns the number deleted; 0 means compaction is complete (safe to retry).
pub fn compact(
    env: &Env,
    caller: &Address,
    stream: &Symbol,
    max_items: u32,
) -> Result<u32, EventPageError> {
    require_admin(env, caller)?;
    if max_items == 0 || max_items > MAX_COMPACT_PER_CALL {
        return Err(EventPageError::InvalidPageSize);
    }
    let mut meta = load_meta(env, stream)?;
    let mut removed = 0u32;
    while meta.physical_floor < meta.oldest && removed < max_items {
        persistent_remove(env, &EvpKey::Event(stream.clone(), meta.physical_floor));
        meta.physical_floor += 1;
        removed += 1;
    }
    save_meta(env, stream, &meta);
    Ok(removed)
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

pub fn first_cursor(env: &Env, stream: &Symbol) -> Result<EventCursor, EventPageError> {
    let meta = load_meta(env, stream)?;
    Ok(EventCursor { stream: stream.clone(), epoch: meta.epoch, next_seq: meta.oldest })
}

/// Recovery path for `CursorExpired` / `CursorEpochMismatch`: returns a
/// cursor at the oldest retained event of the current epoch. Clients must
/// treat the events between their stale cursor and the new one as lost and
/// resync any derived state from an authoritative snapshot.
pub fn recover_cursor(
    env: &Env,
    stream: &Symbol,
    stale: &EventCursor,
) -> Result<EventCursor, EventPageError> {
    if stale.stream != *stream {
        return Err(EventPageError::CursorStreamMismatch);
    }
    let meta = load_meta(env, stream)?;
    let next_seq = if stale.epoch == meta.epoch && stale.next_seq >= meta.oldest && stale.next_seq <= meta.head {
        stale.next_seq
    } else {
        meta.oldest
    };
    Ok(EventCursor { stream: stream.clone(), epoch: meta.epoch, next_seq })
}

fn validate_cursor(meta: &StreamMeta, stream: &Symbol, cursor: &EventCursor) -> Result<(), EventPageError> {
    if cursor.stream != *stream {
        return Err(EventPageError::CursorStreamMismatch);
    }
    if cursor.epoch != meta.epoch {
        return Err(EventPageError::CursorEpochMismatch);
    }
    if cursor.next_seq > meta.head {
        return Err(EventPageError::CursorAhead);
    }
    if cursor.next_seq < meta.oldest {
        return Err(EventPageError::CursorExpired);
    }
    Ok(())
}

/// Fetch a page of at most `limit` events (0 → [`DEFAULT_PAGE_SIZE`]).
/// `cursor = None` starts at the oldest retained event. Read-only.
pub fn fetch_page(
    env: &Env,
    stream: &Symbol,
    cursor: Option<EventCursor>,
    limit: u32,
) -> Result<EventPage, EventPageError> {
    let limit = if limit == 0 { DEFAULT_PAGE_SIZE } else { limit };
    if limit > MAX_PAGE_SIZE {
        return Err(EventPageError::InvalidPageSize);
    }
    let meta = load_meta(env, stream)?;
    let start = match cursor {
        Some(c) => {
            validate_cursor(&meta, stream, &c)?;
            c.next_seq
        }
        None => meta.oldest,
    };
    let end = core::cmp::min(start + limit as u64, meta.head);

    let mut events = Vec::new(env);
    let mut seq = start;
    while seq < end {
        if let Some(ev) = persistent_read::<_, HistoryEvent>(env, &EvpKey::Event(stream.clone(), seq)) {
            events.push_back(ev);
        }
        seq += 1;
    }

    Ok(EventPage {
        events,
        next_cursor: EventCursor { stream: stream.clone(), epoch: meta.epoch, next_seq: end },
        has_more: end < meta.head,
        oldest_available: meta.oldest,
        head: meta.head,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{contract, contractimpl, testutils::Address as _, Address, Env};

    #[contract]
    struct EventPageTestContract;
    #[contractimpl]
    impl EventPageTestContract {}

    fn setup(retention: u32) -> (Env, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        env.budget().reset_unlimited();
        let cid = env.register_contract(None, EventPageTestContract);
        let admin = Address::generate(&env);
        let writer = Address::generate(&env);
        env.as_contract(&cid, || crate::auth::set_admin(&env, &admin));
        init(&env, &cid, &admin, &stream(), retention).unwrap();
        writer_set(&env, &cid, &admin, &stream(), &writer, true).unwrap();
        (env, cid, admin, writer)
    }

    // Each call runs in its own frame, as a real invocation would; Soroban
    // rejects a second `require_auth` for the same address within one frame.
    fn init(env: &Env, cid: &Address, caller: &Address, s: &Symbol, retention: u32) -> Result<StreamMeta, EventPageError> {
        env.as_contract(cid, || init_stream(env, caller, s, retention))
    }

    fn writer_set(env: &Env, cid: &Address, caller: &Address, s: &Symbol, w: &Address, allowed: bool) -> Result<(), EventPageError> {
        env.as_contract(cid, || set_writer(env, caller, s, w, allowed))
    }

    fn append(env: &Env, cid: &Address, w: &Address, s: &Symbol, kind: Symbol, amount: i128) -> Result<u64, EventPageError> {
        env.as_contract(cid, || append_event(env, w, s, kind, amount))
    }

    fn reset(env: &Env, cid: &Address, caller: &Address, s: &Symbol) -> Result<StreamMeta, EventPageError> {
        env.as_contract(cid, || reset_stream(env, caller, s))
    }

    fn compact_at(env: &Env, cid: &Address, caller: &Address, s: &Symbol, max: u32) -> Result<u32, EventPageError> {
        env.as_contract(cid, || compact(env, caller, s, max))
    }

    fn fetch(env: &Env, cid: &Address, s: &Symbol, c: Option<EventCursor>, limit: u32) -> Result<EventPage, EventPageError> {
        env.as_contract(cid, || fetch_page(env, s, c, limit))
    }

    fn recover(env: &Env, cid: &Address, s: &Symbol, c: &EventCursor) -> Result<EventCursor, EventPageError> {
        env.as_contract(cid, || recover_cursor(env, s, c))
    }

    fn meta(env: &Env, cid: &Address, s: &Symbol) -> Option<StreamMeta> {
        env.as_contract(cid, || get_stream_meta(env, s))
    }

    fn stored(env: &Env, cid: &Address, s: &Symbol, seq: u64) -> bool {
        env.as_contract(cid, || persistent_has(env, &EvpKey::Event(s.clone(), seq)))
    }

    fn stream() -> Symbol {
        symbol_short!("treasury")
    }

    fn append_n(env: &Env, cid: &Address, writer: &Address, n: u64) {
        for i in 0..n {
            append(env, cid, writer, &stream(), symbol_short!("deposit"), i as i128).unwrap();
        }
    }

    #[test]
    fn normal_full_traversal_is_ordered_and_complete() {
        let (env, cid, _, writer) = setup(500);
        append_n(&env, &cid, &writer, 123);
        let mut cursor = None;
        let mut seen = 0u64;
        let mut pages = 0u32;
        loop {
            let page = fetch(&env, &cid, &stream(), cursor.clone(), 25).unwrap();
            assert!(page.events.len() <= 25);
            for ev in page.events.iter() {
                assert_eq!(ev.seq, seen);
                assert_eq!(ev.amount, seen as i128);
                seen += 1;
            }
            pages += 1;
            cursor = Some(page.next_cursor.clone());
            if !page.has_more {
                break;
            }
        }
        assert_eq!(seen, 123);
        assert_eq!(pages, 5);
    }

    #[test]
    fn retention_bounds_storage_and_expires_old_cursors() {
        let (env, cid, admin, writer) = setup(10);
        append_n(&env, &cid, &writer, 5);
        let early = fetch(&env, &cid, &stream(), None, 2).unwrap().next_cursor;
        append_n(&env, &cid, &writer, 20);

        let meta = meta(&env, &cid, &stream()).unwrap();
        assert_eq!(meta.head, 25);
        assert_eq!(meta.oldest, 15);
        assert_eq!(meta.physical_floor, 15);
        // Pruned entries are physically gone.
        assert!(!stored(&env, &cid, &stream(), 14));
        assert!(stored(&env, &cid, &stream(), 15));

        assert_eq!(fetch(&env, &cid, &stream(), Some(early.clone()), 5), Err(EventPageError::CursorExpired));
        let recovered = recover(&env, &cid, &stream(), &early).unwrap();
        assert_eq!(recovered.next_seq, 15);
        let page = fetch(&env, &cid, &stream(), Some(recovered), 50).unwrap();
        assert_eq!(page.events.len(), 10);
        assert!(!page.has_more);
        // Compaction has nothing to do when pruning is inline.
        assert_eq!(compact_at(&env, &cid, &admin, &stream(), 10).unwrap(), 0);
    }

    #[test]
    fn failure_invalid_inputs_rejected() {
        let (env, cid, admin, writer) = setup(100);
        append_n(&env, &cid, &writer, 3);
        assert_eq!(fetch(&env, &cid, &stream(), None, MAX_PAGE_SIZE + 1), Err(EventPageError::InvalidPageSize));
        assert_eq!(fetch(&env, &cid, &symbol_short!("nope"), None, 5), Err(EventPageError::StreamNotFound));

        let forged = EventCursor { stream: stream(), epoch: 0, next_seq: 99 };
        assert_eq!(fetch(&env, &cid, &stream(), Some(forged), 5), Err(EventPageError::CursorAhead));
        let wrong = EventCursor { stream: symbol_short!("other"), epoch: 0, next_seq: 0 };
        assert_eq!(fetch(&env, &cid, &stream(), Some(wrong), 5), Err(EventPageError::CursorStreamMismatch));

        assert_eq!(init(&env, &cid, &admin, &symbol_short!("s2"), 0), Err(EventPageError::InvalidRetention));
        assert_eq!(init(&env, &cid, &admin, &symbol_short!("s2"), MAX_RETENTION + 1), Err(EventPageError::InvalidRetention));
        assert_eq!(init(&env, &cid, &admin, &stream(), 100), Err(EventPageError::AlreadyInitialized));
        assert_eq!(compact_at(&env, &cid, &admin, &stream(), 0), Err(EventPageError::InvalidPageSize));
    }

    #[test]
    fn retry_same_cursor_is_deterministic_and_tail_polling_works() {
        let (env, cid, admin, writer) = setup(100);
        append_n(&env, &cid, &writer, 7);
        let c = fetch(&env, &cid, &stream(), None, 5).unwrap().next_cursor;
        let p1 = fetch(&env, &cid, &stream(), Some(c.clone()), 5).unwrap();
        let p2 = fetch(&env, &cid, &stream(), Some(c.clone()), 5).unwrap();
        assert_eq!(p1, p2);
        assert_eq!(p1.events.len(), 2);
        assert!(!p1.has_more);

        // Polling at the head returns an empty page with a stable cursor.
        let tail = fetch(&env, &cid, &stream(), Some(p1.next_cursor.clone()), 5).unwrap();
        assert_eq!(tail.events.len(), 0);
        assert_eq!(tail.next_cursor, p1.next_cursor);
        append_n(&env, &cid, &writer, 1);
        let tail = fetch(&env, &cid, &stream(), Some(p1.next_cursor), 5).unwrap();
        assert_eq!(tail.events.len(), 1);
        assert_eq!(tail.events.get_unchecked(0).seq, 7);

        // Idempotent init retry.
        init(&env, &cid, &admin, &symbol_short!("s3"), 10).unwrap();
        init(&env, &cid, &admin, &symbol_short!("s3"), 10).unwrap();
    }

    #[test]
    fn reset_invalidates_cursors_and_compaction_is_bounded() {
        let (env, cid, admin, writer) = setup(1_000);
        append_n(&env, &cid, &writer, 30);
        let before = fetch(&env, &cid, &stream(), None, 10).unwrap().next_cursor;
        let meta = reset(&env, &cid, &admin, &stream()).unwrap();
        assert_eq!(meta.epoch, 1);
        assert_eq!(meta.oldest, 30);

        assert_eq!(fetch(&env, &cid, &stream(), Some(before.clone()), 10), Err(EventPageError::CursorEpochMismatch));
        let recovered = recover(&env, &cid, &stream(), &before).unwrap();
        assert_eq!(recovered.epoch, 1);
        assert_eq!(recovered.next_seq, 30);
        assert_eq!(fetch(&env, &cid, &stream(), None, 10).unwrap().events.len(), 0);

        // Sequence numbers are never reused after a reset.
        append_n(&env, &cid, &writer, 1);
        let page = fetch(&env, &cid, &stream(), Some(recovered), 10).unwrap();
        assert_eq!(page.events.get_unchecked(0).seq, 30);

        // Bounded compaction: 30 orphans removed in 3 calls, then 0.
        assert_eq!(compact_at(&env, &cid, &admin, &stream(), 12).unwrap(), 12);
        assert_eq!(compact_at(&env, &cid, &admin, &stream(), 12).unwrap(), 12);
        assert_eq!(compact_at(&env, &cid, &admin, &stream(), 12).unwrap(), 6);
        assert_eq!(compact_at(&env, &cid, &admin, &stream(), 12).unwrap(), 0);
        assert!(!stored(&env, &cid, &stream(), 0));
        assert!(stored(&env, &cid, &stream(), 30));
    }

    #[test]
    fn authorization_paths() {
        let (env, cid, admin, writer) = setup(100);
        let outsider = Address::generate(&env);
        assert_eq!(
            append(&env, &cid, &outsider, &stream(), symbol_short!("x"), 1),
            Err(EventPageError::WriterNotAuthorized)
        );
        assert_eq!(init(&env, &cid, &outsider, &symbol_short!("s9"), 10), Err(EventPageError::Unauthorized));
        assert_eq!(writer_set(&env, &cid, &outsider, &stream(), &outsider, true), Err(EventPageError::Unauthorized));
        assert_eq!(reset(&env, &cid, &outsider, &stream()).map(|_| ()), Err(EventPageError::Unauthorized));
        assert_eq!(compact_at(&env, &cid, &outsider, &stream(), 5), Err(EventPageError::Unauthorized));

        // Revoking a writer takes effect immediately.
        append_n(&env, &cid, &writer, 1);
        writer_set(&env, &cid, &admin, &stream(), &writer, false).unwrap();
        assert_eq!(
            append(&env, &cid, &writer, &stream(), symbol_short!("x"), 1),
            Err(EventPageError::WriterNotAuthorized)
        );
        // Reads stay public.
        assert_eq!(fetch(&env, &cid, &stream(), None, 5).unwrap().events.len(), 1);
    }
}
