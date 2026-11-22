//! Deterministic resolution for concurrent client edits (issue #270).

use soroban_sdk::{contracttype, Bytes, BytesN, Env};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConflictCandidate { pub revision: u64, pub payload: Bytes }

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConflictWinner { Left, Right }

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConflictResolutionResult { pub winner: ConflictWinner, pub revision: u64, pub digest: BytesN<32> }

fn digest_is_greater(left: &BytesN<32>, right: &BytesN<32>) -> bool {
    let a = left.to_array();
    let b = right.to_array();
    let mut i = 0;
    while i < 32 {
        if a[i] != b[i] { return a[i] > b[i]; }
        i += 1;
    }
    false
}

/// Resolve two edits without relying on their order of arrival.
pub fn resolve_conflict_pair(env: &Env, left: &ConflictCandidate, right: &ConflictCandidate) -> ConflictResolutionResult {
    let left_digest: BytesN<32> = env.crypto().sha256(&left.payload).into();
    let right_digest: BytesN<32> = env.crypto().sha256(&right.payload).into();
    let winner = if left.revision > right.revision || (left.revision == right.revision && digest_is_greater(&left_digest, &right_digest)) { ConflictWinner::Left } else { ConflictWinner::Right };
    let (revision, digest) = match winner { ConflictWinner::Left => (left.revision, left_digest), ConflictWinner::Right => (right.revision, right_digest) };
    ConflictResolutionResult { winner, revision, digest }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    #[test]
    fn higher_revision_wins_regardless_of_argument_order() {
        let env = Env::default();
        let left = ConflictCandidate { revision: 2, payload: Bytes::from_slice(&env, b"old") };
        let right = ConflictCandidate { revision: 3, payload: Bytes::from_slice(&env, b"new") };
        assert_eq!(resolve_conflict_pair(&env, &left, &right).winner, ConflictWinner::Right);
        assert_eq!(resolve_conflict_pair(&env, &right, &left).winner, ConflictWinner::Left);
    }

    #[test]
    fn equal_revisions_use_a_stable_digest_tie_breaker() {
        let env = Env::default();
        let left = ConflictCandidate { revision: 7, payload: Bytes::from_slice(&env, b"a") };
        let right = ConflictCandidate { revision: 7, payload: Bytes::from_slice(&env, b"b") };
        assert_eq!(resolve_conflict_pair(&env, &left, &right), resolve_conflict_pair(&env, &left, &right));
    }
}
