#![cfg(test)]

use soroban_sdk::{Bytes, BytesN, Env, Vec};

use crate::canonical::{
    canonical_bytes, canonical_bytes_strict, canonical_fingerprint, normalize_text_strict,
    verify_canonical_fingerprint, CanonicalPart, MAX_CANONICAL_PARTS, MAX_FIELD_LEN,
};
use crate::errors::Error;

fn text(env: &Env, s: &[u8]) -> CanonicalPart {
    CanonicalPart::Text(Bytes::from_slice(env, s))
}

fn parts(env: &Env, items: &[CanonicalPart]) -> Vec<CanonicalPart> {
    let mut v = Vec::new(env);
    for item in items {
        v.push_back(item.clone());
    }
    v
}

// ---------------------------------------------------------------------------
// Normal path
// ---------------------------------------------------------------------------

#[test]
fn strict_bytes_match_lenient_encoding_for_canonical_input() {
    let env = Env::default();
    let payload = parts(
        &env,
        &[
            text(&env, b"alpha beta"),
            CanonicalPart::Int(42),
            CanonicalPart::Bool(true),
        ],
    );
    assert_eq!(
        canonical_bytes_strict(&env, &payload).unwrap(),
        canonical_bytes(&env, &payload).unwrap()
    );
}

#[test]
fn strict_fingerprint_verifies_canonical_payload() {
    let env = Env::default();
    let payload = parts(&env, &[text(&env, b"region kenya"), CanonicalPart::Int(-7)]);
    let expected = canonical_fingerprint(&env, &payload).unwrap();
    assert_eq!(verify_canonical_fingerprint(&env, &payload, &expected), Ok(()));
}

#[test]
fn strict_verification_is_order_independent_for_canonical_input() {
    let env = Env::default();
    let signed = parts(&env, &[text(&env, b"alpha"), CanonicalPart::Int(10)]);
    let reordered = parts(&env, &[CanonicalPart::Int(10), text(&env, b"alpha")]);
    let expected = canonical_fingerprint(&env, &signed).unwrap();
    assert_eq!(
        verify_canonical_fingerprint(&env, &reordered, &expected),
        Ok(())
    );
}

// ---------------------------------------------------------------------------
// Failure path: every input that would need rewriting is rejected
// ---------------------------------------------------------------------------

#[test]
fn strict_rejects_every_input_that_would_need_rewriting() {
    let env = Env::default();
    let rejected: [&[u8]; 9] = [
        b"",
        b"Alpha",
        b" alpha",
        b"alpha ",
        b"alpha  beta",
        b"alpha\tbeta",
        b"alpha\nbeta",
        b"caf\xc3\xa9",
        b"alpha\x01",
    ];
    for raw in rejected {
        assert_eq!(
            normalize_text_strict(&env, &Bytes::from_slice(&env, raw)),
            Err(Error::InvalidArgument),
            "strict mode must reject {:?}",
            raw
        );
    }
}

#[test]
fn strict_length_bound_is_inclusive_at_max_field_len() {
    let env = Env::default();
    let at_limit = [b'a'; MAX_FIELD_LEN as usize];
    assert!(normalize_text_strict(&env, &Bytes::from_slice(&env, &at_limit)).is_ok());

    let over_limit = [b'a'; MAX_FIELD_LEN as usize + 1];
    assert_eq!(
        normalize_text_strict(&env, &Bytes::from_slice(&env, &over_limit)),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn strict_caps_part_count_at_the_documented_limit() {
    let env = Env::default();

    let mut at_limit: Vec<CanonicalPart> = Vec::new(&env);
    for _ in 0..MAX_CANONICAL_PARTS {
        at_limit.push_back(CanonicalPart::Int(1));
    }
    assert!(canonical_bytes_strict(&env, &at_limit).is_ok());

    let mut too_many: Vec<CanonicalPart> = Vec::new(&env);
    for _ in 0..=MAX_CANONICAL_PARTS {
        too_many.push_back(CanonicalPart::Int(1));
    }
    assert_eq!(
        canonical_bytes_strict(&env, &too_many),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn lenient_and_strict_diverge_on_non_canonical_input() {
    let env = Env::default();
    let messy = parts(&env, &[text(&env, b"  Alpha  BETA ")]);
    // The lenient encoder converges messy input onto one form...
    assert!(canonical_bytes(&env, &messy).is_ok());
    // ...but a verifier must not accept it as already-signed bytes.
    assert_eq!(
        canonical_bytes_strict(&env, &messy),
        Err(Error::InvalidArgument)
    );
}

// ---------------------------------------------------------------------------
// Authorization path: tampered or malleable payloads never verify
// ---------------------------------------------------------------------------

#[test]
fn verification_rejects_tampered_payload_with_unauthorized() {
    let env = Env::default();
    let signed = parts(&env, &[text(&env, b"amount"), CanonicalPart::Int(100)]);
    let expected = canonical_fingerprint(&env, &signed).unwrap();

    let tampered = parts(&env, &[text(&env, b"amount"), CanonicalPart::Int(101)]);
    assert_eq!(
        verify_canonical_fingerprint(&env, &tampered, &expected),
        Err(Error::Unauthorized)
    );
}

#[test]
fn verification_rejects_wrong_expected_fingerprint() {
    let env = Env::default();
    let payload = parts(&env, &[text(&env, b"amount"), CanonicalPart::Int(100)]);
    let wrong: BytesN<32> = BytesN::from_array(&env, &[0u8; 32]);
    assert_eq!(
        verify_canonical_fingerprint(&env, &payload, &wrong),
        Err(Error::Unauthorized)
    );
}

#[test]
fn verification_refuses_malleable_variant_of_signed_payload() {
    let env = Env::default();
    let signed = parts(&env, &[text(&env, b"alpha beta")]);
    let expected = canonical_fingerprint(&env, &signed).unwrap();

    // Same logical content, different bytes: must not verify, and must be
    // reported as malformed rather than as a valid-but-wrong signature.
    let variant = parts(&env, &[text(&env, b"Alpha  Beta")]);
    assert_eq!(
        verify_canonical_fingerprint(&env, &variant, &expected),
        Err(Error::InvalidArgument)
    );
}

// ---------------------------------------------------------------------------
// Retry path: rejected attempts leave no residue
// ---------------------------------------------------------------------------

#[test]
fn retrying_after_rejection_is_deterministic_and_stateless() {
    let env = Env::default();
    let payload = parts(
        &env,
        &[text(&env, b"retry me"), CanonicalPart::Bool(false)],
    );
    let expected = canonical_fingerprint(&env, &payload).unwrap();

    let bad = parts(&env, &[text(&env, b"RETRY ME"), CanonicalPart::Bool(false)]);
    assert_eq!(
        verify_canonical_fingerprint(&env, &bad, &expected),
        Err(Error::InvalidArgument)
    );

    for _ in 0..3 {
        assert_eq!(
            verify_canonical_fingerprint(&env, &payload, &expected),
            Ok(())
        );
    }
}
