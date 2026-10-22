use soroban_sdk::{Bytes, Env, Vec};

use crate::errors::Error;
use crate::workflow_correlation::{
    check_workflow_chain, validate_workflow_id, MAX_WORKFLOW_ID_LEN,
};

fn id(env: &Env, raw: &[u8]) -> Bytes {
    Bytes::from_slice(env, raw)
}

fn chain(env: &Env, ids: &[Bytes]) -> Vec<Bytes> {
    let mut v = Vec::new(env);
    for item in ids {
        v.push_back(item.clone());
    }
    v
}

#[test]
fn valid_id_with_allowed_characters_is_accepted() {
    let env = Env::default();
    assert_eq!(validate_workflow_id(&id(&env, b"aid-claim_42")), Ok(()));
}

#[test]
fn empty_id_is_rejected() {
    let env = Env::default();
    assert_eq!(
        validate_workflow_id(&id(&env, b"")),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn id_at_the_length_limit_is_accepted_and_one_byte_more_is_rejected() {
    let env = Env::default();
    let at_limit = [b'a'; MAX_WORKFLOW_ID_LEN as usize];
    let over_limit = [b'a'; MAX_WORKFLOW_ID_LEN as usize + 1];

    assert_eq!(validate_workflow_id(&id(&env, &at_limit)), Ok(()));
    assert_eq!(
        validate_workflow_id(&id(&env, &over_limit)),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn ids_with_separators_or_spaces_are_rejected() {
    let env = Env::default();
    let cases: [&[u8]; 4] = [b"aid claim", b"aid.claim", b"aid:claim", b"aid/claim"];
    for raw in cases {
        assert_eq!(
            validate_workflow_id(&id(&env, raw)),
            Err(Error::InvalidArgument),
            "{raw:?} should be rejected"
        );
    }
}

#[test]
fn chain_sharing_one_id_across_contracts_returns_that_id() {
    let env = Env::default();
    let wf = id(&env, b"wf-fund-claim");
    let steps = chain(&env, &[wf.clone(), wf.clone(), wf.clone()]);

    assert_eq!(check_workflow_chain(&steps), Ok(wf));
}

#[test]
fn retried_step_reusing_the_same_id_is_accepted() {
    let env = Env::default();
    let wf = id(&env, b"wf-retry");
    // Aid emits, the call fails, the client retries the same step, then Treasury emits.
    let steps = chain(&env, &[wf.clone(), wf.clone(), wf.clone()]);

    assert_eq!(check_workflow_chain(&steps), Ok(wf));
}

#[test]
fn chain_mixing_two_workflows_is_rejected() {
    let env = Env::default();
    let steps = chain(&env, &[id(&env, b"wf-one"), id(&env, b"wf-two")]);

    assert_eq!(check_workflow_chain(&steps), Err(Error::InvalidArgument));
}

#[test]
fn chain_with_one_invalid_id_is_rejected_even_if_others_match() {
    let env = Env::default();
    let bad = id(&env, b"wf bad");
    let steps = chain(&env, &[bad.clone(), bad.clone()]);

    assert_eq!(check_workflow_chain(&steps), Err(Error::InvalidArgument));
}

#[test]
fn empty_chain_is_rejected() {
    let env = Env::default();
    let steps: Vec<Bytes> = Vec::new(&env);

    assert_eq!(check_workflow_chain(&steps), Err(Error::InvalidArgument));
}

// ---------------------------------------------------------------------------
// Issue #268: Request correlation across API, workers, and external calls
// ---------------------------------------------------------------------------

use crate::workflow_correlation::{
    advance_worker_retry, create_request_context, propagate_to_external_call, propagate_to_worker,
    validate_correlation_context, CorrelationStage, RequestCorrelationContext, MAX_CORRELATION_HOPS,
};

#[test]
fn normal_path_request_correlation_propagates_across_api_worker_and_external_calls() {
    let env = Env::default();
    let root = id(&env, b"req-aid-disburse-99");

    // 1. API Entry
    let api_ctx = create_request_context(&env, &root).expect("API context creation failed");
    assert_eq!(api_ctx.root_id, root);
    assert_eq!(api_ctx.stage, CorrelationStage::Api);
    assert_eq!(api_ctx.hop_count, 0);
    assert_eq!(api_ctx.attempt, 1);

    // 2. Propagate to Worker Enqueue
    let worker_ctx = propagate_to_worker(&env, &api_ctx, true).expect("Worker propagation failed");
    assert_eq!(worker_ctx.root_id, root);
    assert_eq!(worker_ctx.parent_causation_id, root);
    assert_eq!(worker_ctx.stage, CorrelationStage::WorkerEnqueue);
    assert_eq!(worker_ctx.hop_count, 1);
    assert_eq!(worker_ctx.attempt, 1);

    // 3. Propagate from Worker to Downstream External Call
    let ext_ctx = propagate_to_external_call(&env, &worker_ctx).expect("External call propagation failed");
    assert_eq!(ext_ctx.root_id, root);
    assert_eq!(ext_ctx.stage, CorrelationStage::ExternalCall);
    assert_eq!(ext_ctx.hop_count, 2);
    assert_eq!(ext_ctx.attempt, 1);
}

#[test]
fn failure_path_hop_limit_and_malformed_context_rejected() {
    let env = Env::default();
    let root = id(&env, b"req-hop-overflow");
    let mut ctx = create_request_context(&env, &root).expect("Valid root");

    // Advance hop count up to maximum
    for _ in 0..MAX_CORRELATION_HOPS {
        ctx = propagate_to_external_call(&env, &ctx).expect("Within limit");
    }
    assert_eq!(ctx.hop_count, MAX_CORRELATION_HOPS);

    // Exceeding maximum hop limit must fail with InvalidArgument
    assert_eq!(
        propagate_to_external_call(&env, &ctx),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        propagate_to_worker(&env, &ctx, true),
        Err(Error::InvalidArgument)
    );

    // Malformed root ID
    let bad_root = id(&env, b"bad id with space");
    assert_eq!(
        create_request_context(&env, &bad_root),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn retry_path_worker_attempt_increments_and_preserves_root_correlation() {
    let env = Env::default();
    let root = id(&env, b"req-retry-flow-77");
    let api_ctx = create_request_context(&env, &root).unwrap();
    let worker_ctx = propagate_to_worker(&env, &api_ctx, true).unwrap();

    // Advance attempt to 2 (first retry)
    let retry_1 = advance_worker_retry(&env, &worker_ctx, 2).expect("Retry 1 valid");
    assert_eq!(retry_1.root_id, root);
    assert_eq!(retry_1.stage, CorrelationStage::WorkerExecute);
    assert_eq!(retry_1.attempt, 2);

    // Advance attempt to 3 (second retry)
    let retry_2 = advance_worker_retry(&env, &retry_1, 3).expect("Retry 2 valid");
    assert_eq!(retry_2.root_id, root);
    assert_eq!(retry_2.attempt, 3);

    // Attempt regression (non-monotonic) must be rejected
    assert_eq!(
        advance_worker_retry(&env, &retry_2, 2),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        advance_worker_retry(&env, &retry_2, 3),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn authorization_path_unauthorized_worker_propagation_rejected() {
    let env = Env::default();
    let root = id(&env, b"req-auth-test-12");
    let api_ctx = create_request_context(&env, &root).unwrap();

    // Caller without authorization must be rejected immediately
    assert_eq!(
        propagate_to_worker(&env, &api_ctx, false),
        Err(Error::Unauthorized)
    );
}

