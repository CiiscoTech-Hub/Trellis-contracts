//! # Cross-Contract Reentrancy Guard (Issue #538)
//!
//! Reentrancy protection and call-depth tracking for the Trellis Soroban suite.

#![allow(clippy::too_many_arguments)]

use soroban_sdk::{contracterror, contracttype, symbol_short, Env, Symbol};

pub const TOPIC_REENTRANCY_GUARD: Symbol = symbol_short!("reent_gd");
pub const MAX_CALL_DEPTH: u32 = 8;

const REENTRANCY_LOCK_KEY: Symbol = symbol_short!("re_lock");
const CALL_DEPTH_KEY: Symbol = symbol_short!("call_dep");

#[contracterror(export = false)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum GuardError {
    /// Reentrancy detected while operation in progress.
    ReentrancyDetected = 960,
    /// Maximum cross-contract call depth exceeded.
    DepthExceeded = 961,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallDepthTelemetry {
    pub current_depth: u32,
    pub max_depth: u32,
    pub call_count: u64,
}

#[derive(Clone, Debug)]
pub struct GuardToken {
    pub depth: u32,
}

pub fn enter_guarded_call(env: &Env) -> Result<GuardToken, GuardError> {
    let locked: bool = env
        .storage()
        .instance()
        .get(&REENTRANCY_LOCK_KEY)
        .unwrap_or(false);

    if locked {
        return Err(GuardError::ReentrancyDetected);
    }

    let depth: u32 = env
        .storage()
        .instance()
        .get(&CALL_DEPTH_KEY)
        .unwrap_or(0);

    if depth >= MAX_CALL_DEPTH {
        return Err(GuardError::DepthExceeded);
    }

    let next_depth = depth + 1;
    env.storage().instance().set(&REENTRANCY_LOCK_KEY, &true);
    env.storage().instance().set(&CALL_DEPTH_KEY, &next_depth);

    Ok(GuardToken { depth: next_depth })
}

pub fn exit_guarded_call(env: &Env, _token: GuardToken) {
    let depth: u32 = env
        .storage()
        .instance()
        .get(&CALL_DEPTH_KEY)
        .unwrap_or(1);

    env.storage().instance().set(&REENTRANCY_LOCK_KEY, &false);
    env.storage()
        .instance()
        .set(&CALL_DEPTH_KEY, &depth.saturating_sub(1));
}

pub fn get_call_telemetry(env: &Env) -> CallDepthTelemetry {
    let current_depth: u32 = env
        .storage()
        .instance()
        .get(&CALL_DEPTH_KEY)
        .unwrap_or(0);

    CallDepthTelemetry {
        current_depth,
        max_depth: MAX_CALL_DEPTH,
        call_count: 0,
    }
}

pub fn reset_call_telemetry(env: &Env) {
    env.storage().instance().set(&REENTRANCY_LOCK_KEY, &false);
    env.storage().instance().set(&CALL_DEPTH_KEY, &0_u32);
}
