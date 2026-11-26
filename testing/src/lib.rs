//! Testing & Simulation Module for Soroban contracts
//!
//! Provides comprehensive test harnesses, mocks, fuzzing helpers, and simulation tools
//! for all contracts in the trellis-contracts repository.

#![no_std]

extern crate alloc;

pub mod bounded_concurrency;
pub mod checkpoint_recovery;
pub mod concurrency;
#[cfg(test)]
mod concurrency_dup_stale;
pub mod dead_letter;
pub mod examples;
pub mod fault_injection;
pub mod fuzzing;
pub mod helpers;
pub mod lifecycle_events;
pub mod migration;
pub mod mocks;
pub mod replay_harness;
pub mod sandbox;
pub mod simulation;
pub mod synthetic_monitor;
pub mod upgrade;
#[cfg(test)]
mod amount_properties;

pub use bounded_concurrency::*;
pub use checkpoint_recovery::*;
pub use dead_letter::*;
pub use fuzzing::*;
pub use helpers::*;
pub use lifecycle_events::*;
pub use migration::*;
pub use mocks::*;
pub use replay_harness::*;
pub use sandbox::*;
pub use simulation::*;
pub use upgrade::*;
