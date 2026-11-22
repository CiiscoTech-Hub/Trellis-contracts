# Contributing to Trellis Contracts

Thank you for your interest in contributing. This repository contains the Soroban smart contracts that move donor funds on the Stellar blockchain — correctness and security matter more than speed. This guide takes you from a fresh clone to a passing test suite, and explains everything reviewers will look for in your PR.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Local Setup](#local-setup)
- [Build](#build)
- [Testing](#testing)
- [Branch and Commit Conventions](#branch-and-commit-conventions)
- [Pull Request Process](#pull-request-process)
- [What Reviewers Look For](#what-reviewers-look-for)
- [Project Layout](#project-layout)
- [Getting Help](#getting-help)

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Rust | 1.85.0 (pinned) | `rustup` |
| wasm32v1-none target | — | see below |
| Soroban CLI | latest | `cargo install` |

The exact Rust version is pinned in [`rust-toolchain.toml`](rust-toolchain.toml). `rustup` picks it up automatically when you run any `cargo` command inside the repo.

---

## Local Setup

### 1. Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update
```

### 2. Add the WASM target

Soroban contracts compile to WebAssembly. Add the required target:

```bash
rustup target add wasm32v1-none
```

### 3. Install the Soroban CLI

```bash
cargo install --locked soroban-cli
```

### 4. Clone and verify

```bash
git clone https://github.com/TRELLIS-STELLAR/Trellis-contracts.git
cd Trellis-contracts
./scripts/diagnostics.sh
cargo test --workspace
```

All tests should pass. If they do not, open an issue before proceeding.
Run `./scripts/diagnostics.sh` first whenever setup fails — it checks tools,
env vars, RPC reachability, and fixtures with actionable remediation text
(see [`docs/DIAGNOSTICS.md`](docs/DIAGNOSTICS.md)). Validate deployment config
with `./scripts/validate-config.sh` (see
[`docs/CONFIGURATION.md`](docs/CONFIGURATION.md)); it fails fast on missing,
malformed, or unsafe secrets without ever printing them in full.

---

## Build

Build all contracts in release mode:

```bash
cargo build --release
```

Build optimised WASM binaries (required for deployment):

```bash
cargo build \
  --target wasm32v1-none \
  --release
```

---

## Testing

### Run the full test suite

```bash
cargo test --workspace
```

### Run a single crate

```bash
cargo test -p aid-contract
cargo test -p treasury-contract
cargo test -p shared
```

### Run a single test by name

```bash
cargo test -p aid-contract test_claim_aid
```

### Run with output visible

```bash
cargo test --workspace -- --nocapture
```

### Testing utilities

The [`testing/`](testing/) crate provides mocks, helpers, simulation tools, and fuzzing harnesses shared across all contracts. Read [`testing/README.md`](testing/README.md) before writing new tests — it covers:

- `TestEnvironment` for consistent environment setup
- Mock tokens, oracles, and registries
- Time manipulation helpers (`advance_ledger_time`, etc.)
- `DeterministicSimulator` for multi-step scenario testing
- Fuzzing harnesses for access control, payments, and upgradeability

Add the crate to any contract under test:

```toml
[dev-dependencies]
testing = { path = "../../testing", features = ["testutils"] }
```

For the maintainer audit record schema, treasury coverage, and audit-specific
validation command, see [`docs/AUDIT.md`](docs/AUDIT.md).
For the on-chain role/capability model and authorization boundaries, see
[`docs/ACCESS_CONTROL.md`](docs/ACCESS_CONTROL.md).
For stable error codes, safe recovery guidance, and correlation IDs, see
[`docs/ERRORS.md`](docs/ERRORS.md).

---

## Branch and Commit Conventions

### Branches

Branch off `main` for all contributions:

```
feat/short-description
fix/short-description
test/short-description
chore/short-description
docs/short-description
```

Examples: `feat/batch-claim`, `fix/treasury-overflow`, `test/referral-commission`

### Commit messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>: <short imperative summary>
```

| Type | When to use |
|------|-------------|
| `feat` | New behaviour visible in tests or on-chain |
| `fix` | Bug fix |
| `test` | Adding or updating tests only |
| `chore` | Tooling, dependencies, config |
| `build` | Workspace or Cargo changes |
| `docs` | Documentation only |
| `refactor` | No behaviour change |

Keep the subject line under 72 characters. No trailing period.

---

## Pull Request Process

1. **Fork** the repository and create a branch from `main`.
2. **Write tests** for any new contract logic — a PR that adds behaviour without tests will not be merged.
3. **Run CI locally** before pushing:
   ```bash
   ./scripts/diagnostics.sh
   ./scripts/validate-config.sh
   cargo fmt --all -- --check
   cargo clippy --workspace -- -D warnings
   cargo test --workspace
   ```
4. **Open the PR** against `main`. Fill in the description:
   - What changed and why
   - Which contracts are affected
   - How you tested it (paste the relevant test output if non-obvious)
5. **CI must be green.** All four jobs must pass: `Build`, `Clippy`, `Format`, and `Test`.
6. A maintainer will review within a few days. Expect questions about security assumptions, gas impact, and storage layout.

---

## What Reviewers Look For

### Every PR

- CI passes (`Build`, `Clippy`, `Format`, `Test`)
- No new `#[allow(...)]` attributes without a comment explaining why
- `cargo fmt` applied (`rustfmt` is pinned via `rust-toolchain.toml`)

### Contract logic changes

- Unit tests covering the happy path and at least one error path
- No `unwrap()` or `expect()` in contract code — use the typed error enums in `shared/src/errors.rs`
- Overflow-safe arithmetic (use the helpers in `shared/src/math.rs`)
- Access control checked before any state mutation
- Storage keys follow the conventions in `shared/src/storage.rs`

### Security-sensitive changes (payments, treasury, access control)

- A comment in the PR description describing the threat model
- Consider adding a fuzzing harness in `testing/src/fuzzing.rs`
- Tag the PR with the `security` label

### Gas impact

- Note any new persistent storage entries or cross-contract calls
- See [`GAS_OPTIMIZATION.md`](GAS_OPTIMIZATION.md) for the project's gas budget conventions

---

## Project Layout

```
contracts/
├── aid-contract/          # Aid creation, claiming, settlement, escrow
├── treasury-contract/     # Protocol reserves and reward distribution
├── referral-contract/     # Commission calculations and tier rewards
├── governance-contract/   # Upgrade authorisation and admin roles
├── oracle-contract/       # AI verification references and proofs
├── registry-contract/     # Contract discovery and address registry
├── access-control/        # Shared role and permission primitives
├── payments-contract/     # Payment processing helpers
└── rebalancer-contract/   # Portfolio rebalancing strategy

shared/                    # Types, errors, events, auth, math, storage utils
testing/                   # Mocks, helpers, simulation, fuzzing harnesses
ops-checks/                # Synthetic journey monitor + executable incident runbook checks
tests/                     # Workspace-level integration tests
scripts/                   # Deploy, upgrade, initialise, verify
```

Each contract crate is self-contained. Cross-crate logic lives in `shared/`.

---

## Getting Help

- **Bugs and questions** — open a GitHub Issue
- **Security issues** — see [`security/README.md`](security/README.md) for the responsible disclosure process; do not open a public issue for vulnerabilities
- **General discussion** — use the GitHub Discussions tab

---

Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.

---

Licensed under the [MIT License](LICENSE).
