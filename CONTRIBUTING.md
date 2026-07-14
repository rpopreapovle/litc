# Contributing to LiTC

Thanks for your interest in LiTC! This document explains how to get the code
building, how we review changes, and what we expect from contributions.

## Getting started

```bash
git clone https://github.com/litc-project/litc && cd litc
cargo build --locked
cargo test  --locked
```

- Use **Rust stable** (edition 2021).
- Keep the default `--locked` build light: the `litc-pow/small` feature is on
  by default so the node mines without a 512 MB working set. Production-like
  mining drops `small`.
- The optional GPU miner is behind the `gpu` feature and is **not** built by
  default.

## Before you open a pull request

Run the same checks CI runs:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test  --locked
cargo audit
```

- `cargo fmt` must be clean.
- Clippy must pass with `-D warnings` (no warnings allowed).
- All tests must pass. The crypto/PoW tests are intentionally slow because
  they exercise real hashing; CI allows generous timeouts.

## Commit and PR style

- Small, focused commits with clear messages.
- One logical change per PR; keep refactors separate from behavior changes.
- Describe **why**, not just what. Link the relevant `docs/` or `todo` entry.
- Update `docs/` and the `todo` roadmap when your change affects protocol,
  consensus, or the public API.

## Protocol and consensus changes

LiTC is a consensus system: changes to wire format, block/transaction
encoding, PoW, signatures, or validation rules are **consensus changes** and
require:

1. A written rationale in `docs/` (or an update to the spec).
2. A bump in the relevant version/feature flag.
3. A migration or genesis note where applicable (e.g. `todo` #6 w=256 and
   tx-level `ephemeral` required a remined genesis).

When in doubt, open an issue or a draft PR to discuss the design first.

## Code of conduct

By participating you agree to our [Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting security issues

Do **not** open public issues for vulnerabilities. Follow
[SECURITY.md](SECURITY.md) instead.
