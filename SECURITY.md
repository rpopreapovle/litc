# Security Policy

LiTC is experimental, post-quantum cryptography software. Treat it as
**research-grade**: do not store value you cannot afford to lose until a
formal audit and mainnet hardening are complete (see [roadmap](docs/roadmap.md)).

## Supported versions

| Version | Status            | Notes                                          |
|---------|-------------------|------------------------------------------------|
| `main`  | Supported         | Active testnet development branch.             |
| Testnet | Supported         | The only network meant for public experimentation. |
| Mainnet | Not yet released  | See roadmap; no mainnet launch yet.            |

Only the latest `main` and the current public testnet receive security
fixes. Old testnets are not maintained.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub
issues, discussions, or pull requests.**

Instead, email the maintainers at **security@litc.example** with:

- A description of the issue and its impact.
- Steps to reproduce, or a proof-of-concept.
- Affected version(s) / commit(s).
- Any suggested mitigation, if you have one.

You will receive an acknowledgement within **5 business days**. We will keep
you informed of progress and coordinate a fix and disclosure timeline with
you. We aim to credit reporters who wish to be named.

## Scope and known limitations

Areas of particular interest for review:

- **LiteHash PoW** — memory-hardness and time-memory tradeoff resistance
  (see [pow.md](docs/pow.md)). Consensus change: the scratchpad fill must
  stay data-dependent.
- **WOTS+ one-time use** — the wallet and consensus must together reject any
  reuse of a one-time signature key (see [wots.md](docs/wots.md) and the
  `ensure_one_time` / `is_burnt` guards).
- **ML-KEM-512 stealth addresses** — KEM decapsulation, shared-secret
  derivation, and the tx-level `ephemeral` ciphertext handling
  (see [stealth.md](docs/stealth.md)).
- **P2P networking** — frame-size caps, handshake, and DoS surface
  (see [protocol.md](docs/protocol.md)).

Known open items (tracked in `todo`, not yet vulnerabilities):

- Reorg beyond the in-memory undo window of accepted blocks.
- No banscore / per-peer rate limiting yet (basic frame/size limits exist).
- Signature erasure / Utreexo fast-sync deferred to mainnet prep.

## Cryptography dependencies

LiTC relies on `sha2` (SHA-256d), `ripemd` (RIPEMD-160 for HASH160), and
`ml-kem` (ML-KEM-512, FIPS 203) from crates.io. We pin versions via the
committed `Cargo.lock`; run `cargo audit` in CI to track advisories.
