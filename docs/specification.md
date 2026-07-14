# LiTC Specification

This document defines the LiTC protocol. Every parameter is chosen from LiTC's
own properties (6-second blocks, commodity hardware), not copied from Bitcoin
without reason. See [PHILOSOPHY.md](../PHILOSOPHY.md).

> Status: **draft for testnet**. Values marked *(provisional)* are fixed only
> after `benchmarks.md` provides hardware numbers.

## Identity

| Field        | Value                                  |
|--------------|----------------------------------------|
| Name         | LiTC (Lightweight Transaction Coin)    |
| Ticker       | `LIT`                                  |
| Mainnet addr | version byte `0x30` (`L…` in base58)  |
| Testnet addr | version byte `0x6F` (`m…` in base58)  |

## Consensus

- **Type**: Proof of Work.
- **Algorithm**: **our own**, memory-latency-bound PoW — **LiteHash**
  (see [pow.md](pow.md)). A **fixed 512 MB** scratchpad is the memory
  cost; the per-nonce **walk** is a data-dependent random read chain over it,
  so all miners (old CPU, GTX 650, RTX 4090) bottleneck on **memory
  latency**, not ALU — ASICs and flagships cannot dominate.
  - The 512 MB is filled **once per epoch** (`EPOCH_BLOCKS = 2400` ≈
    **10 h** at 15 s) from `SHA-256d(last block of prev epoch)` via a fast
    ChaCha8 stream fill (<1 s, identical on every node). Mining never pauses:
    the next epoch's set is pre-built in a background thread near the switch.
  - Measured (Xeon E5-2689, release): `prepare_epoch` **~0.6 s**,
    `mine` **~585 H/s** per thread. Parameters `N`, `W`, `EPOCH_BLOCKS`
    locked in `benchmarks.md`.
- **PoW hash**: `LiteHash(header, nonce)` (see [pow.md](pow.md)) is
  compared against the current target.
- **Block hash**: the PoW output (a 32-byte LiteHash digest).

## Timing and issuance

Derived from a **6-second** block time.

| Parameter            | Mainnet                  | Testnet (compressed)      | Rationale |
|----------------------|--------------------------|---------------------------|------------|
| Block time           | 15 s                     | 15 s                      | snappy, low orphan risk at 750 KB blocks |
| Difficulty retarget  | every 30 blocks (~7.5 min) | every 30 blocks        | fast convergence, DigiShield-lite, change clamped to ±25% |
| Coinbase maturity    | 100 blocks ≈ **25 min**  | 100 blocks ≈ 25 min      | keep the *meaning* (short settle), not Bitcoin's 16 h |
| Halving interval     | ~8,400,000 blocks ≈ **4 y** | **10,000** blocks     | 4-year cadence on mainnet; testnet compressed ×840 with documented multiplier |
| Block reward (start) | 50 LIT                  | 50 LIT                    | familiar |
| Supply cap           | 84,000,000 LIT          | 84,000,000 LIT           | familiar 4× Bitcoin supply choice |

> Note on halving: at 15 s, one Bitcoin-style ~4-year halving is
> `4*365*24*3600/15 ≈ 8,409,600` blocks. Testnet uses 10,000 so emission is
> observable quickly; the multiplier is recorded here, not hidden.

## Blocks and transactions

- **UTXO model**, like Bitcoin (chosen for wallet/tool compatibility).
- **Max block size**: **derived, not fixed**. `block_size =
  max_bandwidth_per_node × block_time`. Default `max_bandwidth_per_node = 50 KB/s`
  → `50 × 15 = 750 KB` (rounded). To change capacity later, edit one number.
- **Mempool max**: **derived** — `40 × block_size` (≈30 MB at defaults). Not a
  standalone constant.
- **Fee**: minimal, size-based (≈0.0001 LIT/KB). Goal: low fees.
- **Confirmations**:
  - tx in mempool → `pending`;
  - 1 block → `confirmed` (enough for everyday payments);
  - 6 blocks → `high confidence` (large sums).
  The wallet exposes these levels; **6 is not hardcoded as the only path**.

### Transaction

- Inputs: `(prev_txid, prev_index, WOTS+ witness, pubkey_root R)`.
- Outputs: `(value, HASH160(R) script, ephemeral)`.
  - `ephemeral` is the ML-KEM ciphertext (768 bytes) attached to outputs sent
    to a **reusable stealth address**. It is empty (zero-length) for ordinary
    single-use outputs. The recipient decapsulates it with their scan key to
    recover the one-time WOTS+ spend key; see [stealth.md](stealth.md).
- Validation: inputs exist in UTXO set, signatures verify, sum(inputs) ≥
  sum(outputs) + fee. The one-time WOTS+ rule (burnt-keys index) applies as
  before — every stealth output gets a unique `R`, so reuse is impossible.

### Block

Header fields: `version`, `prev_hash`, `merkle_root`, `timestamp`, `target`,
`nonce`. `merkle_root` = double-SHA-256 of transaction hashes. Genesis block
is hardcoded with a fixed hash.

## Cryptography

- **Signatures / keys**: `WOTS+` (hash-based, post-quantum, one-time). See
  [wots.md](wots.md). Address = `base58check(version || HASH160(R))`, where `R`
  is the WOTS+ public root.
- **Reusable addresses (stealth)**: the user-facing address is a fixed
  **ML-KEM-512** encapsulation public key (800 bytes), base58check-encoded with
  its own version byte (`0x31` mainnet, `0x70` testnet). Paying it wraps a
  fresh one-time WOTS+ key (locked into the output's `HASH160(R)` script) and
  carries the KEM ciphertext in `ephemeral`. The recipient scans the chain and
  recovers the WOTS+ spend key. See [stealth.md](stealth.md). This hides the
  one-time nature of WOTS+ behind the wallet: the user copies one address,
  while every on-chain output is unique and unlinkable.
- **Hashing**: SHA-256d for merkle roots and internal digests.
- **PoW**: LiteHash (see [pow.md](pow.md)).

## Storage (traits, not a single store)

Decoupled so each part can change independently:

- `trait BlockStore` — append/get blocks, best tip.
- `trait ChainStore` — chain/height indexing, reorg support.
- `trait UtxoStore` — UTXO get/apply.

Implementations: `Memory*` (tests), `File*` (MVP). `sled` is **not** bound
upfront; it may replace `File*` later behind the same traits.

## Wallet vs KeyStore

- `litc-wallet` builds/queries transactions using stores + keystore. It holds
  **no secrets**.
- `litc-keystore` abstracts secret storage: `FileKeyStore` (`wallet.dat`) now;
  `Ledger`/`Trezor` later — without rewriting the wallet.

## Mining (backend-agnostic)

- `trait MinerBackend { fn mine(template, target, stop) -> Option<nonce> }`.
- `CpuMiner` always available. `GpuMiner` (OpenCL crate, behind `gpu`
  feature) optional. The node calls the backend abstractly.

## Networking — staged, one binary format everywhere

All messaging — the node's local endpoint **and** P2P — uses the single
`litc-wire` binary codec (see [rpc.md](rpc.md) and [protocol.md](protocol.md)).
There is no JSON on any wire and no second serializer.

1. **Local binary RPC first** (`litc-wire` + `litc-node` + `litc-cli`): the
   node listens on a **Unix socket** (default `~/.litc/node.sock`) or TCP
   `127.0.0.1`; `litc-cli` is the client. Enables fast automated tests with the
   exact same frames P2P will use.
2. **TCP P2P later** (`litc-p2p`): same `litc-wire` codec —
   `version, verack, inv, getdata, tx, block, ping, pong, getaddr, addr`
   (12 types). `getaddr`/`addr` let nodes discover peers with no hardcoded
   seeds (decentralized). Compact-block relay (short tx IDs, BIP152-style) is
   required here to keep propagation fast at 15 s / 750 KB blocks.

## Determinism

Releases are reproducible: `Cargo.lock` is committed; build with
`cargo build --locked`. See [reproducible-builds.md](reproducible-builds.md).
