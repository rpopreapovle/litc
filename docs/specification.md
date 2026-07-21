# LiTC Specification

This document defines the LiTC protocol. Every parameter is chosen from LiTC's
own properties (6-second blocks, commodity hardware), not copied from Bitcoin
without reason. See [PHILOSOPHY.md](../PHILOSOPHY.md).

> Status: **draft for testnet**. Values marked *(provisional)* are fixed only
> after `benchmarks.md` provides hardware numbers.

## Identity

| Field        | Value                                            |
|--------------|--------------------------------------------------|
| Name         | LiTC (Lightweight Transaction Coin)              |
| Ticker       | `LIT`                                            |
| Mainnet addr | bech32m `litc1q…` (~40 chars, version `0x31`)   |
| Testnet addr | bech32m `tlitc1q…` (~40 chars, version `0x70`)  |

## Consensus

- **Type**: Proof of Work.
- **Algorithm**: **our own**, memory-latency-bound PoW — **LiteHash**
  (see [pow.md](pow.md)). A **fixed 512 MB** scratchpad is the memory
  cost; the per-nonce **walk** is a data-dependent random read chain over it,
   so the design goal is that miners (old CPU, GTX 650, modern GPU) bottleneck
   on **memory latency**, not ALU. This fairness is a **hypothesis pending GPU
   measurement** (see [pow.md](pow.md) / [benchmarks.md](benchmarks.md)); ASIC
   and flagship dominance is *not yet* ruled out by data.
  - The 512 MB is filled **once per epoch** (`EPOCH_BLOCKS = 2400` ≈
    **10 h** at 15 s) from `SHA-256d(last block of prev epoch)` via a fast
    sequential SHA-256d chain fill (~3 s, identical on every node). Mining never pauses:
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
| Block reward (start) | 5 LIT                   | 5 LIT                     | halves every interval; see note below |
| Supply cap           | 84,000,000 LIT          | 84,000,000 LIT           | fixed: total issuance converges to exactly 84M |

> Note on halving and supply cap: at 15 s, one ~4-year halving is
> `4*365*24*3600/15 ≈ 8,409,600` blocks. The block reward starts at 5 LIT and
> halves every `HALVING_INTERVAL = 8,400,000` blocks (`subsidy = 5 LIT >> epoch`).
> Total issuance is the geometric sum `5 LIT × 8,400,000 × 2 = 84,000,000 LIT`,
> which is exactly the supply cap — no separate cap check is needed because the
> subsidy reaches 0 once the halving epoch exceeds the subsidy's bit-width.
> Testnet uses 10,000-block halvings so emission is observable quickly; the
> multiplier is recorded here, not hidden.

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

- Inputs: `(prev_txid, prev_index, scheme: SignatureScheme, signature,
  pubkey)`. `scheme` declares the signature algorithm authorizing the
  spend (see Cryptography). `Mldsa2` (ML-DSA-2, FIPS 204) is active at
  launch; reserved ids (`Reserved1..3`) are recognized but not yet active,
  and any unknown id is rejected — even with a valid signature. The scheme
  byte is part of the signed message, so a signature is bound to its scheme.
  `signature` is the ML-DSA-2 signature (~2420 bytes). `pubkey` is the full
  ML-DSA-2 public key (1312 bytes), revealed at spend time.
- Outputs: `(value, HASH160(pk) script)`. The script commits to
  `HASH160(ml_dsa_pk)` (20 bytes). The full public key is revealed in the
  input's `pubkey` field when spending.
- Validation: inputs exist in UTXO set, signatures verify, sum(inputs) ≥
  sum(outputs) + fee. ML-DSA-2 keys are reusable (stateless) — no
  one-time-use rule or burnt-keys index needed.

### Block

Header fields: `version`, `prev_hash`, `merkle_root`, `state_root`,
`timestamp`, `height`, `epoch_seed`, `nonce`. `merkle_root` = double-SHA-256
of transaction hashes. `state_root` commits to the entire live consensus state
(UTXO set) after the block is applied — see
[state.md](state.md). `epoch_seed` seeds the PoW scratchpad for the current
epoch (see [pow.md](pow.md)).

**Genesis**: the genesis block is the first block mined at network launch
(`height = 0`, `prev_hash = 0`). Its hash is pinned as a checkpoint at testnet
launch (see Network parameters below) and is then treated as fixed — there is
no pre-mined magic value, but once the network starts the genesis hash is
immutable for that network.

## Cryptography

- **Signatures / keys**: **ML-DSA-2** (Dilithium, NIST FIPS 204, security
  level 2). Pure integer NTT arithmetic (modulo 8380417), no floating-point
  dependency. Stateless and reusable — one key can sign millions of
  transactions. See `litc-primitives::mldsa`.
  - Public key: 1312 bytes
  - Signature: ~2420 bytes
  - Address: `bech32m("litc", version || HASH160(pk))` → ~40 characters
  - At spend time, the full public key (1312 bytes) is revealed in the
    witness; the UTXO script commits to `HASH160(pk)` (20 bytes).
- **Hashing**: SHA-256d for merkle roots and internal digests.
- **PoW**: LiteHash (see [pow.md](pow.md)).

## Storage (traits, not a single store)

Decoupled so each part can change independently:

- `trait BlockStore` — append/get blocks, best tip.
- `trait ChainStore` — chain/height indexing, reorg support.
- `trait UtxoStore` — UTXO get/apply.

Implementations: `Memory*` (tests), `File*` (MVP). `sled` is **not** bound
upfront; it may replace `File*` later behind the same traits.

## Consensus state commitment

The header commits to the entire live state via `state_root =
SHA-256d(utxo_root)`, where `utxo_root` is a Sparse Merkle Tree root
(keyed by `H(txid||index)`; see [state.md](state.md)). A bootstrapping
node verifies the root by applying each block to a read-only overlay and
recomputing it — the PoW therefore secures not just the UTXO *transitions*
but the resulting state.

**Snapshot / fast-sync** (done): a node can start from a trusted snapshot of
the UTXO set plus the tip block, instead of replaying every block
from genesis. Loading is **trustless**: the file's `state_root` is recomputed
from the loaded state and rejected on mismatch (tampering is detected, not
trusted). Snapshot format is versioned (`magic "LITS"`, `version`); a fresh
node then catches up over P2P. This bounds disk/CPU for weak nodes while
keeping verification. See [state.md](state.md).

## Network parameters and checkpoints

Consensus constants are grouped per network in `ChainParams`
(`litc-primitives::chainparams`):

- `magic`: 4-byte wire prefix — `L1TC` (testnet), `L1TM` (mainnet). A mismatch
  means a different network.
- `halving_interval`: 10,000 (testnet, compressed) vs 8,400,000 (mainnet).
- `genesis_hash`: pinned at network launch (see Block above).
- `checkpoints`: a list of `(height, hash)`. A block at a checkpoint height
  **must** carry the pinned hash; this irreversibly finalizes history at and
  below the checkpoint and **bounds fast-sync trust** — a snapshot is only
  accepted if its tip matches the highest checkpoint at or below its height.
  With an empty checkpoint list (a brand-new testnet) this is a no-op; the
  list is filled as the network grows, so "deep enough" becomes concrete
  rather than a vague heuristic.

The node selects the network via `--network <mainnet|testnet>` or the
`LITC_NETWORK` env var (default: testnet).

## Wallet vs KeyStore

- `litc-wallet` builds/queries transactions using stores + keystore. It holds
  **no secrets**.
- `litc-keystore` abstracts secret storage: `FileKeyStore` (`wallet.dat`) now;
  `Ledger`/`Trezor` later — without rewriting the wallet.

## Mining (backend-agnostic)

- `trait MinerBackend { fn mine(template, target, stop) -> Option<nonce> }`.
- `CpuMiner` always available. `GpuMiner` (wgpu crate, behind `gpu`
  feature) optional. The node calls the backend abstractly.

## Networking — one binary format everywhere

All messaging — the node's local endpoint **and** P2P — uses the single
`litc-wire` binary codec (see [rpc.md](rpc.md) and [protocol.md](protocol.md)).
There is no JSON on any wire and no second serializer.

- **Local binary RPC** (`litc-wire` + `litc-node` + `litc-cli`): the node
  exposes the same `request`/`response` (cmd 11/12) frames over a local
  transport; `litc-cli` is the client.
- **TCP P2P** (done, in `litc-node`): same `litc-wire` codec over TCP —
  `version, verack, inv, getdata, tx, block, ping, pong, getaddr, addr`
  (plus the two RPC frames). Handshake exchanges `version`/`verack`, then nodes
  announce `inv`, fetch with `getdata`, relay full `tx`/`block`, and gossip
  addresses via `getaddr`/`addr` (no hardcoded seeds required). Rate limits
  per peer guard against header-rain / tx-flood DoS. Compact-block relay
  (short tx IDs, BIP152-style) is the planned fast path at 15 s / 750 KB blocks;
  full `block` is the current fallback.

## Determinism

Releases are reproducible: `Cargo.lock` is committed; build with
`cargo build --locked`. See [reproducible-builds.md](reproducible-builds.md).
