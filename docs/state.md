# LiTC consensus state & `state_root`

LiTC commits to its **entire consensus state** in every block header via the
`state_root` field. This makes the chain *light-client* and *pruning* friendly:
a node that has discarded old blocks can still verify a new block trustlessly,
because the header binds the work (Proof-of-Work) to the resulting UTXO set.

The `state_root` is a **pure function** of two sets:

- the live **UTXO set** (every unspent output), and
- the set of **burnt WOTS+ commitments** (one-time keys that have been spent,
  so they can never be reused).

## Definition

```
state_root = SHA256( utxo_root || burnt_root )
```

where `utxo_root` and `burnt_root` are the roots of independent **Sparse
Merkle Trees (SMT)** over:

| tree        | key                                   | value                     |
|-------------|---------------------------------------|---------------------------|
| `utxo_root` | `H(txid || output_index)`             | canonical UTXO leaf       |
| `burnt_root`| `H(burnt commitment)`                 | empty (presence only)     |

The SMT is **deterministic** and **order-independent**: the root depends only
on the set of (key, value) pairs, never on the order in which they were
inserted, on `HashMap` iteration order, on timestamps, on caches, on peers, on
the mempool, or on the on-disk layout. Updating one leaf recomputes only the
path from that leaf to the root, so applying a block touches `O(log n)` work
for the state commitment (the full UTXO set is still updated as usual).

The canonical UTXO leaf is:

```
value:u64 (LE) || script_pubkey_len:u32 (LE) || script_pubkey
       || ephemeral_len:u32 (LE) || ephemeral
```

So the committed state includes the per-output KEM ciphertext (`ephemeral`)
that a recipient needs to scan and recover their one-time WOTS+ spend key.

## Why a Sparse Merkle Tree (and not a flat hash / binary Merkle)

- **Flat `BLAKE3` over a serialized map** would depend on serialization order
  (map iteration, lengths) and is awkward to update incrementally.
- **A binary Merkle tree over the UTXO list** depends on list ordering and must
  be rebuilt wholesale on every block.
- The **SMT** gives a canonical, order-independent commitment with cheap,
  incremental updates — the standard choice for UTXO commitments (c.f. Ethereum
  state tries). LiTC uses SHA-256 for the SMT so the whole chain relies on a
  single cryptographic primitive.

## Verifying a block (read-only overlay)

Applying a block mutates the state. To verify `header.state_root` *before*
committing, the validator applies the block to a **copy-on-write overlay**
(`OverlayState`) layered over the live store:

1. `validate_block_value` / `validate_block_header` run first (pure, no side
   effects).
2. If `state_root != 0` (a real commitment), the block is applied to a throwaway
   `OverlayState`. Its `root()` is compared to `header.state_root`.
   - **Match** → the overlay is dropped and the block is applied for real.
   - **Mismatch** → `apply_block` returns `state root mismatch` and the base
     store is untouched (no rollback needed, because nothing was committed).
3. A zero `state_root` means "not committed" (genesis / legacy / tests) and is
   accepted without verification.

This is what lets a pruned node, or a fresh node doing fast-sync, check the
resulting state without replaying history.

## Snapshot & fast-sync

A node can export a **snapshot** of its live state at any height via
`FileStore::save_snapshot(dir)`. This writes the live UTXO set, burnt keys,
coinbase heights, tip, and chain work, plus a trustless `snapshot.meta`:

```
snapshot.meta = { magic: "LITS", version: 1, height, block_hash, work, state_root }
utxo.dat      = live UTXO set (+ per-UTXO KEM ciphertext)
burnt.dat     = burnt WOTS+ commitments
coinbase.dat  = coinbase heights
chainmeta.dat = cumulative work / applied / PoW-valid sets
tip.dat       = current tip hash
chain.dat/.idx= the tip block body only (so the next block's header validates)
```

A bootstrapping node calls `FileStore::load_snapshot(dir)`, which loads the
state and **recomputes `state_root` from the loaded set**, comparing it to the
value stored in `snapshot.meta`. A mismatch means the snapshot is corrupt or
tampered and is rejected — so the check is trustless: we verify by *loading and
recomputing*, never by trusting the file's bytes. The node then continues from
`block_hash` as if it had replayed every block up to that height; only the tip
block body is retained on disk (history before the snapshot is not needed).

Node CLI modes:
- default — open the local store (may be empty → genesis, or already synced).
- `--archive` — keep the full block history (disable pruning).
- `--verify-from-genesis` — discard existing state and replay every block from
  block 0 (the only fully null-trust path; requires the full history).
- `--fast-sync <dir>` — start from a snapshot in `dir` (trustless `state_root`
  verification on load).
- `--save-snapshot <dir>` — write a snapshot of the current state, then continue.

To bound reorg exposure, a snapshot is only trusted once `H` is buried under
enough confirmations that a competing chain rewriting history past it is
practically infeasible (PoW has no finality; this is "deep enough", not
"impossible").

## Invariants

1. `state_root` is recomputed identically by every honest node from the same
   post-block state. It MUST NOT depend on anything outside the UTXO set and
   the burnt set.
2. Every `state_root != 0` block is rejected unless applying it reproduces that
   exact root (verified over a read-only overlay; the base is never partially
   mutated).
3. The SMT and the live UTXO map are always in lock-step: an output added or
   spent in a block changes exactly one SMT leaf.
4. Burnt commitments are accumulated monotonically; a commitment that appears
   in `burnt_root` can never be spent again (enforces WOTS+ one-time use).
5. Loading a snapshot must recompute the same `state_root` as the producer
   stored in `snapshot.meta`; otherwise the snapshot is rejected.
6. `state_root` is part of the PoW `challenge`, so the work binds to the state
   and a block cannot be re-stated after mining.
