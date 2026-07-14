# LiTC Signatures — WOTS+

LiTC signatures use **WOTS+** (Winternitz One-Time Signature Plus): a
hash-based, **post-quantum** signature scheme. This is a deliberate design
choice — LiTC is quantum-resistant from the first block, instead of waiting
for a hard fork to patch a hole later (as coins built on elliptic curves
will have to).

WOTS+ also gives **privacy for free**: every address is used exactly once,
so the transaction graph cannot be linked by address reuse. Combined with a
stateless wallet that derives a fresh address per payment, this is a clean,
simple model (KISS).

## Parameters

| Parameter | Value | Note |
|-----------|-------|------|
| Hash `H`  | SHA-256 | internal digest |
| Digest size `n` | 256 bit | the signed message is a 256-bit sighash |
| Winternitz `w` | 16 | each digit = 4 bits; one byte = two chain digits |
| `l1` | 64 | `256 / 4` message digits |
| `l2` | 3 | checksum digits (max checksum `64*15 = 960` needs 3 base-16 digits; 2 is not enough) |
| `l` | 67 | total chains = `l1 + l2` |
| Chain steps | ≤ 15 | `w - 1` |
| Element size | 32 B | one SHA-256 output |

We choose `w = 16` because it splits a 256-bit hash into clean 4-bit chunks:
one message byte maps to exactly two chain digits (high nibble, low nibble).
No bit-shifting across byte boundaries. `w = 256` would shrink signatures to
~1.1 KB but needs up to 255 iterations per chain — slower verification and
more complex code, for no real gain. KISS wins.

## Keys

A WOTS+ key pair for one address:

- `SK.seed` — 32 B, **secret**. The whole private key.
- `PK.seed` — 32 B, public random value (domain separation).
- `r` — 32 B, public randomizer (the "+" in WOTS+; kills multi-target attacks).
- `sk_i = PRF(SK.seed, i) = SHA-256(SK.seed ‖ BE16(i) ‖ 0x00)`, for `i` in `0..l`.
- `pk_i = chain(sk_i, 0, w-1, i)` — the public chain tip.
- `R = SHA-256(PK.seed ‖ r ‖ pk_0 ‖ … ‖ pk_{l-1})` — 32 B public root.

The **address** commits to `R`:

```
address = base58check(version || HASH160(R))
  mainnet  version 0x30  -> "L…"
  testnet  version 0x6F  -> "m…"
```

`script_pubkey` locks an output to `HASH160(R)`.

## Chain function

```
chain(x, start, end, i, PK_seed, r):
    for j in start .. end:
        x = SHA-256( PK_seed ‖ r ‖ BE16(i) ‖ BE8(j) ‖ x )
    return x
```

`i` (chain index) and `j` (step) are baked into the hash input so no two
positions collide.

## Sign

Input: 256-bit sighash `M`.

1. Split `M` into 64 nibbles `m_0 … m_63` (high nibble first per byte).
2. Checksum `c = Σ (15 - m_i)`; encode `c` as 3 big-endian nibbles
   `m_64, m_65, m_66`.
3. For each `i` in `0..67`: reveal `sig_i = chain(sk_i, 0, m_i, i)`.
4. Witness = `PK_seed (32) ‖ r (32) ‖ sig_0 … sig_66` ≈ **2.2 KB**.

## Verify

1. Parse `PK_seed`, `r`, and the 67 revealed values from the witness.
2. Recompute `pk_i = chain(sig_i, m_i, w-1, i)` (continue each chain to 15).
3. Recompute `R = SHA-256(PK.seed ‖ r ‖ pk_0 … pk_66)`.
4. Check `HASH160(R)` equals the spent output's address hash.
5. Recompute the checksum from `m_0 … m_63` and confirm it equals the
   appended `m_64 … m_66` (this is what makes forgery fail).

## One-time use = security + privacy
A WOTS+ key is **one-time**. Reusing an address reveals secret material and
breaks security. LiTC turns this constraint into a feature:

- The node keeps a **burnt-keys index** (`R → spent`). After an address is
  spent, any later spend to the same address is rejected at validation time
  (`validate_tx` checks `is_burnt`). (UTXO model: the output is consumed; a
  new output reusing the address is blocked by the index.)
- The wallet derives a **fresh address per incoming payment** (and for change)
  from the master seed, so addresses are never reused in normal use.
- **Hard wallet guard (type-level + DB).** Even before a spend confirms, the
  wallet refuses to sign a key it has already used. `Wallet::spend_from` /
  `send_stealth` / `spend_stealth` call `ensure_one_time`, which rejects if the
  commitment is already burnt *or* is in the wallet's persisted used set
  (`<wallet>.used`), then `mark_one_time` records it after signing. This blocks
  the dangerous case of two competing unconfirmed transactions signing the same
  WOTS+ key (which would leak the secret even if only one confirms).
- Because every UTXO has a unique address, the transaction graph is not
  linkable by address reuse. This is the built-in privacy.

## Stateless wallet (why not XMSS)

We use **pure WOTS+**, not XMSS (WOTS+ under a Merkle tree for multi-use
keys). XMSS would require the wallet to store state (the last-used leaf
index); restoring from a seed phrase on a second device would not know which
indexes are spent, and reusing one leaks keys — a real theft risk, and much
more code.

With WOTS+, the wallet is **stateless**: from the master seed it deterministically
regenerates every address/key pair `(SK.seed_i, PK.seed_i, r_i) = PRF(master, i)`
and scans the chain forward until balances stop, exactly like BIP32 discovery
but simpler. No state to lose.

## Reusable addresses without bloat (stealth)

WOTS+ keys are one-time, which is great for privacy but awkward for users who
expect a stable address to put on a website. LiTC hides the one-time nature
behind the wallet using **stealth addresses** built on a post-quantum KEM
(ML-KEM-512), not on top of heavy XMSS trees:

- The user's reusable address is just their ML-KEM **encapsulation public key**
  (800 bytes, base58check with a dedicated version byte). One string, copied
  once, reused forever.
- To pay it, the sender encapsulates a shared secret, derives a **fresh
  one-time WOTS+ key** from that secret, and locks the output to
  `HASH160(R)` while attaching the KEM ciphertext in `TxOut.ephemeral`.
- The recipient scans the chain, decapsulates each `ephemeral` with their scan
  key, and recovers the WOTS+ spend key — without ever reusing an address on
  chain.

Every UTXO still has a unique WOTS+ `R`, so the one-time security and the
burnt-keys index are untouched; the KEM only makes the *user experience*
multi-use. Full design and code layout: [stealth.md](stealth.md).

## Sizes and throughput

- Signature/witness ≈ 2.2 KB (constant `WOTS_SIG = (2 + L) * N = (2 + 67) * 32`);
  address stays compact (20 B hash).
- At the 750 KB block cap a block holds **~300 transactions** (a 1-in/2-out
  P2WOTS tx ≈ 2.3 KB; a stealth-involved tx ≈ 3 KB). At 15 s blocks that is
  ~20 TPS — above Bitcoin (~7) with headroom for launch. If the network fills
  up, `block_size = max_bandwidth_per_node × block_time` lets us raise the cap
  by changing one constant.

### Disk footprint and bloat
WOTS+ signatures cannot be aggregated (unlike Schnorr/BLS) and are
pseudo-random, so they do not compress. Full history therefore grows at
`block_size / block_time` ≈ **~3 GB/day, ~1.5 TB/year** at 750 KB / 15 s.
Mitigations:
- **Pruning (shipped):** weak/full-validation nodes keep only the live UTXO
  set + headers (`prune = true`, default). Disk stays bounded at
  `prune_target_size_mb` (default 512 MB ≈ 12 h of history).
- **Archival nodes** (explorers, indexers) accept the ~1.5 TB/year cost; this
  is inherent to a hash-based OTS and is documented, not a bug.
- **Future optimization (consensus change):** raising `w` to 256 cuts `L` from
  67 to 34 and halves the witness to ~1.1 KB (see Parameters above), doubling
  throughput/bloat efficiency. Not done yet — it requires rewriting the
  base-16 `msg_digits`/checksum to base-256 and is deferred until a real
  capacity need appears.

## Integration

- `litc-primitives` — replace `secp256k1` with a `wots` module
  (`gen_keypair`, `sign`, `verify`, `pubkey_root`, `address_from_root`).
  `TxIn/TxOut` keep their shape; `script_pubkey` still locks to `HASH160(R)`.
- `litc-store` — add a `BurntKeys` index.
- `litc-core` — enforce one-time use during validation.
- `litc-wallet` — deterministic fresh-address derivation from the master seed.
