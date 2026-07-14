# LiTC Proof-of-Work — LiteHash

LiTC uses its **own** memory-latency-bound PoW, **LiteHash**, so mining
stays on commodity hardware (old CPU, GTX 650, RTX 4090 all land
close) and is not captured by ASICs or flagship GPUs.

## Why our own algorithm

`scrypt` (small N) is ASIC-friendly and linear in hardware; `RandomX`
kills GPUs (CPU-only). LiTC wants **CPU + old GPU + new GPU** to be
comparable, so the dominant cost is **memory latency**, not ALU throughput.

## Design

### Scratchpad (the memory cost)
- Fixed working set: **512 MB** = `2^24` lanes x 32 bytes.
- Filled **once per epoch** (see below), not per block, from a
  cryptographic seed.

### Epochs (DAG model)
- Epoch length: `EPOCH_BLOCKS = 2400` blocks = exactly **10 h** at 15 s
  blocks.
- Seed for an epoch = `SHA-256d(hash of last block of previous epoch)`.
- The 512 MB set is reused across the whole epoch, so the heavy fill is
  amortized (see benchmark: ~0.6 s per epoch, not per block).
- At the epoch switch the miner **pre-generates** the next epoch's
  scratchpad in a background thread ~2 blocks before the end, so mining
  never pauses.

### Fill (memory-hard, deterministic)
The 512 MB is filled **sequentially and data-dependently** so the scratchpad
is genuinely memory-hard (see TMTO note below):
- `lane[0] = SHA-256d(seed)`;
- `lane[i] = SHA-256d( SHA-256d(lane[i-1]) ‖ seed )` for `i` in `1..N`;
- each lane depends on the **previous** one, so **every node builds the
  identical 512 MB** from the same seed, deterministically. Fill takes a few
  seconds on CPU (amortized once per 10 h epoch).

> **TMTO resistance.** The fill must *not* be a CTR-mode stream cipher
> (e.g. ChaCha8 keystream `block[i] = ChaCha8(seed, counter=i)`), because then
> any lane `lane[i]` is computable in **O(1)** from the seed alone — an ASIC
> could recompute each walk step on the fly and skip the 512 MB entirely. The
> sequential `lane[i] = H(lane[i-1])` chain removes this: recomputing
> `lane[i]` without storing it costs `i` sequential hashes, so a time-memory
> tradeoff attacker that stores only `1/k` of the pad pays ~`k×` recompute.
> That linear tradeoff is the standard, accepted memory-hardness property.
> (`prepare_epoch` enforces this; `ChaCha8Rng` is no longer used.)

### Per-nonce work (the latency cost)
`mine(scratch, nonce)`:
- start lane seeded by `nonce`;
- **walk**: `W = 2^16` data-dependent random reads over the 512 MB
  (`next = scratch[acc mod N]`); each read depends on the previous, so
  the chain cannot be pipelined — bounded by **memory latency**;
- `challenge = SHA-256d(header with nonce zeroed)` binds the work to the
  block's content (merkle root, prev block, height, timestamp, epoch seed);
- `digest = SHA-256d(walk_end || seed || nonce || challenge)`; valid if
  `< target`. The 512 MB scratchpad (epoch-seeded) still drives the cost, so
  the benchmark hashrate is unchanged.

## Why this is fair
- **Fixed 512 MB** => everyone pays the memory cost; no tiny-cache
  shortcut, no ASIC without ~512 MB of fast on-die RAM.
- **Latency-bound walk** => CPU, GTX 650 and RTX 4090 all wait on
  DRAM latency, so none dominates by orders of magnitude.
- **Our own**, documented => no inherited magic, easy to audit.

## Benchmark (CPU, measured)
Machine: Intel Xeon E5-2689 (16 threads), release build.

| Step | Result |
|------|--------|
| Scratchpad | 512 MB (`2^24` x 32 B) |
| `prepare_epoch` (once / 10 h) | **~3 s** (full 512 MB; sequential fill) |
| `mine` (per nonce, W=`2^16`) | **~1.7 ms => ~585 H/s** (1 thread) |

The per-nonce cost is pure pointer-chasing over 512 MB, so it scales
with memory latency, not core count or ALU — exactly the fairness goal.

## Next validation (GPU)
Port the **walk** to OpenCL and run on the available RTX 3060 (proxy for
RTX 4090) to confirm it lands within ~the same order of magnitude of
H/s as the CPU. Target: close, not 100x. (See `benchmarks.md`.)

## Status
Prototype in `litc-pow`: `prepare_epoch(seed)` + `mine(scratch, nonce)`,
with unit tests (deterministic, nonce changes digest, epoch reproducible,
full 512 MB). Note: unit tests build the full 512 MB, so run them in
release (`cargo test --release -p litc-pow`) — in debug a fill is ~16 s.
Tunable: `N` (512 MB), `W` (walk length), `EPOCH_BLOCKS`.
