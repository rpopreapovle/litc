# LiTC Benchmarks

LiTC's PoW is **our own** memory-latency-bound algorithm, **LiteHash**
(see [pow.md](pow.md) and [specification.md](specification.md)). Its
parameters are fixed by **measurement**, not tradition. This document locks
`N` (working set), `W` (walk length) and `EPOCH_BLOCKS`.

## What we measure
Per device: **H/s**, **RAM/VRAM used** (must be ~512 MB — the fixed
cost everyone pays), and power if known. The fairness goal is that an old
CPU (Xeon E5 / Celeron) and a flagship GPU (RTX 3060 as RTX 4090
proxy) land **close in H/s**, because both wait on memory latency over
the same 512 MB set.

> **GPU results are NOT yet measured.** The CPU numbers below are the only
> measured data. The RTX 3060 is the GPU we have access to; it is **not** a
> proxy for a flagship like the RTX 4090, which has substantially higher memory
> bandwidth (~1 TB/s vs ~360 GB/s) and may parallelise the latency-bound walk
> differently. Fairness on high-end GPUs is a **hypothesis, not a verified
> result** — see "GPU validation" below.

## Devices under test
| Device   | Class               | Notes |
|----------|---------------------|-------|
| Xeon E5  | cheap many-core CPU | measured |
| Celeron  | low-end CPU         | weakest realistic miner |
| GTX 650  | old GPU, 1 GB       | optional; compute 3.0, Vulkan  |
| RX 580   | mid GPU             | common used card |
| RTX 3060 | modern GPU          | available; results pending |

## CPU result (measured, Xeon E5-2689, release)
| Step | Result |
|------|--------|
| Scratchpad | 512 MB (`2^24` lanes x 32 B) |
| `prepare_epoch` (once / 10 h) | ~3 s (sequential SHA-256d chain fill) |
| `mine` (per nonce, W=`2^16`) | ~1.7 ms => ~585 H/s (1 thread) |

## Acceptance criteria
- **Fairness (CPU + GPU)**: Xeon E5 and RTX 3060 must land **within
  ~same order of magnitude** of H/s; neither ASICs nor flagships
  dominate. The fixed 512 MB + latency-bound walk enforces this.
- **GTX 650 welcome**: if it also lands close, the goal is met.
- **Celeron** must still produce blocks eventually on testnet.

## GPU validation (next step — REQUIRED before any mainnet claim)
GPU wgpu walk on the RTX 3060. Confirm H/s is
close to the CPU number. **Then** measure at least one flagship (e.g. RTX 4090)
and one low-end card (e.g. Celeron iGPU / GTX 650) — bandwidth and latency
behaviour differ enough that the 3060 alone does not prove fairness. If any
device is >~10x a Celeron, increase `W` (more latency-bound work) or `N` (more
memory) until it is not. Until these are measured, the "ASIC/flagship cannot
dominate" claim is **unverified**.

## Security status (honest limitations)
LiteHash is **home-grown and has not had an external audit or formal
cryptoanalysis.** Two open risks are acknowledged:
- **Fast-cache advantage.** If part of the 512 MB pad fits in a large on-die
  cache (e.g. an ASIC or a CPU with huge L3), a memory-latency-bound walk may
  become cheaper than on commodity DRAM. The sequential fill raises the cost of
  recomputing a lane, but the cache-size boundary still needs measurement.
- **GPU / parallel advantage.** The walk is pointer-chasing, but a GPU can run
  many walks concurrently; whether aggregate throughput stays within an order
  of magnitude of a CPU is exactly what the GPU benchmark above must confirm.
Treat the fairness property as a *design intent* supported by the CPU numbers,
not a proven theorem.

## Locked parameters
```
N            = 2^24      (512 MB scratchpad)
LANE_BYTES  = 32
WALK        = 2^16      (per-nonce random-read steps)
EPOCH_BLOCKS = 2400       (~10 h at 15 s)
fill         = sequential SHA-256d chain: lane[i] = SHA-256d(SHA-256d(lane[i-1]) || seed)
```

## ML-DSA-2 signature sizing & throughput (post-quantum, reusable sigs)

LiTC spends UTXOs with ML-DSA-2 (Dilithium, NIST FIPS 204, security level 2).
See `litc-primitives::mldsa`.

### Witness size (on-chain cost)
```
witness = public_key (1312) + signature (~2420)  = ~3732 bytes per input
```
The public key is revealed at spend time; the UTXO script commits to
`HASH160(pk)` (20 bytes). ML-DSA-2 keys are reusable — no one-time limit.

### Throughput (measured, release build, Xeon-class CPU)
| Step | Result |
|------|--------|
| public key | 1312 bytes |
| signature | ~2420 bytes |
| `sign`   | ~2 ms |
| `verify` | ~1 ms |

> Debug numbers; a release build is several times faster. The dominant cost is
> the `W-1 = 255` upper-bound chain length, so `verify` (~34×255 hashes) is ~10x
> slower than `sign` (average ~34×127 hashes). Both scale linearly with `L` and
> are constant per signature — no per-user table, no pairing.

### Tradeoff notes
- **Smaller `W` (e.g. 16):** more chains (`L = 66`) but shorter per-chain walks
  (~15 steps). Larger public key / witness, less CPU. Not currently selected.
- **`W = 256` chosen** because it minimises witness size (one digit per byte)
  at the cost of the longest worst-case chain; for a lightweight chain where
  block space is the scarce resource, the 1152 B witness is the right trade.
