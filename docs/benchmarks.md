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

## Devices under test
| Device   | Class               | Notes |
|----------|---------------------|-------|
| Xeon E5  | cheap many-core CPU | measured |
| Celeron  | low-end CPU         | weakest realistic miner |
| GTX 650  | old GPU, 1 GB       | optional; compute 3.0, OpenCL 1.1 |
| RX 580   | mid GPU             | common used card |
| RTX 3060 | modern GPU          | available; RTX 4090 proxy |

## CPU result (measured, Xeon E5-2689, release)
| Step | Result |
|------|--------|
| Scratchpad | 512 MB (`2^24` lanes x 32 B) |
| `prepare_epoch` (once / 10 h) | ~0.6 s |
| `mine` (per nonce, W=`2^16`) | ~1.7 ms => ~585 H/s (1 thread) |

## Acceptance criteria
- **Fairness (CPU + GPU)**: Xeon E5 and RTX 3060 must land **within
  ~same order of magnitude** of H/s; neither ASICs nor flagships
  dominate. The fixed 512 MB + latency-bound walk enforces this.
- **GTX 650 welcome**: if it also lands close, the goal is met.
- **Celeron** must still produce blocks eventually on testnet.

## GPU validation (next step)
Port the **walk** to OpenCL and run on RTX 3060. Confirm H/s is
close to the CPU number. If a flagship is >~10x a Celeron, increase `W`
(more latency-bound work) or `N` (more memory) until it is not.

## Locked parameters
```
N            = 2^24      (512 MB scratchpad)
LANE_BYTES  = 32
WALK        = 2^16      (per-nonce random-read steps)
EPOCH_BLOCKS = 2400       (~10 h at 15 s)
fill         = ChaCha8 seeded by SHA-256d(prev-epoch last block)
```
