# LiTC Mining

LiTC mining must work on **people's hardware**: a Chinese Xeon, a Celeron,
an old GTX 650 — not RTX 4090s and ASIC monsters. Fairness comes
from the **algorithm**, not from banning hardware.

## Algorithm

**LiteHash** — our own memory-latency-bound PoW (see [pow.md](pow.md)
and [specification.md](specification.md)). A fixed **512 MB** scratchpad is
the memory cost; the per-nonce **walk** is a data-dependent random read
chain over it, so all miners bottleneck on **memory latency**, not ALU.

- The 512 MB set is built **once per epoch** (`EPOCH_BLOCKS = 2400`
  blocks ≈ 10 h) from `SHA-256d(last block of prev epoch)` via a fast
  ChaCha8 stream fill (<1 s, identical on every node).
- Mining never pauses: the next epoch's set is pre-built in a background
  thread near the epoch switch.
- Measured (Xeon E5-2689, release): `prepare_epoch` ~0.6 s,
  `mine` ~585 H/s per thread.

## Backend abstraction

```rust
trait MinerBackend {
    fn mine(&self, template: &BlockHeader, target: &Target, stop: &AtomicBool)
            -> Option<u64>; // nonce
}
```

- `CpuMiner` — always built, pure Rust. Proves mining with zero extra deps.
- `GpuMiner` — OpenCL, in a **separate crate** `litc-miner-gpu-opencl`
  behind the `gpu` feature, so a build without OpenCL stays simple.

The node calls `backend.mine(...)` and knows nothing about the hardware.

## Running

```bash
litc node                          # CPU miner only
cargo build --features gpu && \
litc node --miner-backend gpu   # OpenCL on commodity GPUs (GTX 650, RX 580)
```

- `miner.threads = 0` → auto (logical CPUs).
- Coinbase maturity (100 blocks ≈ 25 min) and reward follow
  [specification.md](specification.md).

## Fairness goal

Parameters are tuned so an old GPU (GTX 650, ~1 GB VRAM, compute 3.0)
is competitive with a mid CPU, and a flagship (RTX 4090) is **not**
orders of magnitude ahead. Benchmarks, not hype, decide the final numbers.
