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
- `GpuMiner` — wgpu (Vulkan/Metal/DX12), in a **separate crate**
  `litc-miner-gpu-wgpu` behind the `gpu` feature, so a build without GPU
  deps stays simple.

The node calls `backend.mine(...)` and knows nothing about the hardware.

## Running

```bash
# CPU miner only.
litc node

# With GPU mining backend (requires --features gpu at build time).
cargo build --features gpu
litc node --gpu
```

## Fairness goal

Parameters are tuned so an old GPU (GTX 650, ~1 GB VRAM, compute 3.0)
is competitive with a mid CPU, and a flagship (RTX 4090) is **not**
orders of magnitude ahead. Benchmarks, not hype, decide the final numbers.
