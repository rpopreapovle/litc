# LiTC Philosophy

LiTC (Lightweight Transaction Coin) is a Proof-of-Work coin built for ordinary people.
Its only reason to exist is to be **lighter** than what came before — lighter to
run, lighter to read, lighter to mine, lighter to understand.

Every design choice below is a filter. If a change does not pass the filter, it
is not added.

## Principles

- **Simple** — the code, the protocol, and the spec should fit in a human head.
- **Readable** — anyone who can read Rust should understand LiTC in an afternoon.
- **Portable** — builds and runs on ordinary hardware and ordinary Linux.
- **Deterministic** — `cargo build --locked` produces the same binary everywhere.
- **Open** — the specification is public, compact, and free of hidden magic.
- **Commodity hardware** — mining must work on a humble CPU and an old GPU
  (GTX 650); fairness comes from the algorithm, not from banning hardware.
- **Quantum-resistant by design** — signatures use ML-DSA-2 (Dilithium,
  NIST FIPS 204), a lattice-based post-quantum scheme. LiTC does not need
  a future hard fork to survive a quantum computer; it is built that way
  from the first block.
- **Linux-first** — the reference platform is a plain Linux box, not a cloud.
- **No unnecessary dependencies** — a dependency is a liability. Add one only
  when it clearly makes LiTC *simpler* or *better for the user*.
- **One format** — a single binary codec for the node, its local RPC, and P2P;
  no second serializer, no JSON on the wire.
- **Everything documented** — if it is not written down, it does not exist.
- **Everything testable** — `cargo test` must prove the network works, end to end.

## The one rule

> Any new change must either make LiTC **simpler**, or noticeably **improve it
> for the ordinary user**. If it does neither, do not add it.

This rule beats tradition, beats "everyone does it", and beats feature envy.

## Do not copy Bitcoin without a reason

Bitcoin's numbers exist for Bitcoin's conditions: 10-minute blocks, 2009
hardware, a different threat model. LiTC has **6-second blocks** and **people's
hardware**. So its parameters are chosen from its own properties, not inherited.

Examples of questions we always ask:

- Why `100` blocks of coinbase maturity? At 15 s that is **~25 minutes**, not
  Bitcoin's ~16 hours. We keep the *meaning* (a short settle window), not the
  number.
- Why a fixed block size? We don't hardcode it. `block_size =
  max_bandwidth_per_node × block_time` → `50 KB/s × 15 s = 750 KB`. Change one
  number and capacity follows — no other edits needed years later.
- Why `84,000,000` supply? A conscious familiarity choice, not a default.
- Why a given PoW parameter? Not until `docs/benchmarks.md` shows the
  numbers on real hardware (Xeon E5, Celeron, GTX 650, RX 580, RTX 3060).

When in doubt, derive the number from the 6-second block time and the goal of
"runs on a normal machine", then write the reasoning next to it.

## What a user gets

- a **lighter node** (small codebase, small store, low RAM);
- **faster confirmations** (block ~6 s; 1 block is enough for everyday pay);
- **accessible mining** (CPU first; old GPUs like GTX 650 welcome);
- **simpler code** and a **compact, open specification**.
