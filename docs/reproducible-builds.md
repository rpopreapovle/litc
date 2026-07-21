# LiTC Reproducible Builds

LiTC builds must be **deterministic**: the same source + the same `Cargo.lock`
produce the same binary on any machine. This matters for a coin people trust.

## Rules

1. **Commit `Cargo.lock`.** Never build in CI or releases without it.
2. **Always `--locked`.**
   ```bash
   cargo build --release --locked
   cargo test  --locked
   ```
3. **Pin versions.** No floating `*` or unpinned git deps in the workspace.
4. **Minimal dependencies** (per [PHILOSOPHY.md](../PHILOSOPHY.md)) — fewer
   deps ⇒ smaller supply-chain surface and easier reproduction.
5. **No build-time network.** Builds fetch only from the locked registry; no
   `build.rs` that phones home.

## Verifying

```bash
# on machine A
cargo build --release --locked
sha256sum target/release/litc > litc.sha256

# on machine B (same commit + lock)
cargo build --release --locked
sha256sum -c litc.sha256   # must pass
```

## Notes

- `litc-miner-gpu-wgpu` is an optional feature; reproducible builds cover
  both `--features gpu` and the default CPU-only build.
- If a future dependency breaks reproducibility, it is replaced — not worked
  around — because "Everything testable / Deterministic" is a core principle.
