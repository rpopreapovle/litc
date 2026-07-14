//! GPU mining backend for LiTC using `wgpu` (Vulkan on Linux).
//!
//! The expensive part of LiteHash is the data-dependent walk over the epoch
//! scratchpad; that runs in a WGSL compute shader. The final SHA-256d that
//! yields the PoW digest is computed on the CPU with the trusted `sha2` crate,
//! so even if the shader were subtly wrong it could never emit an invalid
//! block — the CPU simply would not accept the candidate.
//!
//! Enable with `--features gpu`. Without it this crate only re-exports the CPU
//! miner, so default workspace builds stay light. Requires a Vulkan-capable
//! GPU (e.g. the RTX 3060); it cannot run on the absent GTX 650.

pub use litc_miner::{BlockTemplate, CpuMiner, MinerBackend};

#[cfg(feature = "gpu")]
mod gpu {
    use super::{BlockTemplate, MinerBackend};
    use litc_pow::{meets_target, prepare_epoch, LANES, WALK};
    use litc_primitives::{sha256d, to_bytes, Block, BlockHeader, Hash32, Transaction, TxOut};
    use std::sync::mpsc;

    const SHADER: &str = r#"
struct Params {
    challenge: array<u32, 8>,
    seed: array<u32, 8>,
    base: u32,
    lanes: u32,
    walk: u32,
    _pad: u32,
};
@group(0) @binding(0) var<storage, read> scratch: array<u32>;
@group(0) @binding(1) var<uniform> params: Params;
@group(0) @binding(2) var<storage, read_write> candidates: array<u32>;
@group(0) @binding(3) var<storage, read_write> count: atomic<u32>;

fn byte_of(word: u32, i: u32) -> u32 { (word >> ((3u - i) * 8u)) & 0xffu; }

fn add_byte(word: u32, i: u32, v: u32) -> u32 {
    let shift = (3u - i) * 8u;
    let mask = 0xffu32 << shift;
    let nb = (((word >> shift) & 0xffu32) + v) & 0xffu32;
    (word & ~mask) | (nb << shift);
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x;
    let nonce = params.base + i;
    var x: array<u32, 8>;
    for (var k: u32 = 0u; k < 8u; k = k + 1u) { x[k] = params.challenge[k]; }
    // Fold the (little-endian) nonce into the top 4 bytes of x, per-byte with
    // no carry — mirrors the CPU reference exactly.
    x[0] = add_byte(x[0], 0u, nonce & 0xffu);
    x[0] = add_byte(x[0], 1u, (nonce >> 8u) & 0xffu);
    x[0] = add_byte(x[0], 2u, (nonce >> 16u) & 0xffu);
    x[0] = add_byte(x[0], 3u, (nonce >> 24u) & 0xffu);
    for (var w: u32 = 0u; w < params.walk; w = w + 1u) {
        var acc: u64 = 0u;
        acc = (acc << 8u) | u64(byte_of(x[0], 0u));
        acc = (acc << 8u) | u64(byte_of(x[0], 1u));
        acc = (acc << 8u) | u64(byte_of(x[0], 2u));
        acc = (acc << 8u) | u64(byte_of(x[0], 3u));
        acc = (acc << 8u) | u64(byte_of(x[1], 0u));
        acc = (acc << 8u) | u64(byte_of(x[1], 1u));
        acc = (acc << 8u) | u64(byte_of(x[1], 2u));
        acc = (acc << 8u) | u64(byte_of(x[1], 3u));
        let idx = u32(acc % u64(params.lanes));
        let base = idx * 8u;
        for (var k: u32 = 0u; k < 8u; k = k + 1u) { x[k] = scratch[base + k]; }
    }
    // Loose pre-filter (~1/256) keeps the read-back set small; the CPU does
    // the real target check.
    if (byte_of(x[0], 0u) == 0u) {
        let c = atomicAdd(&count, 1u);
        if (c < arrayLength(&candidates) / 9u) {
            let o = c * 9u;
            candidates[o] = nonce;
            for (var k: u32 = 0u; k < 8u; k = k + 1u) { candidates[o + 1u + k] = x[k]; }
        }
    }
}
"#;

    pub struct WgpuMiner {
        device: wgpu::Device,
        queue: wgpu::Queue,
        pipeline: wgpu::ComputePipeline,
        bind_group: wgpu::BindGroup,
        scratch_buf: wgpu::Buffer,
        params_buf: wgpu::Buffer,
        cand_buf: wgpu::Buffer,
        count_buf: wgpu::Buffer,
        staging_count: wgpu::Buffer,
        staging_cand: wgpu::Buffer,
        max_cand: u64,
    }

    impl WgpuMiner {
        pub fn new() -> Result<Self, String> {
            let (device, queue) = pollster::block_on(async {
                let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
                    backends: wgpu::Backends::VULKAN,
                    ..Default::default()
                });
                let adapter = instance
                    .request_adapter(&wgpu::RequestAdapterOptions {
                        power_preference: wgpu::PowerPreference::HighPerformance,
                        compatible_surface: None,
                        force_fallback_adapter: false,
                    })
                    .await
                    .ok_or_else(|| "no Vulkan adapter found".to_string())?;
                let (device, queue) = adapter
                    .request_device(&wgpu::DeviceDescriptor::default(), None)
                    .await
                    .map_err(|e| e.to_string())?;
                Ok::<_, String>((device, queue))
            })?;

            let module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
                label: Some("litc-hash"),
                source: wgpu::ShaderSource::Wgsl(SHADER.into()),
            });
            let layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
                label: None,
                entries: &[
                    wgpu::BindGroupLayoutEntry {
                        binding: 0,
                        visibility: wgpu::ShaderStages::COMPUTE,
                        ty: wgpu::BindingType::Buffer {
                            ty: wgpu::BufferBindingType::Storage { read_only: true },
                            has_dynamic_offset: false,
                            min_binding_size: None,
                        },
                        count: None,
                    },
                    wgpu::BindGroupLayoutEntry {
                        binding: 1,
                        visibility: wgpu::ShaderStages::COMPUTE,
                        ty: wgpu::BindingType::Buffer {
                            ty: wgpu::BufferBindingType::Uniform,
                            has_dynamic_offset: false,
                            min_binding_size: None,
                        },
                        count: None,
                    },
                    wgpu::BindGroupLayoutEntry {
                        binding: 2,
                        visibility: wgpu::ShaderStages::COMPUTE,
                        ty: wgpu::BindingType::Buffer {
                            ty: wgpu::BufferBindingType::Storage { read_only: false },
                            has_dynamic_offset: false,
                            min_binding_size: None,
                        },
                        count: None,
                    },
                    wgpu::BindGroupLayoutEntry {
                        binding: 3,
                        visibility: wgpu::ShaderStages::COMPUTE,
                        ty: wgpu::BindingType::Buffer {
                            ty: wgpu::BufferBindingType::Storage { read_only: false },
                            has_dynamic_offset: false,
                            min_binding_size: None,
                        },
                        count: None,
                    },
                ],
            });
            let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
                label: None,
                layout: Some(
                    &device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
                        label: None,
                        bind_group_layouts: &[&layout],
                        push_constant_ranges: &[],
                    }),
                ),
                module: &module,
                entry_point: "main",
            });
            let max_cand: u64 = 1 << 16;
            let scratch_size = (LANES * 32) as u64;
            let cand_size = max_cand * 9 * 4;
            let scratch_buf = device.create_buffer(&wgpu::BufferDescriptor {
                label: None,
                size: scratch_size,
                usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });
            let params_buf = device.create_buffer(&wgpu::BufferDescriptor {
                label: None,
                size: 80,
                usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });
            let cand_buf = device.create_buffer(&wgpu::BufferDescriptor {
                label: None,
                size: cand_size,
                usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
                mapped_at_creation: false,
            });
            let count_buf = device.create_buffer(&wgpu::BufferDescriptor {
                label: None,
                size: 4,
                usage: wgpu::BufferUsages::STORAGE
                    | wgpu::BufferUsages::COPY_SRC
                    | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });
            let staging_count = device.create_buffer(&wgpu::BufferDescriptor {
                label: None,
                size: 4,
                usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });
            let staging_cand = device.create_buffer(&wgpu::BufferDescriptor {
                label: None,
                size: cand_size,
                usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });
            let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
                label: None,
                layout: &layout,
                entries: &[
                    wgpu::BindGroupEntry {
                        binding: 0,
                        resource: scratch_buf.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 1,
                        resource: params_buf.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 2,
                        resource: cand_buf.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 3,
                        resource: count_buf.as_entire_binding(),
                    },
                ],
            });
            Ok(Self {
                device,
                queue,
                pipeline,
                bind_group,
                scratch_buf,
                params_buf,
                cand_buf,
                count_buf,
                staging_count,
                staging_cand,
                max_cand,
            })
        }

        fn block_challenge_zeroed(&self, t: &BlockTemplate) -> [u8; 32] {
            let header = BlockHeader {
                version: 1,
                prev_block: t.prev_block,
                merkle_root: Hash32([0u8; 32]),
                timestamp: t.timestamp,
                height: t.height,
                epoch_seed: t.epoch_seed,
                nonce: 0,
            };
            let mut b = to_bytes(&header);
            b.truncate(b.len() - 8);
            sha256d(&b).0
        }

        fn assemble(&self, t: &BlockTemplate, nonce: u64) -> Block {
            let coinbase = Transaction {
                version: 1,
                inputs: vec![],
                outputs: vec![TxOut {
                    value: Amount(50 * 100_000_000),
                    script_pubkey: t.coinbase_commit.to_vec(),
                    ephemeral: vec![],
                }],
                ephemeral: vec![],
                lock_time: 0,
            };
            let mut txs = vec![coinbase];
            txs.extend(t.txs.iter().cloned());
            let mut block = Block {
                header: BlockHeader {
                    version: 1,
                    prev_block: t.prev_block,
                    merkle_root: Hash32([0u8; 32]),
                    timestamp: t.timestamp,
                    height: t.height,
                    epoch_seed: t.epoch_seed,
                    nonce,
                },
                txs,
            };
            block.recompute_merkle();
            block
        }

        fn mine_block_impl(&self, t: &BlockTemplate, target: &[u8; 32]) -> Option<Block> {
            let challenge = self.block_challenge_zeroed(t);
            let flat = prepare_epoch(&t.epoch_seed.0).as_bytes().to_vec();
            self.queue.write_buffer(&self.scratch_buf, 0, &flat);

            let seed_words = u32_words(&t.epoch_seed.0);
            let chal_words = u32_words(&challenge);
            let lanes = LANES as u32;
            let walk = WALK as u32;
            let batch: u64 = 1 << 20;
            let mut base: u64 = 0;

            loop {
                let base_u32 = (base & 0xffff_ffff) as u32;
                let mut params: Vec<u8> = Vec::with_capacity(80);
                for w in &chal_words {
                    params.extend_from_slice(&w.to_ne_bytes());
                }
                for w in &seed_words {
                    params.extend_from_slice(&w.to_ne_bytes());
                }
                params.extend_from_slice(&base_u32.to_ne_bytes());
                params.extend_from_slice(&lanes.to_ne_bytes());
                params.extend_from_slice(&walk.to_ne_bytes());
                params.extend_from_slice(&0u32.to_ne_bytes());
                self.queue.write_buffer(&self.params_buf, 0, &params);
                self.queue
                    .write_buffer(&self.count_buf, 0, &0u32.to_ne_bytes());

                let mut enc = self
                    .device
                    .create_command_encoder(&wgpu::CommandEncoderDescriptor { label: None });
                {
                    let mut c = enc.begin_compute_pass(&wgpu::ComputePassDescriptor {
                        label: None,
                        timestamp_writes: None,
                    });
                    c.set_pipeline(&self.pipeline);
                    c.set_bind_group(0, &self.bind_group, &[]);
                    c.dispatch_workgroups((batch / 64) as u32, 1, 1);
                }
                enc.copy_buffer_to_buffer(&self.count_buf, 0, &self.staging_count, 0, 4);
                enc.copy_buffer_to_buffer(
                    &self.cand_buf,
                    0,
                    &self.staging_cand,
                    0,
                    self.max_cand * 9 * 4,
                );
                self.queue.submit(Some(enc.finish()));

                let count = read_u32(&self.device, &self.staging_count);
                if count > 0 {
                    let cands = read_bytes(&self.device, &self.staging_cand);
                    for c in 0..count as usize {
                        let o = c * 9;
                        if o + 9 > cands.len() / 4 {
                            break;
                        }
                        let p = o * 4;
                        let nonce = u32::from_ne_bytes([
                            cands[p],
                            cands[p + 1],
                            cands[p + 2],
                            cands[p + 3],
                        ]);
                        let mut x_words = [0u32; 8];
                        for k in 0..8 {
                            let q = (o + 1 + k) * 4;
                            x_words[k] = u32::from_ne_bytes([
                                cands[q],
                                cands[q + 1],
                                cands[q + 2],
                                cands[q + 3],
                            ]);
                        }
                        let x_bytes = u32_bytes(&x_words);
                        let nb = (base + nonce as u64).to_le_bytes();
                        let mut tail = Vec::with_capacity(32 + 32 + 8 + 32);
                        tail.extend_from_slice(&x_bytes);
                        tail.extend_from_slice(&t.epoch_seed.0);
                        tail.extend_from_slice(&nb);
                        tail.extend_from_slice(&challenge);
                        let digest = sha256d(&tail).0;
                        if meets_target(&digest, target) {
                            return Some(self.assemble(t, base + nonce as u64));
                        }
                    }
                }
                base = base.wrapping_add(batch);
                if base == 0 {
                    return None;
                }
            }
        }
    }

    impl MinerBackend for WgpuMiner {
        fn mine_block(&self, t: &BlockTemplate, target: &[u8; 32]) -> Option<Block> {
            self.mine_block_impl(t, target)
        }
    }

    fn u32_words(b: &[u8; 32]) -> [u32; 8] {
        let mut out = [0u32; 8];
        for k in 0..8 {
            out[k] = u32::from_be_bytes([b[4 * k], b[4 * k + 1], b[4 * k + 2], b[4 * k + 3]]);
        }
        out
    }

    fn u32_bytes(w: &[u32; 8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for k in 0..8 {
            out[4 * k..4 * k + 4].copy_from_slice(&w[k].to_be_bytes());
        }
        out
    }

    fn read_u32(device: &wgpu::Device, buf: &wgpu::Buffer) -> u32 {
        let (tx, rx) = mpsc::channel();
        let slice = buf.slice(..);
        slice.map_async(wgpu::MapMode::Read, move |_| {
            let _ = tx.send(());
        });
        device.poll(wgpu::Maintain::Wait);
        let _ = rx.recv();
        let data = slice.get_mapped_range();
        let v = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
        drop(data);
        buf.unmap();
        v
    }

    fn read_bytes(device: &wgpu::Device, buf: &wgpu::Buffer) -> Vec<u8> {
        let (tx, rx) = mpsc::channel();
        let slice = buf.slice(..);
        slice.map_async(wgpu::MapMode::Read, move |_| {
            let _ = tx.send(());
        });
        device.poll(wgpu::Maintain::Wait);
        let _ = rx.recv();
        let data = slice.get_mapped_range().to_vec();
        buf.unmap();
        data
    }
}

#[cfg(feature = "gpu")]
pub use gpu::WgpuMiner;
