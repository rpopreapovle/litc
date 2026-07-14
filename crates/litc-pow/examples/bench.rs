use litc_pow::{epoch_seed, mine, prepare_epoch, scratch_bytes, EPOCH_BLOCKS};
use std::time::Instant;

fn main() {
    println!("scratch = {} MB", scratch_bytes() / 1024 / 1024);
    println!("epoch = {} blocks", EPOCH_BLOCKS);

    let block_hash = [0xabu8; 32];
    let seed = epoch_seed(&block_hash);

    let t0 = Instant::now();
    let s = prepare_epoch(&seed);
    println!(
        "prepare_epoch (once per epoch, amortized): {:?}",
        t0.elapsed()
    );

    // Block challenge = SHA-256d of the header with the nonce zeroed.
    let challenge = [0xcd; 32];

    let trials = 2000usize;
    let start = Instant::now();
    let mut last = [0u8; 32];
    for n in 0..trials {
        last = mine(&s, n as u64, &challenge);
    }
    let dur = start.elapsed();
    let per = dur.as_secs_f64() / trials as f64;

    println!(
        "{} mines in {:?} -> {:.1} us/mine, {:.2} H/s",
        trials,
        dur,
        per * 1e6,
        trials as f64 / dur.as_secs_f64()
    );
    println!("sample digest: {:02x?}", &last[..8]);
}
