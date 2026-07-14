use sha2::{Digest, Sha256};

#[cfg(feature = "small")]
pub const LANES: usize = 1 << 18; // 2^18 lanes * 32 B = 8 MB (fast tests)
#[cfg(not(feature = "small"))]
pub const LANES: usize = 1 << 24; // 2^24 lanes * 32 B = 512 MB working set
pub const LANE_BYTES: usize = 32;
pub const WALK: usize = 1 << 16;

pub fn scratch_bytes() -> usize {
    LANES * LANE_BYTES
}

pub const EPOCH_BLOCKS: u64 = 2400;

/// Targeted seconds between blocks (used for difficulty retargeting).
pub const BLOCK_TIME: u64 = 15;
/// Seconds per retargeting epoch (≈10 h at 15 s blocks).
pub const TARGET_TIMESPAN: u64 = EPOCH_BLOCKS * BLOCK_TIME;

/// Easiest allowed target (lowest difficulty).
pub const MAX_TARGET: [u8; 32] = [0xff; 32];
/// Hardest allowed target (highest difficulty): 8 leading zero bytes (~64 bits).
pub const MIN_TARGET: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];
/// Genesis target: modest so a CPU can mine the demo (4 leading zero bits).
pub const INITIAL_TARGET: [u8; 32] = [0x0f; 32];

/// Bitcoin-style retarget: `new = prev * actual / ideal`, clamped to
/// `[MIN_TARGET, MAX_TARGET]` and with the timespan swing limited to ±4× so a
/// single stalled epoch cannot flip difficulty to an extreme.
///
/// `actual` and `ideal` are time spans in seconds.
pub fn adjust_target(prev: &[u8; 32], actual: u64, ideal: u64) -> [u8; 32] {
    if ideal == 0 {
        return *prev;
    }
    let lo = ideal / 4;
    let hi = ideal.saturating_mul(4);
    let actual = actual.clamp(lo, hi).max(1);

    let (big, _) = mul256_u64(prev, actual);
    let (mut out, overflow) = div320_u64(&big, ideal);
    if overflow {
        out = MAX_TARGET;
    }
    if out > MAX_TARGET {
        out = MAX_TARGET;
    }
    if out < MIN_TARGET {
        out = MIN_TARGET;
    }
    out
}

/// `a * k` as a 320-bit little-big number (40 bytes, big-endian), no overflow
/// for `a < 2^256` and `k < 2^64`.
fn mul256_u64(a: &[u8; 32], k: u64) -> ([u8; 40], bool) {
    let mut out = [0u8; 40];
    let mut carry: u128 = 0;
    for i in (0..32).rev() {
        let cur = carry + (a[i] as u128) * (k as u128);
        out[i + 8] = (cur & 0xff) as u8;
        carry = cur >> 8;
    }
    let mut c = carry;
    for i in (0..8).rev() {
        out[i] = (c & 0xff) as u8;
        c >>= 8;
    }
    (out, c != 0)
}

/// `a / d` (320-bit big-endian by 64-bit), returning the low 256 bits. `overflow`
/// is set if the quotient needs more than 256 bits.
fn div320_u64(a: &[u8; 40], d: u64) -> ([u8; 32], bool) {
    let mut out = [0u8; 32];
    let mut rem: u128 = 0;
    let mut overflow = false;
    for i in 0..40 {
        let cur = (rem << 8) | a[i] as u128;
        let q = cur / (d as u128);
        rem = cur % (d as u128);
        if i < 8 {
            if q != 0 {
                overflow = true;
            }
        } else {
            out[i - 8] = q as u8;
        }
    }
    (out, overflow)
}

fn sha256d(data: &[u8]) -> [u8; 32] {
    let h1 = Sha256::digest(data);
    let h2 = Sha256::digest(h1);
    let mut o = [0u8; 32];
    o.copy_from_slice(&h2);
    o
}

pub struct Scratch {
    v: Vec<[u8; 32]>,
    seed: [u8; 32],
}

impl Scratch {
    /// Flat byte view of the scratchpad (`LANES * 32` bytes), for uploading to a
    /// GPU buffer. Safe: `prepare_epoch` transmutes a `Vec<u8>` into the
    /// `Vec<[u8; 32]>`, so the memory layout is identical.
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.v.as_ptr() as *const u8, self.v.len() * 32) }
    }
}

pub fn epoch_seed(prev_epoch_last_block_hash: &[u8; 32]) -> [u8; 32] {
    sha256d(prev_epoch_last_block_hash)
}

pub fn prepare_epoch(seed: &[u8; 32]) -> Scratch {
    let mut v: Vec<[u8; 32]> = vec![[0u8; 32]; LANES];
    // Memory-hard fill: each lane depends on the *previous* lane (and the epoch
    // seed), so an arbitrary lane `i` cannot be recomputed in O(1). A TMTO
    // attacker that stores only a fraction of the 512 MB pad must walk the chain
    // from lane 0 to regenerate any missing lane, paying a proportional compute
    // cost — the standard memory-hardness tradeoff (store 1/k of the pad, pay
    // ~k× recompute). A CTR-mode stream cipher here (e.g. ChaCha8) would let any
    // lane be computed in O(1) from the seed, defeating the memory cost entirely
    // and letting an ASIC skip the scratchpad.
    let mut prev = *seed;
    let mut buf = [0u8; 64];
    for slot in v.iter_mut() {
        let d = sha256d(&prev);
        buf[..32].copy_from_slice(&d);
        buf[32..].copy_from_slice(seed);
        let lane = sha256d(&buf);
        *slot = lane;
        prev = lane;
    }
    Scratch { v, seed: *seed }
}

pub fn mine(s: &Scratch, nonce: u64, challenge: &[u8; 32]) -> [u8; 32] {
    // The walk starts from the block `challenge` (SHA-256d of the header with
    // the nonce zeroed), so the work binds to the block content. The 512 MB
    // scratchpad (epoch-seeded) still drives the memory-latency cost.
    let mut x = *challenge;
    let nb = nonce.to_le_bytes();
    for k in 0..8 {
        x[k] = x[k].wrapping_add(nb[k]);
    }
    for _ in 0..WALK {
        let mut acc: u64 = 0;
        for &byte in &x[..8] {
            acc = (acc << 8) | byte as u64;
        }
        x = s.v[(acc as usize) % LANES];
    }
    let mut tail = Vec::with_capacity(64 + 8 + 32);
    tail.extend_from_slice(&x);
    tail.extend_from_slice(&s.seed);
    tail.extend_from_slice(&nb);
    tail.extend_from_slice(challenge);
    sha256d(&tail)
}

/// True if `digest <= target` (both compared as big-endian 256-bit integers).
pub fn meets_target(digest: &[u8; 32], target: &[u8; 32]) -> bool {
    digest <= target
}

/// Cumulative work of a single block at `target`: `floor(2^256 / target)`.
///
/// This must use the *full* 256-bit target so it stays strictly monotonic in
/// `1/target` and consistent with [`meets_target`]. The protocol clamps the
/// target to `[MIN_TARGET, MAX_TARGET]` (~`[2^192, 2^256)`), so the quotient is
/// in `[1, 2^64]` and fits in `u128`. A naive implementation that only looked
/// at the low 128 bits would give two very different targets identical work,
/// breaking heaviest-chain selection.
///
/// Restoring division of the 257-bit dividend `2^256` by the 256-bit `target`.
pub fn block_work(target: &[u8; 32]) -> u128 {
    // `t` as 4 big-endian 64-bit limbs, MSB-first: t[0] = bytes 0..8, ..., t[3] =
    // bytes 24..32 (LSB).
    let mut t = [0u64; 4];
    for i in 0..4 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&target[i * 8..i * 8 + 8]);
        t[i] = u64::from_be_bytes(b);
    }
    // `rem` is 5 limbs MSB-first (rem[4] = bits 256..319 ... rem[0] = bits
    // 0..63). The dividend `2^256` has its only bit at position 256, fed in at
    // the most-significant iteration.
    let mut rem = [0u64; 5];
    // Quotient limbs (LSB-first). Only bits 0..=64 can be set (quotient <=
    // 2^64), but size 5 so the write at `bit / 64` never goes out of bounds.
    let mut quot = [0u64; 5];
    // Target limb aligned to `rem[i]`: the 256-bit target occupies rem[3..0]
    // (MSB t[0] at rem[3], LSB t[3] at rem[0]); rem[4] holds the dividend's
    // extra bit (position 256) and has no target counterpart.
    let tl = |i: usize| -> u64 {
        if i == 4 {
            0
        } else {
            t[3 - i]
        }
    };
    for bit in (0..=256).rev() {
        let mut carry = 0u64;
        #[allow(clippy::needless_range_loop)]
        for i in 0..5 {
            let cur = (rem[i] << 1) | carry;
            carry = rem[i] >> 63;
            rem[i] = cur;
        }
        if bit == 256 {
            rem[0] |= 1;
        }
        let ge = {
            let mut greater = false;
            let mut less = false;
            // Compare MSB-first; stop at first differing limb.
            for i in (0..5).rev() {
                let ti = tl(i);
                if rem[i] > ti {
                    greater = true;
                    break;
                } else if rem[i] < ti {
                    less = true;
                    break;
                }
            }
            greater || !less
        };
        if ge {
            let mut borrow = 0u64;
            #[allow(clippy::needless_range_loop)]
            for i in 0..5 {
                let ti = tl(i);
                let (s1, b1) = rem[i].overflowing_sub(ti);
                let (s2, b2) = s1.overflowing_sub(borrow);
                rem[i] = s2;
                borrow = if b1 || b2 { 1 } else { 0 };
            }
            let qidx = bit / 64;
            let qoff = (bit % 64) as u32;
            quot[qidx] |= 1u64 << qoff;
        }
    }
    eprintln!("DEBUG block_work quot=[{:#x},{:#x},{:#x},{:#x},{:#x}] rem=[{:#x},{:#x},{:#x},{:#x},{:#x}]",
        quot[0], quot[1], quot[2], quot[3], quot[4],
        rem[0], rem[1], rem[2], rem[3], rem[4]);
    ((quot[1] as u128) << 64) | (quot[0] as u128)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let seed = [7u8; 32];
        let s = prepare_epoch(&seed);
        let ch = [1u8; 32];
        assert_eq!(mine(&s, 1, &ch), mine(&s, 1, &ch));
    }

    #[test]
    fn nonce_changes_digest() {
        let s = prepare_epoch(&[7u8; 32]);
        let ch = [1u8; 32];
        assert_ne!(mine(&s, 1, &ch), mine(&s, 2, &ch));
    }

    #[test]
    fn challenge_binds_block() {
        let s = prepare_epoch(&[7u8; 32]);
        assert_ne!(mine(&s, 1, &[1u8; 32]), mine(&s, 1, &[2u8; 32]));
    }

    #[test]
    fn meets_target_cmp() {
        let lo = [0u8; 32];
        let hi = [0xff; 32];
        assert!(meets_target(&lo, &hi));
        assert!(!meets_target(&hi, &lo));
    }

    #[test]
    fn epoch_is_reproducible() {
        let seed = [9u8; 32];
        let a = prepare_epoch(&seed);
        let b = prepare_epoch(&seed);
        assert_eq!(a.v[0], b.v[0]);
        assert_eq!(a.v[LANES - 1], b.v[LANES - 1]);
    }

    #[test]
    fn uses_full_scratch() {
        #[cfg(not(feature = "small"))]
        assert_eq!(scratch_bytes(), 512 * 1024 * 1024);
        #[cfg(feature = "small")]
        assert_eq!(scratch_bytes(), 8 * 1024 * 1024);
    }

    #[test]
    fn retarget_faster_makes_harder() {
        // Blocks came 4x faster than ideal -> target shrinks ~4x (harder).
        let t = adjust_target(&INITIAL_TARGET, TARGET_TIMESPAN / 4, TARGET_TIMESPAN);
        assert!(t < INITIAL_TARGET);
    }

    #[test]
    fn retarget_slower_makes_easier() {
        // Blocks came 4x slower -> target grows ~4x (easier).
        let t = adjust_target(&INITIAL_TARGET, TARGET_TIMESPAN * 4, TARGET_TIMESPAN);
        assert!(t > INITIAL_TARGET);
    }

    #[test]
    fn retarget_on_pace_unchanged() {
        let t = adjust_target(&INITIAL_TARGET, TARGET_TIMESPAN, TARGET_TIMESPAN);
        assert_eq!(t, INITIAL_TARGET);
    }

    #[test]
    fn retarget_clamps_to_max() {
        let huge = [0xee; 32];
        // Slower -> easier; clamp to the easiest allowed target.
        let t = adjust_target(&huge, TARGET_TIMESPAN * 4, TARGET_TIMESPAN);
        assert_eq!(t, MAX_TARGET);
    }

    #[test]
    fn retarget_clamps_to_min() {
        // Faster -> harder; clamp to the hardest allowed target.
        let t = adjust_target(&MIN_TARGET, TARGET_TIMESPAN / 4, TARGET_TIMESPAN);
        assert_eq!(t, MIN_TARGET);
    }

    #[test]
    fn block_work_endpoints() {
        // Easiest target -> work 1.
        assert_eq!(block_work(&MAX_TARGET), 1);
        // Hardest target (~2^192) -> work 2^64.
        assert_eq!(block_work(&MIN_TARGET), 1u128 << 64);
        // Genesis target [0x0f;32] -> 2^256 / (0x0f * 2^248) = 2^8 / 15 = 17.
        assert_eq!(block_work(&[0x0f; 32]), 17);
    }

    #[test]
    fn block_work_monotonic() {
        // Smaller target (harder) must yield strictly more work.
        let mut a = [0x0fu8; 32];
        let b = [0x0fu8; 32];
        a[0] = 0x07; // smaller than 0x0f
        assert!(block_work(&a) > block_work(&b));
        // And consistent ordering across a wide range.
        let mut c = [0xffu8; 32];
        c[0] = 0x00; // much smaller (harder)
        assert!(block_work(&c) > block_work(&a));
        assert!(block_work(&b) > block_work(&MAX_TARGET));
    }
}
