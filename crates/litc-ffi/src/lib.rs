//! LiTC Foreign Function Interface (C ABI).
//!
//! A language-agnostic, `extern "C"` surface over the LiTC cryptography and
//! stealth-address layer. Build as a `cdylib`/`staticlib` and link from any
//! FFI-capable language (C, C++, Rust, Python `ctypes`, Go `cgo`, Swift,
//! Zig, ...). The companion header is `include/litc.h`.
//!
//! # Contract
//! * Every function returns `0` on success and `-1` on error. The last error
//!   message is retrievable with `litc_last_error`.
//! * Output buffers whose size is fixed are passed as pre-allocated pointers the
//!   caller owns (e.g. `out_commit: *mut u8` of 20 bytes).
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(unused_unsafe)]
//! * Variable-length outputs (C strings, byte blobs) are allocated by the
//!   library and returned through a `(ptr, len)` pair; the caller frees them
//!   with `litc_string_free` (C strings) or `litc_free` (byte blobs).
//! * The caller must pass valid, non-null pointers to fixed-size outputs.

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::ptr;
use std::slice;

use litc_keystore::random_seed;
use litc_primitives::{
    base58check_decode, kem, stealth, to_bytes, wots, Amount, Decodable, Reader, TxOut,
};

thread_local! {
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

fn set_err(msg: impl Into<String>) {
    LAST_ERROR.with(|e| *e.borrow_mut() = msg.into());
}

/// Reconstruct a fixed-size array reference from a raw pointer (alignment 1).
unsafe fn arr_ref<const N: usize>(p: *const u8) -> &'static [u8; N] {
    &*(p as *const [u8; N])
}
unsafe fn arr_mut<const N: usize>(p: *mut u8) -> &'static mut [u8; N] {
    &mut *(p as *mut [u8; N])
}

/// Hand a `Vec<u8>` to the caller: shrink to fit (so capacity == length) and
/// forget it, returning `(ptr, len)`. Pair with `litc_free(ptr, len)`.
fn into_raw(v: Vec<u8>) -> (*mut u8, usize) {
    let mut v = v;
    v.shrink_to_fit();
    let ptr = v.as_mut_ptr();
    let len = v.len();
    std::mem::forget(v);
    (ptr, len)
}

// ---------------------------------------------------------------------------
// Sizes
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn litc_kem_pk_len() -> usize {
    kem::KEM_PK_LEN
}
#[no_mangle]
pub extern "C" fn litc_kem_sk_len() -> usize {
    kem::KEM_SK_LEN
}
#[no_mangle]
pub extern "C" fn litc_kem_ct_len() -> usize {
    kem::KEM_CT_LEN
}
#[no_mangle]
pub extern "C" fn litc_kem_ss_len() -> usize {
    kem::KEM_SS_LEN
}
#[no_mangle]
pub extern "C" fn litc_wots_sig_len() -> usize {
    // witness = pk_seed(32) + r(32) + L*32
    (2 + wots::L) * wots::N
}

// ---------------------------------------------------------------------------
// Error / memory management
// ---------------------------------------------------------------------------

/// Copy the last error message into `buf` (truncated to `len`, NUL-terminated).
/// Returns the number of bytes written (excluding the NUL), or 0 if no error.
#[no_mangle]
pub extern "C" fn litc_last_error(buf: *mut c_char, len: usize) -> usize {
    if buf.is_null() || len == 0 {
        return 0;
    }
    let msg = LAST_ERROR.with(|e| e.borrow().clone());
    let bytes = msg.as_bytes();
    let n = bytes.len().min(len - 1);
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, n);
        *buf.add(n) = 0;
    }
    n
}

/// Free a byte blob previously returned through a `(ptr, len)` pair.
#[no_mangle]
pub extern "C" fn litc_free(ptr: *mut c_void, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    let _ = unsafe { Vec::from_raw_parts(ptr as *mut u8, len, len) };
}

/// Free a C string previously returned by the library (e.g. an address).
#[no_mangle]
pub extern "C" fn litc_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe { drop(CString::from_raw(s)) };
}

// ---------------------------------------------------------------------------
// Entropy
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn litc_random_seed(seed_out: *mut u8) -> i32 {
    if seed_out.is_null() {
        set_err("null seed_out");
        return -1;
    }
    match random_seed() {
        Ok(s) => {
            unsafe { ptr::copy_nonoverlapping(s.as_ptr(), seed_out, 32) };
            0
        }
        Err(e) => {
            set_err(e);
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// WOTS+ (one-time signatures)
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn litc_wots_commit(seed: *const u8, index: u32, out_commit: *mut u8) -> i32 {
    if seed.is_null() || out_commit.is_null() {
        set_err("null pointer");
        return -1;
    }
    let s = unsafe { *arr_ref::<32>(seed) };
    let kp = wots::WotsKeypair::derive(&s, index);
    unsafe { ptr::copy_nonoverlapping(kp.pubkey_root_hash160().as_ptr(), out_commit, 20) };
    0
}

#[no_mangle]
pub extern "C" fn litc_wots_address(
    seed: *const u8,
    index: u32,
    testnet: u8,
    out_addr: *mut *mut c_char,
) -> i32 {
    if seed.is_null() || out_addr.is_null() {
        set_err("null pointer");
        return -1;
    }
    let s = unsafe { *arr_ref::<32>(seed) };
    let kp = wots::WotsKeypair::derive(&s, index);
    let version = if testnet != 0 {
        wots::TESTNET_VERSION
    } else {
        wots::MAINNET_VERSION
    };
    let c = match CString::new(kp.address(version)) {
        Ok(c) => c,
        Err(e) => {
            set_err(e.to_string());
            return -1;
        }
    };
    unsafe { *out_addr = c.into_raw() };
    0
}

#[no_mangle]
pub extern "C" fn litc_wots_sign(
    seed: *const u8,
    index: u32,
    msg: *const u8,
    out_sig: *mut u8,
    sig_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if seed.is_null() || msg.is_null() || out_sig.is_null() || out_len.is_null() {
        set_err("null pointer");
        return -1;
    }
    let s = unsafe { *arr_ref::<32>(seed) };
    let m = unsafe { *arr_ref::<32>(msg) };
    let kp = wots::WotsKeypair::derive(&s, index);
    let sig = wots::encode_witness(&kp.sign(&m));
    if sig.len() > sig_cap {
        set_err("signature buffer too small");
        return -1;
    }
    unsafe {
        ptr::copy_nonoverlapping(sig.as_ptr(), out_sig, sig.len());
        *out_len = sig.len();
    }
    0
}

#[no_mangle]
pub extern "C" fn litc_wots_verify(
    commit: *const u8,
    msg: *const u8,
    sig: *const u8,
    sig_len: usize,
) -> i32 {
    if commit.is_null() || msg.is_null() || sig.is_null() {
        set_err("null pointer");
        return -1;
    }
    let c = unsafe { *arr_ref::<20>(commit) };
    let m = unsafe { *arr_ref::<32>(msg) };
    let slice = unsafe { slice::from_raw_parts(sig, sig_len) };
    let witness = match wots::decode_witness(slice) {
        Ok(w) => w,
        Err(_) => return 0,
    };
    if witness.verify(&m, &c) {
        1
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// ML-KEM-512 (post-quantum KEM)
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn litc_kem_keypair(seed: *const u8, out_pk: *mut u8, out_sk: *mut u8) -> i32 {
    if seed.is_null() || out_pk.is_null() || out_sk.is_null() {
        set_err("null pointer");
        return -1;
    }
    let s = unsafe { *arr_ref::<32>(seed) };
    let (pk, sk) = kem::kem_keypair_from_seed(&s);
    unsafe {
        ptr::copy_nonoverlapping(pk.as_ptr(), out_pk, kem::KEM_PK_LEN);
        ptr::copy_nonoverlapping(sk.as_ptr(), out_sk, kem::KEM_SK_LEN);
    }
    0
}

#[no_mangle]
pub extern "C" fn litc_kem_encaps(pk: *const u8, out_ss: *mut u8, out_ct: *mut u8) -> i32 {
    if pk.is_null() || out_ss.is_null() || out_ct.is_null() {
        set_err("null pointer");
        return -1;
    }
    let p = unsafe { *arr_ref::<{ kem::KEM_PK_LEN }>(pk) };
    let (ss, ct) = kem::kem_encaps(&p);
    unsafe {
        ptr::copy_nonoverlapping(ss.as_ptr(), out_ss, kem::KEM_SS_LEN);
        ptr::copy_nonoverlapping(ct.as_ptr(), out_ct, kem::KEM_CT_LEN);
    }
    0
}

#[no_mangle]
pub extern "C" fn litc_kem_decaps(sk: *const u8, ct: *const u8, out_ss: *mut u8) -> i32 {
    if sk.is_null() || ct.is_null() || out_ss.is_null() {
        set_err("null pointer");
        return -1;
    }
    let s = unsafe { *arr_ref::<{ kem::KEM_SK_LEN }>(sk) };
    let c = unsafe { *arr_ref::<{ kem::KEM_CT_LEN }>(ct) };
    let ss = kem::kem_decaps(&s, &c);
    unsafe { ptr::copy_nonoverlapping(ss.as_ptr(), out_ss, kem::KEM_SS_LEN) };
    0
}

// ---------------------------------------------------------------------------
// Stealth addresses (reusable address + one-time WOTS+ output)
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn litc_stealth_address(
    pk: *const u8,
    testnet: u8,
    out_addr: *mut *mut c_char,
) -> i32 {
    if pk.is_null() || out_addr.is_null() {
        set_err("null pointer");
        return -1;
    }
    let p = unsafe { *arr_ref::<{ kem::KEM_PK_LEN }>(pk) };
    let version = if testnet != 0 {
        stealth::STEALTH_VERSION_TESTNET
    } else {
        stealth::STEALTH_VERSION_MAINNET
    };
    let c = match CString::new(stealth::stealth_address(&p, version)) {
        Ok(c) => c,
        Err(e) => {
            set_err(e.to_string());
            return -1;
        }
    };
    unsafe { *out_addr = c.into_raw() };
    0
}

#[no_mangle]
pub extern "C" fn litc_parse_stealth_address(
    addr: *const c_char,
    out_pk: *mut u8,
    out_testnet: *mut u8,
) -> i32 {
    if addr.is_null() || out_pk.is_null() || out_testnet.is_null() {
        set_err("null pointer");
        return -1;
    }
    let cstr = unsafe { CStr::from_ptr(addr) };
    let s = match cstr.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_err("address is not valid UTF-8");
            return -1;
        }
    };
    let (v, payload) = match base58check_decode(s) {
        Some(x) => x,
        None => {
            set_err("not a base58check address");
            return -1;
        }
    };
    if payload.len() != kem::KEM_PK_LEN {
        set_err("address payload has wrong length");
        return -1;
    }
    unsafe {
        ptr::copy_nonoverlapping(payload.as_ptr(), out_pk, kem::KEM_PK_LEN);
        *out_testnet = if v == stealth::STEALTH_VERSION_TESTNET {
            1
        } else {
            0
        };
    }
    0
}

/// Build a one-time output paying a reusable stealth address. Returns the
/// serialized `TxOut` bytes (`out_bytes`, freed with `litc_free`) **and** the
/// KEM ciphertext (`out_ct`, freed with `litc_free`) that must be stored in the
/// transaction's `ephemeral` field. The capsule is randomized, so the script
/// and ciphertext come from a single encapsulation and must stay paired.
#[no_mangle]
pub extern "C" fn litc_stealth_build_output(
    pk: *const u8,
    value_sat: u64,
    out_bytes: *mut *mut u8,
    out_len: *mut usize,
    out_ct: *mut *mut u8,
    out_ct_len: *mut usize,
) -> i32 {
    if pk.is_null()
        || out_bytes.is_null()
        || out_len.is_null()
        || out_ct.is_null()
        || out_ct_len.is_null()
    {
        set_err("null pointer");
        return -1;
    }
    let p = unsafe { *arr_ref::<{ kem::KEM_PK_LEN }>(pk) };
    let (out, ct) = stealth::build_stealth_output(&p, Amount(value_sat));
    let (ptr, len) = into_raw(to_bytes(&out));
    let (cptr, clen) = into_raw(ct.to_vec());
    unsafe {
        *out_bytes = ptr;
        *out_len = len;
        *out_ct = cptr;
        *out_ct_len = clen;
    }
    0
}

/// Recover the one-time WOTS+ commitment (HASH160(R)) for a received output,
/// given the scan secret, the transaction's KEM ciphertext, and the output's
/// `index` within its funding transaction.
#[no_mangle]
pub extern "C" fn litc_stealth_commit(
    sk: *const u8,
    ct: *const u8,
    index: u32,
    out_commit: *mut u8,
) -> i32 {
    if sk.is_null() || ct.is_null() || out_commit.is_null() {
        set_err("null pointer");
        return -1;
    }
    let s = unsafe { *arr_ref::<{ kem::KEM_SK_LEN }>(sk) };
    let c = unsafe { *arr_ref::<{ kem::KEM_CT_LEN }>(ct) };
    let kp = match stealth::recover_stealth_keypair_at(&s, &c, index) {
        Some(k) => k,
        None => {
            set_err("cannot recover stealth key (bad ciphertext)");
            return -1;
        }
    };
    unsafe { ptr::copy_nonoverlapping(kp.pubkey_root_hash160().as_ptr(), out_commit, 20) };
    0
}

/// Sign a spend of a received stealth output, given the scan secret, the
/// transaction's KEM ciphertext, the output's `index` within its funding
/// transaction, and the transaction sighash. `out_sig` must hold
/// `litc_wots_sig_len()` bytes.
#[no_mangle]
pub extern "C" fn litc_stealth_sign(
    sk: *const u8,
    ct: *const u8,
    index: u32,
    msg: *const u8,
    out_sig: *mut u8,
    sig_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if sk.is_null() || ct.is_null() || msg.is_null() || out_sig.is_null() || out_len.is_null() {
        set_err("null pointer");
        return -1;
    }
    let s = unsafe { *arr_ref::<{ kem::KEM_SK_LEN }>(sk) };
    let c = unsafe { *arr_ref::<{ kem::KEM_CT_LEN }>(ct) };
    let m = unsafe { *arr_ref::<32>(msg) };
    let kp = match stealth::recover_stealth_keypair_at(&s, &c, index) {
        Some(k) => k,
        None => {
            set_err("cannot recover stealth key (bad ciphertext)");
            return -1;
        }
    };
    let sig = wots::encode_witness(&kp.sign(&m));
    if sig.len() > sig_cap {
        set_err("signature buffer too small");
        return -1;
    }
    unsafe {
        ptr::copy_nonoverlapping(sig.as_ptr(), out_sig, sig.len());
        *out_len = sig.len();
    }
    0
}

// ---------------------------------------------------------------------------
// TxOut inspection
// ---------------------------------------------------------------------------

/// Decode a serialized `TxOut`. Writes the satoshi `value`, the 20-byte
/// commitment (first 20 bytes of the script, zeroed if shorter), and the
/// KEM ciphertext (ephemeral); the ciphertext blob is allocated by the library
/// and freed with `litc_free`.
#[no_mangle]
pub extern "C" fn litc_txout_decode(
    bytes: *const u8,
    len: usize,
    out_value: *mut u64,
    out_commit: *mut u8,
    out_ephemeral: *mut *mut u8,
    out_ephemeral_len: *mut usize,
) -> i32 {
    if bytes.is_null()
        || out_value.is_null()
        || out_commit.is_null()
        || out_ephemeral.is_null()
        || out_ephemeral_len.is_null()
    {
        set_err("null pointer");
        return -1;
    }
    let slice = unsafe { slice::from_raw_parts(bytes, len) };
    let mut r = Reader::new(slice);
    let txout = match TxOut::decode(&mut r) {
        Ok(t) => t,
        Err(e) => {
            set_err(e);
            return -1;
        }
    };
    unsafe {
        *out_value = txout.value.0;
        let commit = arr_mut::<20>(out_commit);
        commit.iter_mut().for_each(|b| *b = 0);
        let n = txout.script_pubkey.len().min(20);
        commit[..n].copy_from_slice(&txout.script_pubkey[..n]);
        let (ptr, elen) = into_raw(txout.ephemeral);
        *out_ephemeral = ptr;
        *out_ephemeral_len = elen;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_wots_roundtrip() {
        let mut seed = [0u8; 32];
        assert_eq!(unsafe { litc_random_seed(seed.as_mut_ptr()) }, 0);
        let mut commit = [0u8; 20];
        assert_eq!(
            unsafe { litc_wots_commit(seed.as_ptr(), 0, commit.as_mut_ptr()) },
            0
        );

        let mut addr: *mut c_char = ptr::null_mut();
        assert_eq!(
            unsafe { litc_wots_address(seed.as_ptr(), 0, 0, &mut addr) },
            0
        );
        unsafe { drop(CString::from_raw(addr)) };

        let msg = [0xdeu8; 32];
        let mut sig = vec![0u8; litc_wots_sig_len()];
        let mut sig_len = 0usize;
        assert_eq!(
            unsafe {
                litc_wots_sign(
                    seed.as_ptr(),
                    0,
                    msg.as_ptr(),
                    sig.as_mut_ptr(),
                    sig.len(),
                    &mut sig_len,
                )
            },
            0
        );
        assert_eq!(sig_len, litc_wots_sig_len());
        assert_eq!(
            unsafe { litc_wots_verify(commit.as_ptr(), msg.as_ptr(), sig.as_ptr(), sig_len) },
            1
        );
        // Wrong message must fail.
        let bad = [0u8; 32];
        assert_eq!(
            unsafe { litc_wots_verify(commit.as_ptr(), bad.as_ptr(), sig.as_ptr(), sig_len) },
            0
        );
    }

    #[test]
    fn ffi_kem_and_stealth_roundtrip() {
        let mut seed = [0u8; 32];
        assert_eq!(unsafe { litc_random_seed(seed.as_mut_ptr()) }, 0);
        let mut pk = [0u8; 800];
        let mut sk = [0u8; 64];
        assert_eq!(
            unsafe { litc_kem_keypair(seed.as_ptr(), pk.as_mut_ptr(), sk.as_mut_ptr()) },
            0
        );

        let mut ss1 = [0u8; 32];
        let mut ct = [0u8; 768];
        assert_eq!(
            unsafe { litc_kem_encaps(pk.as_ptr(), ss1.as_mut_ptr(), ct.as_mut_ptr()) },
            0
        );
        let mut ss2 = [0u8; 32];
        assert_eq!(
            unsafe { litc_kem_decaps(sk.as_ptr(), ct.as_ptr(), ss2.as_mut_ptr()) },
            0
        );
        assert_eq!(ss1, ss2);

        // Stealth address roundtrip.
        let mut addr: *mut c_char = ptr::null_mut();
        assert_eq!(
            unsafe { litc_stealth_address(pk.as_ptr(), 0, &mut addr) },
            0
        );
        let addr_str = unsafe { CString::from_raw(addr) };
        let cstr = addr_str.to_str().unwrap().to_string();
        drop(addr_str);
        let mut pk2 = [0u8; 800];
        let mut tn = 0u8;
        assert_eq!(
            unsafe {
                litc_parse_stealth_address(
                    cstr.as_ptr() as *const c_char,
                    pk2.as_mut_ptr(),
                    &mut tn,
                )
            },
            0
        );
        assert_eq!(pk, pk2);
        assert_eq!(tn, 0);

        // Build a stealth output + the ciphertext the sender attaches at the
        // transaction level, decode the output, and recover its commitment + sign.
        let mut out_bytes: *mut u8 = ptr::null_mut();
        let mut out_len = 0usize;
        let mut out_ct: *mut u8 = ptr::null_mut();
        let mut out_ct_len = 0usize;
        let value = 123_456_789u64;
        assert_eq!(
            unsafe {
                litc_stealth_build_output(
                    pk.as_ptr(),
                    value,
                    &mut out_bytes,
                    &mut out_len,
                    &mut out_ct,
                    &mut out_ct_len,
                )
            },
            0
        );
        let slice = unsafe { slice::from_raw_parts(out_bytes, out_len) };

        let mut dec_value = 0u64;
        let mut dec_commit = [0u8; 20];
        let mut dec_eph: *mut u8 = ptr::null_mut();
        let mut dec_eph_len = 0usize;
        assert_eq!(
            unsafe {
                litc_txout_decode(
                    slice.as_ptr(),
                    out_len,
                    &mut dec_value,
                    dec_commit.as_mut_ptr(),
                    &mut dec_eph,
                    &mut dec_eph_len,
                )
            },
            0
        );
        assert_eq!(dec_value, value);
        // Aggregated stealth: the output itself carries no ciphertext.
        assert_eq!(dec_eph_len, 0);
        unsafe { litc_free(dec_eph as *mut c_void, dec_eph_len) };

        // The ciphertext returned by build_output is what the sender stores in
        // Transaction.ephemeral; recover the commitment from it at index 0.
        assert_eq!(out_ct_len, 768);
        let ct = unsafe { slice::from_raw_parts(out_ct, out_ct_len) };

        // Recover the commitment from the scan secret + ciphertext at index 0.
        let mut rec_commit = [0u8; 20];
        assert_eq!(
            unsafe { litc_stealth_commit(sk.as_ptr(), ct.as_ptr(), 0, rec_commit.as_mut_ptr()) },
            0
        );
        assert_eq!(rec_commit, dec_commit);

        // Sign a spend with the recovered key and verify it.
        let sighash = [0xabu8; 32];
        let mut sig = vec![0u8; litc_wots_sig_len()];
        let mut sig_len = 0usize;
        assert_eq!(
            unsafe {
                litc_stealth_sign(
                    sk.as_ptr(),
                    ct.as_ptr(),
                    0,
                    sighash.as_ptr(),
                    sig.as_mut_ptr(),
                    sig.len(),
                    &mut sig_len,
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                litc_wots_verify(rec_commit.as_ptr(), sighash.as_ptr(), sig.as_ptr(), sig_len)
            },
            1
        );
        unsafe {
            litc_free(out_bytes as *mut c_void, out_len);
            litc_free(out_ct as *mut c_void, out_ct_len);
        }
    }
}
