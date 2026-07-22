//! LiTC Foreign Function Interface (C ABI).
//!
//! A language-agnostic, `extern "C"` surface over the LiTC ML-DSA-2
//! post-quantum signature layer. Build as a `cdylib`/`staticlib` and link from
//! any FFI-capable language (C, C++, Rust, Python `ctypes`, Go `cgo`, Swift,
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

use litc_keystore::random_seed;
use litc_primitives::{mldsa, Decodable, Reader, TxOut};

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

// ---------------------------------------------------------------------------
// Sizes
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn litc_mldsa_pk_len() -> usize {
    mldsa::PK_LEN
}

#[no_mangle]
pub extern "C" fn litc_mldsa_sig_len() -> usize {
    mldsa::SIG_LEN
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
// ML-DSA-2 (post-quantum signatures)
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn litc_mldsa_keypair(seed: *const u8, out_pk: *mut u8, out_sk: *mut u8) -> i32 {
    if seed.is_null() || out_pk.is_null() || out_sk.is_null() {
        set_err("null pointer");
        return -1;
    }
    let s = unsafe { *arr_ref::<32>(seed) };
    let kp = mldsa::MlDsaKeypair::derive(&s, 0);
    let pk = kp.public_key_bytes();
    let sk = kp.secret_bytes();
    unsafe {
        ptr::copy_nonoverlapping(pk.as_ptr(), out_pk, mldsa::PK_LEN);
        ptr::copy_nonoverlapping(sk.as_ptr(), out_sk, mldsa::SEED_LEN);
    }
    0
}

#[no_mangle]
pub extern "C" fn litc_mldsa_address(
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
    let kp = mldsa::MlDsaKeypair::derive(&s, index);
    let version = if testnet != 0 {
        mldsa::TESTNET_VERSION
    } else {
        mldsa::MAINNET_VERSION
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
pub extern "C" fn litc_mldsa_sign(
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
    let kp = mldsa::MlDsaKeypair::derive(&s, index);
    let sig = kp.sign(&m);
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
pub extern "C" fn litc_mldsa_verify(
    pk: *const u8,
    msg: *const u8,
    sig: *const u8,
    sig_len: usize,
) -> i32 {
    if pk.is_null() || msg.is_null() || sig.is_null() {
        set_err("null pointer");
        return -1;
    }
    let p = unsafe { *arr_ref::<{ mldsa::PK_LEN }>(pk) };
    let m = unsafe { *arr_ref::<32>(msg) };
    let s = unsafe { std::slice::from_raw_parts(sig, sig_len) };
    if mldsa::MlDsaKeypair::verify(&p, &m, s) {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn litc_parse_address(
    addr: *const c_char,
    out_hash: *mut u8,
    out_testnet: *mut u8,
) -> i32 {
    if addr.is_null() || out_hash.is_null() || out_testnet.is_null() {
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
    let (v, hash) = match mldsa::parse_address(s) {
        Some(x) => x,
        None => {
            set_err("not a valid ML-DSA-2 address");
            return -1;
        }
    };
    unsafe {
        ptr::copy_nonoverlapping(hash.as_ptr(), out_hash, 20);
        *out_testnet = if v == mldsa::TESTNET_VERSION { 1 } else { 0 };
    }
    0
}

// ---------------------------------------------------------------------------
// TxOut inspection
// ---------------------------------------------------------------------------

/// Decode a serialized `TxOut`. Writes the satoshi `value` and the 20-byte
/// commitment (first 20 bytes of the script, zeroed if shorter).
#[no_mangle]
pub extern "C" fn litc_txout_decode(
    bytes: *const u8,
    len: usize,
    out_value: *mut u64,
    out_commit: *mut u8,
) -> i32 {
    if bytes.is_null() || out_value.is_null() || out_commit.is_null() {
        set_err("null pointer");
        return -1;
    }
    let slice = unsafe { std::slice::from_raw_parts(bytes, len) };
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
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_mldsa_roundtrip() {
        let mut seed = [0u8; 32];
        assert_eq!(unsafe { litc_random_seed(seed.as_mut_ptr()) }, 0);

        // Key pair
        let mut pk = [0u8; mldsa::PK_LEN];
        let mut sk = [0u8; mldsa::SEED_LEN];
        assert_eq!(
            unsafe { litc_mldsa_keypair(seed.as_ptr(), pk.as_mut_ptr(), sk.as_mut_ptr()) },
            0
        );

        // Address
        let mut addr: *mut c_char = ptr::null_mut();
        assert_eq!(
            unsafe { litc_mldsa_address(seed.as_ptr(), 0, 0, &mut addr) },
            0
        );
        let addr_cstr = unsafe { CString::from_raw(addr) };

        // Parse address
        let mut hash = [0u8; 20];
        let mut tn = 0u8;
        assert_eq!(
            unsafe { litc_parse_address(addr_cstr.as_ptr(), hash.as_mut_ptr(), &mut tn,) },
            0
        );
        assert_eq!(tn, 0);

        // Sign + verify
        let msg = [0xdeu8; 32];
        let mut sig = vec![0u8; mldsa::SIG_LEN];
        let mut sig_len = 0usize;
        assert_eq!(
            unsafe {
                litc_mldsa_sign(
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
        assert_eq!(sig_len, mldsa::SIG_LEN);
        assert_eq!(
            unsafe { litc_mldsa_verify(pk.as_ptr(), msg.as_ptr(), sig.as_ptr(), sig_len) },
            1
        );
        // Wrong message must fail.
        let bad = [0u8; 32];
        assert_eq!(
            unsafe { litc_mldsa_verify(pk.as_ptr(), bad.as_ptr(), sig.as_ptr(), sig_len) },
            0
        );
    }
}
