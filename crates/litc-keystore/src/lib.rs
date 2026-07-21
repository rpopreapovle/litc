//! LiTC key storage. Today: `FileKeyStore`, a flat file holding the wallet's
//! 32-byte master seed. Hardware backends (Ledger, Trezor) can implement the
//! same `KeyStore` trait later without touching the wallet.
//!
//! Entropy sources: `/dev/urandom` (Unix) or a hash-based PRNG fallback (other
//! platforms).

use std::fs;
use std::path::PathBuf;

/// A one-time WOTS+ spend key recovered by scanning the chain for a stealth
/// payment. Persisted by the wallet so owned outputs are remembered across
/// restarts without rescanning.
#[derive(Clone)]
pub struct StealthKey {
    pub commit: [u8; 20],
    pub sk_seed: [u8; 32],
    pub pk_seed: [u8; 32],
    pub r: [u8; 32],
}

impl StealthKey {
    /// Fixed on-disk record size: commit + sk_seed + pk_seed + r.
    pub const RECORD_LEN: usize = 20 + 32 + 32 + 32;
}

/// A store for the wallet's master seed.
pub trait KeyStore {
    /// Load the stored seed.
    fn load_seed(&self) -> Result<[u8; 32], String>;
    /// Persist the seed.
    fn save_seed(&self, seed: &[u8; 32]) -> Result<(), String>;
    /// Whether a seed is already stored.
    fn exists(&self) -> bool;
    /// Load the recovered one-time stealth spend keys.
    fn load_stealth(&self) -> Result<Vec<StealthKey>, String>;
    /// Persist the recovered one-time stealth spend keys (replaces all).
    fn save_stealth(&self, keys: &[StealthKey]) -> Result<(), String>;
    /// Load the 20-byte WOTS+ commitments this wallet has already signed a
    /// spend for. WOTS+ keys are one-time: reusing one leaks the secret, so the
    /// wallet must never sign the same commitment twice — even for an
    /// unconfirmed transaction. See `docs/wots.md`.
    fn load_used(&self) -> Result<Vec<[u8; 20]>, String>;
    /// Persist the spent WOTS+ commitments (replaces all).
    fn save_used(&self, used: &[[u8; 20]]) -> Result<(), String>;
}

/// Flat-file key store at `path`. The seed is stored as raw 32 bytes.
pub struct FileKeyStore {
    path: PathBuf,
}

impl FileKeyStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        FileKeyStore { path: path.into() }
    }

    /// Load the existing seed, or create a fresh one (from `/dev/urandom`) and
    /// save it. Used by the node/wallet on first start.
    pub fn open_or_create(&self) -> Result<[u8; 32], String> {
        if self.path.exists() {
            self.load_seed()
        } else {
            let seed = random_seed()?;
            self.save_seed(&seed)?;
            Ok(seed)
        }
    }
}

impl KeyStore for FileKeyStore {
    fn load_seed(&self) -> Result<[u8; 32], String> {
        let bytes = fs::read(&self.path).map_err(|e| format!("cannot read keystore: {e}"))?;
        if bytes.len() != 32 {
            return Err("keystore file is not 32 bytes".into());
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(seed)
    }

    fn save_seed(&self, seed: &[u8; 32]) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("cannot create dir: {e}"))?;
        }
        fs::write(&self.path, seed).map_err(|e| format!("cannot write keystore: {e}"))
    }

    fn exists(&self) -> bool {
        self.path.exists()
    }

    fn load_stealth(&self) -> Result<Vec<StealthKey>, String> {
        let path = self.path.with_extension("stealth");
        if !path.exists() {
            return Ok(vec![]);
        }
        let bytes = fs::read(&path).map_err(|e| format!("cannot read stealth store: {e}"))?;
        if bytes.len() % StealthKey::RECORD_LEN != 0 {
            return Err("corrupt stealth store".into());
        }
        let mut out = Vec::with_capacity(bytes.len() / StealthKey::RECORD_LEN);
        for chunk in bytes.chunks(StealthKey::RECORD_LEN) {
            let mut commit = [0u8; 20];
            commit.copy_from_slice(&chunk[..20]);
            let mut sk_seed = [0u8; 32];
            sk_seed.copy_from_slice(&chunk[20..52]);
            let mut pk_seed = [0u8; 32];
            pk_seed.copy_from_slice(&chunk[52..84]);
            let mut r = [0u8; 32];
            r.copy_from_slice(&chunk[84..116]);
            out.push(StealthKey {
                commit,
                sk_seed,
                pk_seed,
                r,
            });
        }
        Ok(out)
    }

    fn save_stealth(&self, keys: &[StealthKey]) -> Result<(), String> {
        let path = self.path.with_extension("stealth");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("cannot create dir: {e}"))?;
        }
        let mut buf = Vec::with_capacity(keys.len() * StealthKey::RECORD_LEN);
        for k in keys {
            buf.extend_from_slice(&k.commit);
            buf.extend_from_slice(&k.sk_seed);
            buf.extend_from_slice(&k.pk_seed);
            buf.extend_from_slice(&k.r);
        }
        fs::write(&path, buf).map_err(|e| format!("cannot write stealth store: {e}"))
    }

    fn load_used(&self) -> Result<Vec<[u8; 20]>, String> {
        let path = self.path.with_extension("used");
        if !path.exists() {
            return Ok(vec![]);
        }
        let bytes = fs::read(&path).map_err(|e| format!("cannot read used store: {e}"))?;
        if bytes.len() % 20 != 0 {
            return Err("corrupt used store".into());
        }
        let mut out = Vec::with_capacity(bytes.len() / 20);
        for chunk in bytes.chunks(20) {
            let mut commit = [0u8; 20];
            commit.copy_from_slice(chunk);
            out.push(commit);
        }
        Ok(out)
    }

    fn save_used(&self, used: &[[u8; 20]]) -> Result<(), String> {
        let path = self.path.with_extension("used");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("cannot create dir: {e}"))?;
        }
        let mut buf = Vec::with_capacity(used.len() * 20);
        for c in used {
            buf.extend_from_slice(c);
        }
        fs::write(&path, buf).map_err(|e| format!("cannot write used store: {e}"))
    }
}

/// Fill a buffer with platform entropy.
#[cfg(unix)]
fn fill_random(buf: &mut [u8]) -> Result<(), String> {
    use std::io::Read;
    let mut f =
        fs::File::open("/dev/urandom").map_err(|e| format!("cannot open /dev/urandom: {e}"))?;
    f.read_exact(buf)
        .map_err(|e| format!("cannot read entropy: {e}"))
}

/// Fill a buffer with a hash-based PRNG seeded from time+PID (non-cryptographic
/// fallback for platforms without /dev/urandom, e.g. Windows).
#[cfg(not(unix))]
fn fill_random(buf: &mut [u8]) -> Result<(), String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let pid = std::process::id();
    let mut state = t.as_nanos() as u64 ^ (pid as u64) << 32;
    for chunk in buf.chunks_mut(8) {
        state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        let n = chunk.len().min(8);
        chunk[..n].copy_from_slice(&state.to_le_bytes()[..n]);
    }
    Ok(())
}

/// Gather 32 bytes of entropy.
pub fn random_seed() -> Result<[u8; 32], String> {
    let mut seed = [0u8; 32];
    fill_random(&mut seed)?;
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn tmp_path() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        std::env::temp_dir().join(format!("litc_ks_test_{pid}_{n}"))
    }

    #[test]
    fn create_then_persist() {
        let path = tmp_path();
        let ks = FileKeyStore::new(&path);
        assert!(!ks.exists());
        let seed = ks.open_or_create().unwrap();
        assert!(ks.exists());
        // Reopen: same seed.
        let ks2 = FileKeyStore::new(&path);
        let seed2 = ks2.open_or_create().unwrap();
        assert_eq!(seed, seed2);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn explicit_save_load() {
        let path = tmp_path();
        let ks = FileKeyStore::new(&path);
        let seed = [0x42u8; 32];
        ks.save_seed(&seed).unwrap();
        assert_eq!(ks.load_seed().unwrap(), seed);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn random_seed_has_entropy() {
        // Two calls should (vanishingly unlikely to) differ.
        let a = random_seed().unwrap();
        let b = random_seed().unwrap();
        assert_ne!(a, b);
    }
}
