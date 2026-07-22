//! LiTC key storage. Today: `FileKeyStore`, a flat file holding the wallet's
//! 32-byte master seed. Hardware backends (Ledger, Trezor) can implement the
//! same `KeyStore` trait later without touching the wallet.
//!
//! Entropy sources: `/dev/urandom` (Unix) or a hash-based PRNG fallback (other
//! platforms).

use std::fs;
use std::path::PathBuf;

/// A store for the wallet's master seed.
pub trait KeyStore {
    /// Load the stored seed.
    fn load_seed(&self) -> Result<[u8; 32], String>;
    /// Persist the seed.
    fn save_seed(&self, seed: &[u8; 32]) -> Result<(), String>;
    /// Whether a seed is already stored.
    fn exists(&self) -> bool;
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
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
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
