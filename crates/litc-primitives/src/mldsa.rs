// ---------------------------------------------------------------------------
// ML-DSA-2 (Dilithium, NIST FIPS 204)
//
// Stateless, reusable post-quantum signatures. The public key is 1312 bytes;
// the signature is ~2420 bytes. Addresses are bech32m("litc", 0x31 || HASH160(pk))
// — ~40 characters.
// ---------------------------------------------------------------------------

use ml_dsa::{MlDsa44, Signer, Verifier, KeyInit, KeyExport, Keypair, Seed, SignatureEncoding};
use sha2::{Digest, Sha256};

use crate::{hash160, bech32m_encode, bech32m_decode};

pub const PK_LEN: usize = 1312;
pub const SIG_LEN: usize = 2420;
pub const SEED_LEN: usize = 32;

pub const MAINNET_VERSION: u8 = 0x31;
pub const TESTNET_VERSION: u8 = 0x70;
const HRP_MAINNET: &str = "litc";
const HRP_TESTNET: &str = "tlitc";

/// ML-DSA-2 keypair (seed-based). The seed is the only secret; the full
/// signing key and verifying key are derived deterministically from it.
pub struct MlDsaKeypair {
    pub seed: [u8; SEED_LEN],
}

impl MlDsaKeypair {
    /// Deterministic derivation from a master seed and an address index.
    pub fn derive(master: &[u8; SEED_LEN], index: u32) -> Self {
        let mut seed = [0u8; SEED_LEN];
        let h = Sha256::digest([master.as_slice(), &index.to_le_bytes()].concat());
        seed.copy_from_slice(&h);
        MlDsaKeypair { seed }
    }

    /// The 32-byte seed (secret key material).
    pub fn secret_bytes(&self) -> [u8; SEED_LEN] {
        self.seed
    }

    /// The full 1312-byte ML-DSA-2 public key.
    pub fn public_key_bytes(&self) -> [u8; PK_LEN] {
        let seed: Seed = self.seed.into();
        let sk = ml_dsa::SigningKey::<MlDsa44>::new(&seed);
        let pk = sk.verifying_key();
        let mut out = [0u8; PK_LEN];
        out.copy_from_slice(&pk.to_bytes());
        out
    }

    /// HASH160 of the public key — the 20-byte commitment stored in UTXO scripts.
    pub fn pubkey_hash160(&self) -> [u8; 20] {
        hash160(&self.public_key_bytes())
    }

    /// Bech32m address: bech32m("litc", version || HASH160(pk)).
    pub fn address(&self, version: u8) -> String {
        let hrp = if version == MAINNET_VERSION {
            HRP_MAINNET
        } else {
            HRP_TESTNET
        };
        let mut payload = Vec::with_capacity(21);
        payload.push(version);
        payload.extend_from_slice(&self.pubkey_hash160());
        bech32m_encode(hrp, &payload)
    }

    /// Sign a 32-byte message (sighash). Returns the signature bytes.
    pub fn sign(&self, msg: &[u8; 32]) -> Vec<u8> {
        let seed: Seed = self.seed.into();
        let sk = ml_dsa::SigningKey::<MlDsa44>::new(&seed);
        let sig = sk.sign(msg);
        sig.to_vec()
    }

    /// Verify a signature against a public key and message.
    pub fn verify(pk_bytes: &[u8; PK_LEN], msg: &[u8; 32], sig_bytes: &[u8]) -> bool {
        let pk = match ml_dsa::VerifyingKey::<MlDsa44>::new_from_slice(pk_bytes) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let sig = match ml_dsa::Signature::<MlDsa44>::try_from(sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };
        pk.verify(msg, &sig).is_ok()
    }
}

/// Parse a bech32m ML-DSA-2 address back into the version byte and
/// HASH160(pk). Returns `None` on invalid address.
pub fn parse_address(s: &str) -> Option<(u8, [u8; 20])> {
    let (_hrp, body) = bech32m_decode(s)?;
    if body.is_empty() {
        return None;
    }
    let v = body[0];
    if v != MAINNET_VERSION && v != TESTNET_VERSION {
        return None;
    }
    if body.len() != 21 {
        return None;
    }
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&body[1..21]);
    Some((v, hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_sign_verify() {
        let master = [1u8; 32];
        let kp = MlDsaKeypair::derive(&master, 0);
        let msg = [0xABu8; 32];
        let sig = kp.sign(&msg);
        assert!(MlDsaKeypair::verify(&kp.public_key_bytes(), &msg, &sig));

        // Wrong message should fail
        let mut wrong_msg = msg;
        wrong_msg[0] ^= 0xFF;
        assert!(!MlDsaKeypair::verify(&kp.public_key_bytes(), &wrong_msg, &sig));
    }

    #[test]
    fn deterministic_derivation() {
        let master = [42u8; 32];
        let kp1 = MlDsaKeypair::derive(&master, 0);
        let kp2 = MlDsaKeypair::derive(&master, 0);
        assert_eq!(kp1.secret_bytes(), kp2.secret_bytes());
        assert_eq!(kp1.public_key_bytes(), kp2.public_key_bytes());

        // Different index → different key
        let kp3 = MlDsaKeypair::derive(&master, 1);
        assert_ne!(kp1.public_key_bytes(), kp3.public_key_bytes());
    }

    #[test]
    fn address_roundtrip() {
        let master = [3u8; 32];
        let kp = MlDsaKeypair::derive(&master, 0);
        let addr = kp.address(MAINNET_VERSION);
        assert!(addr.starts_with("litc1"));

        let (v, hash) = parse_address(&addr).unwrap();
        assert_eq!(v, MAINNET_VERSION);
        assert_eq!(hash, kp.pubkey_hash160());
    }

    #[test]
    fn testnet_address() {
        let master = [4u8; 32];
        let kp = MlDsaKeypair::derive(&master, 0);
        let addr = kp.address(TESTNET_VERSION);
        assert!(addr.starts_with("tlitc1"));
    }
}
