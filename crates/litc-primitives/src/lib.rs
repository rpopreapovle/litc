//! LiTC core primitive types and binary serialization.
//!
//! One binary format rules everything: objects here are encoded the same way
//! for hashing, local RPC, and P2P. Integers are little-endian; lengths use a
//! Bitcoin-style compact varint.

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Binary serialization
// ---------------------------------------------------------------------------

/// Anything that can be written to the canonical LiTC byte stream.
pub trait Encodable {
    fn encode(&self, w: &mut Vec<u8>);
}

/// Anything that can be read back from the canonical LiTC byte stream.
pub trait Decodable: Sized {
    fn decode(r: &mut Reader) -> Result<Self, String>;
}

/// Cursor over a byte slice with the helpers used by `Decodable`.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn read(&mut self, n: usize) -> Result<&'a [u8], String> {
        // Use checked arithmetic: a malicious length prefix (e.g. a 0xFF
        // varint) could otherwise overflow `pos + n`, panicking the decoder
        // thread when reached over the network.
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| "length prefix overflow".to_string())?;
        if end > self.buf.len() {
            return Err(format!(
                "unexpected EOF: need {n}, have {}",
                self.remaining()
            ));
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub fn read_u8(&mut self) -> Result<u8, String> {
        Ok(self.read(1)?[0])
    }

    pub fn read_u16(&mut self) -> Result<u16, String> {
        let b = self.read(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn read_u32(&mut self) -> Result<u32, String> {
        let b = self.read(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn read_u64(&mut self) -> Result<u64, String> {
        let b = self.read(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn read_i64(&mut self) -> Result<i64, String> {
        Ok(self.read_u64()? as i64)
    }

    pub fn read_varint(&mut self) -> Result<usize, String> {
        let tag = self.read_u8()?;
        match tag {
            0xFD => Ok(self.read_u16()? as usize),
            0xFE => Ok(self.read_u32()? as usize),
            0xFF => {
                let v = self.read_u64()?;
                Ok(v as usize)
            }
            n => Ok(n as usize),
        }
    }

    pub fn read_bytes(&mut self) -> Result<Vec<u8>, String> {
        let n = self.read_varint()?;
        Ok(self.read(n)?.to_vec())
    }

    pub fn read_string(&mut self) -> Result<String, String> {
        let b = self.read_bytes()?;
        String::from_utf8(b).map_err(|_| "invalid utf8".into())
    }
}

/// Write a compact length prefix (Bitcoin-style varint).
pub fn write_varint(w: &mut Vec<u8>, n: usize) {
    if n < 0xFD {
        w.push(n as u8);
    } else if n <= 0xFFFF {
        w.push(0xFD);
        w.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xFFFF_FFFF {
        w.push(0xFE);
        w.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        w.push(0xFF);
        w.extend_from_slice(&(n as u64).to_le_bytes());
    }
}

impl Encodable for u8 {
    fn encode(&self, w: &mut Vec<u8>) {
        w.push(*self);
    }
}
impl Encodable for u16 {
    fn encode(&self, w: &mut Vec<u8>) {
        w.extend_from_slice(&self.to_le_bytes());
    }
}
impl Encodable for u32 {
    fn encode(&self, w: &mut Vec<u8>) {
        w.extend_from_slice(&self.to_le_bytes());
    }
}
impl Encodable for u64 {
    fn encode(&self, w: &mut Vec<u8>) {
        w.extend_from_slice(&self.to_le_bytes());
    }
}
impl Encodable for i64 {
    fn encode(&self, w: &mut Vec<u8>) {
        w.extend_from_slice(&self.to_le_bytes());
    }
}
impl Encodable for String {
    fn encode(&self, w: &mut Vec<u8>) {
        self.as_bytes().to_vec().encode(w);
    }
}
impl<T: Encodable> Encodable for Vec<T> {
    fn encode(&self, w: &mut Vec<u8>) {
        write_varint(w, self.len());
        for x in self {
            x.encode(w);
        }
    }
}
impl<T: Encodable> Encodable for Option<T> {
    fn encode(&self, w: &mut Vec<u8>) {
        match self {
            None => w.push(0),
            Some(x) => {
                w.push(1);
                x.encode(w);
            }
        }
    }
}

impl Decodable for u8 {
    fn decode(r: &mut Reader) -> Result<Self, String> {
        r.read_u8()
    }
}
impl Decodable for u16 {
    fn decode(r: &mut Reader) -> Result<Self, String> {
        r.read_u16()
    }
}
impl Decodable for u32 {
    fn decode(r: &mut Reader) -> Result<Self, String> {
        r.read_u32()
    }
}
impl Decodable for u64 {
    fn decode(r: &mut Reader) -> Result<Self, String> {
        r.read_u64()
    }
}
impl Decodable for i64 {
    fn decode(r: &mut Reader) -> Result<Self, String> {
        r.read_i64()
    }
}
impl Decodable for String {
    fn decode(r: &mut Reader) -> Result<Self, String> {
        r.read_string()
    }
}
impl<T: Decodable> Decodable for Vec<T> {
    fn decode(r: &mut Reader) -> Result<Self, String> {
        let n = r.read_varint()?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(T::decode(r)?);
        }
        Ok(out)
    }
}
impl<T: Decodable> Decodable for Option<T> {
    fn decode(r: &mut Reader) -> Result<Self, String> {
        match r.read_u8()? {
            0 => Ok(None),
            _ => Ok(Some(T::decode(r)?)),
        }
    }
}

/// Encode any `Encodable` into an owned vector.
pub fn to_bytes<T: Encodable>(v: &T) -> Vec<u8> {
    let mut w = Vec::new();
    v.encode(&mut w);
    w
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// A 32-byte hash (SHA-256d output, stored as raw bytes).
#[derive(Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Hash32(pub [u8; 32]);

impl core::fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl Encodable for Hash32 {
    fn encode(&self, w: &mut Vec<u8>) {
        w.extend_from_slice(&self.0);
    }
}
impl Decodable for Hash32 {
    fn decode(r: &mut Reader) -> Result<Self, String> {
        let b = r.read(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        Ok(Hash32(a))
    }
}

/// SHA-256d: SHA-256 of SHA-256. The LiTC internal digest for merkle roots,
/// block IDs, and PoW base.
pub fn sha256d(data: &[u8]) -> Hash32 {
    let h1 = Sha256::digest(data);
    let h2 = Sha256::digest(h1);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h2);
    Hash32(out)
}

impl Hash32 {
    /// Hex string, low nibble first (Bitcoin byte order).
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in &self.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

// ---------------------------------------------------------------------------
// Amount
// ---------------------------------------------------------------------------

/// Satoshi-like integer amount. 1 LIT = 100_000_000 units.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Debug)]
pub struct Amount(pub u64);

impl Encodable for Amount {
    fn encode(&self, w: &mut Vec<u8>) {
        self.0.encode(w);
    }
}
impl Decodable for Amount {
    fn decode(r: &mut Reader) -> Result<Self, String> {
        Ok(Amount(u64::decode(r)?))
    }
}

pub const COIN: u64 = 100_000_000;

// ---------------------------------------------------------------------------
// Transactions
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct OutPoint {
    pub txid: Hash32,
    pub index: u32,
}

/// Signature scheme used to authorize a transaction input. `Mldsa2` (ML-DSA-2,
/// NIST FIPS 204) is the active scheme; reserved values leave room for future
/// post-quantum schemes without a chain-wide flag day.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum SignatureScheme {
    /// ML-DSA-2 (Dilithium, FIPS 204) — the launch scheme.
    Mldsa2 = 0,
    /// Reserved for a future scheme.
    Reserved1 = 1,
    /// Reserved for a future scheme.
    Reserved2 = 2,
    /// Reserved for a future scheme.
    Reserved3 = 3,
    /// Any scheme id not recognized by this implementation.
    Unknown = 255,
}

impl SignatureScheme {
    pub fn from_u8(b: u8) -> Self {
        match b {
            0 => SignatureScheme::Mldsa2,
            1 => SignatureScheme::Reserved1,
            2 => SignatureScheme::Reserved2,
            3 => SignatureScheme::Reserved3,
            _ => SignatureScheme::Unknown,
        }
    }
    pub fn to_u8(self) -> u8 {
        self as u8
    }
    /// Whether this scheme is accepted by the validator.
    pub fn is_active(self) -> bool {
        self == SignatureScheme::Mldsa2
    }
}

impl Encodable for SignatureScheme {
    fn encode(&self, w: &mut Vec<u8>) {
        self.to_u8().encode(w);
    }
}
impl Decodable for SignatureScheme {
    fn decode(r: &mut Reader) -> Result<Self, String> {
        Ok(SignatureScheme::from_u8(u8::decode(r)?))
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TxIn {
    pub prevout: OutPoint,
    pub scheme: SignatureScheme,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TxOut {
    pub value: Amount,
    pub script_pubkey: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
}

impl Encodable for OutPoint {
    fn encode(&self, w: &mut Vec<u8>) {
        self.txid.encode(w);
        self.index.encode(w);
    }
}
impl Decodable for OutPoint {
    fn decode(r: &mut Reader) -> Result<Self, String> {
        Ok(OutPoint {
            txid: Hash32::decode(r)?,
            index: u32::decode(r)?,
        })
    }
}
impl Encodable for TxIn {
    fn encode(&self, w: &mut Vec<u8>) {
        self.prevout.encode(w);
        self.scheme.encode(w);
        self.script_sig.encode(w);
        self.sequence.encode(w);
    }
}
impl Decodable for TxIn {
    fn decode(r: &mut Reader) -> Result<Self, String> {
        Ok(TxIn {
            prevout: OutPoint::decode(r)?,
            scheme: SignatureScheme::decode(r)?,
            script_sig: Vec::<u8>::decode(r)?,
            sequence: u32::decode(r)?,
        })
    }
}
impl Encodable for TxOut {
    fn encode(&self, w: &mut Vec<u8>) {
        self.value.encode(w);
        self.script_pubkey.encode(w);
    }
}
impl Decodable for TxOut {
    fn decode(r: &mut Reader) -> Result<Self, String> {
        Ok(TxOut {
            value: Amount::decode(r)?,
            script_pubkey: Vec::<u8>::decode(r)?,
        })
    }
}
impl Encodable for Transaction {
    fn encode(&self, w: &mut Vec<u8>) {
        self.version.encode(w);
        self.inputs.encode(w);
        self.outputs.encode(w);
        self.lock_time.encode(w);
    }
}
impl Decodable for Transaction {
    fn decode(r: &mut Reader) -> Result<Self, String> {
        Ok(Transaction {
            version: u32::decode(r)?,
            inputs: Vec::<TxIn>::decode(r)?,
            outputs: Vec::<TxOut>::decode(r)?,
            lock_time: u32::decode(r)?,
        })
    }
}

impl Transaction {
    /// Txid = SHA-256d of the serialized transaction.
    pub fn txid(&self) -> Hash32 {
        sha256d(&to_bytes(self))
    }
}

// ---------------------------------------------------------------------------
// Blocks
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BlockHeader {
    pub version: u32,
    pub prev_block: Hash32,
    pub merkle_root: Hash32,
    /// Root committing to the full live consensus state (UTXO set) after
    /// this block is applied. See `docs/state.md`. Lets a node bootstrap
    /// from a snapshot without trusting developers, peers, or hardcoded
    /// checkpoints — only the Proof-of-Work securing the header.
    pub state_root: Hash32,
    pub timestamp: u64,
    pub height: u64,
    pub epoch_seed: Hash32,
    pub nonce: u64,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<Transaction>,
}

impl Encodable for BlockHeader {
    fn encode(&self, w: &mut Vec<u8>) {
        self.version.encode(w);
        self.prev_block.encode(w);
        self.merkle_root.encode(w);
        self.state_root.encode(w);
        self.timestamp.encode(w);
        self.height.encode(w);
        self.epoch_seed.encode(w);
        self.nonce.encode(w);
    }
}
impl Decodable for BlockHeader {
    fn decode(r: &mut Reader) -> Result<Self, String> {
        Ok(BlockHeader {
            version: u32::decode(r)?,
            prev_block: Hash32::decode(r)?,
            merkle_root: Hash32::decode(r)?,
            state_root: Hash32::decode(r)?,
            timestamp: u64::decode(r)?,
            height: u64::decode(r)?,
            epoch_seed: Hash32::decode(r)?,
            nonce: u64::decode(r)?,
        })
    }
}
impl Encodable for Block {
    fn encode(&self, w: &mut Vec<u8>) {
        self.header.encode(w);
        self.txs.encode(w);
    }
}
impl Decodable for Block {
    fn decode(r: &mut Reader) -> Result<Self, String> {
        Ok(Block {
            header: BlockHeader::decode(r)?,
            txs: Vec::<Transaction>::decode(r)?,
        })
    }
}

impl BlockHeader {
    /// Block hash = SHA-256d of the serialized header.
    pub fn hash(&self) -> Hash32 {
        sha256d(&to_bytes(self))
    }
}

impl Block {
    /// Recompute and stamp the merkle root from the current tx set.
    pub fn recompute_merkle(&mut self) {
        self.header.merkle_root = merkle_root(&self.txs);
    }

    pub fn block_hash(&self) -> Hash32 {
        self.header.hash()
    }
}

// ---------------------------------------------------------------------------
// Merkle tree
// ---------------------------------------------------------------------------

/// Bitcoin-style merkle root over transaction ids. Duplicates the last leaf
/// when the level has an odd number of nodes.
pub fn merkle_root(txs: &[Transaction]) -> Hash32 {
    if txs.is_empty() {
        return Hash32([0u8; 32]);
    }
    let mut level: Vec<Hash32> = txs.iter().map(|t| t.txid()).collect();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&pair[0].0);
            buf[32..].copy_from_slice(&pair[1].0);
            next.push(sha256d(&buf));
        }
        level = next;
    }
    level[0]
}

// ---------------------------------------------------------------------------
// RIPEMD-160 (for HASH160) + base58check
// ---------------------------------------------------------------------------

use ripemd::Ripemd160;

/// HASH160 = RIPEMD-160(SHA-256(x)) — the 20-byte value committed by an
/// address and by a `script_pubkey`.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let rip = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&rip);
    out
}

const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode bytes in Bitcoin-style base58 (leading zero bytes become '1').
pub fn base58_encode(input: &[u8]) -> String {
    let zeros = input.iter().take_while(|&&b| b == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &byte in input {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut s = String::new();
    for _ in 0..zeros {
        s.push('1');
    }
    for &d in digits.iter().rev() {
        s.push(BASE58_ALPHABET[d as usize] as char);
    }
    s
}

/// Decode a base58 string back to bytes. Returns `None` on invalid symbol.
pub fn base58_decode(s: &str) -> Option<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::new();
    for c in s.chars() {
        let val = BASE58_ALPHABET.iter().position(|&b| b as char == c)? as u32;
        let mut carry = val;
        for b in bytes.iter_mut() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let zeros = s.chars().take_while(|&c| c == '1').count();
    let mut out = vec![0u8; zeros];
    out.extend(bytes.iter().rev());
    Some(out)
}

/// base58check: `version` byte + `payload`, with a 4-byte SHA-256d checksum.
pub fn base58check_encode(version: u8, payload: &[u8]) -> String {
    let mut body = Vec::with_capacity(payload.len() + 1);
    body.push(version);
    body.extend_from_slice(payload);
    let checksum = &sha256d(&body).0[..4];
    let mut full = body;
    full.extend_from_slice(checksum);
    base58_encode(&full)
}

/// Decode base58check, verifying the checksum and returning `(version, payload)`.
pub fn base58check_decode(s: &str) -> Option<(u8, Vec<u8>)> {
    let full = base58_decode(s)?;
    if full.len() < 5 {
        return None;
    }
    let (body, checksum) = full.split_at(full.len() - 4);
    if &sha256d(body).0[..4] != checksum {
        return None;
    }
    Some((body[0], body[1..].to_vec()))
}

// ---------------------------------------------------------------------------
// Bech32m (BIP350) — lowercase, checksummed, copy-friendly encoding. Used for
// ML-DSA-2 addresses: bech32m("litc", version || HASH160(pk)) → ~40 chars.
// ---------------------------------------------------------------------------

const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn bech32_polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ (v as u32);
        for (i, g) in [0x3b6a57, 0x26508e, 0x1ea119, 0x3d4233, 0x2a1462]
            .iter()
            .enumerate()
        {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn bech32m_hrp_expand(hrp: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(hrp.len() * 2 + 1);
    for &b in hrp {
        out.push(b >> 5);
    }
    out.push(0);
    for &b in hrp {
        out.push(b & 0x1f);
    }
    out
}

fn bech32m_checksum(hrp: &[u8], data: &[u8]) -> Vec<u8> {
    let mut values = bech32m_hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    let polymod = bech32_polymod(&values) ^ 0x2bc830a3;
    (0..6)
        .map(|i| ((polymod >> (5 * (5 - i))) & 0x1f) as u8)
        .collect()
}

/// Convert `data` between bit groups. `pad = true` appends a final partial
/// group; `pad = false` errors if leftover bits are non-zero.
fn convertbits(data: &[u8], frombits: u32, tobits: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    let maxv: u32 = (1 << tobits) - 1;
    for &b in data {
        acc = (acc << frombits) | (b as u32);
        bits += frombits;
        while bits >= tobits {
            bits -= tobits;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (tobits - bits)) & maxv) as u8);
        }
    } else if bits >= frombits || ((acc << (tobits - bits)) & maxv) != 0 {
        return None;
    }
    Some(out)
}

/// Encode `payload` (raw bytes) as a Bech32m string with the given HRP.
pub fn bech32m_encode(hrp: &str, payload: &[u8]) -> String {
    let data = convertbits(payload, 8, 5, true).unwrap_or_default();
    let checksum = bech32m_checksum(hrp.as_bytes(), &data);
    let mut s = hrp.to_ascii_lowercase();
    s.push('1');
    for b in data.iter().chain(checksum.iter()) {
        s.push(BECH32_CHARSET[*b as usize] as char);
    }
    s
}

/// Decode a Bech32m string, returning `(hrp, payload_bytes)`. `None` on any
/// format or checksum error (including mixed case).
pub fn bech32m_decode(s: &str) -> Option<(String, Vec<u8>)> {
    if s.chars().any(|c| c.is_uppercase()) && s.chars().any(|c| c.is_lowercase()) {
        return None;
    }
    let lower = s.to_ascii_lowercase();
    let pos = lower.rfind('1')?;
    if pos == 0 || pos + 7 > lower.len() {
        return None;
    }
    let hrp = &lower[..pos];
    let data_part = &lower[pos + 1..];
    if data_part.len() < 6 {
        return None;
    }
    let mut data = Vec::with_capacity(data_part.len());
    for c in data_part.chars() {
        let idx = BECH32_CHARSET.iter().position(|b| *b == c as u8)?;
        data.push(idx as u8);
    }
    let checksum = &data[data.len() - 6..];
    let mut values = bech32m_hrp_expand(hrp.as_bytes());
    values.extend_from_slice(&data[..data.len() - 6]);
    values.extend_from_slice(checksum);
    if bech32_polymod(&values) != 0x2bc830a3 {
        return None;
    }
    let payload = convertbits(&data[..data.len() - 6], 5, 8, false)?;
    Some((hrp.to_string(), payload))
}

// ---------------------------------------------------------------------------
// ML-DSA-2 (post-quantum, reusable signatures)
// ---------------------------------------------------------------------------

pub mod mldsa;

/// Network-wide consensus constants that a node must agree on with its peers.
/// These are *not* negotiated on the wire; a mismatch means you are on a
/// different network (e.g. testnet vs mainnet).
pub mod chainparams {
    use crate::Hash32;

    /// Which LiTC network a node participates in. Selects the wire magic,
    /// emission schedule, and checkpoint set.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Network {
        Mainnet,
        Testnet,
    }

    impl Network {
        pub fn as_str(&self) -> &'static str {
            match self {
                Network::Mainnet => "mainnet",
                Network::Testnet => "testnet",
            }
        }

    }

    impl std::str::FromStr for Network {
        type Err = String;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s.to_ascii_lowercase().as_str() {
                "mainnet" => Ok(Network::Mainnet),
                "testnet" => Ok(Network::Testnet),
                _ => Err(format!("unknown network: {s}")),
            }
        }
    }

    /// Consensus constants and the checkpoint set for one network.
    #[derive(Debug, Clone)]
    pub struct ChainParams {
        pub network: Network,
        /// 4-byte wire magic prefix used by `litc-wire` framing.
        pub magic: [u8; 4],
        /// Blocks between subsidy halvings. Testnet compresses mainnet's
        /// 8,400,000 to 10,000 so emission is observable quickly.
        pub halving_interval: u64,
        /// Genesis block hash. For testnet this is pinned to whatever the first
        /// seed node mines at network launch (set once, then treated as fixed).
        /// For mainnet it is a hard-coded, pre-mined value.
        pub genesis_hash: Option<[u8; 32]>,
        /// Height -> block-hash checkpoints. A block at a checkpoint height MUST
        /// carry the checkpoint hash; this irreversibly finalizes history at and
        /// below the checkpoint and bounds the trust placed in a fast-sync
        /// snapshot (see `docs/state.md`).
        pub checkpoints: Vec<(u64, [u8; 32])>,
    }

    impl ChainParams {
        /// Testnet parameters. `magic` is `L1TC`; emission is compressed
        /// (`halving_interval = 10_000`). The genesis hash and checkpoint list
        /// are empty until the testnet is launched and its first blocks are
        /// pinned (see `docs/roadmap.md`).
        pub fn testnet() -> Self {
            ChainParams {
                network: Network::Testnet,
                magic: *b"L1TC",
                halving_interval: 10_000,
                genesis_hash: None,
                checkpoints: Vec::new(),
            }
        }

        /// Mainnet parameters. `magic` is `L1TM`; full 8,400,000-block halving.
        pub fn mainnet() -> Self {
            ChainParams {
                network: Network::Mainnet,
                magic: *b"L1TM",
                halving_interval: 8_400_000,
                genesis_hash: None,
                checkpoints: Vec::new(),
            }
        }

        /// The required hash at `height`, if `height` is a checkpoint.
        pub fn checkpoint_hash(&self, height: u64) -> Option<Hash32> {
            self.checkpoints
                .iter()
                .find(|(h, _)| *h == height)
                .map(|(_, hash)| Hash32(*hash))
        }

        /// Height of the highest configured checkpoint, if any.
        pub fn last_checkpoint_height(&self) -> Option<u64> {
            self.checkpoints.iter().map(|(h, _)| *h).max()
        }

        /// The checkpoint hash that must be an ancestor of (or equal to) a tip
        /// at `tip_height`, i.e. the highest checkpoint at or below `tip_height`.
        pub fn checkpoint_at_or_below(&self, tip_height: u64) -> Option<Hash32> {
            self.checkpoints
                .iter()
                .filter(|(h, _)| *h <= tip_height)
                .max_by_key(|(h, _)| *h)
                .map(|(_, hash)| Hash32(*hash))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ripemd::Ripemd160;

    #[test]
    fn varint_roundtrip() {
        for n in [0usize, 0xFC, 0xFD, 0xFFFF, 0x10000, 0xFFFF_FFFF] {
            let mut w = Vec::new();
            write_varint(&mut w, n);
            let mut r = Reader::new(&w);
            assert_eq!(r.read_varint().unwrap(), n);
        }
    }

    #[test]
    fn sha256d_empty() {
        // Double SHA-256 of the empty string.
        assert_eq!(
            sha256d(b"").to_hex(),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
    }

    #[test]
    fn ripemd160_empty() {
        let h = Ripemd160::digest(b"");
        assert_eq!(
            &h[..],
            &[
                0x9c, 0x11, 0x85, 0xa5, 0xc5, 0xe9, 0xfc, 0x54, 0x61, 0x28, 0x08, 0x97, 0x7e, 0xe8,
                0xf5, 0x48, 0xb2, 0x25, 0x8d, 0x31
            ]
        );
    }

    #[test]
    fn base58_roundtrip() {
        let data = [0u8, 0, 1, 2, 3, 255, 16, 32];
        let s = base58_encode(&data);
        let back = base58_decode(&s).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn base58check_roundtrip() {
        let payload = [0xabu8; 20];
        let s = base58check_encode(0x30, &payload);
        let (v, p) = base58check_decode(&s).unwrap();
        assert_eq!(v, 0x30);
        assert_eq!(p, payload);
        // Tampered checksum must fail.
        let mut chars: Vec<char> = s.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '1' { '2' } else { '1' };
        let bad: String = chars.into_iter().collect();
        assert!(base58check_decode(&bad).is_none());
    }

    #[test]
    fn bech32m_roundtrip() {
        // 800-byte payload like a KEM public key, prefixed with a version byte.
        let mut payload = vec![0x31u8];
        payload.extend_from_slice(&[0x42u8; 800]);
        let s = bech32m_encode("litc", &payload);
        assert!(s.starts_with("litc1"));
        assert!(s.chars().all(|c| !c.is_uppercase()));
        let (hrp, back) = bech32m_decode(&s).unwrap();
        assert_eq!(hrp, "litc");
        assert_eq!(back, payload);
        // Tampered character breaks the checksum.
        let mut chars: Vec<char> = s.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'p' { 'q' } else { 'p' };
        let bad: String = chars.into_iter().collect();
        assert!(bech32m_decode(&bad).is_none());
        // Mixed case is invalid.
        let mixed = s[..5].to_uppercase() + &s[5..];
        assert!(bech32m_decode(&mixed).is_none());
    }

    #[test]
    fn encode_decode_transaction() {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prevout: OutPoint {
                    txid: Hash32([7u8; 32]),
                    index: 3,
                },
                scheme: SignatureScheme::Mldsa2,
                script_sig: vec![1, 2, 3, 4],
                sequence: 0xFFFF_FFFF,
            }],
            outputs: vec![TxOut {
                value: Amount(50 * COIN),
                script_pubkey: vec![0x76, 0xa9],
            }],
            lock_time: 0,
        };
        let bytes = to_bytes(&tx);
        let mut r = Reader::new(&bytes);
        let back = Transaction::decode(&mut r).unwrap();
        assert_eq!(tx, back);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn merkle_single_and_pair() {
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
        };
        // Single tx -> merkle root equals its txid.
        assert_eq!(merkle_root(std::slice::from_ref(&tx)), tx.txid());

        let mut tx2 = tx.clone();
        tx2.lock_time = 1;
        let root = merkle_root(&[tx.clone(), tx2.clone()]);
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&tx.txid().0);
        buf[32..].copy_from_slice(&tx2.txid().0);
        assert_eq!(root, sha256d(&buf));
    }

    #[test]
    fn block_hash_deterministic() {
        let mut block = Block {
            header: BlockHeader {
                version: 1,
                prev_block: Hash32([1u8; 32]),
                merkle_root: Hash32([2u8; 32]),
                state_root: Hash32([4u8; 32]),
                timestamp: 1_700_000_000,
                height: 42,
                epoch_seed: Hash32([3u8; 32]),
                nonce: 999,
            },
            txs: vec![],
        };
        block.recompute_merkle();
        let h1 = block.block_hash();
        let h2 = block.block_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn mldsa_sign_verify() {
        let kp = mldsa::MlDsaKeypair::derive(&[0x42u8; 32], 0);
        let msg = [0xdeu8; 32];
        let sig = kp.sign(&msg);
        assert!(mldsa::MlDsaKeypair::verify(&kp.public_key_bytes(), &msg, &sig));
        // Wrong message must fail.
        let bad = [0x00u8; 32];
        assert!(!mldsa::MlDsaKeypair::verify(&kp.public_key_bytes(), &bad, &sig));
    }

    #[test]
    fn mldsa_derive_deterministic() {
        let a = mldsa::MlDsaKeypair::derive(&[0x11u8; 32], 7);
        let b = mldsa::MlDsaKeypair::derive(&[0x11u8; 32], 7);
        assert_eq!(a.public_key_bytes(), b.public_key_bytes());
        let c = mldsa::MlDsaKeypair::derive(&[0x11u8; 32], 8);
        assert_ne!(a.public_key_bytes(), c.public_key_bytes());
    }

    #[test]
    fn mldsa_address_roundtrip() {
        let kp = mldsa::MlDsaKeypair::derive(&[0x99u8; 32], 0);
        let addr = kp.address(mldsa::MAINNET_VERSION);
        assert!(addr.starts_with("litc1"));
        let (v, hash) = mldsa::parse_address(&addr).unwrap();
        assert_eq!(v, mldsa::MAINNET_VERSION);
        assert_eq!(hash, kp.pubkey_hash160());
    }

    #[test]
    fn mldsa_signature_encoding_roundtrip() {
        let kp = mldsa::MlDsaKeypair::derive(&[0x55u8; 32], 0);
        let msg = [0xaau8; 32];
        let sig = kp.sign(&msg);
        // Signature is just raw bytes; verify still works.
        assert!(mldsa::MlDsaKeypair::verify(&kp.public_key_bytes(), &msg, &sig));
    }

    #[test]
    fn chainparams_networks_differ() {
        let t = chainparams::ChainParams::testnet();
        let m = chainparams::ChainParams::mainnet();
        assert_eq!(t.network, chainparams::Network::Testnet);
        assert_eq!(m.network, chainparams::Network::Mainnet);
        assert_ne!(t.magic, m.magic);
        assert_eq!(t.halving_interval, 10_000);
        assert_eq!(m.halving_interval, 8_400_000);
        assert_eq!(t.network.as_str(), "testnet");
        assert_eq!("MAINNET".parse::<chainparams::Network>(), Ok(chainparams::Network::Mainnet));
        assert_eq!("nope".parse::<chainparams::Network>(), Err("unknown network: nope".to_string()));
    }

    #[test]
    fn chainparams_checkpoints() {
        let mut p = chainparams::ChainParams::testnet();
        p.checkpoints = vec![
            (100, [9u8; 32]),
            (1_000, [7u8; 32]),
            (10_000, [3u8; 32]),
        ];
        assert_eq!(p.checkpoint_hash(100), Some(Hash32([9u8; 32])));
        assert_eq!(p.checkpoint_hash(101), None);
        assert_eq!(p.last_checkpoint_height(), Some(10_000));
        // Tip at 5_000 must descend from the checkpoint at height 1_000.
        assert_eq!(p.checkpoint_at_or_below(5_000), Some(Hash32([7u8; 32])));
        assert_eq!(p.checkpoint_at_or_below(99), None);
    }
}
