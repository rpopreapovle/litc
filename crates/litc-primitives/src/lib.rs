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

/// Signature scheme used to authorize a transaction input. Only `Wots256` is
/// active today; the reserved values leave room for future post-quantum (or
/// hybrid) schemes without a chain-wide flag day, and `Unknown` rejects
/// anything unrecognized. The scheme is carried per-input so a single
/// transaction may mix schemes once more than one is active.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum SignatureScheme {
    /// WOTS+ with Winternitz parameter w = 256 (the launch scheme).
    Wots256 = 0,
    /// Reserved for a future scheme (e.g. a different WOTS+ parameterization).
    Reserved1 = 1,
    /// Reserved for a future scheme (e.g. a SPHINCS+-style few-time signature).
    Reserved2 = 2,
    /// Reserved for a future scheme (e.g. a hybrid Falcon + WOTS+ construction).
    Reserved3 = 3,
    /// Any scheme id not recognized by this implementation.
    Unknown = 255,
}

impl SignatureScheme {
    pub fn from_u8(b: u8) -> Self {
        match b {
            0 => SignatureScheme::Wots256,
            1 => SignatureScheme::Reserved1,
            2 => SignatureScheme::Reserved2,
            3 => SignatureScheme::Reserved3,
            _ => SignatureScheme::Unknown,
        }
    }
    pub fn to_u8(self) -> u8 {
        self as u8
    }
    /// Whether this scheme is accepted by the validator. Reserved schemes are
    /// not yet active; `Unknown` is never accepted.
    pub fn is_active(self) -> bool {
        self == SignatureScheme::Wots256
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
    /// Stealth-address ciphertext (ML-KEM) for outputs sent to a reusable
    /// address. Empty for ordinary single-use outputs. Carried in the UTXO so
    /// the recipient can scan and recover the one-time WOTS+ spend key.
    pub ephemeral: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    /// Transaction-level KEM ciphertext for aggregated stealth outputs (see
    /// `docs/stealth.md`). When a transaction pays one or more reusable stealth
    /// addresses, the sender encapsulates **once** and attaches the single
    /// ciphertext here; each stealth output derives its one-time WOTS+ key as
    /// `derive(stealth_seed(ss), output_index)`. This avoids repeating the
    /// ~768-byte ciphertext per output. Empty for transactions with no stealth
    /// outputs. The per-output `TxOut.ephemeral` is no longer used.
    pub ephemeral: Vec<u8>,
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
        self.ephemeral.encode(w);
    }
}
impl Decodable for TxOut {
    fn decode(r: &mut Reader) -> Result<Self, String> {
        Ok(TxOut {
            value: Amount::decode(r)?,
            script_pubkey: Vec::<u8>::decode(r)?,
            ephemeral: Vec::<u8>::decode(r)?,
        })
    }
}
impl Encodable for Transaction {
    fn encode(&self, w: &mut Vec<u8>) {
        self.version.encode(w);
        self.inputs.encode(w);
        self.outputs.encode(w);
        self.ephemeral.encode(w);
        self.lock_time.encode(w);
    }
}
impl Decodable for Transaction {
    fn decode(r: &mut Reader) -> Result<Self, String> {
        Ok(Transaction {
            version: u32::decode(r)?,
            inputs: Vec::<TxIn>::decode(r)?,
            outputs: Vec::<TxOut>::decode(r)?,
            ephemeral: Vec::<u8>::decode(r)?,
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
    /// Root committing to the full live consensus state (UTXO set + burnt
    /// keys) after this block is applied. See `docs/state.md`. Lets a node
    /// bootstrap from a snapshot without trusting developers, peers, or
    /// hardcoded checkpoints — only the Proof-of-Work securing the header.
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
// the (large) reusable stealth address so it is at least case-insensitive and
// self-verifying. NOTE: this is *cosmetic* — the 800-byte KEM key is still
// encoded in full, so the string stays long; a truly short address needs a
// protocol change (see docs/stealth.md).
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
// WOTS+ (post-quantum, one-time signatures)
// ---------------------------------------------------------------------------

/// Winternitz One-Time Signature Plus. Hash-based, quantum-resistant. Each
/// key pair is used for exactly one signature; see `docs/wots.md`.
pub mod wots {
    use super::*;

    pub const W: usize = 256;
    pub const N: usize = 32;
    pub const L1: usize = 32;
    pub const L2: usize = 2;
    pub const L: usize = L1 + L2; // 34 chains

    pub const MAINNET_VERSION: u8 = 0x30;
    pub const TESTNET_VERSION: u8 = 0x6F;

    /// A WOTS+ key pair for one address. `sk_seed` is the secret; `pk_seed`
    /// and `r` are public and required for signing/verification.
    #[derive(Clone)]
    pub struct WotsKeypair {
        pub sk_seed: [u8; N],
        pub pk_seed: [u8; N],
        pub r: [u8; N],
    }

    /// A WOTS+ signature — the spending witness.
    pub struct WotsSignature {
        pub pk_seed: [u8; N],
        pub r: [u8; N],
        pub sig: [[u8; N]; L],
    }

    fn prf(key: &[u8; N], label: u8, index: u32, out: &mut [u8; N]) {
        let mut h = Sha256::new();
        h.update(key);
        h.update(index.to_be_bytes());
        h.update([label]);
        let d = h.finalize();
        out.copy_from_slice(&d);
    }

    impl WotsKeypair {
        pub fn new(sk_seed: [u8; N], pk_seed: [u8; N], r: [u8; N]) -> Self {
            WotsKeypair {
                sk_seed,
                pk_seed,
                r,
            }
        }

        /// Deterministic derivation from a master seed and an address index.
        /// The stateless wallet derives one fresh key pair per index.
        pub fn derive(master: &[u8; N], index: u32) -> Self {
            let mut sk = [0u8; N];
            prf(master, 1, index, &mut sk);
            let mut pk = [0u8; N];
            prf(master, 2, index, &mut pk);
            let mut r = [0u8; N];
            prf(master, 3, index, &mut r);
            WotsKeypair::new(sk, pk, r)
        }

        fn sk_i(&self, i: usize) -> [u8; N] {
            let mut h = Sha256::new();
            h.update(self.sk_seed);
            h.update((i as u16).to_be_bytes());
            h.update([0u8]);
            let d = h.finalize();
            let mut out = [0u8; N];
            out.copy_from_slice(&d);
            out
        }

        /// Public root `R` (the committed key).
        pub fn pubkey_root(&self) -> [u8; N] {
            let mut root_input = Vec::with_capacity(2 * N + L * N);
            root_input.extend_from_slice(&self.pk_seed);
            root_input.extend_from_slice(&self.r);
            for i in 0..L {
                let sk = self.sk_i(i);
                let pk = chain(&sk, 0, (W - 1) as u8, i as u16, &self.pk_seed, &self.r);
                root_input.extend_from_slice(&pk);
            }
            let d = Sha256::digest(&root_input);
            let mut out = [0u8; N];
            out.copy_from_slice(&d);
            out
        }

        pub fn pubkey_root_hash160(&self) -> [u8; 20] {
            hash160(&self.pubkey_root())
        }

        /// Address = base58check(version || HASH160(R)).
        pub fn address(&self, version: u8) -> String {
            base58check_encode(version, &self.pubkey_root_hash160())
        }

        pub fn sign(&self, msg: &[u8; N]) -> WotsSignature {
            let digits = msg_digits(msg);
            let mut sig = [[0u8; N]; L];
            for i in 0..L {
                let sk = self.sk_i(i);
                sig[i] = chain(&sk, 0, digits[i], i as u16, &self.pk_seed, &self.r);
            }
            WotsSignature {
                pk_seed: self.pk_seed,
                r: self.r,
                sig,
            }
        }
    }

    impl WotsSignature {
        /// Verify against a 256-bit message and the expected HASH160(R)
        /// committed by the output's script.
        pub fn verify(&self, msg: &[u8; N], root_hash: &[u8; 20]) -> bool {
            let digits = msg_digits(msg);
            let mut root_input = Vec::with_capacity(2 * N + L * N);
            root_input.extend_from_slice(&self.pk_seed);
            root_input.extend_from_slice(&self.r);
            for (i, (sig_i, &d)) in self.sig.iter().zip(digits.iter()).enumerate() {
                let pk = chain(sig_i, d, (W - 1) as u8, i as u16, &self.pk_seed, &self.r);
                root_input.extend_from_slice(&pk);
            }
            let d = Sha256::digest(&root_input);
            let mut root = [0u8; N];
            root.copy_from_slice(&d);
            hash160(&root) == *root_hash
        }
    }

    impl Encodable for WotsSignature {
        fn encode(&self, w: &mut Vec<u8>) {
            w.extend_from_slice(&self.pk_seed);
            w.extend_from_slice(&self.r);
            for s in &self.sig {
                w.extend_from_slice(s);
            }
        }
    }

    impl Decodable for WotsSignature {
        fn decode(r: &mut Reader) -> Result<Self, String> {
            let pk_seed: [u8; N] = r.read(N)?.try_into().map_err(|_| "bad witness")?;
            let r2: [u8; N] = r.read(N)?.try_into().map_err(|_| "bad witness")?;
            let mut sig = [[0u8; N]; L];
            for s in sig.iter_mut() {
                *s = r.read(N)?.try_into().map_err(|_| "bad witness")?;
            }
            Ok(WotsSignature {
                pk_seed,
                r: r2,
                sig,
            })
        }
    }

    /// Encode a signature into the canonical witness bytes (for `script_sig`).
    pub fn encode_witness(sig: &WotsSignature) -> Vec<u8> {
        to_bytes(sig)
    }

    /// Decode canonical witness bytes back into a signature.
    pub fn decode_witness(b: &[u8]) -> Result<WotsSignature, String> {
        let mut r = Reader::new(b);
        let s = WotsSignature::decode(&mut r)?;
        if r.remaining() != 0 {
            return Err("trailing bytes in witness".into());
        }
        Ok(s)
    }

    /// Split a 256-bit message into `L` base-`W` digits, including an `L2`-digit
    /// checksum. The decomposition is generic over `W` (here `W = 256`, so each
    /// message byte is exactly one digit; the checksum `Σ(W-1 - d_i)` fits in
    /// `L2` base-`W` digits). Smaller `W` (e.g. 16) would take more chains but
    /// fewer hash iterations per chain — a size/CPU tradeoff.
    fn msg_digits(msg: &[u8; N]) -> [u8; L] {
        let mut digits = [0u8; L];
        if W >= 256 {
            // One digit per message byte.
            for (b, byte) in msg.iter().enumerate().take(L1) {
                digits[b] = *byte;
            }
        } else {
            // W = 16: two base-16 nibbles per message byte.
            for (b, byte) in msg.iter().enumerate().take(32) {
                digits[2 * b] = (byte >> 4) & 0x0F;
                digits[2 * b + 1] = byte & 0x0F;
            }
        }
        let mut c: u32 = 0;
        for &d in &digits[..L1] {
            c += (W as u32 - 1) - d as u32;
        }
        // Big-endian base-W encoding of the checksum into the last L2 digits.
        for i in (0..L2).rev() {
            digits[L1 + i] = (c % (W as u32)) as u8;
            c /= W as u32;
        }
        digits
    }

    /// WOTS+ chain function: iterate the hash from `start` to `end` (exclusive).
    /// The position (chain index `i`, step `j`) is baked into the hash input so
    /// no two steps collide.
    fn chain(x: &[u8; N], start: u8, end: u8, i: u16, pk_seed: &[u8; N], r: &[u8; N]) -> [u8; N] {
        let mut buf = [0u8; N + N + 2 + 1 + N]; // pk_seed || r || i || j || x
        buf[..N].copy_from_slice(pk_seed);
        buf[N..2 * N].copy_from_slice(r);
        buf[2 * N..2 * N + 2].copy_from_slice(&i.to_be_bytes());
        let mut out = *x;
        for j in start..end {
            buf[2 * N + 2] = j;
            buf[2 * N + 3..].copy_from_slice(&out);
            let d = Sha256::digest(buf);
            out.copy_from_slice(&d);
        }
        out
    }
}

// ---------------------------------------------------------------------------
// ML-KEM-512 (post-quantum Key Encapsulation Mechanism)
//
// Used only to build *reusable* stealth addresses on top of the one-time
// WOTS+ signatures. The KEM never signs anything — it just lets a sender
// establish a shared secret with the recipient's long-term scan key, from
// which a fresh one-time WOTS+ key is derived per payment. This hides the
// one-time-use nature of WOTS+ behind the wallet, so the user-facing address
// stays fixed and compact (800 bytes) while every on-chain output is unique.
// ---------------------------------------------------------------------------

pub mod kem {
    use ml_kem::{
        Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, KeyExport, KeyInit, MlKem512,
        TryKeyInit,
    };
    use sha2::{Digest, Sha256};

    pub const KEM_PK_LEN: usize = 800;
    pub const KEM_SK_LEN: usize = 64;
    pub const KEM_CT_LEN: usize = 768;
    pub const KEM_SS_LEN: usize = 32;

    /// Deterministic 64-byte ML-KEM seed derived from the wallet master seed.
    fn derive_kem_seed(master: &[u8; 32]) -> [u8; KEM_SK_LEN] {
        let mut out = [0u8; KEM_SK_LEN];
        let h0 = Sha256::digest([master.as_slice(), &[0u8]].concat());
        let h1 = Sha256::digest([master.as_slice(), &[1u8]].concat());
        out[..32].copy_from_slice(&h0);
        out[32..].copy_from_slice(&h1);
        out
    }

    /// Deterministic KEM keypair from the wallet master seed: returns the
    /// 800-byte encapsulation (public) key and the 64-byte decapsulation seed.
    /// The seed is all that must be kept secret; the public key is recomputed
    /// from it, so the wallet stays stateless (one master seed).
    pub fn kem_keypair_from_seed(master: &[u8; 32]) -> ([u8; KEM_PK_LEN], [u8; KEM_SK_LEN]) {
        let sk = derive_kem_seed(master);
        let dk: DecapsulationKey<MlKem512> = KeyInit::new_from_slice(&sk).expect("bad KEM seed");
        let ek = dk.encapsulation_key();
        let mut pk = [0u8; KEM_PK_LEN];
        pk.copy_from_slice(ek.to_bytes().as_slice());
        (pk, sk)
    }

    /// Encapsulate a shared secret to `pk`; returns (shared_secret, ciphertext).
    pub fn kem_encaps(pk: &[u8; KEM_PK_LEN]) -> ([u8; KEM_SS_LEN], [u8; KEM_CT_LEN]) {
        let ek: EncapsulationKey<MlKem512> =
            TryKeyInit::new_from_slice(pk).expect("bad KEM public key");
        let (ct, ss) = ek.encapsulate();
        let mut out_ct = [0u8; KEM_CT_LEN];
        out_ct.copy_from_slice(ct.as_slice());
        (ss.0, out_ct)
    }

    /// Decapsulate the shared secret from `ct` using the 64-byte `sk` seed.
    pub fn kem_decaps(sk: &[u8; KEM_SK_LEN], ct: &[u8; KEM_CT_LEN]) -> [u8; KEM_SS_LEN] {
        let dk: DecapsulationKey<MlKem512> = KeyInit::new_from_slice(sk).expect("bad KEM seed");
        let ss = dk.decapsulate_slice(ct).expect("decapsulation failed");
        ss.0
    }
}

// ---------------------------------------------------------------------------
// Stealth addresses (reusable address + one-time WOTS+ output)
//
// A user's reusable address is just their KEM encapsulation public key
// (800 bytes), encoded as a Bech32m string (HRP `litc` mainnet / `tlitc`
// testnet). Bech32m keeps it lowercase and self-verifying, though the string
// is still long because the full key is encoded — a truly short address needs
// a protocol change (see docs/stealth.md). To pay it, the sender encapsulates
// a shared secret, derives a unique WOTS+ key from it, and locks the output to
// that key's commitment while attaching the KEM ciphertext. The recipient
// scans the chain, decapsulates each ciphertext with their scan secret, and
// recovers the one-time WOTS+ spend key — without ever reusing an address.
// ---------------------------------------------------------------------------

pub mod stealth {
    use super::*;

    pub const STEALTH_VERSION_MAINNET: u8 = 0x31;
    pub const STEALTH_VERSION_TESTNET: u8 = 0x70;
    const HRP_MAINNET: &str = "litc";
    const HRP_TESTNET: &str = "tlitc";

    const DOMAIN: &[u8] = b"litc-stealth-v1";

    /// Derive the per-payment WOTS+ master seed from a KEM shared secret.
    pub fn stealth_seed(ss: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DOMAIN);
        h.update(ss);
        let d = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        out
    }

    /// The reusable (multi-use) stealth address from a KEM public key.
    pub fn stealth_address(kem_pk: &[u8; kem::KEM_PK_LEN], version: u8) -> String {
        let hrp = if version == STEALTH_VERSION_MAINNET {
            HRP_MAINNET
        } else {
            HRP_TESTNET
        };
        let mut payload = Vec::with_capacity(kem::KEM_PK_LEN + 1);
        payload.push(version);
        payload.extend_from_slice(kem_pk);
        bech32m_encode(hrp, &payload)
    }

    /// Parse a stealth address back into a KEM public key (or `None`).
    pub fn parse_stealth_address(s: &str) -> Option<(u8, [u8; kem::KEM_PK_LEN])> {
        let (hrp, body) = bech32m_decode(s)?;
        if body.is_empty() {
            return None;
        }
        let v = body[0];
        let expected_hrp = if v == STEALTH_VERSION_MAINNET {
            HRP_MAINNET
        } else if v == STEALTH_VERSION_TESTNET {
            HRP_TESTNET
        } else {
            return None;
        };
        if hrp != expected_hrp {
            return None;
        }
        if body.len() != 1 + kem::KEM_PK_LEN {
            return None;
        }
        let mut a = [0u8; kem::KEM_PK_LEN];
        a.copy_from_slice(&body[1..]);
        Some((v, a))
    }

    /// Build a one-time output paying a reusable stealth address: encapsulates
    /// once to `kem_pk`, derives the unique WOTS+ key at index 0, and returns
    /// `(output, ciphertext)`. The output's script is HASH160(R); the caller
    /// must place the returned `ciphertext` in the transaction's `ephemeral`
    /// field (aggregated stealth, see `docs/stealth.md`) so the recipient can
    /// recover the same shared secret. Encapsulation is randomized, so the
    /// script and ciphertext come from one encapsulation and must stay paired.
    pub fn build_stealth_output(
        kem_pk: &[u8; kem::KEM_PK_LEN],
        value: Amount,
    ) -> (TxOut, [u8; kem::KEM_CT_LEN]) {
        let (ss, ct) = kem::kem_encaps(kem_pk);
        let out = TxOut {
            value,
            script_pubkey: stealth_script(&ss, 0).to_vec(),
            ephemeral: vec![],
        };
        (out, ct)
    }

    /// The locking script (HASH160(R)) for a stealth output at `index`, derived
    /// from the shared secret `ss`.
    pub fn stealth_script(ss: &[u8; 32], index: u32) -> [u8; 20] {
        wots::WotsKeypair::derive(&stealth_seed(ss), index).pubkey_root_hash160()
    }

    /// Recover the one-time WOTS+ keypair for a received output, given the
    /// recipient's KEM secret key and the output's ciphertext. Returns `None`
    /// if `ct` is malformed. Derives at index 0.
    pub fn recover_stealth_keypair(
        kem_sk: &[u8; kem::KEM_SK_LEN],
        ct: &[u8],
    ) -> Option<wots::WotsKeypair> {
        recover_stealth_keypair_at(kem_sk, ct, 0)
    }

    /// As `recover_stealth_keypair`, but derives the WOTS+ key at `index`
    /// (the output's position in the funding transaction). Used when a single
    /// transaction pays several stealth outputs from one shared secret.
    pub fn recover_stealth_keypair_at(
        kem_sk: &[u8; kem::KEM_SK_LEN],
        ct: &[u8],
        index: u32,
    ) -> Option<wots::WotsKeypair> {
        if ct.len() != kem::KEM_CT_LEN {
            return None;
        }
        let mut c = [0u8; kem::KEM_CT_LEN];
        c.copy_from_slice(ct);
        let ss = kem::kem_decaps(kem_sk, &c);
        Some(wots::WotsKeypair::derive(&stealth_seed(&ss), index))
    }
}

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

        pub fn from_str(s: &str) -> Option<Network> {
            match s.to_ascii_lowercase().as_str() {
                "mainnet" => Some(Network::Mainnet),
                "testnet" => Some(Network::Testnet),
                _ => None,
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
    fn stealth_address_bech32m() {
        let pk = [0x37u8; kem::KEM_PK_LEN];
        let addr = stealth::stealth_address(&pk, stealth::STEALTH_VERSION_MAINNET);
        assert!(addr.starts_with("litc1"));
        let (_, back) = stealth::parse_stealth_address(&addr).unwrap();
        assert_eq!(back, pk);
        // Testnet HRP differs; both encode the same key so they decode to the
        // same public key, but the address strings are distinct.
        let taddr = stealth::stealth_address(&pk, stealth::STEALTH_VERSION_TESTNET);
        assert!(taddr.starts_with("tlitc1"));
        assert_eq!(addr, stealth::stealth_address(&pk, stealth::STEALTH_VERSION_MAINNET));
        assert_ne!(addr, taddr);
        assert_eq!(stealth::parse_stealth_address(&addr).unwrap().1, pk);
        assert_eq!(stealth::parse_stealth_address(&taddr).unwrap().1, pk);
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
                scheme: SignatureScheme::Wots256,
                script_sig: vec![1, 2, 3, 4],
                sequence: 0xFFFF_FFFF,
            }],
            outputs: vec![TxOut {
                value: Amount(50 * COIN),
                script_pubkey: vec![0x76, 0xa9],
                ephemeral: vec![],
            }],
            ephemeral: vec![],
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
            ephemeral: vec![],
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
    fn wots_sign_verify() {
        let kp = wots::WotsKeypair::derive(&[0x42u8; 32], 0);
        let msg = [0xdeu8; 32];
        let sig = kp.sign(&msg);
        let root_hash = kp.pubkey_root_hash160();
        assert!(sig.verify(&msg, &root_hash));
        // Wrong message must fail.
        let bad = [0x00u8; 32];
        assert!(!sig.verify(&bad, &root_hash));
        // Wrong committed root must fail.
        let wrong = [0xffu8; 20];
        assert!(!sig.verify(&msg, &wrong));
    }

    #[test]
    fn wots_derive_deterministic() {
        let a = wots::WotsKeypair::derive(&[0x11u8; 32], 7);
        let b = wots::WotsKeypair::derive(&[0x11u8; 32], 7);
        assert_eq!(a.pubkey_root(), b.pubkey_root());
        let c = wots::WotsKeypair::derive(&[0x11u8; 32], 8);
        assert_ne!(a.pubkey_root(), c.pubkey_root());
    }

    #[test]
    fn wots_address_roundtrip() {
        let kp = wots::WotsKeypair::derive(&[0x99u8; 32], 0);
        let addr = kp.address(wots::MAINNET_VERSION);
        assert!(addr.starts_with('L'));
        let (v, h) = base58check_decode(&addr).unwrap();
        assert_eq!(v, wots::MAINNET_VERSION);
        assert_eq!(&h[..], &kp.pubkey_root_hash160()[..]);
    }

    #[test]
    fn wots_witness_roundtrip() {
        let kp = wots::WotsKeypair::derive(&[0x55u8; 32], 0);
        let msg = [0xaau8; 32];
        let sig = kp.sign(&msg);
        let bytes = wots::encode_witness(&sig);
        let back = wots::decode_witness(&bytes).unwrap();
        let root_hash = kp.pubkey_root_hash160();
        assert!(back.verify(&msg, &root_hash));
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
        assert_eq!(chainparams::Network::from_str("MAINNET"), Some(chainparams::Network::Mainnet));
        assert_eq!(chainparams::Network::from_str("nope"), None);
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
