use std::fmt;

pub type Hash = [u8; 32];

/// Hard cap on a single wire frame's payload (16 MiB). Frames larger than
/// this are rejected, which bounds memory use from a peer.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvVect {
    pub kind: u8,
    pub hash: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetAddr {
    pub services: u64,
    pub ip: [u8; 16],
    pub port: u16,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Version {
        version: u32,
        services: u64,
        timestamp: u64,
        from: NetAddr,
        nonce: u64,
        best_height: u64,
    },
    Verack,
    Inv(Vec<InvVect>),
    GetData(Vec<InvVect>),
    Tx(Vec<u8>),
    Block(Vec<u8>),
    Ping(u64),
    Pong(u64),
    GetAddr,
    Addr(Vec<NetAddr>),
    /// Request the block inventory starting just after the highest locator
    /// hash the sender knows. Used for initial chain sync.
    GetBlocks(Vec<Hash>),
    Request {
        id: u32,
        method: u8,
        params: Vec<u8>,
    },
    Response {
        id: u32,
        ok: bool,
        data: Vec<u8>,
    },
}

pub trait Encode {
    fn encode(&self, w: &mut Vec<u8>);
}

pub trait Decode: Sized {
    fn decode(r: &mut Reader) -> Result<Self>;
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

#[derive(Debug)]
pub struct WireError(pub String);

pub type Result<T> = std::result::Result<T, WireError>;

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "wire error: {}", self.0)
    }
}

impl std::error::Error for WireError {}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= self.buf.len() {
            return Err(WireError("eof u8".into()));
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(b)
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        if self.remaining() < 4 {
            return Err(WireError("eof u32".into()));
        }
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.buf[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(u32::from_be_bytes(b))
    }

    pub fn read_u64(&mut self) -> Result<u64> {
        if self.remaining() < 8 {
            return Err(WireError("eof u64".into()));
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_be_bytes(b))
    }

    pub fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        if self.remaining() < n {
            return Err(WireError("eof bytes".into()));
        }
        let v = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(v)
    }

    pub fn read_hash(&mut self) -> Result<Hash> {
        let v = self.read_bytes(32)?;
        let mut h = [0u8; 32];
        h.copy_from_slice(&v);
        Ok(h)
    }

    pub fn read_vec(&mut self) -> Result<Vec<u8>> {
        let n = self.read_u32()? as usize;
        self.read_bytes(n)
    }
}

fn put_u32(w: &mut Vec<u8>, v: u32) {
    w.extend_from_slice(&v.to_be_bytes());
}

fn put_u64(w: &mut Vec<u8>, v: u64) {
    w.extend_from_slice(&v.to_be_bytes());
}

fn put_vec(w: &mut Vec<u8>, v: &[u8]) {
    put_u32(w, v.len() as u32);
    w.extend_from_slice(v);
}

impl Encode for InvVect {
    fn encode(&self, w: &mut Vec<u8>) {
        w.push(self.kind);
        w.extend_from_slice(&self.hash);
    }
}

impl Decode for InvVect {
    fn decode(r: &mut Reader) -> Result<Self> {
        let kind = r.read_u8()?;
        let hash = r.read_hash()?;
        Ok(InvVect { kind, hash })
    }
}

fn encode_inv_list(w: &mut Vec<u8>, items: &[InvVect]) {
    put_u32(w, items.len() as u32);
    for it in items {
        it.encode(w);
    }
}

fn decode_inv_list(r: &mut Reader) -> Result<Vec<InvVect>> {
    let n = r.read_u32()? as usize;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(InvVect::decode(r)?);
    }
    Ok(out)
}

impl Encode for NetAddr {
    fn encode(&self, w: &mut Vec<u8>) {
        put_u64(w, self.services);
        w.extend_from_slice(&self.ip);
        w.extend_from_slice(&self.port.to_be_bytes());
        put_u64(w, self.timestamp);
    }
}

impl Decode for NetAddr {
    fn decode(r: &mut Reader) -> Result<Self> {
        let services = r.read_u64()?;
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&r.read_bytes(16)?);
        let mut pb = [0u8; 2];
        pb.copy_from_slice(&r.read_bytes(2)?);
        let port = u16::from_be_bytes(pb);
        let timestamp = r.read_u64()?;
        Ok(NetAddr {
            services,
            ip,
            port,
            timestamp,
        })
    }
}

fn encode_addr_list(w: &mut Vec<u8>, items: &[NetAddr]) {
    put_u32(w, items.len() as u32);
    for it in items {
        it.encode(w);
    }
}

fn decode_addr_list(r: &mut Reader) -> Result<Vec<NetAddr>> {
    let n = r.read_u32()? as usize;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(NetAddr::decode(r)?);
    }
    Ok(out)
}

fn encode_hash_list(w: &mut Vec<u8>, items: &[Hash]) {
    put_u32(w, items.len() as u32);
    for h in items {
        w.extend_from_slice(h);
    }
}

fn decode_hash_list(r: &mut Reader) -> Result<Vec<Hash>> {
    let n = r.read_u32()? as usize;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(r.read_hash()?);
    }
    Ok(out)
}

impl Encode for Message {
    fn encode(&self, w: &mut Vec<u8>) {
        match self {
            Message::Version {
                version,
                services,
                timestamp,
                from,
                nonce,
                best_height,
            } => {
                put_u32(w, *version);
                put_u64(w, *services);
                put_u64(w, *timestamp);
                from.encode(w);
                put_u64(w, *nonce);
                put_u64(w, *best_height);
            }
            Message::Verack => {}
            Message::Inv(items) | Message::GetData(items) => {
                encode_inv_list(w, items);
            }
            Message::Tx(raw) | Message::Block(raw) => {
                put_vec(w, raw);
            }
            Message::Ping(n) | Message::Pong(n) => {
                put_u64(w, *n);
            }
            Message::GetAddr => {}
            Message::Addr(items) => {
                encode_addr_list(w, items);
            }
            Message::GetBlocks(items) => {
                encode_hash_list(w, items);
            }
            Message::Request { id, method, params } => {
                put_u32(w, *id);
                w.push(*method);
                put_vec(w, params);
            }
            Message::Response { id, ok, data } => {
                put_u32(w, *id);
                w.push(if *ok { 1 } else { 0 });
                put_vec(w, data);
            }
        }
    }
}

fn cmd_of(m: &Message) -> u8 {
    match m {
        Message::Version { .. } => 1,
        Message::Verack => 2,
        Message::Inv(_) => 3,
        Message::GetData(_) => 4,
        Message::Tx(_) => 5,
        Message::Block(_) => 6,
        Message::Ping(_) => 7,
        Message::Pong(_) => 8,
        Message::GetAddr => 9,
        Message::Addr(_) => 10,
        Message::GetBlocks(_) => 13,
        Message::Request { .. } => 11,
        Message::Response { .. } => 12,
    }
}

fn decode_payload(cmd: u8, r: &mut Reader) -> Result<Message> {
    match cmd {
        1 => Ok(Message::Version {
            version: r.read_u32()?,
            services: r.read_u64()?,
            timestamp: r.read_u64()?,
            from: NetAddr::decode(r)?,
            nonce: r.read_u64()?,
            best_height: r.read_u64()?,
        }),
        2 => Ok(Message::Verack),
        3 => Ok(Message::Inv(decode_inv_list(r)?)),
        4 => Ok(Message::GetData(decode_inv_list(r)?)),
        5 => Ok(Message::Tx(r.read_vec()?)),
        6 => Ok(Message::Block(r.read_vec()?)),
        7 => Ok(Message::Ping(r.read_u64()?)),
        8 => Ok(Message::Pong(r.read_u64()?)),
        9 => Ok(Message::GetAddr),
        10 => Ok(Message::Addr(decode_addr_list(r)?)),
        13 => Ok(Message::GetBlocks(decode_hash_list(r)?)),
        11 => Ok(Message::Request {
            id: r.read_u32()?,
            method: r.read_u8()?,
            params: r.read_vec()?,
        }),
        12 => Ok(Message::Response {
            id: r.read_u32()?,
            ok: r.read_u8()? == 1,
            data: r.read_vec()?,
        }),
        other => Err(WireError(format!("unknown cmd {other}"))),
    }
}

pub struct Codec {
    pub magic: [u8; 4],
}

impl Codec {
    pub fn new(magic: [u8; 4]) -> Self {
        Codec { magic }
    }

    pub fn frame(&self, msg: &Message) -> Vec<u8> {
        let mut payload = Vec::new();
        msg.encode(&mut payload);
        let mut out = Vec::with_capacity(9 + payload.len());
        out.extend_from_slice(&self.magic);
        out.push(cmd_of(msg));
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    pub fn parse(&self, buf: &[u8]) -> Result<Option<(Message, usize)>> {
        if buf.len() < 9 {
            return Ok(None);
        }
        if buf[0..4] != self.magic {
            return Err(WireError("bad magic".into()));
        }
        let cmd = buf[4];
        let len = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) as usize;
        if len > MAX_FRAME {
            return Err(WireError("frame too large".into()));
        }
        if buf.len() < 9 + len {
            return Ok(None);
        }
        let mut r = Reader::new(&buf[9..9 + len]);
        let msg = decode_payload(cmd, &mut r)?;
        Ok(Some((msg, 9 + len)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codec() -> Codec {
        Codec::new(*b"L1TC")
    }

    fn roundtrip(m: Message) {
        let c = codec();
        let f = c.frame(&m);
        let (m2, n) = c.parse(&f).unwrap().unwrap();
        assert_eq!(m, m2);
        assert_eq!(n, f.len());
    }

    #[test]
    fn all_messages_roundtrip() {
        roundtrip(Message::Version {
            version: 1,
            services: 7,
            timestamp: 123,
            from: NetAddr {
                services: 1,
                ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1],
                port: 8333,
                timestamp: 0,
            },
            nonce: 9,
            best_height: 42,
        });
        roundtrip(Message::Verack);
        roundtrip(Message::Inv(vec![InvVect {
            kind: 1,
            hash: [3u8; 32],
        }]));
        roundtrip(Message::GetData(vec![]));
        roundtrip(Message::Tx(vec![1, 2, 3, 4]));
        roundtrip(Message::Block(vec![]));
        roundtrip(Message::Ping(555));
        roundtrip(Message::Pong(777));
        roundtrip(Message::GetAddr);
        roundtrip(Message::Addr(vec![NetAddr {
            services: 1,
            ip: [0x20u8; 16],
            port: 8333,
            timestamp: 99,
        }]));
        roundtrip(Message::Request {
            id: 11,
            method: 2,
            params: vec![9, 8, 7],
        });
        roundtrip(Message::Response {
            id: 12,
            ok: true,
            data: vec![1],
        });
    }

    #[test]
    fn partial_frame_is_none() {
        let c = codec();
        let f = c.frame(&Message::Ping(1));
        assert!(c.parse(&f[..5]).unwrap().is_none());
    }

    #[test]
    fn bad_magic_errors() {
        let c = codec();
        let mut f = c.frame(&Message::Ping(1));
        f[0] = b'X';
        assert!(c.parse(&f).is_err());
    }
}
