use std::io::{BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use litc_keystore::FileKeyStore;
use litc_primitives::{
    base58check_decode, to_bytes, Amount, Block, Decodable, Hash32, Reader, COIN,
};
use litc_store::{BlockStore, FileStore, UtxoStore};
use litc_wallet::Wallet;

use crate::{write_tx, Node, PeerMap};

const RPC_VERSION: u8 = 1;

#[derive(Deserialize)]
struct RpcRequest {
    #[serde(rename = "jsonrpc")]
    #[allow(dead_code)]
    _jsonrpc: Option<String>,
    method: String,
    #[serde(default)]
    params: Vec<Value>,
    id: Option<Value>,
}

#[derive(Serialize)]
struct RpcResponse {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcErrorBody>,
    id: Value,
}

#[derive(Serialize)]
struct RpcErrorBody {
    code: i64,
    message: String,
}

fn ok(result: Value, id: Value) -> String {
    let resp = RpcResponse {
        jsonrpc: "2.0".into(),
        result: Some(result),
        error: None,
        id,
    };
    serde_json::to_string(&resp).unwrap()
}

fn err(code: i64, message: &str, id: Value) -> String {
    let resp = RpcResponse {
        jsonrpc: "2.0".into(),
        result: None,
        error: Some(RpcErrorBody {
            code,
            message: message.into(),
        }),
        id,
    };
    serde_json::to_string(&resp).unwrap()
}

fn parse_amount(s: &str) -> Result<u64, String> {
    if let Some((whole, frac)) = s.split_once('.') {
        let whole: u64 = whole.parse().map_err(|_| "bad amount".to_string())?;
        let frac = frac.trim_end_matches('0');
        let frac_val: u64 = if frac.is_empty() {
            0
        } else {
            frac.parse().map_err(|_| "bad amount".to_string())?
        };
        let scale = 10u64
            .checked_pow(8u32.saturating_sub(frac.len() as u32))
            .ok_or("bad amount")?;
        Ok(whole * COIN + frac_val * scale)
    } else {
        s.parse::<u64>().map_err(|_| "bad amount".to_string())
    }
}

fn format_amount(amt: u64) -> String {
    format!("{}.{:08} LIT", amt / COIN, amt % COIN)
}

fn commit_from_address(a: &str) -> Result<[u8; 20], String> {
    let (_v, payload) = base58check_decode(a).ok_or_else(|| "bad address".to_string())?;
    if payload.len() != 20 {
        return Err("address must encode a 20-byte commitment".into());
    }
    let mut c = [0u8; 20];
    c.copy_from_slice(&payload);
    Ok(c)
}

fn get_balance_for_wallet(store: &impl UtxoStore, w: &Wallet) -> u64 {
    let mut total = 0u64;
    for (op, out, _eph) in UtxoStore::iter_utxos(store) {
        for i in 0..=1_000_000u32 {
            let c = w.commitment_at(i);
            if UtxoStore::find_by_commit(store, &c).map(|found| found == op).unwrap_or(false) {
                total += out.value.0;
                break;
            }
        }
    }
    total
}

fn handle_getblockcount(node: &Node<FileStore>, _params: &[Value], id: Value) -> String {
    ok(json!(node.best_height()), id)
}

fn handle_getbestblockhash(node: &Node<FileStore>, _params: &[Value], id: Value) -> String {
    ok(json!(node.tip.to_hex()), id)
}

fn handle_getblockhash(node: &Node<FileStore>, params: &[Value], id: Value) -> String {
    let height = params.get(0).and_then(|v| v.as_u64()).unwrap_or(0);
    match node.chain.get(&height) {
        Some((hash, _ts)) => ok(json!(hash.to_hex()), id),
        None => err(-5, "block height out of range", id),
    }
}

fn hash32_from_hex(s: &str) -> Option<Hash32> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Some(Hash32(h))
}

fn handle_getblock(node: &Node<FileStore>, params: &[Value], id: Value) -> String {
    let hash_hex = params
        .get(0)
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let hash = match hash32_from_hex(hash_hex) {
        Some(h) => h,
        None => return err(-5, "invalid block hash", id),
    };
    match node.store.get_block(&hash) {
        Some(block) => {
            let verbose = params.get(1).and_then(|v| v.as_u64()).unwrap_or(1);
            if verbose == 0 {
                ok(json!(hex::encode(to_bytes(&block))), id)
            } else {
                let tx_hashes: Vec<String> = block
                    .txs
                    .iter()
                    .map(|tx| tx.txid().to_hex())
                    .collect();
                ok(json!({
                    "hash": hash.to_hex(),
                    "height": block.header.height,
                    "version": block.header.version,
                    "prev_block": block.header.prev_block.to_hex(),
                    "merkle_root": block.header.merkle_root.to_hex(),
                    "state_root": block.header.state_root.to_hex(),
                    "timestamp": block.header.timestamp,
                    "nonce": block.header.nonce,
                    "difficulty_bits": {
                        "leading_zeros": block.header.nonce.leading_zeros(),
                    },
                    "tx_count": block.txs.len(),
                    "tx": tx_hashes,
                }), id)
            }
        }
        None => err(-5, "block not found", id),
    }
}

fn handle_getinfo(node: &Node<FileStore>, peers: &PeerMap, _params: &[Value], id: Value) -> String {
    let peers_len = peers.lock().unwrap().len();
    ok(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "network": node.params.network.as_str(),
        "blocks": node.best_height(),
        "best_block_hash": node.tip.to_hex(),
        "difficulty_bits": node.difficulty_bits(),
        "mempool_size": node.mempool.len(),
        "known_txs": node.known_txs.len(),
        "connections": peers_len,
    }), id)
}

fn handle_getbalance(node: &Node<FileStore>, w: &Wallet, ks: &FileKeyStore, _params: &[Value], id: Value) -> String {
    let legacy = get_balance_for_wallet(&node.store, w);
    let owned = w.scan_chain(&node.store, ks).unwrap_or_default();
    let stealth: u64 = owned.iter().map(|o| o.value.0).sum();
    ok(json!({
        "legacy": legacy,
        "legacy_formatted": format_amount(legacy),
        "stealth": stealth,
        "stealth_formatted": format_amount(stealth),
        "total": legacy + stealth,
        "total_formatted": format_amount(legacy + stealth),
    }), id)
}

fn handle_getnewaddress(node: &Node<FileStore>, w: &Wallet, _params: &[Value], id: Value) -> String {
    let idx = w.next_unused_index(&node.store, 20);
    ok(json!(w.address_at(idx, RPC_VERSION)), id)
}

fn handle_getstealthaddress(_node: &Node<FileStore>, w: &Wallet, _params: &[Value], id: Value) -> String {
    ok(json!(w.stealth_address(RPC_VERSION)), id)
}

fn handle_gettransaction(node: &Node<FileStore>, params: &[Value], id: Value) -> String {
    let txid_hex = params.get(0).and_then(|v| v.as_str()).unwrap_or("");
    let txid = match hash32_from_hex(txid_hex) {
        Some(h) => h,
        None => return err(-5, "invalid txid", id),
    };
    for tx in &node.mempool {
        if tx.txid() == txid {
            return ok(json!({
                "txid": txid.to_hex(),
                "hex": hex::encode(to_bytes(tx)),
                "mempool": true,
                "inputs": tx.inputs.len(),
                "outputs": tx.outputs.len(),
            }), id);
        }
    }
    err(-5, "transaction not found", id)
}

fn handle_listunspent(node: &Node<FileStore>, w: &Wallet, params: &[Value], id: Value) -> String {
    let min_amt = params.get(0).and_then(|v| v.as_u64()).unwrap_or(0);
    let mut utxos: Vec<Value> = Vec::new();
    let store: &FileStore = &node.store;
    for (op, out, _eph) in UtxoStore::iter_utxos(store) {
        if out.value.0 < min_amt {
            continue;
        }
        let address = w.address_at(0, RPC_VERSION);
        utxos.push(json!({
            "txid": op.txid.to_hex(),
            "vout": op.index,
            "address": address,
            "amount": out.value.0,
            "amount_formatted": format_amount(out.value.0),
            "script_pubkey_hex": hex::encode(&out.script_pubkey),
        }));
    }
    ok(json!(utxos), id)
}

fn handle_sendtoaddress(
    node: &Node<FileStore>,
    w: &Wallet,
    ks: &FileKeyStore,
    params: &[Value],
    id: Value,
) -> String {
    let to_str = params.get(0).and_then(|v| v.as_str()).unwrap_or("");
    let to = match commit_from_address(to_str) {
        Ok(c) => c,
        Err(e) => return err(-5, &e, id),
    };
    let value = match params
        .get(1)
        .and_then(|v| v.as_str())
        .map(|s| parse_amount(s))
    {
        Some(Ok(v)) => Amount(v),
        Some(Err(e)) => return err(-5, &e, id),
        None => return err(-32602, "invalid amount", id),
    };
    let from: u32 = params.get(2).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    match w.spend_from(&node.store, ks, from, to, value) {
        Ok(tx) => {
            write_tx(&tx);
            let hex_str: String = to_bytes(&tx).iter().map(|b| format!("{b:02x}")).collect();
            ok(json!({
                "txid": tx.txid().to_hex(),
                "hex": hex_str,
            }), id)
        }
        Err(e) => err(-5, &format!("send failed: {e}"), id),
    }
}

fn handle_sendtostealthaddress(
    node: &Node<FileStore>,
    w: &Wallet,
    ks: &FileKeyStore,
    params: &[Value],
    id: Value,
) -> String {
    let to = params.get(0).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let value = match params
        .get(1)
        .and_then(|v| v.as_str())
        .map(|s| parse_amount(s))
    {
        Some(Ok(v)) => Amount(v),
        Some(Err(e)) => return err(-5, &e, id),
        None => return err(-32602, "invalid amount", id),
    };
    let from: u32 = params.get(2).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    match w.send_stealth(&node.store, ks, from, &to, value) {
        Ok(tx) => {
            write_tx(&tx);
            let hex_str: String = to_bytes(&tx).iter().map(|b| format!("{b:02x}")).collect();
            ok(json!({
                "txid": tx.txid().to_hex(),
                "hex": hex_str,
            }), id)
        }
        Err(e) => err(-5, &format!("send failed: {e}"), id),
    }
}

fn handle_getmininginfo(node: &Node<FileStore>, _params: &[Value], id: Value) -> String {
    ok(json!({
        "blocks": node.best_height(),
        "difficulty_bits": node.difficulty_bits(),
        "mempool_count": node.mempool.len(),
    }), id)
}

fn handle_submitblock(node: &mut Node<FileStore>, params: &[Value], id: Value) -> String {
    let hex_str = params.get(0).and_then(|v| v.as_str()).unwrap_or("");
    let bytes = match hex::decode(hex_str) {
        Ok(b) => b,
        Err(_) => return err(-5, "invalid hex", id),
    };
    let block = match Block::decode(&mut Reader::new(&bytes)) {
        Ok(b) => b,
        Err(_) => return err(-5, "invalid block encoding", id),
    };
    let from = "0.0.0.0:0".parse().unwrap();
    if node.accept_block(block, from) {
        ok(json!(true), id)
    } else {
        err(-25, "block rejected", id)
    }
}

fn handle_getpeerinfo(_node: &Node<FileStore>, peers: &PeerMap, _params: &[Value], id: Value) -> String {
    let peers_guard = peers.lock().unwrap();
    let info: Vec<Value> = peers_guard
        .keys()
        .map(|addr| json!({"addr": addr.to_string()}))
        .collect();
    ok(json!(info), id)
}

fn handle_getconnectioncount(_node: &Node<FileStore>, peers: &PeerMap, _params: &[Value], id: Value) -> String {
    ok(json!(peers.lock().unwrap().len()), id)
}

fn handle_request(
    node: &Arc<Mutex<Node<FileStore>>>,
    ks: &FileKeyStore,
    wallet: &Wallet,
    peers: &PeerMap,
    req: RpcRequest,
) -> String {
    let id = req.id.unwrap_or(Value::Null);

    match req.method.as_str() {
        "getblockcount" => {
            let n = node.lock().unwrap();
            handle_getblockcount(&n, &req.params, id)
        }
        "getbestblockhash" => {
            let n = node.lock().unwrap();
            handle_getbestblockhash(&n, &req.params, id)
        }
        "getblockhash" => {
            let n = node.lock().unwrap();
            handle_getblockhash(&n, &req.params, id)
        }
        "getblock" => {
            let n = node.lock().unwrap();
            handle_getblock(&n, &req.params, id)
        }
        "getinfo" => {
            let n = node.lock().unwrap();
            handle_getinfo(&n, peers, &req.params, id)
        }
        "getbalance" => {
            let n = node.lock().unwrap();
            handle_getbalance(&n, wallet, ks, &req.params, id)
        }
        "getnewaddress" => {
            let n = node.lock().unwrap();
            handle_getnewaddress(&n, wallet, &req.params, id)
        }
        "getstealthaddress" => {
            let n = node.lock().unwrap();
            handle_getstealthaddress(&n, wallet, &req.params, id)
        }
        "gettransaction" => {
            let n = node.lock().unwrap();
            handle_gettransaction(&n, &req.params, id)
        }
        "listunspent" => {
            let n = node.lock().unwrap();
            handle_listunspent(&n, wallet, &req.params, id)
        }
        "sendtoaddress" => {
            let n = node.lock().unwrap();
            handle_sendtoaddress(&n, wallet, ks, &req.params, id)
        }
        "sendtostealthaddress" => {
            let n = node.lock().unwrap();
            handle_sendtostealthaddress(&n, wallet, ks, &req.params, id)
        }
        "getmininginfo" => {
            let n = node.lock().unwrap();
            handle_getmininginfo(&n, &req.params, id)
        }
        "submitblock" => {
            let mut n = node.lock().unwrap();
            handle_submitblock(&mut n, &req.params, id)
        }
        "getpeerinfo" => {
            let n = node.lock().unwrap();
            handle_getpeerinfo(&n, peers, &req.params, id)
        }
        "getconnectioncount" => {
            let n = node.lock().unwrap();
            handle_getconnectioncount(&n, peers, &req.params, id)
        }
        _ => err(-32601, &format!("method not found: {}", req.method), id),
    }
}

fn handle_conn(
    mut stream: TcpStream,
    node: Arc<Mutex<Node<FileStore>>>,
    ks: FileKeyStore,
    wallet: Wallet,
    peers: PeerMap,
) {
    let mut reader = std::io::BufReader::new(&mut stream);
    let mut buf = Vec::new();

    // Parse the first line: METHOD /path HTTP/1.1
    buf.clear();
    let _ = reader.read_until(b'\n', &mut buf);

    // Parse headers, looking for Content-Length.
    let mut content_length: usize = 0;
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break,
        }
        let line = String::from_utf8_lossy(&buf).trim().to_string();
        if line.is_empty() {
            break;
        }
        if let Some(cl) = line.strip_prefix("Content-Length:").or_else(|| line.strip_prefix("content-length:")) {
            if let Ok(n) = cl.trim().parse::<usize>() {
                content_length = n;
            }
        }
    }

    // Read exactly Content-Length bytes for the body.
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        let _ = reader.read_exact(&mut body);
    }

    let content = String::from_utf8_lossy(&body);
    let req: RpcRequest = match serde_json::from_str(&content) {
        Ok(r) => r,
        Err(e) => {
            let resp = err(-32700, &format!("parse error: {e}"), Value::Null);
            let _ = write_response(&mut stream, &resp);
            return;
        }
    };

    let resp = handle_request(&node, &ks, &wallet, &peers, req);
    let _ = write_response(&mut stream, &resp);
}

fn write_response(stream: &mut TcpStream, body: &str) -> std::io::Result<()> {
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

pub fn start(
    port: u16,
    node: Arc<Mutex<Node<FileStore>>>,
    wallet_seed: [u8; 32],
    peers: PeerMap,
) {
    let addr: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
    let listener = match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[rpc] cannot bind port {port}: {e}");
            return;
        }
    };
    println!("[rpc] listening on {addr}");

    for stream in listener.incoming().flatten() {
        let node = node.clone();
        let wallet = Wallet::new(wallet_seed);
        let peers = peers.clone();
        thread::spawn(move || {
            let ks = FileKeyStore::new(std::env::var("LITC_DATADIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| std::path::PathBuf::from("data"))
                .join("wallet.dat"));
            handle_conn(stream, node, ks, wallet, peers);
        });
    }
}
