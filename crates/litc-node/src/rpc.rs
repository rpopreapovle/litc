use std::io::{BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// ANSI color helpers (mirrored from lib.rs).
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const RED: &str = "\x1b[31m";
const MAGENTA: &str = "\x1b[35m";

use litc_keystore::FileKeyStore;
use litc_primitives::{mldsa, to_bytes, Amount, Block, Decodable, Hash32, Reader, Transaction, COIN};
use litc_store::{BlockStore, FileStore, SpendStore, UtxoStore};
use litc_wallet::Wallet;

use crate::{write_tx, Node, PeerMap};

#[derive(Clone, Copy, PartialEq)]
enum Access { Admin, Public }

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

fn handle_getblockcount(node: &Node<FileStore>, _params: &[Value], id: Value) -> String {
    ok(json!(node.best_height()), id)
}

fn handle_getbestblockhash(node: &Node<FileStore>, _params: &[Value], id: Value) -> String {
    ok(json!(node.tip.to_hex()), id)
}

fn handle_getblockhash(node: &Node<FileStore>, params: &[Value], id: Value) -> String {
    let height = params.first().and_then(|v| v.as_u64()).unwrap_or(0);
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
    let hash_hex = params.first().and_then(|v| v.as_str()).unwrap_or("");
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
                let tx_hashes: Vec<String> =
                    block.txs.iter().map(|tx| tx.txid().to_hex()).collect();
                ok(
                    json!({
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
                    }),
                    id,
                )
            }
        }
        None => err(-5, "block not found", id),
    }
}

fn handle_getinfo(node: &Node<FileStore>, peers: &PeerMap, _params: &[Value], id: Value) -> String {
    let peers_len = peers.lock().unwrap().len();
    ok(
        json!({
            "version": env!("CARGO_PKG_VERSION"),
            "network": node.params.network.as_str(),
            "blocks": node.best_height(),
            "best_block_hash": node.tip.to_hex(),
            "difficulty_bits": node.difficulty_bits(),
            "mempool_size": node.mempool.len(),
            "known_txs": node.known_txs.len(),
            "connections": peers_len,
        }),
        id,
    )
}

fn handle_getbalance(
    node: &Node<FileStore>,
    w: &Wallet,
    _params: &[Value],
    id: Value,
) -> String {
    let mut sum: u64 = 0;
    let mut commits = std::collections::HashSet::new();
    for idx in 0..=200u32 {
        commits.insert(w.commitment_at(idx));
    }
    for (_op, out) in &node.store.iter_utxos() {
        if out.script_pubkey.len() >= 20 {
            let mut prefix = [0u8; 20];
            prefix.copy_from_slice(&out.script_pubkey[..20]);
            if commits.contains(&prefix) {
                sum += out.value.0;
            }
        }
    }
    ok(json!({"balance": sum, "balance_formatted": format_amount(sum)}), id)
}

fn handle_getaddress(_node: &Node<FileStore>, w: &Wallet, _params: &[Value], id: Value) -> String {
    ok(json!(w.address_at(0, mldsa::MAINNET_VERSION)), id)
}

fn handle_signmessage(_node: &Node<FileStore>, w: &Wallet, params: &[Value], id: Value) -> String {
    let index = params.get(0).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let msg_hex = params.get(1).and_then(|v| v.as_str()).unwrap_or("");
    if msg_hex.is_empty() {
        return err(-32602, "signmessage requires index and message_hex", id);
    }
    let msg = match hex::decode(msg_hex) {
        Ok(b) if b.len() == 32 => { let mut h = [0u8; 32]; h.copy_from_slice(&b); h }
        _ => return err(-5, "message_hex must be 32 bytes (64 hex chars)", id),
    };
    let kp = w.keypair_at(index);
    let pk = kp.public_key_bytes();
    let sig = kp.sign(&msg);
    ok(json!({
        "pubkey_hex": hex::encode(pk),
        "signature_hex": hex::encode(sig),
        "address": kp.address(mldsa::MAINNET_VERSION),
    }), id)
}

fn handle_gettransaction(node: &Node<FileStore>, params: &[Value], id: Value) -> String {
    let txid_hex = params.first().and_then(|v| v.as_str()).unwrap_or("");
    let txid = match hash32_from_hex(txid_hex) {
        Some(h) => h,
        None => return err(-5, "invalid txid", id),
    };
    for tx in &node.mempool {
        if tx.txid() == txid {
            return ok(
                json!({
                    "txid": txid.to_hex(),
                    "hex": hex::encode(to_bytes(tx)),
                    "mempool": true,
                    "inputs": tx.inputs.len(),
                    "outputs": tx.outputs.len(),
                }),
                id,
            );
        }
    }
    err(-5, "transaction not found", id)
}

fn handle_listunspent(node: &Node<FileStore>, _w: &Wallet, params: &[Value], id: Value) -> String {
    let min_amt = params.first().and_then(|v| v.as_u64()).unwrap_or(0);
    let mut utxos: Vec<Value> = Vec::new();
    let store: &FileStore = &node.store;
    for (op, out) in UtxoStore::iter_utxos(store) {
        if out.value.0 < min_amt {
            continue;
        }
        utxos.push(json!({
            "txid": op.txid.to_hex(),
            "vout": op.index,
            "amount": out.value.0,
            "amount_formatted": format_amount(out.value.0),
            "script_pubkey_hex": hex::encode(&out.script_pubkey),
        }));
    }
    ok(json!(utxos), id)
}

fn handle_send(
    node: &Node<FileStore>,
    w: &Wallet,
    _ks: &FileKeyStore,
    params: &[Value],
    id: Value,
) -> String {
    let to = params
        .first()
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let value = match params.get(1).and_then(|v| v.as_str()).map(parse_amount) {
        Some(Ok(v)) => Amount(v),
        Some(Err(e)) => return err(-5, &e, id),
        None => return err(-32602, "invalid amount", id),
    };
    let from: u32 = params.get(2).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let (_v, to_commit) = match litc_primitives::mldsa::parse_address(&to) {
        Some(c) => c,
        None => return err(-5, "invalid ML-DSA-2 address", id),
    };
    match w.spend_from(&node.store, from, to_commit, value) {
        Ok(tx) => {
            write_tx(&tx);
            let hex_str: String = to_bytes(&tx).iter().map(|b| format!("{b:02x}")).collect();
            ok(
                json!({
                    "txid": tx.txid().to_hex(),
                    "hex": hex_str,
                }),
                id,
            )
        }
        Err(e) => err(-5, &format!("send failed: {e}"), id),
    }
}

fn handle_getmininginfo(node: &Node<FileStore>, _params: &[Value], id: Value) -> String {
    ok(
        json!({
            "blocks": node.best_height(),
            "difficulty_bits": node.difficulty_bits(),
            "mempool_count": node.mempool.len(),
        }),
        id,
    )
}

fn handle_submitblock(node: &mut Node<FileStore>, params: &[Value], id: Value) -> String {
    let hex_str = params.first().and_then(|v| v.as_str()).unwrap_or("");
    let bytes = match hex::decode(hex_str) {
        Ok(b) => b,
        Err(_) => return err(-5, "invalid hex", id),
    };
    let block = match Block::decode(&mut Reader::new(&bytes)) {
        Ok(b) => b,
        Err(_) => return err(-5, "invalid block encoding", id),
    };
    let from = "0.0.0.0:0".parse().unwrap();
    if !node.accept_block(block, from) {
        return err(-25, "block rejected", id);
    }

    let actual_height = node.best_height();
    let subsidy = litc_core::block_subsidy(actual_height).0;
    let fee_pct = node.pool_config.fee_pct;
    let earned = ((subsidy as f64) * (1.0 - fee_pct / 100.0)) as u64;

    // Check if submitter is a registered session (session_token as 2nd param).
    let second = params.get(1).and_then(|v| v.as_str()).unwrap_or("");
    let is_session = second.len() == 64 && hex::decode(second).is_ok();

    if is_session {
        let token = Hash32(hex::decode(second).unwrap().try_into().unwrap());
        if let Some(s) = node.pool_sessions.iter_mut().find(|s| s.session_token == token) {
            s.blocks_found += 1;
            s.last_height = actual_height;
            s.balance_sat += earned;
            s.total_earned_sat += earned;
            s.events.push(json!({
                "event": "block_found",
                "height": actual_height,
                "reward_sat": earned,
                "reward_formatted": format_amount(earned),
                "balance_sat": s.balance_sat,
                "balance_formatted": format_amount(s.balance_sat),
            }).to_string());

            // Auto-payout trigger — wallet access happens via pool_withdraw.
            if s.balance_sat >= s.min_payout_sat {
                s.events.push(json!({
                    "event": "auto_payout_triggered",
                    "balance_sat": s.balance_sat,
                    "min_payout_sat": s.min_payout_sat,
                }).to_string());
            }
        }
    } else {
        // Legacy worker tracking.
        let worker_name = second.to_string();
        let payout_addr = params.get(2).and_then(|v| v.as_str())
            .filter(|s| !s.is_empty()).map(|s| s.to_string());
        let addr = from;
        if let Some(w) = node.pool_workers.iter_mut().find(|w| w.name == worker_name) {
            w.blocks_found += 1;
            w.last_height = actual_height;
            w.earned += earned;
            if payout_addr.is_some() {
                w.payout_addr = payout_addr;
            }
        } else {
            node.pool_workers.push(crate::PoolWorker {
                addr,
                name: worker_name,
                blocks_found: 1,
                shares: 0,
                last_height: actual_height,
                payout_addr,
                earned,
            });
        }
    }
    ok(json!(true), id)
}

fn handle_getblocktemplate(node: &mut Node<FileStore>, params: &[Value], id: Value) -> String {
    // If first param is a 64-char hex, treat as session_token; else legacy worker name.
    let first = params.first().and_then(|v| v.as_str()).unwrap_or("anon");
    let is_session = first.len() == 64 && hex::decode(first).is_ok();

    if is_session {
        let token = Hash32(hex::decode(first).unwrap().try_into().unwrap());
        let bh = node.best_height();
        if let Some(s) = node.pool_sessions.iter_mut().find(|s| s.session_token == token) {
            s.last_height = bh;
        }
    } else {
        // Legacy worker tracking.
        let worker_name = first.to_string();
        let payout_addr = params.get(1).and_then(|v| v.as_str())
            .filter(|s| !s.is_empty()).map(|s| s.to_string());
        let addr = "0.0.0.0:0".parse().unwrap();
        if let Some(w) = node.pool_workers.iter_mut().find(|w| w.name == worker_name) {
            if payout_addr.is_some() {
                w.payout_addr = payout_addr;
            }
        } else {
            node.pool_workers.push(crate::PoolWorker {
                addr,
                name: worker_name,
                blocks_found: 0,
                shares: 0,
                last_height: 0,
                payout_addr,
                earned: 0,
            });
        }
    }

    let (template, target) = node.make_template();
    let candidate = crate::assemble_block(&template);
    let header_nonce0 = to_bytes(&candidate.header);
    let block_hex = to_bytes(&candidate);
    ok(
        json!({
            "height": template.height,
            "header_hex": hex::encode(&header_nonce0),
            "block_hex": hex::encode(&block_hex),
            "target_hex": hex::encode(target),
            "prev_block": template.prev_block.to_hex(),
            "epoch_seed": template.epoch_seed.to_hex(),
            "state_root": template.state_root.to_hex(),
            "coinbase_value": template.coinbase_value.0,
        }),
        id,
    )
}

fn handle_getpoolinfo(node: &Node<FileStore>, _params: &[Value], id: Value) -> String {
    let workers: Vec<Value> = node
        .pool_workers
        .iter()
        .map(|w| {
            json!({
                "name": w.name,
                "addr": w.addr.to_string(),
                "blocks_found": w.blocks_found,
                "shares": w.shares,
                "last_height": w.last_height,
                "payout_addr": w.payout_addr,
                "earned": w.earned,
                "earned_formatted": format_amount(w.earned),
            })
        })
        .collect();
    let sessions: Vec<Value> = node
        .pool_sessions
        .iter()
        .map(|s| {
            json!({
                "session_token": s.session_token.to_hex(),
                "address": s.address,
                "label": s.label,
                "blocks_found": s.blocks_found,
                "balance_sat": s.balance_sat,
                "balance_formatted": format_amount(s.balance_sat),
                "total_earned_sat": s.total_earned_sat,
                "total_earned_formatted": format_amount(s.total_earned_sat),
            })
        })
        .collect();
    ok(
        json!({
            "legacy_workers": workers,
            "sessions": sessions,
            "total_sessions": sessions.len(),
            "fee_pct": node.pool_config.fee_pct,
        }),
        id,
    )
}

/// Register a new pool mining session with ML-DSA-2 proof of address ownership.
/// Params: [address, pubkey_hex, signature_hex, min_payout_str?, label?]
fn handle_pool_register(
    node: &mut Node<FileStore>,
    params: &[Value],
    id: Value,
) -> String {
    let address = params.get(0).and_then(|v| v.as_str()).unwrap_or("");
    let pubkey_hex = params.get(1).and_then(|v| v.as_str()).unwrap_or("");
    let sig_hex = params.get(2).and_then(|v| v.as_str()).unwrap_or("");
    let min_payout_str = params.get(3).and_then(|v| v.as_str()).unwrap_or("");
    let label = params.get(4).and_then(|v| v.as_str()).unwrap_or("anon");

    if address.is_empty() || pubkey_hex.is_empty() || sig_hex.is_empty() {
        return err(-32602, "pool_register requires address, pubkey_hex, signature_hex", id);
    }

    // Decode pubkey (1312 bytes for ML-DSA-2).
    let pubkey = match hex::decode(pubkey_hex) {
        Ok(b) if b.len() == mldsa::PK_LEN => {
            let mut pk = [0u8; mldsa::PK_LEN];
            pk.copy_from_slice(&b);
            pk
        }
        _ => return err(-5, "invalid pubkey (expected 1312 hex bytes)", id),
    };

    // Verify: sha256(pubkey) -> commitment must match the address's commitment.
    let (_, addr_commit) = match mldsa::parse_address(address) {
        Some(c) => c,
        None => return err(-5, "invalid ML-DSA-2 address", id),
    };
    let derived_commit = litc_primitives::hash160(&pubkey);
    if derived_commit != addr_commit {
        return err(-5, "pubkey does not match address", id);
    }

    // Verify signature: signed sha256("pool-register:" || address || min_payout_str).
    let msg = {
        let payload = format!("pool-register:{}:{}", address, min_payout_str);
        let h = litc_primitives::sha256d(payload.as_bytes());
        h.0
    };
    let sig = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(_) => return err(-5, "invalid signature hex", id),
    };
    if !mldsa::MlDsaKeypair::verify(&pubkey, &msg, &sig) {
        return err(-5, "signature verification failed — not the address owner", id);
    }

    // Compute min_payout in satoshis.
    let min_payout_sat = if min_payout_str.is_empty() {
        node.pool_config.min_payout_sat()
    } else {
        parse_amount_sat(min_payout_str)
    };

    // Create or update session.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let existing = node.pool_sessions.iter_mut().find(|s| s.commitment == addr_commit);
    if let Some(session) = existing {
        session.label = label.to_string();
        session.min_payout_sat = min_payout_sat;
        session.events.push(json!({"event": "registered"}).to_string());
        return ok(json!({
            "session_token": session.session_token.to_hex(),
            "fee_pct": node.pool_config.fee_pct,
            "min_payout": min_payout_sat,
            "existing": true,
        }), id);
    }

    let token = litc_keystore::random_seed().unwrap_or([0u8; 32]);
    let session = crate::PoolSession {
        session_token: Hash32(token),
        address: address.to_string(),
        pubkey,
        commitment: addr_commit,
        label: label.to_string(),
        min_payout_sat,
        balance_sat: 0,
        total_earned_sat: 0,
        blocks_found: 0,
        last_height: 0,
        created_at: now,
        events: vec![json!({"event": "registered", "fee_pct": node.pool_config.fee_pct}).to_string()],
    };
    node.pool_sessions.push(session);

    ok(json!({
        "session_token": Hash32(token).to_hex(),
        "fee_pct": node.pool_config.fee_pct,
        "min_payout": min_payout_sat,
        "existing": false,
    }), id)
}

/// Get pool balance and stats for a session.
/// Params: [session_token_hex]
fn handle_pool_balance(
    node: &Node<FileStore>,
    params: &[Value],
    id: Value,
) -> String {
    let token_hex = params.get(0).and_then(|v| v.as_str()).unwrap_or("");
    let token = match hash32_from_hex(token_hex) {
        Some(t) => t,
        None => return err(-5, "invalid session token", id),
    };
    let session = match node.pool_sessions.iter().find(|s| s.session_token == token) {
        Some(s) => s,
        None => return err(-5, "session not found", id),
    };
    ok(json!({
        "address": session.address,
        "label": session.label,
        "balance_sat": session.balance_sat,
        "balance_formatted": format_amount(session.balance_sat),
        "total_earned_sat": session.total_earned_sat,
        "total_earned_formatted": format_amount(session.total_earned_sat),
        "blocks_found": session.blocks_found,
        "min_payout_sat": session.min_payout_sat,
        "min_payout_formatted": format_amount(session.min_payout_sat),
    }), id)
}

/// Withdraw pool balance to the registered address.
/// Params: [session_token_hex, amount_str?]
/// If amount_str is omitted, withdraws entire balance.
fn handle_pool_withdraw(
    node: &mut Node<FileStore>,
    w: &Wallet,
    params: &[Value],
    id: Value,
) -> String {
    let token_hex = params.get(0).and_then(|v| v.as_str()).unwrap_or("");
    let token = match hash32_from_hex(token_hex) {
        Some(t) => t,
        None => return err(-5, "invalid session token", id),
    };
    let (to_commit, amount_sat) = {
        let session = match node.pool_sessions.iter().find(|s| s.session_token == token) {
            Some(s) => s,
            None => return err(-5, "session not found", id),
        };
        let amt = params.get(1).and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(parse_amount_sat)
            .unwrap_or(session.balance_sat);
        if amt == 0 {
            return err(-5, "zero amount — nothing to withdraw", id);
        }
        if amt > session.balance_sat {
            return err(-5, &format!("insufficient balance: have {} sat, need {amt} sat", session.balance_sat), id);
        }
        let (_, commit) = mldsa::parse_address(&session.address).unwrap();
        (commit, amt)
    };

    match w.spend_from(&node.store, 0, to_commit, Amount(amount_sat)) {
        Ok(tx) => {
            if let Some(session) = node.pool_sessions.iter_mut().find(|s| s.session_token == token) {
                session.balance_sat = session.balance_sat.saturating_sub(amount_sat);
                session.events.push(json!({
                    "event": "payout",
                    "amount_sat": amount_sat,
                    "amount_formatted": format_amount(amount_sat),
                    "txid": tx.txid().to_hex(),
                }).to_string());
            }
            write_tx(&tx);
            ok(json!({
                "amount_sat": amount_sat,
                "amount_formatted": format_amount(amount_sat),
                "txid": tx.txid().to_hex(),
                "remaining_sat": node.pool_sessions.iter()
                    .find(|s| s.session_token == token).map(|s| s.balance_sat).unwrap_or(0),
            }), id)
        }
        Err(e) => err(-5, &format!("withdrawal failed: {e}"), id),
    }
}

/// Legacy batch payout: pays all workers (both legacy and sessions).
fn handle_pool_payout(
    node: &mut Node<FileStore>,
    w: &Wallet,
    _ks: &FileKeyStore,
    params: &[Value],
    id: Value,
) -> String {
    let only_name = params.first().and_then(|v| v.as_str()).map(|s| s.to_string());
    let mut total_paid: u64 = 0;
    let mut payouts: Vec<Value> = Vec::new();

    // Pay legacy workers.
    for worker in &node.pool_workers.clone() {
        if worker.earned == 0 || worker.payout_addr.is_none() { continue; }
        if let Some(ref only) = only_name { if &worker.name != only { continue; } }
        let addr = worker.payout_addr.as_ref().unwrap();
        let (_, to_commit) = match mldsa::parse_address(addr) {
            Some(c) => c,
            None => { payouts.push(json!({"worker": worker.name, "error": "invalid payout address"})); continue; }
        };
        match w.spend_from(&node.store, 0, to_commit, Amount(worker.earned)) {
            Ok(tx) => {
                total_paid += worker.earned;
                payouts.push(json!({"worker": worker.name, "amount": worker.earned, "amount_formatted": format_amount(worker.earned), "txid": tx.txid().to_hex()}));
                write_tx(&tx);
                if let Some(w2) = node.pool_workers.iter_mut().find(|w2| w2.name == worker.name) { w2.earned = 0; }
            }
            Err(e) => { payouts.push(json!({"worker": worker.name, "error": format!("send failed: {e}")})); }
        }
    }

    // Pay registered sessions.
    for session in &node.pool_sessions.clone() {
        if session.balance_sat == 0 { continue; }
        if let Some(ref only) = only_name { if &session.label != only { continue; } }
        let (_, to_commit) = mldsa::parse_address(&session.address).unwrap();
        match w.spend_from(&node.store, 0, to_commit, Amount(session.balance_sat)) {
            Ok(tx) => {
                total_paid += session.balance_sat;
                payouts.push(json!({"worker": session.label, "amount": session.balance_sat, "amount_formatted": format_amount(session.balance_sat), "txid": tx.txid().to_hex()}));
                write_tx(&tx);
                if let Some(s) = node.pool_sessions.iter_mut().find(|s| s.session_token == session.session_token) {
                    s.balance_sat = 0;
                }
            }
            Err(e) => { payouts.push(json!({"worker": session.label, "error": format!("send failed: {e}")})); }
        }
    }

    ok(json!({"total_paid": total_paid, "total_paid_formatted": format_amount(total_paid), "payouts": payouts}), id)
}

/// Parse an amount string (e.g. "1.5" → 150_000_000 sat) or raw satoshi count.
fn parse_amount_sat(s: &str) -> u64 {
    let s = s.trim();
    if s.contains('.') {
        // LIT format
        if let Some((whole, frac)) = s.split_once('.') {
            let whole: u64 = whole.parse().unwrap_or(0);
            let frac = frac.trim_end_matches('0');
            let frac_val: u64 = frac.parse().unwrap_or(0);
            let scale = 10u64.pow(8u32.saturating_sub(frac.len() as u32));
            whole * COIN + frac_val * scale
        } else {
            s.parse().unwrap_or(0)
        }
    } else {
        // Raw satoshis or LIT without decimal
        s.parse().unwrap_or(0)
    }
}

fn handle_getpeerinfo(
    _node: &Node<FileStore>,
    peers: &PeerMap,
    _params: &[Value],
    id: Value,
) -> String {
    let peers_guard = peers.lock().unwrap();
    let info: Vec<Value> = peers_guard
        .keys()
        .map(|addr| json!({"addr": addr.to_string()}))
        .collect();
    ok(json!(info), id)
}

fn handle_setmining(node: &mut Node<FileStore>, params: &[Value], id: Value) -> String {
    let enabled = params.first().and_then(|v| v.as_bool()).unwrap_or(false);
    node.mining_enabled = enabled;
    ok(json!({"mining_enabled": enabled}), id)
}

fn handle_getminingstatus(node: &Node<FileStore>, _params: &[Value], id: Value) -> String {
    ok(json!({"mining_enabled": node.mining_enabled}), id)
}

fn handle_getconnectioncount(
    _node: &Node<FileStore>,
    peers: &PeerMap,
    _params: &[Value],
    id: Value,
) -> String {
    ok(json!(peers.lock().unwrap().len()), id)
}

fn handle_get_utxos(node: &Node<FileStore>, params: &[Value], id: Value) -> String {
    let commits: Vec<String> = match params.first() {
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        _ => return err(-32602, "expected array of hex commitments", id),
    };
    // Build a set of commits to filter on.
    let targets: Vec<Option<[u8; 20]>> = commits
        .iter()
        .map(|h| {
            let b = hex::decode(h).ok()?;
            if b.len() != 20 {
                return None;
            }
            let mut c = [0u8; 20];
            c.copy_from_slice(&b);
            Some(c)
        })
        .collect();
    let mut results = Vec::new();
    for (op, out) in node.store.iter_utxos() {
        let Ok(commit) = <[u8; 20]>::try_from(out.script_pubkey.as_slice()) else {
            continue;
        };
        if !targets.iter().any(|t| t.as_ref() == Some(&commit)) {
            continue;
        }
        let height = node.store.coinbase_height(&op).unwrap_or(0);
        results.push(json!({
            "txid": op.txid.to_hex(),
            "vout": op.index,
            "value": out.value.0,
            "commit": hex::encode(out.script_pubkey),
            "height": height,
        }));
    }
    ok(json!(results), id)
}

fn handle_get_tx(node: &Node<FileStore>, params: &[Value], id: Value) -> String {
    let txid_hex = params.first().and_then(|v| v.as_str()).unwrap_or("");
    let txid = match hash32_from_hex(txid_hex) {
        Some(h) => h,
        None => return err(-5, "invalid txid", id),
    };
    // Check mempool first.
    for tx in &node.mempool {
        if tx.txid() == txid {
            return ok(
                json!({
                    "hex": hex::encode(to_bytes(tx)),
                    "confirmations": 0,
                }),
                id,
            );
        }
    }
    // Walk the best chain backwards to find the tx.
    let mut cur = node.tip;
    let tip_height = node.best_height();
    while cur.0 != [0u8; 32] {
        if let Some(block) = node.store.get_block(&cur) {
            for tx in &block.txs {
                if tx.txid() == txid {
                    let confirmations = tip_height.saturating_sub(block.header.height) + 1;
                    return ok(
                        json!({
                            "hex": hex::encode(to_bytes(tx)),
                            "confirmations": confirmations,
                        }),
                        id,
                    );
                }
            }
            cur = block.header.prev_block;
        } else {
            break;
        }
    }
    err(-5, "transaction not found", id)
}

fn handle_broadcast_raw_tx(node: &mut Node<FileStore>, params: &[Value], id: Value) -> String {
    let hex_str = params.first().and_then(|v| v.as_str()).unwrap_or("");
    let bytes = match hex::decode(hex_str) {
        Ok(b) => b,
        Err(_) => return err(-5, "invalid hex", id),
    };
    let tx = match Transaction::decode(&mut Reader::new(&bytes)) {
        Ok(t) => t,
        Err(_) => return err(-5, "invalid tx encoding", id),
    };
    let from: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
    if !node.accept_tx(tx.clone(), from) {
        return err(-25, "transaction rejected", id);
    }
    write_tx(&tx);
    ok(json!(tx.txid().to_hex()), id)
}

fn handle_get_header_by_height(node: &Node<FileStore>, params: &[Value], id: Value) -> String {
    let height = params.first().and_then(|v| v.as_u64()).unwrap_or(0);
    let hash = match node.chain.get(&height) {
        Some((h, _)) => *h,
        None => return err(-5, "height out of range", id),
    };
    let block = match node.store.get_block(&hash) {
        Some(b) => b,
        None => return err(-5, "block not found", id),
    };
    ok(
        json!({
            "hex": hex::encode(to_bytes(&block.header)),
            "hash": hash.to_hex(),
            "height": height,
        }),
        id,
    )
}

fn handle_get_network_params(node: &Node<FileStore>, _params: &[Value], id: Value) -> String {
    ok(
        json!({
            "version": 1,
            "subsidy": litc_core::block_subsidy(node.best_height()).0,
            "halving_interval": litc_core::HALVING_INTERVAL,
            "coinbase_maturity": litc_core::COINBASE_MATURITY,
            "target_interval": 15,
            "decimals": 8,
        }),
        id,
    )
}

/// Methods safe to expose publicly (read-only + light wallet + pool mining).
const PUBLIC_METHODS: &[&str] = &[
    "getblockcount", "getbestblockhash", "getblockhash", "getblock",
    "getinfo", "getmininginfo", "getconnectioncount", "getpeerinfo",
    "get_utxos", "get_tx", "broadcast_raw_tx",
    "get_header_by_height", "get_network_params",
    "getblocktemplate", "submitblock", "getpoolinfo",
    "pool_register", "pool_balance",
];

fn handle_request(
    node: &Arc<Mutex<Node<FileStore>>>,
    ks: &FileKeyStore,
    wallet: &Wallet,
    peers: &PeerMap,
    req: RpcRequest,
    access: Access,
) -> String {
    let id = req.id.unwrap_or(Value::Null);

    if access == Access::Public && !PUBLIC_METHODS.contains(&req.method.as_str()) {
        return err(-32601, &format!("method not found: {}", req.method), id);
    }

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
            handle_getbalance(&n, wallet, &req.params, id)
        }
        "getaddress" => {
            let n = node.lock().unwrap();
            handle_getaddress(&n, wallet, &req.params, id)
        }
        "signmessage" => {
            let n = node.lock().unwrap();
            handle_signmessage(&n, wallet, &req.params, id)
        }
        "gettransaction" => {
            let n = node.lock().unwrap();
            handle_gettransaction(&n, &req.params, id)
        }
        "listunspent" => {
            let n = node.lock().unwrap();
            handle_listunspent(&n, wallet, &req.params, id)
        }
        "send" => {
            let n = node.lock().unwrap();
            handle_send(&n, wallet, ks, &req.params, id)
        }
        "getmininginfo" => {
            let n = node.lock().unwrap();
            handle_getmininginfo(&n, &req.params, id)
        }
        "getblocktemplate" => {
            let mut n = node.lock().unwrap();
            handle_getblocktemplate(&mut n, &req.params, id)
        }
        "submitblock" => {
            let mut n = node.lock().unwrap();
            handle_submitblock(&mut n, &req.params, id)
        }
        "pool_register" => {
            let mut n = node.lock().unwrap();
            handle_pool_register(&mut n, &req.params, id)
        }
        "pool_balance" => {
            let n = node.lock().unwrap();
            handle_pool_balance(&n, &req.params, id)
        }
        "pool_withdraw" => {
            let mut n = node.lock().unwrap();
            handle_pool_withdraw(&mut n, wallet, &req.params, id)
        }
        "pool_payout" => {
            let mut n = node.lock().unwrap();
            handle_pool_payout(&mut n, wallet, ks, &req.params, id)
        }
        "getpoolinfo" => {
            let n = node.lock().unwrap();
            handle_getpoolinfo(&n, &req.params, id)
        }
        "getpeerinfo" => {
            let n = node.lock().unwrap();
            handle_getpeerinfo(&n, peers, &req.params, id)
        }
        "setmining" => {
            let mut n = node.lock().unwrap();
            handle_setmining(&mut n, &req.params, id)
        }
        "getminingstatus" => {
            let n = node.lock().unwrap();
            handle_getminingstatus(&n, &req.params, id)
        }
        "getconnectioncount" => {
            let n = node.lock().unwrap();
            handle_getconnectioncount(&n, peers, &req.params, id)
        }
        "get_utxos" => {
            let n = node.lock().unwrap();
            handle_get_utxos(&n, &req.params, id)
        }
        "get_tx" => {
            let n = node.lock().unwrap();
            handle_get_tx(&n, &req.params, id)
        }
        "broadcast_raw_tx" => {
            let mut n = node.lock().unwrap();
            handle_broadcast_raw_tx(&mut n, &req.params, id)
        }
        "get_header_by_height" => {
            let n = node.lock().unwrap();
            handle_get_header_by_height(&n, &req.params, id)
        }
        "get_network_params" => {
            let n = node.lock().unwrap();
            handle_get_network_params(&n, &req.params, id)
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
    access: Access,
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
        if let Some(cl) = line
            .strip_prefix("Content-Length:")
            .or_else(|| line.strip_prefix("content-length:"))
        {
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

    let resp = handle_request(&node, &ks, &wallet, &peers, req, access);
    let _ = write_response(&mut stream, &resp);
}

fn start_listener(
    bind_addr: std::net::SocketAddr,
    node: Arc<Mutex<Node<FileStore>>>,
    wallet_seed: Option<[u8; 32]>,
    peers: PeerMap,
    access: Access,
    label: &str,
) {
    let addr = bind_addr;
    let listener = match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("{RED}{BOLD}[{label}]{RESET} {RED}cannot bind {addr}: {e}{RESET}");
            return;
        }
    };
    println!("{MAGENTA}{BOLD}[{label}]{RESET} {MAGENTA}listening on {addr}{RESET}");

    for stream in listener.incoming().flatten() {
        let node = node.clone();
        let peers = peers.clone();
        let seed = wallet_seed;
        let acc = access;
        thread::spawn(move || {
            let wallet = Wallet::new(seed.unwrap_or([0u8; 32]));
            let ks = FileKeyStore::new(
                std::env::var("LITC_DATADIR")
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|_| std::path::PathBuf::from("data"))
                    .join("wallet.dat"),
            );
            handle_conn(stream, node, ks, wallet, peers, acc);
        });
    }
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
    bind_addr: std::net::SocketAddr,
    node: Arc<Mutex<Node<FileStore>>>,
    wallet_seed: [u8; 32],
    peers: PeerMap,
) {
    start_listener(bind_addr, node, Some(wallet_seed), peers, Access::Admin, "rpc");
}

pub fn start_public(
    bind_addr: std::net::SocketAddr,
    node: Arc<Mutex<Node<FileStore>>>,
    peers: PeerMap,
) {
    start_listener(bind_addr, node, None, peers, Access::Public, "pub");
}

/// Start an SSE event server for pool miners on `bind_addr`.
/// Miners connect to `http://<host>:<port>/events?session=<token>` and receive
/// real-time events (block_found, payout, balance).
pub fn start_events(
    bind_addr: std::net::SocketAddr,
    node: Arc<Mutex<Node<FileStore>>>,
) {
    let listener = match TcpListener::bind(bind_addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("{RED}{BOLD}[events]{RESET} {RED}cannot bind {bind_addr}: {e}{RESET}");
            return;
        }
    };
    println!("{MAGENTA}{BOLD}[events]{RESET} {MAGENTA}SSE events on {bind_addr}{RESET}");

    for stream in listener.incoming().flatten() {
        let node = node.clone();
        thread::spawn(move || handle_sse(stream, node));
    }
}

fn handle_sse(mut stream: TcpStream, node: Arc<Mutex<Node<FileStore>>>) {
    let mut reader = std::io::BufReader::new(&mut stream);
    let mut buf = Vec::new();

    // Read request line: GET /events?session=<token> HTTP/1.1
    buf.clear();
    if reader.read_until(b'\n', &mut buf).is_err() {
        return;
    }
    let request_line = String::from_utf8_lossy(&buf);
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let path = parts[1];

    // Parse session token from query param `?session=`.
    let token_hex = if let Some(query) = path.split('?').nth(1) {
        let mut t = String::new();
        for pair in query.split('&') {
            if let Some(val) = pair.strip_prefix("session=") {
                t = val.to_string();
                break;
            }
        }
        t
    } else {
        String::new()
    };
    let token = match hash32_from_hex(&token_hex) {
        Some(t) => t,
        None => {
            let resp = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nmissing or invalid session token";
            let _ = stream.write_all(resp.as_bytes());
            return;
        }
    };

    // Check session exists.
    {
        let n = node.lock().unwrap();
        if !n.pool_sessions.iter().any(|s| s.session_token == token) {
            let resp = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nsession not found";
            let _ = stream.write_all(resp.as_bytes());
            return;
        }
    }

    // Read remaining headers (drain).
    loop {
        buf.clear();
        if reader.read_until(b'\n', &mut buf).is_err() { break; }
        let line = String::from_utf8_lossy(&buf).trim().to_string();
        if line.is_empty() || line == "\r" { break; }
    }

    // Send SSE headers.
    let headers = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\nAccess-Control-Allow-Origin: *\r\n\r\n";
    if stream.write_all(headers.as_bytes()).is_err() {
        return;
    }
    let _ = stream.flush();

    // Track which events we've already sent.
    let mut sent_count: usize = 0;

    loop {
        let events: Vec<String> = {
            let n = node.lock().unwrap();
            if let Some(s) = n.pool_sessions.iter().find(|s| s.session_token == token) {
                s.events[sent_count..].to_vec()
            } else {
                break;
            }
        };

        if events.is_empty() {
            // Send a keepalive comment every 2 seconds.
            if stream.write_all(b": keepalive\n\n").is_err() { break; }
            let _ = stream.flush();
            std::thread::sleep(std::time::Duration::from_secs(2));
            continue;
        }

        for event_str in &events {
            // event_str is JSON like {"event": "block_found", ...}
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(event_str) {
                if let Some(event_type) = val.get("event").and_then(|v| v.as_str()) {
                    let data = serde_json::to_string(&val).unwrap_or_default();
                    let sse = format!("event: {event_type}\ndata: {data}\n\n");
                    if stream.write_all(sse.as_bytes()).is_err() { return; }
                }
            }
        }
        let _ = stream.flush();
        sent_count += events.len();
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
