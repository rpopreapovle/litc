//! The `litc` command-line client.
//!
//! Subcommands:
//!   litc node [...]                 — run the P2P/node daemon
//!   litc wallet new                 — create wallet, print mnemonic + address
//!   litc wallet restore <phrase>    — restore wallet from BIP39 mnemonic phrase
//!   litc wallet balance             — show confirmed balance
//!
//! State lives under `$LITC_DATADIR` (default `./data`): `wallet.dat` (32-byte
//! seed derived from BIP39 mnemonic), and the chain files (`chain.dat`,
//! `chain.idx`, `utxo.dat`, `tip.dat`).
//! `litc wallet send` writes the signed transaction to `data/mempool/<txid>.tx`;
//! a running `litc node` picks it up and mines it.

use std::env;
use std::path::PathBuf;

use std::thread;

use bip39::{Language, Mnemonic};
use litc_keystore::{FileKeyStore, KeyStore};
use litc_pow::{meets_target, mine, prepare_epoch};
use litc_primitives::{mldsa, sha256d, to_bytes, Amount, Block, Decodable, Hash32, Reader, Transaction, COIN};
use litc_store::{FileStore, UtxoStore};
use litc_wallet::Wallet;

use serde_json::json;

fn datadir() -> PathBuf {
    env::var("LITC_DATADIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("data"))
}

fn open_wallet() -> (Wallet, FileKeyStore) {
    let ks = FileKeyStore::new(datadir().join("wallet.dat"));
    let seed = ks.open_or_create().expect("cannot open keystore");
    (Wallet::new(seed), ks)
}

/// Derive a 32-byte wallet seed from a BIP39 mnemonic (PBKDF2 → first 32 bytes).
fn seed_from_mnemonic(phrase: &str) -> Result<[u8; 32], String> {
    let m = Mnemonic::parse_in_normalized(Language::English, phrase)
        .map_err(|e| format!("invalid BIP39 phrase: {e}"))?;
    let seed64 = m.to_seed("");
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed64[..32]);
    Ok(seed)
}

fn open_store() -> FileStore {
    FileStore::open(datadir(), None).expect("cannot open chain store")
}

/// Parse an amount: either whole satoshis, or `<n>.<frac>LIT`.
fn parse_amount(s: &str) -> Result<u64, String> {
    if let Some((whole, frac)) = s.split_once('.') {
        let whole: u64 = whole.parse().map_err(|_| "bad amount".to_string())?;
        let frac = frac.trim_end_matches('0');
        let frac_val: u64 = if frac.is_empty() {
            0
        } else {
            frac.parse().map_err(|_| "bad amount".to_string())?
        };
        // frac is up to 8 digits; scale to satoshis.
        let scale = 10u64
            .checked_pow(8u32.saturating_sub(frac.len() as u32))
            .ok_or("bad amount")?;
        Ok(whole * COIN + frac_val * scale)
    } else {
        s.parse::<u64>().map_err(|_| "bad amount".to_string())
    }
}

fn write_tx(tx: &Transaction) {
    let id: Hash32 = tx.txid();
    let dir = datadir().join("mempool");
    std::fs::create_dir_all(&dir).expect("cannot create mempool dir");
    let path = dir.join(format!("{}.tx", id.to_hex()));
    std::fs::write(&path, to_bytes(tx)).expect("cannot write tx");
    let hex: String = to_bytes(tx).iter().map(|b| format!("{b:02x}")).collect();
    println!("txid  {}", id.to_hex());
    println!("hex   {}", hex);
    println!("saved  {}", path.display());
}

fn cmd_wallet(args: &[String]) {
    if args.is_empty() {
        eprintln!("usage: litc wallet <new|restore|address|addresses|balance|history|send|export|debug>");
        return;
    }
    match args[0].as_str() {
        "new" => {
            let ks = FileKeyStore::new(datadir().join("wallet.dat"));
            if ks.exists() {
                eprintln!("wallet already exists at {}", datadir().join("wallet.dat").display());
                return;
            }
            // Generate 256-bit entropy → BIP39 24-word mnemonic → PBKDF2 seed.
            let entropy = litc_keystore::random_seed().expect("cannot get entropy");
            let mnemonic = Mnemonic::from_entropy(&entropy).expect("valid entropy");
            let seed64 = mnemonic.to_seed("");
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&seed64[..32]);
            ks.save_seed(&seed).expect("cannot save keystore");
            let w = Wallet::new(seed);
            println!("mnemonic seed phrase (24 words — write this down!):");
            println!("{}", mnemonic);
            println!();
            println!("address: {}",
                w.address_at(0, mldsa::MAINNET_VERSION));
        }
        "restore" => {
            if args.len() < 2 {
                eprintln!("usage: litc wallet restore \"<24-word BIP39 phrase>\"");
                return;
            }
            let ks = FileKeyStore::new(datadir().join("wallet.dat"));
            if ks.exists() {
                eprintln!("wallet already exists; remove {} first",
                    datadir().join("wallet.dat").display());
                return;
            }
            let seed = match seed_from_mnemonic(&args[1]) {
                Ok(s) => s,
                Err(e) => { eprintln!("{e}"); return; }
            };
            ks.save_seed(&seed).expect("cannot save keystore");
            let w = Wallet::new(seed);
            println!("restored from mnemonic");
            println!("address: {}",
                w.address_at(0, mldsa::MAINNET_VERSION));
        }
        "address" => {
            let (w, _ks) = open_wallet();
            let idx: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            println!("{}", w.address_at(idx, mldsa::MAINNET_VERSION));
        }
        "addresses" => {
            let (w, _ks) = open_wallet();
            let count: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(10);
            for i in 0..count as u32 {
                println!("{}  index={i}", w.address_at(i, mldsa::MAINNET_VERSION));
            }
        }
        "balance" => {
            let (w, _ks) = open_wallet();
            let store = open_store();
            let utxos = store.iter_utxos();
            let mut sum: u64 = 0;
            let mut count = 0u64;
            for (_op, out) in &utxos {
                for idx in 0..=200u32 {
                    let commit = w.commitment_at(idx);
                    if out.script_pubkey.len() >= 20 && &out.script_pubkey[..20] == commit {
                        sum += out.value.0;
                        count += 1;
                        break;
                    }
                }
            }
            println!("balance  {} sat ({}.{:08} LIT) in {count} UTXOs",
                sum, sum / COIN, sum % COIN);
        }
        "history" => {
            let (w, _ks) = open_wallet();
            let store = open_store();
            let mut idx = 0u32;
            let mut found_any = false;
            loop {
                let commit = w.commitment_at(idx);
                if let Some(op) = store.find_by_commit(&commit) {
                    if let Some(out) = store.utxo(&op) {
                        println!("  {}  index={idx}  {}.{:08} LIT",
                            op.txid.to_hex(),
                            out.value.0 / COIN,
                            out.value.0 % COIN);
                        found_any = true;
                    }
                    idx += 1;
                } else {
                    let mut found_more = false;
                    for gap in 1..=20u32 {
                        if let Some(op2) = store.find_by_commit(&w.commitment_at(idx + gap)) {
                            if let Some(out2) = store.utxo(&op2) {
                                println!("  {}  index={}  {}.{:08} LIT",
                                    op2.txid.to_hex(),
                                    idx + gap,
                                    out2.value.0 / COIN,
                                    out2.value.0 % COIN);
                                found_any = true;
                            }
                            found_more = true;
                        }
                    }
                    if found_more {
                        idx += 1;
                        continue;
                    }
                    break;
                }
            }
            if !found_any {
                println!("no transactions found");
            }
        }
        "send" => {
            if args.len() < 3 {
                eprintln!("usage: litc wallet send <to-address> <amount> [--from idx]");
                return;
            }
            let to = args[1].clone();
            let value = match parse_amount(&args[2]) {
                Ok(v) => Amount(v),
                Err(e) => {
                    eprintln!("{e}");
                    return;
                }
            };
            let from = parse_from(&args[3..]);
            let (w, _ks) = open_wallet();
            let store = open_store();
            // Parse bech32m recipient address → 20-byte commitment.
            let (_v, to_commit) = match mldsa::parse_address(&to) {
                Some(c) => c,
                None => {
                    eprintln!("invalid ML-DSA-2 address: {to}");
                    return;
                }
            };
            match w.spend_from(&store, from, to_commit, value) {
                Ok(tx) => write_tx(&tx),
                Err(e) => eprintln!("send failed: {e}"),
            }
        }
        "export" => {
            let ks = FileKeyStore::new(datadir().join("wallet.dat"));
            let seed = ks.load_seed().expect("cannot load keystore");
            // Regenerate mnemonic from seed (not perfectly round-trippable via
            // PBKDF2, so we just show the raw hex seed).
            println!("seed (hex): {}", seed.iter().map(|b| format!("{b:02x}")).collect::<String>());
            println!();
            let w = Wallet::new(seed);
            println!("address: {}",
                w.address_at(0, mldsa::MAINNET_VERSION));
        }
        "debug" => {
            let (w, _ks) = open_wallet();
            let store = open_store();
            let utxos = store.iter_utxos();
            eprintln!("=== DEBUG: all UTXOs in store ({}) ===", utxos.len());
            for (op, out) in &utxos {
                eprintln!("  txid={} idx={} val={} script={} script_hex={}",
                    op.txid.to_hex(), op.index, out.value.0,
                    out.script_pubkey.len(),
                    out.script_pubkey.iter().map(|b| format!("{b:02x}")).collect::<String>());
            }
            eprintln!("=== wallet commitment at index 0 ===");
            let commit = w.commitment_at(0);
            eprintln!("  commit_hex={}", commit.iter().map(|b| format!("{b:02x}")).collect::<String>());
            eprintln!("  address={}", w.address_at(0, mldsa::MAINNET_VERSION));
            eprintln!("=== scanning ===");
            let mut idx = 0u32;
            loop {
                let c = w.commitment_at(idx);
                let found = store.find_by_commit(&c);
                eprintln!("  idx={idx} commit={} found={}",
                    c.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    found.is_some());
                if found.is_none() { break; }
                idx += 1;
                if idx > 20 { break; }
            }
        }
        other => eprintln!("unknown wallet subcommand: {other}"),
    }
}

/// Parse a trailing `--from <idx>` argument; default 0.
fn parse_from(rest: &[String]) -> u32 {
    let mut i = 0;
    while i + 1 < rest.len() {
        if rest[i] == "--from" {
            if let Ok(v) = rest[i + 1].parse() {
                return v;
            }
        }
        i += 1;
    }
    0
}

/// Call a JSON-RPC method on a pool node. Returns the result value.
fn rpc_call(url: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
    });
    let resp = ureq::post(url)
        .set("Content-Type", "application/json")
        .send_json(body)
        .map_err(|e| format!("RPC error: {e}"))?;
    let v: serde_json::Value = resp.into_json().map_err(|e| format!("bad JSON: {e}"))?;
    if let Some(e) = v.get("error") {
        if !e.is_null() {
            return Err(format!("RPC error: {e}"));
        }
    }
    v.get("result")
        .cloned()
        .ok_or_else(|| "no result in RPC response".to_string())
}

/// Pool mining client: fetches block templates from a pool node and mines them.
fn cmd_pool_mine(args: &[String]) {
    if args.is_empty() {
        eprintln!("usage: litc pool-mine <rpc-url> [worker-name]");
        return;
    }
    let url = args[0].trim_end_matches('/');
    let worker = args.get(1).cloned().unwrap_or_default();
    let mut nonce_start: u64 = {
        let seed = litc_keystore::random_seed().unwrap_or([0u8; 32]);
        u64::from_be_bytes(seed[..8].try_into().unwrap())
    };
    let mut last_epoch = Hash32([0u8; 32]);
    let mut scratch: Option<litc_pow::Scratch> = None;
    loop {
        // Fetch a fresh block template.
        let tmpl = match rpc_call(&url, "getblocktemplate", json!([worker])) {
            Ok(v) => v,
            Err(e) => { eprintln!("[pool] {e}"); thread::sleep(std::time::Duration::from_secs(5)); continue; }
        };
        let block_hex = tmpl["block_hex"].as_str().unwrap_or("");
        let target_hex = tmpl["target_hex"].as_str().unwrap_or("");
        let height = tmpl["height"].as_u64().unwrap_or(0);
        let block_bytes = match hex::decode(block_hex) {
            Ok(b) => b,
            Err(_) => { eprintln!("[pool] bad block hex"); thread::sleep(std::time::Duration::from_secs(5)); continue; }
        };
        let target = match hex::decode(target_hex) {
            Ok(b) if b.len() == 32 => { let mut t = [0u8; 32]; t.copy_from_slice(&b); t }
            _ => { eprintln!("[pool] bad target"); thread::sleep(std::time::Duration::from_secs(5)); continue; }
        };
        let mut block = match Block::decode(&mut Reader::new(&block_bytes)) {
            Ok(b) => b,
            Err(_) => { eprintln!("[pool] bad block"); thread::sleep(std::time::Duration::from_secs(5)); continue; }
        };
        // Prepare scratchpad once per epoch.
        let epoch_seed = block.header.epoch_seed;
        if scratch.is_none() || epoch_seed != last_epoch {
            scratch = Some(prepare_epoch(&epoch_seed.0));
            last_epoch = epoch_seed;
            eprintln!("[pool] new epoch at height {height}");
        }
        // Compute the PoW challenge (SHA-256d of header without nonce).
        let mut hb = to_bytes(&block.header);
        hb.truncate(hb.len() - 8);
        let challenge = sha256d(&hb).0;
        let mut nonce = nonce_start;
        let start = nonce;
        loop {
            let digest = mine(scratch.as_ref().unwrap(), nonce, &challenge);
            if meets_target(&digest, &target) {
                block.header.nonce = nonce;
                let submit_hex: String = to_bytes(&block).iter().map(|b| format!("{b:02x}")).collect();
                match rpc_call(&url, "submitblock", json!([submit_hex, worker])) {
                    Ok(_) => eprintln!("[pool] block #{height} found! nonce={nonce}"),
                    Err(e) => eprintln!("[pool] submit failed: {e}"),
                }
                nonce_start = nonce.wrapping_add(1);
                break;
            }
            nonce = nonce.wrapping_add(1);
            if nonce == start {
                eprintln!("[pool] height {height}: nonce space exhausted");
                thread::sleep(std::time::Duration::from_secs(1));
                break;
            }
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: litc <node|wallet|pool-mine> [...]");
        return;
    }
    match args[1].as_str() {
        "node" => {
            // Hand the remaining args to the node, prefixed with a program name.
            let mut v = vec!["litc-node".to_string()];
            v.extend_from_slice(&args[2..]);
            litc_node::run(v);
        }
        "wallet" => cmd_wallet(&args[2..]),
        "pool-mine" => cmd_pool_mine(&args[2..]),
        other => eprintln!("unknown subcommand: {other} (expected `node` | `wallet` | `pool-mine`)"),
    }
}
