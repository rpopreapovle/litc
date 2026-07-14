//! The `litc` command-line client.
//!
//! Subcommands:
//!   litc node [...]            — run the P2P/node daemon (see `litc-node --help`)
//!   litc wallet new            — create the wallet (master seed) and print addresses
//!   litc wallet address [i]  — print the legacy WOTS+ address at index i
//!   litc wallet stealth       — print the reusable stealth address
//!   litc wallet balance      — show confirmed balance (legacy + stealth)
//!   litc wallet scan         — list owned stealth outputs found by scanning
//!   litc wallet send <to> <amt> [--from i]      — pay a legacy address
//!   litc wallet send-stealth <to> <amt> [--from i] — pay a stealth address
//!
//! State lives under `$LITC_DATADIR` (default `./data`): `wallet.dat` (seed),
//! `wallet.dat.stealth` (recovered spend keys), and the chain files
//! (`chain.dat`, `chain.idx`, `utxo.dat`, `burnt.dat`, `tip.dat`).
//! `wallet send*` writes the signed transaction to `data/mempool/<txid>.tx`;
//! a running `litc node` picks it up and mines it.

use std::env;
use std::path::PathBuf;

use litc_keystore::FileKeyStore;
use litc_primitives::{base58check_decode, to_bytes, Amount, Hash32, Transaction, COIN};
use litc_store::{FileStore, UtxoStore};
use litc_wallet::Wallet;

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

/// Decode a legacy address (`version || HASH160(R)`) to its 20-byte commitment.
fn commit_from_address(a: &str) -> Result<[u8; 20], String> {
    let (_v, payload) = base58check_decode(a).ok_or_else(|| "bad address".to_string())?;
    if payload.len() != 20 {
        return Err("address must encode a 20-byte commitment".into());
    }
    let mut c = [0u8; 20];
    c.copy_from_slice(&payload);
    Ok(c)
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

fn legacy_balance(store: &FileStore, w: &Wallet) -> u64 {
    // Find the highest used index with a 20-address gap limit.
    let mut max_idx = 0u32;
    let mut gap = 0u32;
    let mut idx = 0u32;
    loop {
        let c = w.commitment_at(idx);
        if store.find_by_commit(&c).is_some() {
            max_idx = idx;
            gap = 0;
        } else {
            gap += 1;
            if gap >= 20 {
                break;
            }
        }
        idx += 1;
        if idx > 1_000_000 {
            break;
        }
    }
    let mut total = 0u64;
    for i in 0..=max_idx {
        let c = w.commitment_at(i);
        if let Some(op) = store.find_by_commit(&c) {
            if let Some(out) = store.utxo(&op) {
                total += out.value.0;
            }
        }
    }
    total
}

fn cmd_wallet(args: &[String]) {
    if args.is_empty() {
        eprintln!("usage: litc wallet <new|address|stealth|balance|scan|send|send-stealth>");
        return;
    }
    match args[0].as_str() {
        "new" => {
            let (w, _ks) = open_wallet();
            println!(
                "legacy address (idx 0): {}",
                w.address_at(0, litc_primitives::wots::MAINNET_VERSION)
            );
            println!(
                "stealth address:        {}",
                w.stealth_address(litc_primitives::stealth::STEALTH_VERSION_MAINNET)
            );
        }
        "address" => {
            let (w, _ks) = open_wallet();
            let idx: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            println!(
                "{}",
                w.address_at(idx, litc_primitives::wots::MAINNET_VERSION)
            );
        }
        "stealth" => {
            let (w, _ks) = open_wallet();
            println!(
                "{}",
                w.stealth_address(litc_primitives::stealth::STEALTH_VERSION_MAINNET)
            );
        }
        "balance" => {
            let (w, _ks) = open_wallet();
            let store = open_store();
            let legacy = legacy_balance(&store, &w);
            // Stealth balance via a scan (also persists recovered keys).
            let (_w2, ks) = open_wallet();
            let owned = w.scan_chain(&store, &ks).unwrap_or_default();
            let stealth: u64 = owned.iter().map(|o| o.value.0).sum();
            println!(
                "legacy  {:>16} sat ({}.{:08} LIT)",
                legacy,
                legacy / COIN,
                legacy % COIN
            );
            println!(
                "stealth {:>16} sat ({}.{:08} LIT)",
                stealth,
                stealth / COIN,
                stealth % COIN
            );
            println!(
                "total   {:>16} sat ({}.{:08} LIT)",
                legacy + stealth,
                (legacy + stealth) / COIN,
                (legacy + stealth) % COIN
            );
        }
        "scan" => {
            let (w, ks) = open_wallet();
            let store = open_store();
            let owned = w.scan_chain(&store, &ks).unwrap_or_default();
            if owned.is_empty() {
                println!("no stealth outputs found");
            }
            for o in &owned {
                println!(
                    "{} value={} ({}.{:08} LIT)",
                    o.outpoint.txid.to_hex(),
                    o.value.0,
                    o.value.0 / COIN,
                    o.value.0 % COIN
                );
            }
        }
        "send" => {
            if args.len() < 3 {
                eprintln!("usage: litc wallet send <to-legacy-addr> <amount> [--from idx]");
                return;
            }
            let to = match commit_from_address(&args[1]) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("{e}");
                    return;
                }
            };
            let value = match parse_amount(&args[2]) {
                Ok(v) => Amount(v),
                Err(e) => {
                    eprintln!("{e}");
                    return;
                }
            };
            let from = parse_from(&args[3..]);
            let (w, ks) = open_wallet();
            let store = open_store();
            match w.spend_from(&store, &ks, from, to, value) {
                Ok(tx) => write_tx(&tx),
                Err(e) => eprintln!("send failed: {e}"),
            }
        }
        "send-stealth" => {
            if args.len() < 3 {
                eprintln!(
                    "usage: litc wallet send-stealth <to-stealth-addr> <amount> [--from idx]"
                );
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
            let (w, ks) = open_wallet();
            let store = open_store();
            match w.send_stealth(&store, &ks, from, &to, value) {
                Ok(tx) => write_tx(&tx),
                Err(e) => eprintln!("send failed: {e}"),
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

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: litc <node|wallet> [...]");
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
        other => eprintln!("unknown subcommand: {other} (expected `node` or `wallet`)"),
    }
}
