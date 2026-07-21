//! The `litc` command-line client.
//!
//! Subcommands:
//!   litc node [...]                 — run the P2P/node daemon
//!   litc wallet new                 — create wallet, print mnemonic + stealth address
//!   litc wallet restore <phrase>    — restore wallet from BIP39 mnemonic phrase
//!   litc wallet stealth             — print the reusable stealth address
//!   litc wallet balance             — show confirmed balance (stealth)
//!   litc wallet scan                — list owned stealth outputs
//!   litc wallet send-stealth <to> <amt> [--from i] — pay a stealth address
//!
//! State lives under `$LITC_DATADIR` (default `./data`): `wallet.dat` (32-byte
//! seed derived from BIP39 mnemonic), `wallet.dat.stealth` (recovered spend
//! keys), and the chain files (`chain.dat`, `chain.idx`, `utxo.dat`,
//! `burnt.dat`, `tip.dat`).
//! `wallet send-stealth` writes the signed transaction to `data/mempool/<txid>.tx`;
//! a running `litc node` picks it up and mines it.

use std::env;
use std::path::PathBuf;

use bip39::{Language, Mnemonic};
use litc_keystore::{FileKeyStore, KeyStore};
use litc_primitives::{to_bytes, Amount, Hash32, Transaction, COIN};
use litc_store::FileStore;
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
        eprintln!("usage: litc wallet <new|restore|stealth|balance|scan|send-stealth>");
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
            println!("stealth address: {}",
                w.stealth_address(litc_primitives::stealth::STEALTH_VERSION_MAINNET));
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
            println!("stealth address: {}",
                w.stealth_address(litc_primitives::stealth::STEALTH_VERSION_MAINNET));
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
            let owned = w.scan_chain(&store, &_ks).unwrap_or_default();
            let stealth: u64 = owned.iter().map(|o| o.value.0).sum();
            println!(
                "stealth {:>16} sat ({}.{:08} LIT)",
                stealth,
                stealth / COIN,
                stealth % COIN
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
