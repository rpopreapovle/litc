use litc_core::sighash;
use litc_keystore::{KeyStore, StealthKey};
use litc_primitives::{
    kem, stealth, wots, Amount, Hash32, OutPoint, SignatureScheme, Transaction, TxIn, TxOut,
};
use litc_wallet::{OwnedStealth, Wallet};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoInfo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub commit: String,
    pub height: u64,
    pub ephemeral: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxInfo {
    pub hex: String,
    pub confirmations: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderInfo {
    pub hex: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkParams {
    pub version: u64,
    pub subsidy: u64,
    pub halving_interval: u64,
    pub coinbase_maturity: u64,
    pub target_interval: u64,
    pub decimals: u64,
}

#[derive(Debug)]
pub enum Error {
    Http(String),
    Json(String),
    Api(i64, String),
    Wallet(String),
    InvalidAddress(String),
    InsufficientFunds { have: u64, need: u64 },
}

pub struct LightWallet {
    wallet: Wallet,
    server_url: String,
}

impl LightWallet {
    pub fn new(seed: [u8; 32], server_url: &str) -> Self {
        LightWallet {
            wallet: Wallet::new(seed),
            server_url: server_url.trim_end_matches('/').to_string(),
        }
    }

    pub fn address_at(&self, index: u32, version: u8) -> String {
        self.wallet.address_at(index, version)
    }

    pub fn commitment_at(&self, index: u32) -> [u8; 20] {
        self.wallet.commitment_at(index)
    }

    pub fn stealth_address(&self, version: u8) -> String {
        self.wallet.stealth_address(version)
    }

    pub fn kem_keypair(&self) -> ([u8; kem::KEM_PK_LEN], [u8; kem::KEM_SK_LEN]) {
        self.wallet.kem_keypair()
    }

    fn rpc_call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, Error> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        });
        #[cfg(not(target_arch = "wasm32"))]
        {
            let resp = ureq::post(&self.server_url)
                .set("Content-Type", "application/json")
                .send_string(&body.to_string())
                .map_err(|e| Error::Http(e.to_string()))?;
            let json: serde_json::Value = resp
                .into_json()
                .map_err(|e| Error::Json(e.to_string()))?;
            if let Some(err) = json.get("error").and_then(|e| e.as_object()) {
                let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
                let msg = err
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown");
                return Err(Error::Api(code, msg.to_string()));
            }
            Ok(json.get("result").cloned().unwrap_or(serde_json::Value::Null))
        }
        #[cfg(target_arch = "wasm32")]
        Err(Error::Http("HTTP not available on wasm32".into()))
    }

    pub fn fetch_network_params(&self) -> Result<NetworkParams, Error> {
        let v = self.rpc_call("get_network_params", serde_json::json!([]))?;
        serde_json::from_value(v).map_err(|e| Error::Json(e.to_string()))
    }

    pub fn fetch_balance(&self, commitments: &[[u8; 20]]) -> Result<(u64, Vec<UtxoInfo>), Error> {
        let utxos = self.fetch_utxos(commitments)?;
        let total: u64 = utxos.iter().map(|u| u.value).sum();
        Ok((total, utxos))
    }

    pub fn fetch_utxos(&self, commitments: &[[u8; 20]]) -> Result<Vec<UtxoInfo>, Error> {
        let hex_list: Vec<String> = commitments.iter().map(|c| hex::encode(c)).collect();
        let v = self.rpc_call("get_utxos", serde_json::json!([hex_list]))?;
        serde_json::from_value(v).map_err(|e| Error::Json(e.to_string()))
    }

    pub fn fetch_tx(&self, txid: &str) -> Result<TxInfo, Error> {
        let v = self.rpc_call("get_tx", serde_json::json!([txid]))?;
        serde_json::from_value(v).map_err(|e| Error::Json(e.to_string()))
    }

    pub fn fetch_header(&self, height: u64) -> Result<HeaderInfo, Error> {
        let v = self.rpc_call("get_header_by_height", serde_json::json!([height]))?;
        serde_json::from_value(v).map_err(|e| Error::Json(e.to_string()))
    }

    pub fn fetch_block_count(&self) -> Result<u64, Error> {
        let v = self.rpc_call("getblockcount", serde_json::json!([]))?;
        v.as_u64()
            .ok_or_else(|| Error::Json("expected u64".into()))
    }

    fn ensure_one_time(ks: &dyn KeyStore, commit: &[u8; 20]) -> Result<(), Error> {
        let used = ks.load_used().map_err(|e| Error::Wallet(e.to_string()))?;
        if used.iter().any(|c| c == commit) {
            return Err(Error::Wallet(
                "WOTS+ key already used — one-time signatures must never be reused".into(),
            ));
        }
        Ok(())
    }

    fn mark_one_time(ks: &dyn KeyStore, commit: &[u8; 20]) -> Result<(), Error> {
        let mut used = ks.load_used().map_err(|e| Error::Wallet(e.to_string()))?;
        if !used.iter().any(|c| c == commit) {
            used.push(*commit);
            ks.save_used(&used)
                .map_err(|e| Error::Wallet(e.to_string()))?;
        }
        Ok(())
    }

    pub fn build_send(
        &self,
        utxo: &UtxoInfo,
        from_index: u32,
        to_commit: [u8; 20],
        value: Amount,
        ks: &dyn KeyStore,
    ) -> Result<Transaction, Error> {
        let kp = self.wallet.keypair_at(from_index);
        let commit = kp.pubkey_root_hash160();
        Self::ensure_one_time(ks, &commit)?;
        let total = utxo.value;
        if value.0 > total {
            return Err(Error::InsufficientFunds {
                have: total,
                need: value.0,
            });
        }
        let change = total - value.0;
        let change_commit = self.wallet.commitment_at(from_index + 1);
        let outpoint = OutPoint {
            txid: hex_to_hash32(&utxo.txid)?,
            index: utxo.vout,
        };
        let prev_script = hex_to_vec(&utxo.commit)?;

        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prevout: outpoint,
                script_sig: vec![],
                scheme: SignatureScheme::Wots256,
                sequence: 0xFFFF_FFFF,
            }],
            outputs: vec![
                TxOut {
                    value,
                    script_pubkey: to_commit.to_vec(),
                    ephemeral: vec![],
                },
                TxOut {
                    value: Amount(change),
                    script_pubkey: change_commit.to_vec(),
                    ephemeral: vec![],
                },
            ],
            ephemeral: vec![],
            lock_time: 0,
        };
        let msg = sighash(&tx, 0, &prev_script);
        tx.inputs[0].script_sig = wots::encode_witness(&kp.sign(&msg));
        Self::mark_one_time(ks, &commit)?;
        Ok(tx)
    }

    pub fn build_send_stealth(
        &self,
        utxo: &UtxoInfo,
        from_index: u32,
        recipient: &str,
        value: Amount,
        ks: &dyn KeyStore,
    ) -> Result<Transaction, Error> {
        let (_, kem_pk) = stealth::parse_stealth_address(recipient)
            .ok_or_else(|| Error::InvalidAddress("not a stealth address".into()))?;
        let kp = self.wallet.keypair_at(from_index);
        let commit = kp.pubkey_root_hash160();
        Self::ensure_one_time(ks, &commit)?;
        let total = utxo.value;
        if value.0 > total {
            return Err(Error::InsufficientFunds {
                have: total,
                need: value.0,
            });
        }
        let change = total - value.0;
        let change_commit = self.wallet.commitment_at(from_index + 1);
        let outpoint = OutPoint {
            txid: hex_to_hash32(&utxo.txid)?,
            index: utxo.vout,
        };
        let prev_script = hex_to_vec(&utxo.commit)?;

        let (ss, ct) = kem::kem_encaps(&kem_pk);
        let stealth_out = TxOut {
            value,
            script_pubkey: stealth::stealth_script(&ss, 0).to_vec(),
            ephemeral: vec![],
        };
        let mut outputs = vec![stealth_out];
        if change > 0 {
            outputs.push(TxOut {
                value: Amount(change),
                script_pubkey: change_commit.to_vec(),
                ephemeral: vec![],
            });
        }
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prevout: outpoint,
                script_sig: vec![],
                scheme: SignatureScheme::Wots256,
                sequence: 0xFFFF_FFFF,
            }],
            outputs,
            ephemeral: ct.to_vec(),
            lock_time: 0,
        };
        let msg = sighash(&tx, 0, &prev_script);
        tx.inputs[0].script_sig = wots::encode_witness(&kp.sign(&msg));
        Self::mark_one_time(ks, &commit)?;
        Ok(tx)
    }

    pub fn build_spend_stealth(
        &self,
        utxo: &UtxoInfo,
        ks: &dyn KeyStore,
        to_commit: [u8; 20],
    ) -> Result<Transaction, Error> {
        let commit_bytes = hex_to_vec(&utxo.commit)?;
        let commit: [u8; 20] = commit_bytes
            .try_into()
            .map_err(|_| Error::InvalidAddress("bad commit hex".into()))?;
        Self::ensure_one_time(ks, &commit)?;
        let entry = ks
            .load_stealth()
            .map_err(|e| Error::Wallet(e.to_string()))?
            .into_iter()
            .find(|k| k.commit == commit)
            .ok_or_else(|| Error::Wallet("no stealth key for this output".into()))?;
        let kp = wots::WotsKeypair::new(entry.sk_seed, entry.pk_seed, entry.r);
        let outpoint = OutPoint {
            txid: hex_to_hash32(&utxo.txid)?,
            index: utxo.vout,
        };
        let prev_script = hex_to_vec(&utxo.commit)?;

        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prevout: outpoint,
                script_sig: vec![],
                scheme: SignatureScheme::Wots256,
                sequence: 0xFFFF_FFFF,
            }],
            outputs: vec![TxOut {
                value: Amount(utxo.value),
                script_pubkey: to_commit.to_vec(),
                ephemeral: vec![],
            }],
            ephemeral: vec![],
            lock_time: 0,
        };
        let msg = sighash(&tx, 0, &prev_script);
        tx.inputs[0].script_sig = wots::encode_witness(&kp.sign(&msg));
        Self::mark_one_time(ks, &commit)?;
        Ok(tx)
    }

    pub fn scan_stealth(
        &self,
        utxos: &[UtxoInfo],
        ks: &dyn KeyStore,
    ) -> Result<Vec<OwnedStealth>, Error> {
        let (_, sk) = self.wallet.kem_keypair();
        let mut known = ks.load_stealth().unwrap_or_default();
        let mut found = Vec::new();
        for utxo in utxos {
            let ephemeral = hex::decode(&utxo.ephemeral).map_err(|e| Error::Json(e.to_string()))?;
            if ephemeral.is_empty() {
                continue;
            }
            let kp = match stealth::recover_stealth_keypair_at(&sk, &ephemeral, utxo.vout) {
                Some(kp) => kp,
                None => continue,
            };
            let commit = kp.pubkey_root_hash160();
            let commit_hex = hex::encode(commit);
            if commit_hex != utxo.commit {
                continue;
            }
            let outpoint = OutPoint {
                txid: hex_to_hash32(&utxo.txid)?,
                index: utxo.vout,
            };
            if !known.iter().any(|k| k.commit == commit) {
                known.push(StealthKey {
                    commit,
                    sk_seed: kp.sk_seed,
                    pk_seed: kp.pk_seed,
                    r: kp.r,
                });
            }
            found.push(OwnedStealth {
                outpoint,
                keypair: kp,
                value: Amount(utxo.value),
            });
        }
        ks.save_stealth(&known)
            .map_err(|e| Error::Wallet(e.to_string()))?;
        Ok(found)
    }

    pub fn broadcast(&self, tx_hex: &str) -> Result<String, Error> {
        let v = self.rpc_call("broadcast_raw_tx", serde_json::json!([tx_hex]))?;
        v.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| Error::Json("expected string".into()))
    }
}

fn hex_to_hash32(s: &str) -> Result<Hash32, Error> {
    let b = hex::decode(s).map_err(|e| Error::Json(e.to_string()))?;
    if b.len() != 32 {
        return Err(Error::Json("expected 32 bytes".into()));
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&b);
    Ok(Hash32(h))
}

fn hex_to_vec(s: &str) -> Result<Vec<u8>, Error> {
    hex::decode(s).map_err(|e| Error::Json(e.to_string()))
}
