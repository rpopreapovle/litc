use litc_core::sighash;
use litc_keystore::KeyStore;
use litc_primitives::{mldsa, Amount, Hash32, OutPoint, SignatureScheme, Transaction, TxIn, TxOut};
use litc_wallet::Wallet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoInfo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub commit: String,
    pub height: u64,
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

    pub fn build_send(
        &self,
        utxo: &UtxoInfo,
        from_index: u32,
        to_commit: [u8; 20],
        value: Amount,
        _ks: &dyn KeyStore,
    ) -> Result<Transaction, Error> {
        let kp = self.wallet.keypair_at(from_index);
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
                scheme: SignatureScheme::Mldsa2,
                sequence: 0xFFFF_FFFF,
            }],
            outputs: vec![
                TxOut {
                    value,
                    script_pubkey: to_commit.to_vec(),
                },
                TxOut {
                    value: Amount(change),
                    script_pubkey: change_commit.to_vec(),
                },
            ],
            lock_time: 0,
        };
        let msg = sighash(&tx, 0, &prev_script);
        let pk = kp.public_key_bytes();
        let sig = kp.sign(&msg);
        let mut script_sig = Vec::with_capacity(mldsa::PK_LEN + mldsa::SIG_LEN);
        script_sig.extend_from_slice(&pk);
        script_sig.extend_from_slice(&sig);
        tx.inputs[0].script_sig = script_sig;
        Ok(tx)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_send_basic() {
        let seed = [0xABu8; 32];
        let lw = LightWallet::new(seed, "http://localhost:8080");
        let kp = lw.wallet.keypair_at(0);
        let commit = kp.pubkey_hash160();

        let utxo = UtxoInfo {
            txid: "0000000000000000000000000000000000000000000000000000000000000001".into(),
            vout: 0,
            value: 500_000_000,
            commit: hex::encode(commit),
            height: 1,
        };

        let to_commit = [0xCDu8; 20];
        let ks = litc_keystore::FileKeyStore::new("/tmp/lw_test_keystore");
        let tx = lw
            .build_send(&utxo, 0, to_commit, Amount(100_000_000), &ks)
            .unwrap();

        assert_eq!(tx.version, 1);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(tx.outputs[0].value, Amount(100_000_000));
        assert_eq!(tx.outputs[0].script_pubkey, to_commit.to_vec());
        assert_eq!(tx.outputs[1].value, Amount(400_000_000));
        assert_eq!(tx.outputs[1].script_pubkey, lw.wallet.commitment_at(1).to_vec());
        assert_eq!(tx.inputs[0].scheme, SignatureScheme::Mldsa2);
        // script_sig = pk (1312) + sig (2420) = 3732 bytes
        assert_eq!(tx.inputs[0].script_sig.len(), mldsa::PK_LEN + mldsa::SIG_LEN);
    }

    #[test]
    fn build_send_insufficient_funds() {
        let seed = [0xABu8; 32];
        let lw = LightWallet::new(seed, "http://localhost:8080");
        let kp = lw.wallet.keypair_at(0);
        let commit = kp.pubkey_hash160();

        let utxo = UtxoInfo {
            txid: "0000000000000000000000000000000000000000000000000000000000000001".into(),
            vout: 0,
            value: 100,
            commit: hex::encode(commit),
            height: 1,
        };

        let to_commit = [0xCDu8; 20];
        let ks = litc_keystore::FileKeyStore::new("/tmp/lw_test_keystore2");
        let err = lw
            .build_send(&utxo, 0, to_commit, Amount(200), &ks)
            .unwrap_err();
        match err {
            Error::InsufficientFunds { have, need } => {
                assert_eq!(have, 100);
                assert_eq!(need, 200);
            }
            other => panic!("expected InsufficientFunds, got {other:?}"),
        }
    }

    #[test]
    fn utxo_info_no_ephemeral() {
        let info = UtxoInfo {
            txid: "0000000000000000000000000000000000000000000000000000000000000001".into(),
            vout: 0,
            value: 500_000_000,
            commit: "abcdef".into(),
            height: 1,
        };
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: UtxoInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.value, 500_000_000);
        // No ephemeral field present in JSON
        assert!(!json.contains("ephemeral"));
    }

    #[test]
    fn build_send_all_to_one_output() {
        let seed = [0x11u8; 32];
        let lw = LightWallet::new(seed, "http://localhost:8080");
        let kp = lw.wallet.keypair_at(0);
        let commit = kp.pubkey_hash160();

        let utxo = UtxoInfo {
            txid: "0000000000000000000000000000000000000000000000000000000000000002".into(),
            vout: 0,
            value: 100_000_000,
            commit: hex::encode(commit),
            height: 5,
        };

        let to_commit = [0x99u8; 20];
        let ks = litc_keystore::FileKeyStore::new("/tmp/lw_test_keystore3");
        // Send the entire UTXO value (change = 0, second output still created)
        let tx = lw
            .build_send(&utxo, 0, to_commit, Amount(100_000_000), &ks)
            .unwrap();

        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(tx.outputs[0].value, Amount(100_000_000));
        assert_eq!(tx.outputs[1].value, Amount(0));
    }
}
