use eframe::egui;
use litc_primitives::{Decodable, Reader};
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Default)]
struct NodeInfo {
    version: String,
    network: String,
    blocks: u64,
    best_hash: String,
    connections: u64,
    mempool_size: u64,
}

#[derive(Clone)]
struct WalletInfo {
    address: String,
    balance: u64,
    balance_fmt: String,
    utxos: Vec<UtxoEntry>,
}

#[derive(Clone)]
struct UtxoEntry {
    txid: String,
    vout: u32,
    amount: u64,
    amount_fmt: String,
}

impl Default for WalletInfo {
    fn default() -> Self {
        Self { address: String::new(), balance: 0, balance_fmt: "0.00000000 LIT".into(), utxos: Vec::new() }
    }
}

#[derive(Clone, Default)]
struct AppState {
    node_info: Option<NodeInfo>,
    wallet_info: Option<WalletInfo>,
    mining_enabled: bool,
    error: Option<String>,
}

enum Tab { Node, Miner, Wallet }

fn rpc_call(url: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
    let url = url.trim_end_matches('/');
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(format!("Bad URL: '{url}' (method={method})"));
    }
    let body = json!({ "jsonrpc": "2.0", "method": method, "params": params, "id": 1 });
    let resp = ureq::post(url)
        .set("Content-Type", "application/json")
        .timeout(Duration::from_secs(5))
        .send_json(body)
        .map_err(|e| format!("{e}"))?;
    let v: serde_json::Value = resp.into_json().map_err(|e| format!("bad JSON: {e}"))?;
    if let Some(e) = v.get("error") {
        if !e.is_null() { return Err(format!("{}", e)); }
    }
    v.get("result").cloned().ok_or_else(|| "no result".to_string())
}

fn poll_background(state: &Arc<Mutex<AppState>>, url: &str) {
    let url = url.to_string();
    let s = state.clone();
    std::thread::spawn(move || {
        let node_info = rpc_call(&url, "getinfo", json!([])).ok().map(|v| NodeInfo {
            version: v["version"].as_str().unwrap_or("?").to_string(),
            network: v["network"].as_str().unwrap_or("?").to_string(),
            blocks: v["blocks"].as_u64().unwrap_or(0),
            best_hash: v["best_block_hash"].as_str().unwrap_or("?").to_string(),
            connections: v["connections"].as_u64().unwrap_or(0),
            mempool_size: v["mempool_size"].as_u64().unwrap_or(0),
        });

        let mining_enabled = rpc_call(&url, "getminingstatus", json!([])).ok()
            .and_then(|v| v["mining_enabled"].as_bool()).unwrap_or(false);

        let wallet_info = {
            let addr = rpc_call(&url, "getaddress", json!([])).ok().and_then(|v| v.as_str().map(String::from));
            let bal = rpc_call(&url, "getbalance", json!([])).ok();
            let utxos = rpc_call(&url, "listunspent", json!([])).ok()
                .and_then(|v| v.as_array().cloned()).unwrap_or_default();
            let entries: Vec<UtxoEntry> = utxos.iter().map(|u| UtxoEntry {
                txid: u["txid"].as_str().unwrap_or("").to_string(),
                vout: u["vout"].as_u64().unwrap_or(0) as u32,
                amount: u["amount"].as_u64().unwrap_or(0),
                amount_fmt: u["amount_formatted"].as_str().unwrap_or("0 LIT").to_string(),
            }).collect();
            let (balance, bf) = if let Some(ref b) = bal {
                (b["balance"].as_u64().unwrap_or(0), b["balance_formatted"].as_str().unwrap_or("0 LIT").to_string())
            } else { (0, "0.00000000 LIT".into()) };
            Some(WalletInfo { address: addr.unwrap_or_default(), balance, balance_fmt: bf, utxos: entries })
        };

        let mut lock = s.lock().unwrap();
        lock.node_info = node_info;
        lock.wallet_info = wallet_info;
        lock.mining_enabled = mining_enabled;
        lock.error = None;
    });
}

fn rpc_setmining(url: &str, enabled: bool) -> Result<serde_json::Value, String> {
    rpc_call(url, "setmining", json!([enabled]))
}

fn rpc_send(url: &str, to: &str, amount: &str) -> Result<serde_json::Value, String> {
    rpc_call(url, "send", json!([to, amount]))
}

fn pool_mine_loop(url: &str, worker: &str, running: Arc<AtomicBool>) {
        let url = url.trim_end_matches('/').to_string();
        let worker = worker.to_string();
        std::thread::spawn(move || {
        let mut nonce_start: u64 = {
            let seed = match litc_keystore::random_seed() {
                Ok(s) => s,
                Err(_) => [0u8; 32],
            };
            u64::from_be_bytes(seed[..8].try_into().unwrap())
        };
        let mut last_epoch = litc_primitives::Hash32([0u8; 32]);
        let mut scratch: Option<litc_pow::Scratch> = None;

        while running.load(Ordering::Relaxed) {
            let tmpl = match rpc_call(&url, "getblocktemplate", json!([worker])) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[pool] {e}");
                    std::thread::sleep(Duration::from_secs(5));
                    continue;
                }
            };
            let block_hex = tmpl["block_hex"].as_str().unwrap_or("");
            let target_hex = tmpl["target_hex"].as_str().unwrap_or("");
            let height = tmpl["height"].as_u64().unwrap_or(0);
            let block_bytes = match hex::decode(block_hex) {
                Ok(b) => b,
                Err(_) => { std::thread::sleep(Duration::from_secs(5)); continue; }
            };
            let target = match hex::decode(target_hex) {
                Ok(b) if b.len() == 32 => { let mut t = [0u8; 32]; t.copy_from_slice(&b); t }
                _ => { std::thread::sleep(Duration::from_secs(5)); continue; }
            };
            let mut block = match litc_primitives::Block::decode(&mut Reader::new(&block_bytes)) {
                Ok(b) => b,
                Err(_) => { std::thread::sleep(Duration::from_secs(5)); continue; }
            };
            let epoch_seed = block.header.epoch_seed;
            if scratch.is_none() || epoch_seed != last_epoch {
                scratch = Some(litc_pow::prepare_epoch(&epoch_seed.0));
                last_epoch = epoch_seed;
                eprintln!("[pool] new epoch at height {height}");
            }
            let mut hb = litc_primitives::to_bytes(&block.header);
            hb.truncate(hb.len() - 8);
            let challenge = litc_primitives::sha256d(&hb).0;
            let mut nonce = nonce_start;
            let start = nonce;
            loop {
                if !running.load(Ordering::Relaxed) { return; }
                let digest = litc_pow::mine(scratch.as_ref().unwrap(), nonce, &challenge);
                if litc_pow::meets_target(&digest, &target) {
                    block.header.nonce = nonce;
                    let submit_hex: String = litc_primitives::to_bytes(&block)
                        .iter().map(|b| format!("{b:02x}")).collect();
                    match rpc_call(&url, "submitblock", json!([submit_hex, worker])) {
                        Ok(_) => {
                            eprintln!("[pool] block #{height} found! nonce={nonce}");
                            std::thread::sleep(Duration::from_millis(500));
                        }
                        Err(e) => {
                            eprintln!("[pool] submit failed: {e}");
                            std::thread::sleep(Duration::from_secs(1));
                        }
                    }
                    nonce_start = nonce.wrapping_add(1);
                    break;
                }
                nonce = nonce.wrapping_add(1);
                if nonce == start {
                    std::thread::sleep(Duration::from_millis(500));
                    break;
                }
            }
        }
    });
}

struct LiTCGui {
    rpc_url: String,
    tab: Tab,
    state: Arc<Mutex<AppState>>,
    poll_count: u64,

    // Node process
    node_process: Option<std::process::Child>,

    // Send form
    send_to: String,
    send_amount: String,
    send_status: String,

    // Pool mining
    pool_url: String,
    pool_worker: String,
    pool_running: Arc<AtomicBool>,
    pool_status: String,
}

impl Default for LiTCGui {
    fn default() -> Self {
        Self {
            rpc_url: "http://127.0.0.1:18334".into(),
            tab: Tab::Node,
            state: Arc::new(Mutex::new(AppState::default())),
            poll_count: 0,
            node_process: None,
            send_to: String::new(),
            send_amount: String::new(),
            send_status: String::new(),
            pool_url: "http://127.0.0.1:18335".into(),
            pool_worker: "gui-miner".into(),
            pool_running: Arc::new(AtomicBool::new(false)),
            pool_status: String::new(),
        }
    }
}

impl Drop for LiTCGui {
    fn drop(&mut self) {
        self.pool_running.store(false, Ordering::Relaxed);
        if let Some(mut p) = self.node_process.take() {
            let _ = p.kill();
        }
    }
}

impl eframe::App for LiTCGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_count += 1;
        if self.poll_count % 4 == 0 {
            poll_background(&self.state, &self.rpc_url);
        }

        let state = self.state.lock().unwrap().clone();

        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("LiTC");
                ui.label(format!("v{}", env!("CARGO_PKG_VERSION")));
                ui.separator();
                let connected = state.node_info.is_some();
                let color = if connected { egui::Color32::GREEN } else { egui::Color32::RED };
                ui.colored_label(color, if connected { "●" } else { "○" });
                ui.label(if connected { "Connected" } else { "Disconnected" });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.horizontal(|ui| {
                        ui.label("RPC:");
                        let resp = ui.add(egui::TextEdit::singleline(&mut self.rpc_url).desired_width(200.0));
                        if resp.changed() { self.poll_count = 0; }
                    });
                });
            });
        });

        egui::SidePanel::left("tabs").resizable(false).default_width(100.0).show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(8.0);
                if ui.selectable_label(matches!(self.tab, Tab::Node), "Node").clicked() { self.tab = Tab::Node; }
                if ui.selectable_label(matches!(self.tab, Tab::Miner), "Miner").clicked() { self.tab = Tab::Miner; }
                if ui.selectable_label(matches!(self.tab, Tab::Wallet), "Wallet").clicked() { self.tab = Tab::Wallet; }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            match self.tab {
                Tab::Node => self.show_node(ui, &state),
                Tab::Miner => self.show_miner(ui, &state),
                Tab::Wallet => self.show_wallet(ui, &state),
            }
        });

        ctx.request_repaint_after(Duration::from_millis(500));
    }
}

impl LiTCGui {
    fn show_node(&mut self, ui: &mut egui::Ui, state: &AppState) {
        ui.heading("Node");
        ui.separator();

        ui.horizontal(|ui| {
            if self.node_process.is_some() {
                if ui.button("Stop Node").clicked() {
                    if let Some(mut p) = self.node_process.take() {
                        let _ = p.kill();
                        let _ = p.wait();
                    }
                }
            } else {
                if ui.button("Start Node").clicked() {
                    match std::process::Command::new("litc")
                        .args(["node", "--rpc-port", "18334", "--public-rpc-port", "18335"])
                        .spawn()
                    {
                        Ok(child) => {
                            self.node_process = Some(child);
                        }
                        Err(e) => {
                            let mut s = self.state.lock().unwrap();
                            s.error = Some(format!("Failed to start node: {e}"));
                        }
                    }
                }
            }
            ui.add_space(16.0);
            if state.node_info.is_some() {
                ui.colored_label(egui::Color32::GREEN, "● Running");
            } else {
                ui.colored_label(egui::Color32::GRAY, "Click Start Node or connect to existing");
            }
        });
        ui.add_space(4.0);
        ui.label("Admin RPC: localhost:18334 (wallet, control)");
        ui.label("Public RPC: any — 18335 (blockchain, pool mining)");

        ui.add_space(8.0);
        ui.separator();
        ui.heading("Status");

        if let Some(ref info) = state.node_info {
            egui::Grid::new("node_grid").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
                ui.label("Version:"); ui.label(&info.version); ui.end_row();
                ui.label("Network:"); ui.label(&info.network); ui.end_row();
                ui.label("Blocks:"); ui.label(format!("{}", info.blocks)); ui.end_row();
                ui.label("Best Block:"); ui.monospace(&info.best_hash[..16.min(info.best_hash.len())]); ui.end_row();
                ui.label("Peers:"); ui.label(format!("{}", info.connections)); ui.end_row();
                ui.label("Mempool:"); ui.label(format!("{} txs", info.mempool_size)); ui.end_row();
            });
        } else {
            ui.colored_label(egui::Color32::GRAY, "Waiting for connection...");
        }

        if let Some(ref e) = state.error {
            ui.add_space(4.0);
            ui.colored_label(egui::Color32::RED, e);
        }
    }

    fn show_miner(&mut self, ui: &mut egui::Ui, state: &AppState) {
        ui.heading("Miner");
        ui.separator();

        ui.heading("Local Mining");
        if state.node_info.is_some() {
            ui.horizontal(|ui| {
                let enabled = state.mining_enabled;
                if enabled {
                    if ui.button("Stop Mining").clicked() {
                        let url = self.rpc_url.clone();
                        std::thread::spawn(move || { let _ = rpc_setmining(&url, false); });
                    }
                } else {
                    if ui.button("Start Mining").clicked() {
                        let url = self.rpc_url.clone();
                        std::thread::spawn(move || { let _ = rpc_setmining(&url, true); });
                    }
                }
                ui.add_space(8.0);
                if enabled {
                    ui.colored_label(egui::Color32::GREEN, "● Mining");
                } else {
                    ui.colored_label(egui::Color32::GRAY, "○ Idle");
                }
            });
        } else {
            ui.colored_label(egui::Color32::GRAY, "Connect to a node first");
        }

        ui.add_space(16.0);
        ui.separator();
        ui.heading("Pool Mining");
        ui.horizontal(|ui| {
            ui.label("Pool URL:");
            ui.add(egui::TextEdit::singleline(&mut self.pool_url).desired_width(250.0));
        });
        ui.horizontal(|ui| {
            ui.label("Worker:");
            ui.add(egui::TextEdit::singleline(&mut self.pool_worker).desired_width(150.0));
        });
        ui.horizontal(|ui| {
            let running = self.pool_running.load(Ordering::Relaxed);
            if running {
                if ui.button("Stop Pool Mining").clicked() {
                    self.pool_running.store(false, Ordering::Relaxed);
                    self.pool_status = "Pool mining stopped.".into();
                }
                ui.colored_label(egui::Color32::GREEN, "● Pool mining");
            } else {
                if ui.button("Start Pool Mining").clicked() {
                    let url = self.pool_url.trim().to_string();
                    if !url.starts_with("http://") && !url.starts_with("https://") {
                        self.pool_status = "Invalid pool URL — must start with http:// or https://".into();
                    } else {
                        self.pool_running.store(true, Ordering::Relaxed);
                        self.pool_status = "Pool mining started.".into();
                        pool_mine_loop(&url, &self.pool_worker, self.pool_running.clone());
                    }
                }
                ui.colored_label(egui::Color32::GRAY, "○ Not mining");
            }
        });
        if !self.pool_status.is_empty() {
            ui.label(&self.pool_status);
        }
    }

    fn show_wallet(&mut self, ui: &mut egui::Ui, state: &AppState) {
        ui.heading("Wallet");
        ui.separator();
        if let Some(ref info) = state.wallet_info {
            ui.horizontal(|ui| {
                ui.label("Address:");
                ui.monospace(if info.address.len() > 25 {
                    format!("{}...", &info.address[..25])
                } else { info.address.clone() });
                if ui.button("Copy").clicked() {
                    ui.ctx().output_mut(|o| o.copied_text = info.address.clone());
                }
            });
            ui.horizontal(|ui| {
                ui.label("Balance:");
                ui.monospace(format!("{} ({} sat)", &info.balance_fmt, info.balance));
            });
            ui.add_space(8.0);
            ui.separator();
            ui.heading("Send");
            ui.horizontal(|ui| {
                ui.label("To:");
                ui.add(egui::TextEdit::singleline(&mut self.send_to).desired_width(280.0).hint_text("litc1q..."));
            });
            ui.horizontal(|ui| {
                ui.label("Amount:");
                ui.add(egui::TextEdit::singleline(&mut self.send_amount).desired_width(120.0).hint_text("1.5"));
                ui.label("LIT");
            });
            if ui.button("Send").clicked() {
                if self.send_to.is_empty() || self.send_amount.is_empty() {
                    self.send_status = "Fill in recipient and amount.".into();
                } else {
                    let url = self.rpc_url.clone();
                    let to = self.send_to.clone();
                    let amt = self.send_amount.clone();
                    std::thread::spawn(move || {
                        match rpc_send(&url, &to, &amt) {
                            Ok(v) => eprintln!("[gui] sent! txid={}", v["txid"].as_str().unwrap_or("?")),
                            Err(e) => eprintln!("[gui] send failed: {e}"),
                        }
                    });
                    self.send_status = "Transaction submitted.".into();
                }
            }
            if !self.send_status.is_empty() {
                ui.label(&self.send_status);
            }
            ui.add_space(8.0);
            ui.separator();
            ui.heading("UTXOs");
            ui.label(format!("{} entries", info.utxos.len()));
            egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                for utxo in &info.utxos {
                    ui.horizontal(|ui| {
                        ui.monospace(format!("{}:{}", &utxo.txid[..8], utxo.vout));
                        ui.label("→");
                        ui.monospace(format!("{} ({} sat)", &utxo.amount_fmt, utxo.amount));
                    });
                }
            });
        } else {
            ui.colored_label(egui::Color32::GRAY, "Node not connected.");
        }
    }
}

pub fn run(_args: Vec<String>) {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([720.0, 480.0]),
        ..Default::default()
    };
    if let Err(e) = eframe::run_native("LiTC GUI", options, Box::new(|_cc| Box::new(LiTCGui::default()))) {
        eprintln!("GUI error: {e}");
    }
}
