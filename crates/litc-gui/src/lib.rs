use eframe::egui;
use litc_primitives::{sha256d, Decodable, Reader};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Persisted GUI settings (saved to gui-config.json next to the binary).
#[derive(Clone, Serialize, Deserialize)]
struct GuiConfig {
    rpc_url: String,
    pool_url: String,
    pool_address: String,
    pool_label: String,
    pool_min_payout: String,
    pool_session_token: String,
}

impl Default for GuiConfig {
    fn default() -> Self {
        GuiConfig {
            rpc_url: "http://127.0.0.1:18334".into(),
            pool_url: "http://127.0.0.1:18335".into(),
            pool_address: String::new(),
            pool_label: "gui-miner".into(),
            pool_min_payout: String::new(),
            pool_session_token: String::new(),
        }
    }
}

fn gui_config_path() -> std::path::PathBuf {
    std::env::var("LITC_DATADIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("data"))
        .join("gui-config.json")
}

fn save_config(cfg: &GuiConfig) {
    if let Ok(s) = serde_json::to_string_pretty(cfg) {
        let path = gui_config_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&path, &s);
    }
}

fn load_config() -> GuiConfig {
    let path = gui_config_path();
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

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

fn pool_mine_loop(url: &str, worker: &str, payout_addr: &str, running: Arc<AtomicBool>) {
        let url = url.trim_end_matches('/').to_string();
        let worker = worker.to_string();
        let payout_addr = if payout_addr.is_empty() { String::new() } else { payout_addr.to_string() };
        let pool_label = url.clone();
        std::thread::spawn(move || {
        eprintln!("[pool] mining against {pool_label} as '{worker}'");
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
            let params = if payout_addr.is_empty() { json!([worker]) } else { json!([worker, payout_addr]) };
            let tmpl = match rpc_call(&url, "getblocktemplate", params) {
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
                    let submit_params = if payout_addr.is_empty() { json!([submit_hex, worker]) } else { json!([submit_hex, worker, payout_addr]) };
                    match rpc_call(&url, "submitblock", submit_params) {
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
    config: GuiConfig,
    tab: Tab,
    state: Arc<Mutex<AppState>>,
    poll_count: u64,

    // Node process
    node_process: Option<std::process::Child>,

    // Send form
    send_to: String,
    send_amount: String,
    send_status: String,

    // Pool
    pool_mining_running: Arc<AtomicBool>,
    pool_connected: bool,
    pool_status: String,
    pool_balance_sat: u64,
    pool_balance_fmt: String,
    pool_blocks_found: u64,
    pool_total_earned_fmt: String,
    pool_events: Vec<String>,
    pool_register_in_progress: bool,
}

impl LiTCGui {
    fn save(&self) {
        save_config(&self.config);
    }
    fn load() -> Self {
        let cfg = load_config();
        let mut s = Self::default();
        s.config = cfg;
        s
    }
}

impl Default for LiTCGui {
    fn default() -> Self {
        let cfg = GuiConfig::default();
        Self {
            config: cfg,
            tab: Tab::Node,
            state: Arc::new(Mutex::new(AppState::default())),
            poll_count: 0,
            node_process: None,
            send_to: String::new(),
            send_amount: String::new(),
            send_status: String::new(),
            pool_mining_running: Arc::new(AtomicBool::new(false)),
            pool_connected: false,
            pool_status: String::new(),
            pool_balance_sat: 0,
            pool_balance_fmt: "0.00000000 LIT".into(),
            pool_blocks_found: 0,
            pool_total_earned_fmt: "0.00000000 LIT".into(),
            pool_events: Vec::new(),
            pool_register_in_progress: false,
        }
    }
}

impl Drop for LiTCGui {
    fn drop(&mut self) {
        self.pool_mining_running.store(false, Ordering::Relaxed);
        self.save();
        if let Some(mut p) = self.node_process.take() {
            let _ = p.kill();
        }
    }
}

/// Poll pool balance in the background when connected.
fn poll_pool_balance(config: &GuiConfig, connected: &Arc<Mutex<bool>>, balance_sat: &Arc<Mutex<u64>>, balance_fmt: &Arc<Mutex<String>>, blocks: &Arc<Mutex<u64>>, earned: &Arc<Mutex<String>>) {
    if config.pool_session_token.is_empty() { return; }
    let token = config.pool_session_token.clone();
    let url = config.pool_url.clone();
    let c = connected.clone();
    let bs = balance_sat.clone();
    let bf = balance_fmt.clone();
    let bl = blocks.clone();
    let er = earned.clone();
    std::thread::spawn(move || {
        match rpc_call(&url, "pool_balance", json!([token])) {
            Ok(v) => {
                if !*c.lock().unwrap() { return; }
                *bs.lock().unwrap() = v["balance_sat"].as_u64().unwrap_or(0);
                *bf.lock().unwrap() = v["balance_formatted"].as_str().unwrap_or("0 LIT").to_string();
                *bl.lock().unwrap() = v["blocks_found"].as_u64().unwrap_or(0);
                *er.lock().unwrap() = v["total_earned_formatted"].as_str().unwrap_or("0 LIT").to_string();
            }
            Err(_) => {
                // Session expired — clear connection.
                *c.lock().unwrap() = false;
            }
        }
    });
}

/// Auto-register with the pool. Saves session token to gui-config.json on success.
fn auto_register(admin_url: &str, pool_url: &str, address: &str, label: &str, min_payout: &str, _token: &str) {
    if address.is_empty() { return; }
    let admin_url = admin_url.to_string();
    let pool_url = pool_url.to_string();
    let address = address.to_string();
    let label = label.to_string();
    let min_payout = min_payout.to_string();

    std::thread::spawn(move || {
        let payload = format!("pool-register:{}:{}", address, min_payout);
        let msg_hash = sha256d(payload.as_bytes());
        let msg_hex = hex::encode(msg_hash.0);

        match rpc_call(&admin_url, "signmessage", json!([0, msg_hex])) {
            Ok(sig_resp) => {
                let pk = sig_resp["pubkey_hex"].as_str().unwrap_or("").to_string();
                let sig = sig_resp["signature_hex"].as_str().unwrap_or("").to_string();
                match rpc_call(&pool_url, "pool_register", json!([address, pk, sig, min_payout, label])) {
                    Ok(reg) => {
                        if let Some(token) = reg["session_token"].as_str() {
                            let mut cfg = load_config();
                            cfg.pool_session_token = token.to_string();
                            cfg.pool_url = pool_url;
                            cfg.pool_address = address;
                            cfg.pool_label = label;
                            cfg.pool_min_payout = min_payout;
                            save_config(&cfg);
                            eprintln!("[pool] registered, session={token}");
                        }
                    }
                    Err(e) => eprintln!("[pool] register failed: {e}"),
                }
            }
            Err(e) => eprintln!("[pool] signmessage failed: {e}"),
        }
    });
}

impl eframe::App for LiTCGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_count += 1;
        if self.poll_count % 4 == 0 {
            poll_background(&self.state, &self.config.rpc_url);
        }
        // If registration was started, check if token was saved.
        if self.pool_register_in_progress {
            let cfg = load_config();
            if !cfg.pool_session_token.is_empty() {
                self.config.pool_session_token = cfg.pool_session_token.clone();
                self.pool_connected = true;
                self.pool_register_in_progress = false;
                self.pool_status = "Connected.".into();
            }
        }

        // Poll pool balance every ~2 seconds when connected.
        if self.poll_count % 4 == 0 && self.pool_connected && !self.config.pool_session_token.is_empty() {
            let bs = Arc::new(Mutex::new(self.pool_balance_sat));
            let bf = Arc::new(Mutex::new(self.pool_balance_fmt.clone()));
            let bl = Arc::new(Mutex::new(self.pool_blocks_found));
            let er = Arc::new(Mutex::new(self.pool_total_earned_fmt.clone()));
            let cn = Arc::new(Mutex::new(self.pool_connected));
            poll_pool_balance(&self.config, &cn, &bs, &bf, &bl, &er);
            self.pool_balance_sat = *bs.lock().unwrap();
            self.pool_balance_fmt = bf.lock().unwrap().clone();
            self.pool_blocks_found = *bl.lock().unwrap();
            self.pool_total_earned_fmt = er.lock().unwrap().clone();
            self.pool_connected = *cn.lock().unwrap();
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
                        let resp = ui.add(egui::TextEdit::singleline(&mut self.config.rpc_url).desired_width(200.0));
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

        // ── Local Mining ──
        ui.heading("Local Mining");
        ui.label("Майнит в кошелёк ноды (ваш баланс).");
        if state.node_info.is_some() {
            ui.horizontal(|ui| {
                let enabled = state.mining_enabled;
                if enabled {
                    if ui.button("Stop Mining").clicked() {
                        let url = self.config.rpc_url.clone();
                        std::thread::spawn(move || { let _ = rpc_setmining(&url, false); });
                    }
                } else {
                    if ui.button("Start Mining").clicked() {
                        let url = self.config.rpc_url.clone();
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

        // ── Smart Pool — настройки подключения ──
        ui.heading("Pool Connection");
        ui.label("Настройки сохраняются автоматически. При подключении — авторегистрация через ML-DSA-2.");

        ui.horizontal(|ui| {
            ui.label("Pool URL:");
            let resp = ui.add(egui::TextEdit::singleline(&mut self.config.pool_url).desired_width(250.0));
            if resp.changed() { self.save(); }
        });
        ui.horizontal(|ui| {
            ui.label("Your Address:");
            let resp = ui.add(egui::TextEdit::singleline(&mut self.config.pool_address).desired_width(280.0).hint_text("litc1q..."));
            if resp.changed() { self.save(); }
            if ui.button("Paste").clicked() {
                if let Some(ref info) = state.wallet_info {
                    self.config.pool_address = info.address.clone();
                    self.save();
                }
            }
        });
        ui.horizontal(|ui| {
            ui.label("Worker Label:");
            let resp = ui.add(egui::TextEdit::singleline(&mut self.config.pool_label).desired_width(150.0));
            if resp.changed() { self.save(); }
        });
        ui.horizontal(|ui| {
            ui.label("Min Payout:");
            let resp = ui.add(egui::TextEdit::singleline(&mut self.config.pool_min_payout).desired_width(100.0).hint_text("0.1 LIT"));
            if resp.changed() { self.save(); }
        });

        // ── Connect / Disconnect ──
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if self.pool_connected {
                if ui.button("Disconnect").clicked() {
                    self.pool_mining_running.store(false, Ordering::Relaxed);
                    self.pool_connected = false;
                    self.config.pool_session_token.clear();
                    self.pool_status = "Disconnected.".into();
                    self.save();
                }
                ui.colored_label(egui::Color32::GREEN, "● Connected");
            } else {
                if ui.button("Connect to Pool").clicked() {
                    let url = self.config.pool_url.trim().to_string();
                    if !url.starts_with("http://") && !url.starts_with("https://") {
                        self.pool_status = "Invalid pool URL".into();
                    } else if self.config.pool_address.is_empty() {
                        self.pool_status = "Enter your LIT address first.".into();
                    } else {
                        self.save();
                        self.pool_register_in_progress = true;
                        self.pool_status = "Connecting...".into();

                        let admin_url = self.config.rpc_url.clone();
                        let pool_url = url.clone();
                        let address = self.config.pool_address.clone();
                        let label = self.config.pool_label.clone();
                        let min_payout = self.config.pool_min_payout.clone();
                        let existing_token = self.config.pool_session_token.clone();

                        // Try existing session; if it fails, auto-register.
                        std::thread::spawn(move || {
                            // Check existing session first.
                            if !existing_token.is_empty() {
                                if let Ok(v) = rpc_call(&pool_url, "pool_balance", json!([existing_token])) {
                                    let bal = v["balance_formatted"].as_str().unwrap_or("0 LIT");
                                    eprintln!("[pool] reconnected, balance={bal}");
                                    return; // session still valid
                                }
                            }
                            // Auto-register.
                            auto_register(&admin_url, &pool_url, &address, &label, &min_payout, &existing_token.clone());
                        });
                    }
                }
                if self.pool_register_in_progress {
                    ui.label("⏳");
                }
                ui.colored_label(egui::Color32::GRAY, "○ Disconnected");
            }
        });

        // ── Status when connected ──
        if self.pool_connected && !self.config.pool_session_token.is_empty() {
            ui.add_space(8.0);
            ui.separator();
            ui.heading("Pool Status");
            egui::Grid::new("pool_status_grid").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
                ui.label("Session:");
                ui.monospace(&self.config.pool_session_token[..16.min(self.config.pool_session_token.len())]);
                ui.end_row();
                ui.label("Balance:");
                ui.monospace(&self.pool_balance_fmt);
                ui.end_row();
                ui.label("Blocks Found:");
                ui.label(format!("{}", self.pool_blocks_found));
                ui.end_row();
                ui.label("Total Earned:");
                ui.monospace(&self.pool_total_earned_fmt);
                ui.end_row();
            });
            ui.horizontal(|ui| {
                if ui.button("Refresh").clicked() {
                    let url = self.config.pool_url.clone();
                    let token = self.config.pool_session_token.clone();
                    std::thread::spawn(move || {
                        match rpc_call(&url, "pool_balance", json!([token])) {
                            Ok(v) => eprintln!("[pool] balance={}", v["balance_formatted"].as_str().unwrap_or("?")),
                            Err(e) => eprintln!("[pool] balance error: {e}"),
                        }
                    });
                }
                if ui.button("Withdraw All").clicked() {
                    let url = self.config.rpc_url.clone();
                    let token = self.config.pool_session_token.clone();
                    std::thread::spawn(move || {
                        match rpc_call(&url, "pool_withdraw", json!([token, ""])) {
                            Ok(v) => eprintln!("[pool] withdrawn: {} txid={}",
                                v["amount_formatted"].as_str().unwrap_or("?"),
                                v["txid"].as_str().unwrap_or("?")),
                            Err(e) => eprintln!("[pool] withdraw failed: {e}"),
                        }
                    });
                }
            });
            // Events
            if !self.pool_events.is_empty() {
                ui.add_space(4.0);
                ui.separator();
                ui.label("Events");
                egui::ScrollArea::vertical().max_height(120.0).show(ui, |ui| {
                    for ev in &self.pool_events {
                        ui.monospace(ev);
                    }
                });
            }
        }

        // ── Status message ──
        if !self.pool_status.is_empty() {
            ui.add_space(4.0);
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
                    let url = self.config.rpc_url.clone();
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
    let app = LiTCGui::load();
    if let Err(e) = eframe::run_native("LiTC GUI", options, Box::new(|_cc| Box::new(app))) {
        eprintln!("GUI error: {e}");
    }
}
