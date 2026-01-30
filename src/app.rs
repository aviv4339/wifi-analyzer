use crate::components::{Component, DetailPanel, DeviceDetail, DeviceTable, NetworkTable, SignalChart, StatusBar};
use crate::connection::{connect_to_network, get_current_connection, import_known_networks};
use crate::db::{ConnectionRecord, Database, ScanResultRecord};
use crate::ip::get_all_ips;
use crate::scanner::{get_scan_detected_connection, scan_networks, FrequencyBand, Network, SecurityType};
use crate::scoring::calculate_all_scores;
use crate::speedtest::{run_speed_test, SpeedTestResult};
use chrono::Utc;
use color_eyre::Result;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::Frame;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use std::sync::Mutex;

static SCANNED_DEVICES: Mutex<Option<Vec<crate::network_map::Device>>> = Mutex::new(None);

const SIGNAL_HISTORY_SIZE: usize = 30;

fn parse_device_type(s: &str) -> crate::network_map::DeviceType {
    match s {
        "Router" => crate::network_map::DeviceType::Router,
        "Phone" => crate::network_map::DeviceType::Phone,
        "Computer" => crate::network_map::DeviceType::Computer,
        "Laptop" => crate::network_map::DeviceType::Laptop,
        "Tablet" => crate::network_map::DeviceType::Tablet,
        "Smart TV" => crate::network_map::DeviceType::SmartTV,
        "Printer" => crate::network_map::DeviceType::Printer,
        "NAS" => crate::network_map::DeviceType::NAS,
        "IoT Device" => crate::network_map::DeviceType::IoT,
        "Game Console" => crate::network_map::DeviceType::GameConsole,
        _ => crate::network_map::DeviceType::Unknown,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    Auto,
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortField {
    Score,
    Signal,
    Name,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AppView {
    #[default]
    WifiNetworks,
    NetworkDevices,
}

pub struct App {
    pub networks: Vec<Network>,
    pub selected_index: usize,
    /// Signal history keyed by BSSID (MAC address)
    pub signal_history: HashMap<String, VecDeque<i32>>,
    pub scan_mode: ScanMode,
    pub auto_interval: Duration,
    pub last_scan: Instant,
    pub is_scanning: bool,
    pub sort_by: SortField,
    pub should_quit: bool,
    pub show_help: bool,
    pub error_message: Option<String>,
    /// Database connection (None if persistence disabled)
    pub db: Option<Database>,
    /// Current location ID for persistence
    pub current_location_id: Option<i64>,
    /// Current location name for display
    pub current_location_name: Option<String>,
    /// BSSID of currently connected network (None if not connected)
    pub connected_bssid: Option<String>,
    /// SSID of currently connected network
    pub connected_ssid: Option<String>,
    /// Show connection confirmation popup
    pub show_connect_popup: bool,
    /// Show speed test confirmation popup (for connected network)
    pub show_speedtest_popup: bool,
    /// Status message (shown in status bar)
    pub status_message: Option<String>,
    /// Connection history cache for selected network
    pub cached_connection_history: Option<(String, Vec<ConnectionRecord>)>,
    /// Cached speed test result for selected network
    pub cached_speed_test: Option<(String, SpeedTestResult)>,
    /// Cached recent IPs for selected network
    pub cached_recent_ips: Option<(String, Vec<String>)>,
    /// Current local IP address (for connected network)
    pub current_local_ip: Option<String>,
    /// Current public IP address (for connected network)
    pub current_public_ip: Option<String>,
    /// Speed test running in background (network MAC, start time)
    pub speedtest_running: Option<(String, Instant)>,
    /// Channel to receive speed test result
    pub speedtest_receiver: Option<std::sync::mpsc::Receiver<SpeedTestResult>>,
    /// Current view mode
    pub current_view: AppView,
    /// Discovered network devices
    pub devices: Vec<crate::network_map::Device>,
    /// Selected device index
    pub selected_device_index: usize,
    /// Device scan in progress
    pub device_scan_progress: Option<crate::network_map::ScanProgress>,
    /// Channel to receive device scan progress
    pub device_scan_receiver: Option<std::sync::mpsc::Receiver<crate::network_map::ScanProgress>>,
    /// Show device detail panel
    pub show_device_detail: bool,
    /// Show rename dialog
    pub show_rename_dialog: bool,
    /// Rename dialog input buffer
    pub rename_input: String,
}

impl App {
    pub fn new(auto_interval: Duration, start_auto: bool) -> Self {
        Self {
            networks: Vec::new(),
            selected_index: 0,
            signal_history: HashMap::new(),
            scan_mode: if start_auto {
                ScanMode::Auto
            } else {
                ScanMode::Manual
            },
            auto_interval,
            last_scan: Instant::now() - auto_interval, // Trigger immediate scan
            is_scanning: false,
            sort_by: SortField::Score,
            should_quit: false,
            show_help: false,
            error_message: None,
            db: None,
            current_location_id: None,
            current_location_name: None,
            connected_bssid: None,
            connected_ssid: None,
            show_connect_popup: false,
            show_speedtest_popup: false,
            status_message: None,
            cached_connection_history: None,
            cached_speed_test: None,
            cached_recent_ips: None,
            current_local_ip: None,
            current_public_ip: None,
            speedtest_running: None,
            speedtest_receiver: None,
            current_view: AppView::default(),
            devices: Vec::new(),
            selected_device_index: 0,
            device_scan_progress: None,
            device_scan_receiver: None,
            show_device_detail: false,
            show_rename_dialog: false,
            rename_input: String::new(),
        }
    }

    /// Configure the app with database persistence
    pub fn with_database(mut self, db: Database, location_id: i64, location_name: String) -> Self {
        self.db = Some(db);
        self.current_location_id = Some(location_id);
        self.current_location_name = Some(location_name);
        self
    }

    /// Load existing networks from the database for the current location
    pub fn load_networks_from_db(&mut self) -> Result<()> {
        if let (Some(db), Some(location_id)) = (&self.db, self.current_location_id) {
            let loaded = db.load_networks_for_location(location_id)?;

            for ln in loaded {
                let network = Network {
                    ssid: ln.ssid,
                    mac: ln.bssid,
                    channel: ln.channel,
                    signal_dbm: ln.signal_dbm,
                    security: SecurityType::from_str(&ln.security),
                    frequency_band: FrequencyBand::from_str(&ln.frequency_band),
                    score: ln.score,
                    last_seen: ln.last_seen,
                };

                // Add to networks (keyed by MAC for dedup)
                if let Some(existing) = self.networks.iter_mut().find(|n| n.mac == network.mac) {
                    // Update existing if loaded data is newer
                    if network.last_seen > existing.last_seen {
                        *existing = network;
                    }
                } else {
                    self.networks.push(network);
                }
            }

            self.sort_networks();
        }
        Ok(())
    }

    /// Initialize connection state on startup (fast - no network calls)
    pub fn init_connection_state(&mut self) -> Result<()> {
        // Detect current WiFi connection
        self.refresh_current_connection()?;

        // Get local IP immediately (fast, no network call)
        if self.connected_ssid.is_some() {
            self.current_local_ip = crate::ip::get_local_ip().ok();
            // Public IP will be fetched lazily when viewing detail panel
        }

        // Import known networks from plist (if database available)
        if let Some(db) = &self.db {
            // Only import if we haven't imported before
            let count = db.get_known_networks_count()?;
            if count == 0 {
                let imported = import_known_networks(db)?;
                if imported > 0 {
                    self.status_message = Some(format!("Imported {} known networks", imported));
                }
            }
        }

        // Load connection data for the initially selected network
        self.load_selected_network_data();

        Ok(())
    }

    /// Fetch public IP lazily (called when viewing connected network details)
    pub fn fetch_public_ip_if_needed(&mut self) {
        // Only fetch if connected and we don't have it yet
        if self.connected_ssid.is_some() && self.current_public_ip.is_none() {
            self.current_public_ip = crate::ip::get_public_ip();
        }
    }

    /// Refresh the current connection status
    pub fn refresh_current_connection(&mut self) -> Result<()> {
        // Method 1: Use connection info detected during scan (most reliable on modern macOS)
        if let Some(scan_conn) = get_scan_detected_connection() {
            self.connected_ssid = Some(scan_conn.ssid);
            self.connected_bssid = scan_conn.bssid;
            return Ok(());
        }

        // Method 2: Try system APIs (works on older macOS)
        match get_current_connection() {
            Ok(Some(conn)) => {
                self.connected_ssid = Some(conn.ssid);
                self.connected_bssid = conn.bssid;
            }
            Ok(None) => {
                // Couldn't determine SSID via system APIs (macOS privacy restrictions)
                // Try to detect by checking which network we're likely connected to
                self.detect_connected_by_signal();
            }
            Err(_) => {
                // Silently ignore connection detection errors
                self.detect_connected_by_signal();
            }
        }
        Ok(())
    }

    /// Try to detect connected network using channel from system_profiler
    /// On modern macOS, we may not be able to get SSID directly due to privacy restrictions
    fn detect_connected_by_signal(&mut self) {
        // Check if we have an IP (indicating we're connected to something)
        if let Ok(output) = std::process::Command::new("ipconfig")
            .args(["getifaddr", "en0"])
            .output()
        {
            let ip = String::from_utf8_lossy(&output.stdout);
            if ip.trim().is_empty() {
                // No IP, not connected
                self.connected_ssid = None;
                self.connected_bssid = None;
                return;
            }
        } else {
            return;
        }

        // Method 1: Get current channel from system_profiler and match
        if let Some(channel) = get_current_channel() {
            // Find the network on this channel with the strongest signal
            if let Some(network) = self.networks.iter()
                .filter(|n| n.channel as u32 == channel)
                .max_by_key(|n| n.signal_dbm)
            {
                self.connected_ssid = Some(network.ssid.clone());
                self.connected_bssid = Some(network.mac.clone());
                return;
            }
        }

        // Method 2: Find the network with the strongest signal (> -45 dBm typically means connected)
        if let Some(strongest) = self.networks.iter()
            .filter(|n| n.signal_dbm > -45) // Very strong signal indicates connected
            .max_by_key(|n| n.signal_dbm)
        {
            self.connected_ssid = Some(strongest.ssid.clone());
            self.connected_bssid = Some(strongest.mac.clone());
        }
    }

    /// Check if a network is the currently connected one
    pub fn is_connected(&self, network: &Network) -> bool {
        // First try SSID match (if we have it)
        if let Some(ref ssid) = self.connected_ssid {
            if network.ssid == *ssid {
                return true;
            }
        }

        // Try BSSID match (exact or prefix match for router MAC)
        if let Some(ref bssid) = self.connected_bssid {
            let network_mac = network.mac.to_uppercase();
            let connected_mac = bssid.to_uppercase();

            // Exact match
            if network_mac == connected_mac {
                return true;
            }

            // Prefix match (first 5 octets) - router MAC and AP BSSID often share prefix
            // e.g., router MAC c8:7f:54:bf:29:1c and BSSID c8:7f:54:bf:29:1d
            if network_mac.len() >= 14 && connected_mac.len() >= 14 {
                let network_prefix = &network_mac[..14]; // First 5 octets (14 chars with colons)
                let connected_prefix = &connected_mac[..14];
                if network_prefix == connected_prefix {
                    return true;
                }
            }
        }

        false
    }

    /// Check if a network is known (previously connected)
    pub fn is_known_network(&self, ssid: &str) -> bool {
        if let Some(ref db) = self.db {
            db.is_known_network(ssid).unwrap_or(false)
        } else {
            false
        }
    }

    /// Show the connection confirmation popup (or speed test popup if connected)
    pub fn show_connect_dialog(&mut self) {
        if self.networks.is_empty() {
            return;
        }

        let network = &self.networks[self.selected_index];

        // Check if already connected - offer speed test instead
        if self.is_connected(network) {
            self.show_speedtest_popup = true;
            return;
        }

        self.show_connect_popup = true;
    }

    /// Cancel the connection popup
    pub fn cancel_connect_dialog(&mut self) {
        self.show_connect_popup = false;
    }

    /// Cancel the speed test popup
    pub fn cancel_speedtest_dialog(&mut self) {
        self.show_speedtest_popup = false;
    }

    /// Start speed test in background on currently connected network
    pub fn confirm_speedtest(&mut self) -> Result<()> {
        self.show_speedtest_popup = false;

        if self.networks.is_empty() {
            return Ok(());
        }

        let network = self.networks[self.selected_index].clone();

        // Create channel for result
        let (tx, rx) = std::sync::mpsc::channel();

        // Store start time and receiver
        self.speedtest_running = Some((network.mac.clone(), Instant::now()));
        self.speedtest_receiver = Some(rx);

        // Spawn background thread for speed test
        std::thread::spawn(move || {
            if let Ok(result) = run_speed_test() {
                let _ = tx.send(result);
            }
        });

        Ok(())
    }

    /// Check if background speed test has completed
    pub fn check_speedtest_result(&mut self) {
        // Check if we have a pending result
        if let Some(ref rx) = self.speedtest_receiver {
            match rx.try_recv() {
                Ok(result) => {
                    // Speed test completed!
                    if let Some((ref mac, _)) = self.speedtest_running {
                        let mac = mac.clone();

                        // Store in database if available
                        if let Some(ref db) = self.db {
                            if let Ok(Some(network_id)) = db.get_network_id_by_bssid(&mac) {
                                let _ = db.insert_connection(
                                    network_id,
                                    self.current_local_ip.as_deref(),
                                    self.current_public_ip.as_deref(),
                                    Some(result.download_mbps),
                                    Some(result.upload_mbps),
                                );
                            }
                        }

                        // Cache and display the result
                        self.cached_speed_test = Some((mac, result.clone()));
                        self.status_message = Some(format!(
                            "Speed test complete: ↓{:.1} Mbps  ↑{:.1} Mbps",
                            result.download_mbps, result.upload_mbps
                        ));

                        // Refresh connection history cache
                        self.clear_connection_cache();
                        self.load_selected_network_data();
                    }

                    // Clear running state
                    self.speedtest_running = None;
                    self.speedtest_receiver = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    // Still running - nothing to do
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    // Thread died without sending result
                    self.status_message = Some("Speed test failed".to_string());
                    self.speedtest_running = None;
                    self.speedtest_receiver = None;
                }
            }
        }
    }

    /// Get speed test progress message if running
    pub fn get_speedtest_status(&self) -> Option<String> {
        if let Some((_, start_time)) = &self.speedtest_running {
            let elapsed = start_time.elapsed().as_secs();
            if elapsed < 5 {
                Some(format!("Speed test: downloading... {}s", elapsed))
            } else {
                Some(format!("Speed test: uploading... {}s", elapsed.saturating_sub(5)))
            }
        } else {
            None
        }
    }

    /// Get time until next auto-refresh
    pub fn get_next_refresh_secs(&self) -> Option<u64> {
        if matches!(self.scan_mode, ScanMode::Auto) && !self.is_scanning {
            let elapsed = self.last_scan.elapsed();
            if elapsed < self.auto_interval {
                Some((self.auto_interval - elapsed).as_secs())
            } else {
                Some(0)
            }
        } else {
            None
        }
    }

    /// Execute the connection (dialog already dismissed by caller)
    pub fn do_connect(&mut self) -> Result<()> {
        if self.networks.is_empty() {
            return Ok(());
        }

        let network = self.networks[self.selected_index].clone();

        // Try command-line connection first
        match connect_to_network(&network.ssid) {
            Ok(true) => {
                // Connection verified - refresh state and gather stats
                self.refresh_current_connection()?;
                self.on_connect_success(&network)?;
            }
            Ok(false) => {
                // Command-line connection failed - open System Settings
                self.status_message = Some(format!(
                    "Opening WiFi Settings - please connect to {} manually",
                    network.ssid
                ));
                // Open WiFi settings pane
                let _ = std::process::Command::new("open")
                    .arg("x-apple.systempreferences:com.apple.wifi-settings-extension")
                    .spawn();
            }
            Err(e) => {
                self.status_message = Some(format!("Connection error: {}", e));
            }
        }

        Ok(())
    }

    /// Legacy method for compatibility
    pub fn confirm_connect(&mut self) -> Result<()> {
        self.show_connect_popup = false;
        self.do_connect()
    }

    /// Called after successful connection - gather IPs, run speed test, persist
    fn on_connect_success(&mut self, network: &Network) -> Result<()> {
        self.status_message = Some(format!("Connected to {}! Gathering stats...", network.ssid));

        // Get IPs
        let (local_ip, public_ip) = get_all_ips();

        // Run speed test
        self.status_message = Some("Running speed test...".to_string());
        let speed_result = run_speed_test().ok();

        // Persist connection to database
        if let Some(ref db) = self.db {
            if let Some(network_id) = db.get_network_id_by_bssid(&network.mac)? {
                let (download, upload) = speed_result
                    .as_ref()
                    .map(|r| (Some(r.download_mbps), Some(r.upload_mbps)))
                    .unwrap_or((None, None));

                db.insert_connection(
                    network_id,
                    local_ip.as_deref(),
                    public_ip.as_deref(),
                    download,
                    upload,
                )?;

                // Cache the speed test result
                if let Some(result) = speed_result {
                    self.cached_speed_test = Some((network.mac.clone(), result.clone()));
                    self.status_message = Some(format!(
                        "Connected! ↓{:.1} Mbps ↑{:.1} Mbps",
                        result.download_mbps, result.upload_mbps
                    ));
                } else {
                    self.status_message = Some(format!("Connected to {}", network.ssid));
                }
            }
        } else {
            self.status_message = Some(format!("Connected to {}", network.ssid));
        }

        Ok(())
    }

    /// Get connection history for a network (cached)
    pub fn get_connection_history(&mut self, bssid: &str) -> Option<&Vec<ConnectionRecord>> {
        // Check if we have cached data for this network
        if let Some((cached_bssid, _)) = &self.cached_connection_history {
            if cached_bssid == bssid {
                return self.cached_connection_history.as_ref().map(|(_, v)| v);
            }
        }

        // Load from database
        if let Some(ref db) = self.db {
            if let Ok(Some(network_id)) = db.get_network_id_by_bssid(bssid) {
                if let Ok(history) = db.get_connection_history(network_id, 10) {
                    self.cached_connection_history = Some((bssid.to_string(), history));
                    return self.cached_connection_history.as_ref().map(|(_, v)| v);
                }
            }
        }

        None
    }

    /// Get connection count for a network
    pub fn get_connection_count(&self, bssid: &str) -> Option<i64> {
        if let Some(ref db) = self.db {
            if let Ok(Some(network_id)) = db.get_network_id_by_bssid(bssid) {
                return db.get_connection_count(network_id).ok();
            }
        }
        None
    }

    /// Get recent IPs for a network (cached)
    pub fn get_recent_ips(&mut self, bssid: &str) -> Option<&Vec<String>> {
        // Check cache
        if let Some((cached_bssid, _)) = &self.cached_recent_ips {
            if cached_bssid == bssid {
                return self.cached_recent_ips.as_ref().map(|(_, v)| v);
            }
        }

        // Load from database
        if let Some(ref db) = self.db {
            if let Ok(Some(network_id)) = db.get_network_id_by_bssid(bssid) {
                if let Ok(ips) = db.get_recent_ips(network_id, 5) {
                    self.cached_recent_ips = Some((bssid.to_string(), ips));
                    return self.cached_recent_ips.as_ref().map(|(_, v)| v);
                }
            }
        }

        None
    }

    /// Clear cached connection data (call when selection changes)
    pub fn clear_connection_cache(&mut self) {
        self.cached_connection_history = None;
        self.cached_speed_test = None;
        self.cached_recent_ips = None;
    }

    /// Load connection data for the currently selected network
    pub fn load_selected_network_data(&mut self) {
        if let Some(network) = self.networks.get(self.selected_index) {
            let bssid = network.mac.clone();
            let is_connected = self.is_connected(network);

            // Load connection history (this also populates the cache)
            let _ = self.get_connection_history(&bssid);
            // Load recent IPs
            let _ = self.get_recent_ips(&bssid);

            // If viewing the connected network, fetch public IP lazily
            if is_connected {
                self.fetch_public_ip_if_needed();
            }
        }
    }

    /// Set status message
    pub fn set_status(&mut self, msg: String) {
        self.status_message = Some(msg);
    }

    /// Clear status message
    pub fn clear_status(&mut self) {
        self.status_message = None;
    }

    pub fn set_error(&mut self, msg: String) {
        self.error_message = Some(msg);
    }

    pub fn clear_error(&mut self) {
        self.error_message = None;
    }

    pub fn navigate_up(&mut self) {
        if !self.networks.is_empty() && self.selected_index > 0 {
            self.selected_index -= 1;
            self.clear_connection_cache();
            self.load_selected_network_data();
        }
    }

    pub fn navigate_down(&mut self) {
        if !self.networks.is_empty() && self.selected_index < self.networks.len() - 1 {
            self.selected_index += 1;
            self.clear_connection_cache();
            self.load_selected_network_data();
        }
    }

    pub fn toggle_scan_mode(&mut self) {
        self.scan_mode = match self.scan_mode {
            ScanMode::Auto => ScanMode::Manual,
            ScanMode::Manual => ScanMode::Auto,
        };
    }

    pub fn cycle_sort(&mut self) {
        self.sort_by = match self.sort_by {
            SortField::Score => SortField::Signal,
            SortField::Signal => SortField::Name,
            SortField::Name => SortField::Score,
        };
        self.sort_networks();
    }

    pub fn toggle_help(&mut self) {
        self.show_help = !self.show_help;
    }

    pub fn quit(&mut self) {
        self.should_quit = true;
    }

    pub fn switch_view(&mut self) {
        self.current_view = match self.current_view {
            AppView::WifiNetworks => AppView::NetworkDevices,
            AppView::NetworkDevices => AppView::WifiNetworks,
        };
    }

    pub fn device_navigate_up(&mut self) {
        if !self.devices.is_empty() && self.selected_device_index > 0 {
            self.selected_device_index -= 1;
        }
    }

    pub fn device_navigate_down(&mut self) {
        if !self.devices.is_empty() && self.selected_device_index < self.devices.len() - 1 {
            self.selected_device_index += 1;
        }
    }

    pub fn toggle_device_detail(&mut self) {
        self.show_device_detail = !self.show_device_detail;
    }

    pub fn start_rename_device(&mut self) {
        if !self.devices.is_empty() {
            let device = &self.devices[self.selected_device_index];
            self.rename_input = device.custom_name.clone().unwrap_or_default();
            self.show_rename_dialog = true;
        }
    }

    pub fn cancel_rename(&mut self) {
        self.show_rename_dialog = false;
        self.rename_input.clear();
    }

    pub fn confirm_rename(&mut self) {
        if !self.devices.is_empty() && !self.rename_input.is_empty() {
            let device = &mut self.devices[self.selected_device_index];
            device.custom_name = Some(self.rename_input.clone());

            // Persist to database
            if let Some(ref db) = self.db {
                let _ = db.update_device_name(&device.mac_address, &self.rename_input);
            }
        }
        self.show_rename_dialog = false;
        self.rename_input.clear();
    }

    pub fn rename_input_char(&mut self, c: char) {
        if self.rename_input.len() < 32 {
            self.rename_input.push(c);
        }
    }

    pub fn rename_input_backspace(&mut self) {
        self.rename_input.pop();
    }

    /// Start a network device scan
    pub fn start_device_scan(&mut self) {
        if self.device_scan_progress.is_some() {
            return; // Already scanning
        }

        let (tx, rx) = std::sync::mpsc::channel();
        self.device_scan_receiver = Some(rx);

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                use crate::network_map::{discover_devices, identify_all_devices, scan_devices_ports, ScanPhase, ScanProgress};

                let (progress_tx, mut progress_rx) = tokio::sync::mpsc::channel(10);

                // Forward progress to main thread
                let tx_clone = tx.clone();
                tokio::spawn(async move {
                    while let Some(progress) = progress_rx.recv().await {
                        let _ = tx_clone.send(progress);
                    }
                });

                // Phase 1: Discover devices
                let mut devices = match discover_devices(Some(progress_tx.clone())).await {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("Device discovery error: {}", e);
                        return;
                    }
                };

                // Phase 2: Scan ports
                if let Err(e) = scan_devices_ports(&mut devices, Some(progress_tx.clone())).await {
                    eprintln!("Port scan error: {}", e);
                }

                // Phase 3: Identify devices
                let _ = progress_tx.send(ScanProgress {
                    phase: ScanPhase::Identification,
                    devices_found: devices.len(),
                    current_device: None,
                    ports_scanned: 0,
                    total_ports: 0,
                }).await;

                identify_all_devices(&mut devices);

                // Send complete signal
                let _ = progress_tx.send(ScanProgress {
                    phase: ScanPhase::Complete,
                    devices_found: devices.len(),
                    current_device: None,
                    ports_scanned: 0,
                    total_ports: 0,
                }).await;

                // Store devices for main thread to pick up
                SCANNED_DEVICES.lock().unwrap().replace(devices);
            });
        });

        self.device_scan_progress = Some(crate::network_map::ScanProgress {
            phase: crate::network_map::ScanPhase::Discovery,
            devices_found: 0,
            current_device: None,
            ports_scanned: 0,
            total_ports: 0,
        });
    }

    /// Check for device scan progress updates
    pub fn check_device_scan_progress(&mut self) {
        if let Some(ref rx) = self.device_scan_receiver {
            while let Ok(progress) = rx.try_recv() {
                if matches!(progress.phase, crate::network_map::ScanPhase::Complete) {
                    if let Some(devices) = SCANNED_DEVICES.lock().unwrap().take() {
                        self.devices = devices;
                        self.persist_devices();
                    }
                    self.device_scan_progress = None;
                    self.device_scan_receiver = None;
                    self.status_message = Some(format!("Found {} devices", self.devices.len()));
                    return;
                }
                // Only update progress if it's advancing (don't let late port scan messages
                // overwrite identification progress due to async message ordering)
                let is_stale = match (&self.device_scan_progress, &progress.phase) {
                    (Some(current), new_phase) => {
                        use crate::network_map::ScanPhase;
                        let current_ord = match current.phase {
                            ScanPhase::Discovery => 0,
                            ScanPhase::PortScan => 1,
                            ScanPhase::Identification => 2,
                            ScanPhase::Complete => 3,
                        };
                        let new_ord = match new_phase {
                            ScanPhase::Discovery => 0,
                            ScanPhase::PortScan => 1,
                            ScanPhase::Identification => 2,
                            ScanPhase::Complete => 3,
                        };
                        new_ord < current_ord
                    }
                    _ => false,
                };
                if !is_stale {
                    self.device_scan_progress = Some(progress);
                }
            }
        }
    }

    /// Cancel ongoing device scan
    pub fn cancel_device_scan(&mut self) {
        self.device_scan_progress = None;
        self.device_scan_receiver = None;
    }

    /// Persist scanned devices to database
    fn persist_devices(&self) {
        let Some(ref db) = self.db else { return };
        let network_bssid = self.connected_bssid.as_deref();

        for device in &self.devices {
            let device_id = match db.upsert_device(
                &device.mac_address,
                &device.ip_address,
                device.hostname.as_deref(),
                device.vendor.as_deref(),
                &format!("{}", device.device_type),
                device.custom_name.as_deref(),
                network_bssid,
            ) {
                Ok(id) => id,
                Err(_) => continue,
            };

            for service in &device.services {
                if matches!(service.state, crate::network_map::PortState::Open) {
                    let _ = db.upsert_device_service(
                        device_id,
                        service.port,
                        &format!("{}", service.protocol),
                        service.service_name.as_deref(),
                        service.banner.as_deref(),
                        service.detected_agent.as_deref(),
                    );
                }
            }
        }
    }

    /// Load devices from database
    pub fn load_devices_from_db(&mut self) {
        let Some(ref db) = self.db else { return };

        let network_bssid = self.connected_bssid.as_deref();
        let records = match db.get_devices_for_network(network_bssid) {
            Ok(r) => r,
            Err(_) => return,
        };

        self.devices = records
            .into_iter()
            .map(|r| {
                let mut device = crate::network_map::Device::new(r.mac_address, r.ip_address.unwrap_or_default());
                device.hostname = r.hostname;
                device.vendor = r.vendor;
                device.device_type = r.device_type
                    .as_deref()
                    .map(parse_device_type)
                    .unwrap_or_default();
                device.custom_name = r.custom_name;
                device.first_seen = r.first_seen;
                device.last_seen = r.last_seen;
                device.is_online = false;
                device
            })
            .collect();
    }

    pub fn should_scan(&self) -> bool {
        if self.is_scanning {
            return false;
        }
        match self.scan_mode {
            ScanMode::Auto => self.last_scan.elapsed() >= self.auto_interval,
            ScanMode::Manual => false,
        }
    }

    pub fn trigger_scan(&mut self) {
        if !self.is_scanning {
            self.is_scanning = true;
        }
    }

    pub async fn perform_scan(&mut self) -> Result<()> {
        self.is_scanning = true;
        let mut scanned_networks = scan_networks().await?;
        calculate_all_scores(&mut scanned_networks);

        // Persist to database if available
        if let (Some(db), Some(location_id)) = (&self.db, self.current_location_id)
            && let Err(e) = self.persist_scan_results(db, location_id, &scanned_networks)
        {
            // Log error but don't fail the scan
            eprintln!("Failed to persist scan: {}", e);
        }

        // Update signal history (keyed by BSSID/MAC address for uniqueness)
        for network in &scanned_networks {
            let history = self
                .signal_history
                .entry(network.mac.clone())
                .or_default();
            history.push_back(network.signal_dbm);
            while history.len() > SIGNAL_HISTORY_SIZE {
                history.pop_front();
            }
        }

        // Preserve selection if possible (by MAC address for stability)
        let selected_mac = self.networks.get(self.selected_index).map(|n| n.mac.clone());

        // Merge scanned networks with existing (accumulate, don't replace)
        let now = Utc::now();
        for scanned in scanned_networks {
            if let Some(existing) = self.networks.iter_mut().find(|n| n.mac == scanned.mac) {
                // Update existing network with new scan data
                existing.ssid = scanned.ssid;
                existing.channel = scanned.channel;
                existing.signal_dbm = scanned.signal_dbm;
                existing.security = scanned.security;
                existing.frequency_band = scanned.frequency_band;
                existing.score = scanned.score;
                existing.last_seen = now;
            } else {
                // Add new network
                let mut network = scanned;
                network.last_seen = now;
                self.networks.push(network);
            }
        }

        self.sort_networks();

        // Try to maintain selection by MAC address
        if let Some(mac) = selected_mac
            && let Some(idx) = self.networks.iter().position(|n| n.mac == mac)
        {
            self.selected_index = idx;
        }

        // Clamp selection index
        if !self.networks.is_empty() {
            self.selected_index = self.selected_index.min(self.networks.len() - 1);
        } else {
            self.selected_index = 0;
        }

        self.last_scan = Instant::now();
        self.is_scanning = false;

        // Load connection data for the selected network
        self.load_selected_network_data();

        Ok(())
    }

    /// Persist scan results to the database
    fn persist_scan_results(
        &self,
        db: &Database,
        location_id: i64,
        networks: &[Network],
    ) -> Result<()> {
        let scan_id = db.create_scan(location_id)?;

        let records: Vec<ScanResultRecord> = networks
            .iter()
            .map(|n| ScanResultRecord {
                bssid: n.mac.clone(),
                ssid: n.ssid.clone(),
                channel: n.channel,
                signal_dbm: n.signal_dbm,
                security: format!("{:?}", n.security),
                frequency_band: format!("{:?}", n.frequency_band),
                score: n.score,
            })
            .collect();

        db.record_scan_results(scan_id, &records)?;
        Ok(())
    }

    fn sort_networks(&mut self) {
        match self.sort_by {
            SortField::Score => self.networks.sort_by(|a, b| b.score.cmp(&a.score)),
            SortField::Signal => self.networks.sort_by(|a, b| b.signal_dbm.cmp(&a.signal_dbm)),
            SortField::Name => self.networks.sort_by(|a, b| a.ssid.cmp(&b.ssid)),
        }
    }

    pub fn render(&self, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),  // Header/tabs
                Constraint::Min(10),    // Main content
                Constraint::Length(1),  // Status bar
            ])
            .split(frame.area());

        // Header with tabs
        self.render_header_with_tabs(frame, chunks[0]);

        // Main content based on current view
        match self.current_view {
            AppView::WifiNetworks => {
                let main_chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
                    .split(chunks[1]);

                NetworkTable.render(frame, main_chunks[0], self);

                let detail_chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(10), Constraint::Length(5)])
                    .split(main_chunks[1]);

                DetailPanel.render(frame, detail_chunks[0], self);
                SignalChart.render(frame, detail_chunks[1], self);
            }
            AppView::NetworkDevices => {
                let main_chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
                    .split(chunks[1]);

                DeviceTable.render(frame, main_chunks[0], self);
                DeviceDetail.render(frame, main_chunks[1], self);
            }
        }

        // Status bar
        StatusBar.render(frame, chunks[2], self);

        // Overlays
        if self.show_help {
            self.render_help_overlay(frame);
        }
        if self.show_connect_popup {
            self.render_connect_popup(frame);
        }
        if self.show_speedtest_popup {
            self.render_speedtest_popup(frame);
        }
        if self.show_rename_dialog {
            self.render_rename_dialog(frame);
        }
        if let Some(ref progress) = self.device_scan_progress {
            self.render_scan_progress_overlay(frame, progress);
        }
        if let Some(ref error) = self.error_message {
            self.render_error_overlay(frame, error);
        }
    }

    fn render_connect_popup(&self, frame: &mut Frame) {
        use ratatui::style::{Color, Style};
        use ratatui::text::{Line, Span};
        use ratatui::widgets::{Block, Borders, Clear, Paragraph};

        let area = centered_rect(40, 25, frame.area());

        let ssid = self
            .networks
            .get(self.selected_index)
            .map(|n| n.ssid.as_str())
            .unwrap_or("Unknown");

        let popup_text = vec![
            Line::from(""),
            Line::from(format!("Connect to \"{}\"?", ssid)),
            Line::from(""),
            Line::from(""),
            Line::from(vec![
                Span::styled("[Y]", Style::default().fg(Color::Green)),
                Span::raw("es    "),
                Span::styled("[N]", Style::default().fg(Color::Red)),
                Span::raw("o"),
            ]),
        ];

        let paragraph = Paragraph::new(popup_text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan))
                    .title(Span::styled(
                        " Connect to Network? ",
                        Style::default().fg(Color::Cyan),
                    )),
            )
            .alignment(ratatui::layout::Alignment::Center);

        frame.render_widget(Clear, area);
        frame.render_widget(paragraph, area);
    }

    fn render_speedtest_popup(&self, frame: &mut Frame) {
        use ratatui::style::{Color, Style};
        use ratatui::text::{Line, Span};
        use ratatui::widgets::{Block, Borders, Clear, Paragraph};

        let area = centered_rect(45, 30, frame.area());

        let ssid = self
            .networks
            .get(self.selected_index)
            .map(|n| n.ssid.as_str())
            .unwrap_or("Unknown");

        let popup_text = vec![
            Line::from(""),
            Line::from(format!("Run speed test on \"{}\"?", ssid)),
            Line::from(""),
            Line::from(Span::styled(
                "(~10 seconds: 5s download + 5s upload)",
                Style::default().fg(Color::Gray),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("[Y]", Style::default().fg(Color::Green)),
                Span::raw("es    "),
                Span::styled("[N]", Style::default().fg(Color::Red)),
                Span::raw("o"),
            ]),
        ];

        let paragraph = Paragraph::new(popup_text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow))
                    .title(Span::styled(
                        " Speed Test? ",
                        Style::default().fg(Color::Yellow),
                    )),
            )
            .alignment(ratatui::layout::Alignment::Center);

        frame.render_widget(Clear, area);
        frame.render_widget(paragraph, area);
    }

    fn render_error_overlay(&self, frame: &mut Frame, error: &str) {
        use ratatui::style::{Color, Style};
        use ratatui::text::{Line, Span};
        use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

        let area = centered_rect(70, 50, frame.area());

        let error_text = vec![
            Line::from(""),
            Line::from(Span::styled(
                "WiFi Scan Failed",
                Style::default().fg(Color::Red),
            )),
            Line::from(""),
            Line::from(error.to_string()),
            Line::from(""),
            Line::from(""),
            Line::from(Span::styled(
                "Tip: Run with --demo flag to see the app with simulated networks:",
                Style::default().fg(Color::Yellow),
            )),
            Line::from(""),
            Line::from("  cargo run -- --demo"),
            Line::from(""),
            Line::from(""),
            Line::from("Press 'd' to switch to demo mode, or 'q' to quit"),
        ];

        let paragraph = Paragraph::new(error_text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Red))
                    .title(Span::styled(
                        " Error ",
                        Style::default().fg(Color::Red),
                    )),
            )
            .wrap(Wrap { trim: true });

        frame.render_widget(Clear, area);
        frame.render_widget(paragraph, area);
    }

    fn render_header_with_tabs(&self, frame: &mut Frame, area: Rect) {
        use ratatui::style::{Color, Modifier, Style};
        use ratatui::text::{Line, Span};
        use ratatui::widgets::Paragraph;

        let wifi_style = if matches!(self.current_view, AppView::WifiNetworks) {
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };

        let devices_style = if matches!(self.current_view, AppView::NetworkDevices) {
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };

        let line = Line::from(vec![
            Span::raw(" "),
            Span::styled("[WiFi Networks]", wifi_style),
            Span::raw("  "),
            Span::styled("[Network Devices]", devices_style),
            Span::raw("                              "),
            Span::styled("Tab", Style::default().fg(Color::DarkGray)),
            Span::raw(" to switch"),
        ]);

        let paragraph = Paragraph::new(line);
        frame.render_widget(paragraph, area);
    }

    fn render_help_overlay(&self, frame: &mut Frame) {
        use ratatui::text::{Line, Span};
        use ratatui::widgets::{Block, Borders, Clear, Paragraph};
        use crate::theme::Theme;

        let area = centered_rect(50, 60, frame.area());

        let help_text = vec![
            Line::from(""),
            Line::from(Span::styled("Keyboard Shortcuts", Theme::title_style())),
            Line::from(""),
            Line::from("\u{2191}/\u{2193} or j/k   Navigate networks"),
            Line::from("Enter          Connect to network"),
            Line::from("r              Refresh scan"),
            Line::from("a              Toggle auto/manual mode"),
            Line::from("s              Cycle sort order"),
            Line::from("?              Toggle this help"),
            Line::from("q / Esc        Quit"),
            Line::from(""),
            Line::from(Span::styled("Score Legend", Theme::title_style())),
            Line::from(""),
            Line::from(vec![
                Span::styled("80-100", Theme::score_style(90)),
                Span::raw("  Excellent"),
            ]),
            Line::from(vec![
                Span::styled("60-79 ", Theme::score_style(70)),
                Span::raw("  Good"),
            ]),
            Line::from(vec![
                Span::styled("40-59 ", Theme::score_style(50)),
                Span::raw("  Fair"),
            ]),
            Line::from(vec![
                Span::styled("0-39  ", Theme::score_style(20)),
                Span::raw("  Poor"),
            ]),
            Line::from(""),
            Line::from("Press ? to close"),
        ];

        let paragraph = Paragraph::new(help_text).block(
            Block::default()
                .borders(Borders::ALL)
                .style(Theme::border_style())
                .title(Span::styled(" Help ", Theme::title_style())),
        );

        frame.render_widget(Clear, area);
        frame.render_widget(paragraph, area);
    }

    fn render_rename_dialog(&self, frame: &mut Frame) {
        use ratatui::style::{Color, Style};
        use ratatui::text::{Line, Span};
        use ratatui::widgets::{Block, Borders, Clear, Paragraph};

        let area = centered_rect(50, 25, frame.area());

        let lines = vec![
            Line::from(""),
            Line::from("Enter a custom name for this device:"),
            Line::from(""),
            Line::from(Span::styled(
                format!("{}_", self.rename_input),
                Style::default().fg(Color::Cyan),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("[Enter]", Style::default().fg(Color::Green)),
                Span::raw(" Save  "),
                Span::styled("[Esc]", Style::default().fg(Color::Red)),
                Span::raw(" Cancel"),
            ]),
        ];

        let paragraph = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan))
                    .title(Span::styled(" Rename Device ", Style::default().fg(Color::Cyan))),
            )
            .alignment(ratatui::layout::Alignment::Center);

        frame.render_widget(Clear, area);
        frame.render_widget(paragraph, area);
    }

    fn render_scan_progress_overlay(&self, frame: &mut Frame, progress: &crate::network_map::ScanProgress) {
        use crate::network_map::ScanPhase;
        use ratatui::style::{Color, Style};
        use ratatui::text::{Line, Span};
        use ratatui::widgets::{Block, Borders, Clear, Paragraph};

        let area = centered_rect(40, 20, frame.area());

        let phase_str = format!("{}", progress.phase);

        // Phase-specific progress display
        let (progress_bar, detail_line) = match progress.phase {
            ScanPhase::Discovery => {
                let spinner = ["\u{25dc}", "\u{25dd}", "\u{25de}", "\u{25df}"];
                let idx = (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() / 250) as usize % 4;
                (
                    format!("  {}  Scanning ARP cache...", spinner[idx]),
                    format!("{} devices found so far", progress.devices_found),
                )
            }
            ScanPhase::PortScan => {
                let device_str = progress.current_device.as_deref().unwrap_or("...");
                if progress.total_ports > 0 {
                    let pct = (progress.ports_scanned * 100) / progress.total_ports;
                    let filled = pct / 5;
                    let empty = 20 - filled;
                    (
                        format!("[{}{}] {}%", "\u{2588}".repeat(filled), "\u{2591}".repeat(empty), pct),
                        format!("Scanning: {}", device_str),
                    )
                } else {
                    (
                        "[\u{2591}\u{2591}\u{2591}\u{2591}\u{2591}\u{2591}\u{2591}\u{2591}\u{2591}\u{2591}\u{2591}\u{2591}\u{2591}\u{2591}\u{2591}\u{2591}\u{2591}\u{2591}\u{2591}\u{2591}]".to_string(),
                        format!("Scanning: {}", device_str),
                    )
                }
            }
            ScanPhase::Identification => {
                let spinner = ["\u{25dc}", "\u{25dd}", "\u{25de}", "\u{25df}"];
                let idx = (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() / 250) as usize % 4;
                (
                    format!("  {}  Looking up vendors...", spinner[idx]),
                    format!("Processing {} devices", progress.devices_found),
                )
            }
            ScanPhase::Complete => {
                (
                    "[\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}] 100%".to_string(),
                    "Done!".to_string(),
                )
            }
        };

        let lines = vec![
            Line::from(""),
            Line::from(Span::styled(&phase_str, Style::default().fg(Color::Cyan))),
            Line::from(""),
            Line::from(progress_bar),
            Line::from(""),
            Line::from(format!("Devices found: {}", progress.devices_found)),
            Line::from(detail_line),
            Line::from(""),
            Line::from(Span::styled("[Esc] Cancel", Style::default().fg(Color::Gray))),
        ];

        let paragraph = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow))
                    .title(Span::styled(" Scanning Network ", Style::default().fg(Color::Yellow))),
            )
            .alignment(ratatui::layout::Alignment::Center);

        frame.render_widget(Clear, area);
        frame.render_widget(paragraph, area);
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

/// Get the current WiFi channel from system_profiler
fn get_current_channel() -> Option<u32> {
    let output = std::process::Command::new("system_profiler")
        .args(["SPAirPortDataType"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut in_current_network = false;

    for line in stdout.lines() {
        let trimmed = line.trim();

        if trimmed.contains("Current Network Information:") {
            in_current_network = true;
            continue;
        }

        if in_current_network && trimmed.starts_with("Channel:") {
            // Parse "Channel: 37 (6GHz, 160MHz)" format
            let channel_part = trimmed.strip_prefix("Channel:")?.trim();
            let channel_num = channel_part
                .split_whitespace()
                .next()?
                .parse::<u32>()
                .ok()?;
            return Some(channel_num);
        }

        // Stop if we've moved past the current network section
        if in_current_network && (trimmed.starts_with("Other Local") || trimmed.is_empty() && line.len() < 10) {
            break;
        }
    }

    None
}
