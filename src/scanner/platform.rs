use crate::scanner::{FrequencyBand, Network, SecurityType};
use chrono::Utc;
use color_eyre::Result;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static DEMO_MODE: AtomicBool = AtomicBool::new(false);

/// Number of scan passes to perform for thorough network discovery
const SCAN_PASSES: usize = 2;

/// Delay between scan passes in milliseconds
const SCAN_DELAY_MS: u64 = 500;

/// Enable demo mode with simulated networks
pub fn enable_demo_mode() {
    DEMO_MODE.store(true, Ordering::SeqCst);
}

/// Check if demo mode is enabled
pub fn is_demo_mode() -> bool {
    DEMO_MODE.load(Ordering::SeqCst)
}

/// Scan WiFi networks using Swift CoreWLAN helper (works on modern macOS)
#[cfg(target_os = "macos")]
async fn scan_macos_swift() -> Result<Vec<Network>> {
    // Find the Swift script relative to the executable or current directory
    let script_paths = [
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.join("../scripts/wifi_scan.swift")))
            .unwrap_or_default(),
        std::path::PathBuf::from("scripts/wifi_scan.swift"),
        std::path::PathBuf::from("./scripts/wifi_scan.swift"),
    ];

    let script_path = script_paths
        .iter()
        .find(|p| p.exists())
        .ok_or_else(|| color_eyre::eyre::eyre!("Swift scanner script not found"))?
        .clone();

    let output = tokio::task::spawn_blocking(move || {
        Command::new("swift")
            .arg(&script_path)
            .output()
    })
    .await??;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(color_eyre::eyre::eyre!("Swift scanner failed: {}", stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_swift_scanner_output(&stdout)
}

/// Current connection info detected during scan
#[derive(Debug, Clone)]
pub struct CurrentConnectionInfo {
    pub ssid: String,
    pub bssid: Option<String>,
}

/// Thread-safe storage for current connection detected during scan
static CURRENT_CONNECTION: std::sync::OnceLock<std::sync::Mutex<Option<CurrentConnectionInfo>>> =
    std::sync::OnceLock::new();

/// Get the current connection info detected during the last scan
pub fn get_scan_detected_connection() -> Option<CurrentConnectionInfo> {
    CURRENT_CONNECTION
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
}

/// Parse Swift scanner output: SSID|BSSID|CHANNEL|RSSI|SECURITY
/// Also looks for CONNECTED|SSID|BSSID line for current connection
#[cfg(target_os = "macos")]
fn parse_swift_scanner_output(output: &str) -> Result<Vec<Network>> {
    let mut networks = Vec::new();

    for line in output.lines() {
        let parts: Vec<&str> = line.split('|').collect();

        // Check for current connection info line: CONNECTED|SSID|BSSID
        if parts.len() >= 2 && parts[0] == "CONNECTED" {
            let ssid = parts[1].to_string();
            let bssid = if parts.len() >= 3 && !parts[2].is_empty() {
                Some(parts[2].to_uppercase())
            } else {
                None
            };

            // Store the current connection info
            if let Some(mutex) = CURRENT_CONNECTION.get_or_init(|| std::sync::Mutex::new(None)).lock().ok().as_mut() {
                **mutex = Some(CurrentConnectionInfo { ssid, bssid });
            }
            continue;
        }

        // Parse network line: SSID|BSSID|CHANNEL|RSSI|SECURITY
        if parts.len() >= 5 {
            let ssid = if parts[0].is_empty() || parts[0] == "<Hidden>" {
                "<Hidden>".to_string()
            } else {
                parts[0].to_string()
            };
            let channel = parts[2].parse::<u8>().unwrap_or(0);
            let signal_dbm = parts[3].parse::<i32>().unwrap_or(-100);
            let security = parse_security(parts[4]);
            let frequency_band = FrequencyBand::from_channel(channel);

            // Use BSSID if available, otherwise generate synthetic one from SSID+channel
            // (macOS Sonoma+ doesn't return BSSID due to privacy restrictions)
            let mac = if parts[1].is_empty() {
                generate_synthetic_mac(&ssid, channel)
            } else {
                parts[1].to_string()
            };

            networks.push(Network {
                ssid,
                mac,
                channel,
                signal_dbm,
                security,
                frequency_band,
                score: 0,
                last_seen: Utc::now(),
            });
        }
    }

    Ok(networks)
}

/// Generate a synthetic MAC address from SSID and channel for consistent tracking
/// when real BSSID is not available (macOS privacy restrictions)
fn generate_synthetic_mac(ssid: &str, channel: u8) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    ssid.hash(&mut hasher);
    channel.hash(&mut hasher);
    let hash = hasher.finish();

    // Generate MAC-like string: XX:XX:XX:XX:XX:XX
    // Use 02 prefix to indicate locally administered address
    format!(
        "02:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        ((hash >> 40) & 0xFF) as u8,
        ((hash >> 32) & 0xFF) as u8,
        ((hash >> 24) & 0xFF) as u8,
        ((hash >> 16) & 0xFF) as u8,
        ((hash >> 8) & 0xFF) as u8,
    )
}

/// Perform a multi-pass WiFi scan with deduplication.
/// Runs multiple scan passes and merges results, keeping the strongest signal per access point.
pub async fn scan_networks() -> Result<Vec<Network>> {
    // If demo mode is enabled, return simulated networks (no multi-pass needed)
    if is_demo_mode() {
        return Ok(generate_demo_networks());
    }

    let mut all_networks: HashMap<String, Network> = HashMap::new();

    // Perform multiple scan passes to catch all networks
    for pass in 0..SCAN_PASSES {
        // Add delay between passes (but not before the first one)
        if pass > 0 {
            tokio::time::sleep(Duration::from_millis(SCAN_DELAY_MS)).await;
        }

        // Perform a single scan
        let networks = single_scan().await?;

        // Merge results: keep the strongest signal per unique network
        for network in networks {
            // Use BSSID if available, otherwise fall back to SSID+channel
            // (macOS Sonoma+ doesn't return BSSID due to privacy restrictions)
            let key = if network.mac.is_empty() {
                format!("{}:{}", network.ssid, network.channel)
            } else {
                network.mac.to_uppercase()
            };

            match all_networks.entry(key) {
                Entry::Vacant(e) => {
                    e.insert(network);
                }
                Entry::Occupied(mut e) => {
                    // Keep the network with stronger signal
                    if network.signal_dbm > e.get().signal_dbm {
                        e.insert(network);
                    }
                }
            }
        }
    }

    Ok(all_networks.into_values().collect())
}

/// Perform a single WiFi scan pass
async fn single_scan() -> Result<Vec<Network>> {
    // Try Swift CoreWLAN scanner first (works on Sonoma/Sequoia/Tahoe)
    #[cfg(target_os = "macos")]
    {
        match scan_macos_swift().await {
            Ok(networks) if !networks.is_empty() => return Ok(networks),
            _ => {}
        }
    }

    // Fallback to wifiscanner crate (works on older macOS, Linux, Windows)
    let result = tokio::task::spawn_blocking(wifiscanner::scan).await?;

    match result {
        Ok(wifi_networks) => {
            let networks: Vec<Network> = wifi_networks
                .into_iter()
                .map(|wifi| {
                    let channel = wifi.channel.parse::<u8>().unwrap_or(0);
                    let signal_dbm = parse_signal(&wifi.signal_level);
                    let security = parse_security(&wifi.security);
                    let frequency_band = FrequencyBand::from_channel(channel);

                    Network {
                        ssid: if wifi.ssid.is_empty() {
                            "<Hidden>".to_string()
                        } else {
                            wifi.ssid
                        },
                        mac: wifi.mac,
                        channel,
                        signal_dbm,
                        security,
                        frequency_band,
                        score: 0,
                        last_seen: Utc::now(),
                    }
                })
                .collect();

            Ok(networks)
        }
        Err(e) => Err(color_eyre::eyre::eyre!(
            "WiFi scan failed: {:?}\n\nTry running with --demo flag for simulated data.",
            e
        )),
    }
}

/// Generate simulated networks for demo mode
fn generate_demo_networks() -> Vec<Network> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let base_networks = vec![
        ("CoffeeShop_Free", SecurityType::Open, 36, -42, "A1:B2:C3:D4:E5:F6"),
        ("Airport_WiFi", SecurityType::Open, 6, -55, "11:22:33:44:55:66"),
        ("Starbucks_WiFi", SecurityType::WPA2, 11, -62, "AA:BB:CC:DD:EE:FF"),
        ("Hotel_Guest", SecurityType::Open, 1, -48, "12:34:56:78:9A:BC"),
        ("Library_Public", SecurityType::Open, 149, -58, "DE:AD:BE:EF:CA:FE"),
        ("FastFood_Free", SecurityType::Open, 6, -70, "FE:ED:FA:CE:00:11"),
        ("Mall_WiFi", SecurityType::WPA2, 44, -65, "22:33:44:55:66:77"),
        ("Neighbor_5G", SecurityType::WPA3, 36, -78, "88:99:AA:BB:CC:DD"),
        ("xfinitywifi", SecurityType::Open, 1, -72, "EE:FF:00:11:22:33"),
        ("ATT_WiFi", SecurityType::WPA2, 11, -80, "44:55:66:77:88:99"),
        ("<Hidden>", SecurityType::WPA2, 6, -85, "00:11:22:33:44:55"),
    ];

    base_networks
        .into_iter()
        .enumerate()
        .map(|(idx, (ssid, security, channel, base_signal, mac))| {
            let variance = ((seed.wrapping_add(idx as u64) % 7) as i32) - 3;
            let signal_dbm = base_signal + variance;

            Network {
                ssid: ssid.to_string(),
                mac: mac.to_string(),
                channel,
                signal_dbm,
                security,
                frequency_band: FrequencyBand::from_channel(channel),
                score: 0,
                last_seen: Utc::now(),
            }
        })
        .collect()
}

fn parse_signal(signal: &str) -> i32 {
    signal
        .trim()
        .trim_end_matches(" dBm")
        .trim_end_matches('%')
        .split_whitespace()
        .next()
        .unwrap_or("-100")
        .parse::<i32>()
        .unwrap_or(-100)
}

fn parse_security(security: &str) -> SecurityType {
    let security_lower = security.to_lowercase();

    if security_lower.is_empty() || security_lower.contains("none") || security_lower.contains("open") {
        SecurityType::Open
    } else if security_lower.contains("wpa3") {
        SecurityType::WPA3
    } else if security_lower.contains("wpa2") {
        SecurityType::WPA2
    } else if security_lower.contains("wpa") {
        SecurityType::WPA
    } else if security_lower.contains("wep") {
        SecurityType::WEP
    } else {
        SecurityType::Unknown
    }
}
