use crate::scanner::{FrequencyBand, Network, SecurityType};
use color_eyre::Result;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

static DEMO_MODE: AtomicBool = AtomicBool::new(false);

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

/// Parse Swift scanner output: SSID|BSSID|CHANNEL|RSSI|SECURITY
#[cfg(target_os = "macos")]
fn parse_swift_scanner_output(output: &str) -> Result<Vec<Network>> {
    let mut networks = Vec::new();

    for line in output.lines() {
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() >= 5 {
            let ssid = if parts[0].is_empty() || parts[0] == "<Hidden>" {
                "<Hidden>".to_string()
            } else {
                parts[0].to_string()
            };
            let mac = parts[1].to_string();
            let channel = parts[2].parse::<u8>().unwrap_or(0);
            let signal_dbm = parts[3].parse::<i32>().unwrap_or(-100);
            let security = parse_security(parts[4]);
            let frequency_band = FrequencyBand::from_channel(channel);

            networks.push(Network {
                ssid,
                mac,
                channel,
                signal_dbm,
                security,
                frequency_band,
                score: 0,
            });
        }
    }

    Ok(networks)
}

pub async fn scan_networks() -> Result<Vec<Network>> {
    // If demo mode is enabled, return simulated networks
    if is_demo_mode() {
        return Ok(generate_demo_networks());
    }

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
