//! WiFi connection management module
//!
//! Handles detecting current connection, connecting to networks,
//! and importing known networks from macOS plist.

use chrono::{DateTime, Utc};
use color_eyre::Result;
use std::process::Command;

use crate::db::Database;

/// Result of getting current WiFi connection
#[derive(Debug, Clone)]
pub struct CurrentConnection {
    pub ssid: String,
    pub bssid: Option<String>,
}

/// Get the currently connected WiFi network on macOS
pub fn get_current_connection() -> Result<Option<CurrentConnection>> {
    // Try multiple methods to detect the current connection

    // Method 1: Use networksetup (works on older macOS)
    if let Some(conn) = try_networksetup_method() {
        return Ok(Some(conn));
    }

    // Method 2: Use Swift CoreWLAN script
    if let Some(conn) = try_swift_method() {
        return Ok(Some(conn));
    }

    // Method 3: Check if we have an IP on en0 (we're connected to something)
    // In this case, we can't determine the SSID but we know we're connected
    if is_interface_connected() {
        // We're connected but can't get SSID due to macOS privacy restrictions
        // The app will need to match based on signal strength or user confirmation
        return Ok(None);
    }

    Ok(None)
}

/// Try using networksetup command (works on older macOS versions)
fn try_networksetup_method() -> Option<CurrentConnection> {
    let output = Command::new("networksetup")
        .args(["-getairportnetwork", "en0"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Check if not connected
    if stdout.contains("You are not associated") || stdout.contains("not associated") {
        return None;
    }

    // Parse the SSID
    let ssid = stdout
        .trim()
        .strip_prefix("Current Wi-Fi Network: ")
        .map(|s| s.to_string())?;

    if ssid.is_empty() {
        return None;
    }

    // Try to get BSSID
    let bssid = get_current_bssid();

    Some(CurrentConnection { ssid, bssid })
}

/// Try using Swift CoreWLAN script
fn try_swift_method() -> Option<CurrentConnection> {
    let script_path = std::env::current_exe()
        .ok()?
        .parent()?
        .parent()?
        .parent()?
        .join("scripts/wifi_current.swift");

    // Also try relative to working directory
    let script_paths = [
        script_path,
        std::path::PathBuf::from("scripts/wifi_current.swift"),
        std::path::PathBuf::from("./scripts/wifi_current.swift"),
    ];

    for path in &script_paths {
        if path.exists() {
            if let Ok(output) = Command::new("swift").arg(path).output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                return parse_swift_output(&stdout);
            }
        }
    }

    None
}

/// Parse output from wifi_current.swift script
fn parse_swift_output(output: &str) -> Option<CurrentConnection> {
    let mut ssid = None;
    let mut bssid = None;

    for line in output.lines() {
        if let Some(s) = line.strip_prefix("SSID:") {
            let s = s.trim();
            if !s.is_empty() {
                ssid = Some(s.to_string());
            }
        } else if let Some(b) = line.strip_prefix("BSSID:") {
            let b = b.trim();
            if !b.is_empty() {
                bssid = Some(b.to_uppercase());
            }
        }
    }

    ssid.map(|ssid| CurrentConnection { ssid, bssid })
}

/// Check if en0 interface has an IP address (indicating connection)
fn is_interface_connected() -> bool {
    if let Ok(output) = Command::new("ipconfig")
        .args(["getifaddr", "en0"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        !stdout.trim().is_empty()
    } else {
        false
    }
}

/// Get the BSSID of the current connection using various methods
fn get_current_bssid() -> Option<String> {
    // Try airport utility (older macOS)
    let airport_paths = [
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
        "/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport",
    ];

    for airport_path in &airport_paths {
        if std::path::Path::new(airport_path).exists() {
            if let Ok(output) = Command::new(airport_path).arg("-I").output() {
                let stdout = String::from_utf8_lossy(&output.stdout);

                for line in stdout.lines() {
                    let line = line.trim();
                    if line.starts_with("BSSID:") {
                        if let Some(bssid) = line.strip_prefix("BSSID:") {
                            let bssid = bssid.trim();
                            if !bssid.is_empty() && bssid != "0:0:0:0:0:0" {
                                return Some(bssid.to_uppercase());
                            }
                        }
                    }
                }
            }
        }
    }

    // Try to get gateway MAC from ARP table - this is often the router/AP MAC
    if let Some(gateway_mac) = get_gateway_mac() {
        return Some(gateway_mac);
    }

    None
}

/// Get the default gateway's MAC address from ARP table
/// This is typically very close to or matches the WiFi AP's BSSID
pub fn get_gateway_mac() -> Option<String> {
    // First get the default gateway IP
    let route_output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;

    let route_stdout = String::from_utf8_lossy(&route_output.stdout);
    let mut gateway_ip = None;

    for line in route_stdout.lines() {
        let line = line.trim();
        if line.starts_with("gateway:") {
            gateway_ip = line.strip_prefix("gateway:").map(|s| s.trim().to_string());
            break;
        }
    }

    let gateway_ip = gateway_ip?;

    // Now look up the MAC address in the ARP table
    let arp_output = Command::new("arp")
        .args(["-n", &gateway_ip])
        .output()
        .ok()?;

    let arp_stdout = String::from_utf8_lossy(&arp_output.stdout);

    // Parse ARP output: "? (192.168.50.1) at c8:7f:54:bf:29:1c on en0 ..."
    for line in arp_stdout.lines() {
        if line.contains(&gateway_ip) && line.contains(" at ") {
            let parts: Vec<&str> = line.split(" at ").collect();
            if parts.len() >= 2 {
                let mac_part = parts[1].split_whitespace().next()?;
                // Normalize MAC format (add leading zeros if needed)
                let mac = normalize_mac(mac_part);
                return Some(mac);
            }
        }
    }

    None
}

/// Normalize MAC address format (ensure uppercase, proper format)
fn normalize_mac(mac: &str) -> String {
    mac.split(':')
        .map(|octet| {
            if octet.len() == 1 {
                format!("0{}", octet)
            } else {
                octet.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(":")
        .to_uppercase()
}

/// Connect to a WiFi network by SSID
/// Note: This only works for known networks (password already saved in keychain)
pub fn connect_to_network(ssid: &str) -> Result<bool> {
    // Try Swift CoreWLAN method first (more reliable on modern macOS)
    if let Some(result) = try_swift_connect(ssid) {
        return Ok(result);
    }

    // Fallback to networksetup
    let output = Command::new("networksetup")
        .args(["-setairportnetwork", "en0", ssid])
        .output()?;

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    if stderr.contains("Error") || stdout.contains("Could not find") || stdout.contains("Failed") {
        return Ok(false);
    }

    // Give the connection time to establish (reduced for faster feedback)
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Quick poll for connection (3 seconds max)
    for _ in 0..3 {
        if let Ok(Some(conn)) = get_current_connection() {
            if conn.ssid == ssid {
                return Ok(true);
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    if let Ok(Some(conn)) = get_current_connection() {
        Ok(conn.ssid == ssid)
    } else {
        Ok(false)
    }
}

/// Try connecting using Swift CoreWLAN script
fn try_swift_connect(ssid: &str) -> Option<bool> {
    // Find the Swift script
    let script_paths = [
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.join("../scripts/wifi_connect.swift")))
            .unwrap_or_default(),
        std::path::PathBuf::from("scripts/wifi_connect.swift"),
        std::path::PathBuf::from("./scripts/wifi_connect.swift"),
    ];

    let script_path = script_paths.iter().find(|p| p.exists())?;

    let output = Command::new("swift")
        .arg(script_path)
        .arg(ssid)
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if stdout.contains("SUCCESS:") {
        Some(true)
    } else if stderr.contains("ERROR:") {
        Some(false)
    } else {
        None // Let fallback handle it
    }
}

/// Import known networks from macOS
pub fn import_known_networks(db: &Database) -> Result<usize> {
    // Method 1: Use networksetup to list preferred networks (most reliable)
    if let Ok(count) = import_from_networksetup(db) {
        if count > 0 {
            return Ok(count);
        }
    }

    // Method 2: Try plist file as fallback
    let plist_path = "/Library/Preferences/com.apple.wifi.known-networks.plist";
    if std::path::Path::new(plist_path).exists() {
        return import_from_plist(db, plist_path);
    }

    // Try user-level plist
    let home = std::env::var("HOME").unwrap_or_default();
    let user_plist = format!("{}/Library/Preferences/com.apple.wifi.known-networks.plist", home);
    if std::path::Path::new(&user_plist).exists() {
        return import_from_plist(db, &user_plist);
    }

    Ok(0)
}

/// Import known networks using networksetup command
fn import_from_networksetup(db: &Database) -> Result<usize> {
    let output = Command::new("networksetup")
        .args(["-listpreferredwirelessnetworks", "en0"])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut imported = 0;

    for line in stdout.lines().skip(1) {
        // Lines are indented with a tab, like: "\tNetworkName"
        let ssid = line.trim();
        if !ssid.is_empty() {
            db.import_known_network(ssid, None, None)?;
            imported += 1;
        }
    }

    Ok(imported)
}

/// Parse and import networks from a plist file
fn import_from_plist(db: &Database, path: &str) -> Result<usize> {
    let file = std::fs::File::open(path)?;
    let plist: plist::Value = plist::from_reader(file)?;

    let mut imported = 0;

    // The plist structure varies by macOS version
    // Modern format has networks keyed by identifier
    if let Some(dict) = plist.as_dictionary() {
        for (_key, value) in dict {
            if let Some(network_dict) = value.as_dictionary() {
                // Try to extract SSID
                let ssid = network_dict
                    .get("SSIDString")
                    .and_then(|v| v.as_string())
                    .or_else(|| {
                        network_dict
                            .get("SSID")
                            .and_then(|v| v.as_string())
                    });

                if let Some(ssid) = ssid {
                    // Try to extract timestamps
                    // plist::Date can be converted to SystemTime, then to chrono
                    let last_connected = network_dict
                        .get("LastConnected")
                        .and_then(|v| v.as_date())
                        .and_then(|d| {
                            let system_time: std::time::SystemTime = d.into();
                            system_time
                                .duration_since(std::time::UNIX_EPOCH)
                                .ok()
                                .map(|dur| DateTime::from_timestamp(dur.as_secs() as i64, 0))
                                .flatten()
                        });

                    let added_at = network_dict
                        .get("AddedAt")
                        .and_then(|v| v.as_date())
                        .and_then(|d| {
                            let system_time: std::time::SystemTime = d.into();
                            system_time
                                .duration_since(std::time::UNIX_EPOCH)
                                .ok()
                                .map(|dur| DateTime::from_timestamp(dur.as_secs() as i64, 0))
                                .flatten()
                        });

                    db.import_known_network(ssid, last_connected, added_at)?;
                    imported += 1;
                }
            }
        }
    }

    Ok(imported)
}

/// Check if a network is in the known networks list (from plist import)
pub fn is_known_network(db: &Database, ssid: &str) -> Result<bool> {
    db.is_known_network(ssid)
}

/// Get last connection time for a network from known_networks table
pub fn get_known_network_last_connected(db: &Database, ssid: &str) -> Result<Option<DateTime<Utc>>> {
    let networks = db.get_known_networks()?;
    for network in networks {
        if network.ssid == ssid {
            return Ok(network.last_connected_at);
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_current_connection() {
        // This test just verifies the function doesn't panic
        let result = get_current_connection();
        assert!(result.is_ok());
    }
}
