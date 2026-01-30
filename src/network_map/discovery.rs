use crate::network_map::{Device, ScanPhase, ScanProgress};
use color_eyre::Result;
use ipnetwork::IpNetwork;
use std::net::IpAddr;
use std::process::Command;
use tokio::sync::mpsc;

/// Discover devices on the local network using ARP cache
pub async fn discover_devices(
    progress_tx: Option<mpsc::Sender<ScanProgress>>,
) -> Result<Vec<Device>> {
    if let Some(ref tx) = progress_tx {
        let _ = tx.send(ScanProgress {
            phase: ScanPhase::Discovery,
            devices_found: 0,
            current_device: None,
            ports_scanned: 0,
            total_ports: 0,
        }).await;
    }

    let (local_ip, _subnet) = get_local_network_info()?;
    let mut devices = parse_arp_cache()?;

    if let Some(gateway) = get_default_gateway()? {
        if !devices.iter().any(|d| d.ip_address == gateway) {
            let gateway_mac = get_mac_for_ip(&gateway).unwrap_or_else(|| "00:00:00:00:00:00".to_string());
            let mut gw_device = Device::new(gateway_mac, gateway);
            gw_device.device_type = crate::network_map::DeviceType::Router;
            devices.push(gw_device);
        }
    }

    for device in &mut devices {
        if device.ip_address == local_ip {
            device.hostname = Some("This device".to_string());
        }
    }

    if let Some(ref tx) = progress_tx {
        let _ = tx.send(ScanProgress {
            phase: ScanPhase::Discovery,
            devices_found: devices.len(),
            current_device: None,
            ports_scanned: 0,
            total_ports: 0,
        }).await;
    }

    Ok(devices)
}

fn get_local_network_info() -> Result<(String, IpNetwork)> {
    let local_ip = local_ip_address::local_ip()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to get local IP: {}", e))?;
    let ip_str = local_ip.to_string();
    let network: IpNetwork = format!("{}/24", ip_str).parse()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to parse network: {}", e))?;
    Ok((ip_str, network))
}

fn parse_arp_cache() -> Result<Vec<Device>> {
    let output = Command::new("arp")
        .arg("-a")
        .output()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to run arp: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut devices = Vec::new();
    let mut seen_macs = std::collections::HashSet::new();

    for line in stdout.lines() {
        if let Some((ip, mac)) = parse_arp_line(line) {
            if mac == "(incomplete)" || mac == "ff:ff:ff:ff:ff:ff" {
                continue;
            }
            let mac_upper = mac.to_uppercase();
            if seen_macs.contains(&mac_upper) {
                continue;
            }
            seen_macs.insert(mac_upper.clone());
            devices.push(Device::new(mac_upper, ip));
        }
    }
    Ok(devices)
}

fn parse_arp_line(line: &str) -> Option<(String, String)> {
    let ip_start = line.find('(')? + 1;
    let ip_end = line.find(')')?;
    let ip = line[ip_start..ip_end].to_string();

    let at_pos = line.find(" at ")?;
    let after_at = &line[at_pos + 4..];
    let mac_end = after_at.find(' ').unwrap_or(after_at.len());
    let mac = after_at[..mac_end].to_string();

    if ip.parse::<IpAddr>().is_err() {
        return None;
    }
    Some((ip, mac))
}

fn get_default_gateway() -> Result<Option<String>> {
    let output = Command::new("netstat")
        .args(["-nr"])
        .output()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to run netstat: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[0] == "default" {
            let gateway = parts[1].to_string();
            if gateway.parse::<IpAddr>().is_ok() {
                return Ok(Some(gateway));
            }
        }
    }
    Ok(None)
}

fn get_mac_for_ip(ip: &str) -> Option<String> {
    let output = Command::new("arp")
        .arg("-n")
        .arg(ip)
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_arp_line(&stdout).map(|(_, mac)| mac)
}

#[allow(dead_code)]
pub async fn ping_sweep(subnet: &IpNetwork) -> Result<()> {
    use tokio::process::Command as TokioCommand;
    use tokio::time::{timeout, Duration};

    let mut handles = Vec::new();
    for ip in subnet.iter() {
        if ip.is_loopback() { continue; }
        let ip_str = ip.to_string();
        let handle = tokio::spawn(async move {
            let _ = timeout(
                Duration::from_millis(500),
                TokioCommand::new("ping")
                    .args(["-c", "1", "-W", "1", &ip_str])
                    .output()
            ).await;
        });
        handles.push(handle);
        if handles.len() >= 50 {
            for h in handles.drain(..) { let _ = h.await; }
        }
    }
    for h in handles { let _ = h.await; }
    Ok(())
}
