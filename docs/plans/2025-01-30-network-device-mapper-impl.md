# Network Device Mapper Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add Fing-like network device discovery with port scanning, device identification, AI agent detection, and DuckDB persistence.

**Architecture:** New `network_map` module handles device discovery via ARP cache parsing and async TCP port scanning. Tab-based UI switches between WiFi Networks and Network Devices views. All data persisted to DuckDB.

**Tech Stack:** Rust, Tokio (async TCP), Ratatui, DuckDB, embedded OUI database

---

## Task 1: Add Dependencies

**Files:**
- Modify: `Cargo.toml`

**Step 1: Add new dependencies**

```toml
# Add after line 21 (after local-ip-address)
ipnetwork = "0.20"
```

**Step 2: Verify compilation**

Run: `cargo check`
Expected: Compiles without errors

**Step 3: Commit**

```bash
git add Cargo.toml
git commit -m "feat: add ipnetwork dependency for network scanning"
```

---

## Task 2: Create Device Data Types

**Files:**
- Create: `src/network_map/mod.rs`
- Create: `src/network_map/types.rs`
- Modify: `src/lib.rs`

**Step 1: Create the module directory**

Run: `mkdir -p src/network_map`

**Step 2: Create types.rs with core data structures**

```rust
// src/network_map/types.rs
use chrono::{DateTime, Utc};

/// A device discovered on the network
#[derive(Debug, Clone)]
pub struct Device {
    pub mac_address: String,
    pub ip_address: String,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub device_type: DeviceType,
    pub custom_name: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub is_online: bool,
    pub services: Vec<Service>,
    pub detected_agents: Vec<String>,
}

impl Device {
    pub fn new(mac_address: String, ip_address: String) -> Self {
        let now = Utc::now();
        Self {
            mac_address,
            ip_address,
            hostname: None,
            vendor: None,
            device_type: DeviceType::Unknown,
            custom_name: None,
            first_seen: now,
            last_seen: now,
            is_online: true,
            services: Vec::new(),
            detected_agents: Vec::new(),
        }
    }

    /// Get display name (custom name > hostname > vendor + type > MAC)
    pub fn display_name(&self) -> String {
        if let Some(ref name) = self.custom_name {
            return name.clone();
        }
        if let Some(ref hostname) = self.hostname {
            return hostname.clone();
        }
        if let Some(ref vendor) = self.vendor {
            return format!("{} {}", vendor, self.device_type);
        }
        self.mac_address.clone()
    }
}

/// Device type inferred from ports and vendor
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceType {
    Router,
    Phone,
    Computer,
    Laptop,
    Tablet,
    SmartTV,
    Printer,
    NAS,
    IoT,
    GameConsole,
    #[default]
    Unknown,
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceType::Router => write!(f, "Router"),
            DeviceType::Phone => write!(f, "Phone"),
            DeviceType::Computer => write!(f, "Computer"),
            DeviceType::Laptop => write!(f, "Laptop"),
            DeviceType::Tablet => write!(f, "Tablet"),
            DeviceType::SmartTV => write!(f, "Smart TV"),
            DeviceType::Printer => write!(f, "Printer"),
            DeviceType::NAS => write!(f, "NAS"),
            DeviceType::IoT => write!(f, "IoT Device"),
            DeviceType::GameConsole => write!(f, "Game Console"),
            DeviceType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// A service/port discovered on a device
#[derive(Debug, Clone)]
pub struct Service {
    pub port: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub service_name: Option<String>,
    pub banner: Option<String>,
    pub detected_agent: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

/// Progress of a network scan
#[derive(Debug, Clone)]
pub struct ScanProgress {
    pub phase: ScanPhase,
    pub devices_found: usize,
    pub current_device: Option<String>,
    pub ports_scanned: usize,
    pub total_ports: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanPhase {
    Discovery,
    PortScan,
    Identification,
    Complete,
}

impl std::fmt::Display for ScanPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanPhase::Discovery => write!(f, "Discovering devices"),
            ScanPhase::PortScan => write!(f, "Scanning ports"),
            ScanPhase::Identification => write!(f, "Identifying devices"),
            ScanPhase::Complete => write!(f, "Complete"),
        }
    }
}

/// Common ports to scan in quick mode
pub const COMMON_PORTS: &[u16] = &[
    21,    // FTP
    22,    // SSH
    23,    // Telnet
    25,    // SMTP
    53,    // DNS
    80,    // HTTP
    443,   // HTTPS
    139,   // NetBIOS
    445,   // SMB
    548,   // AFP
    554,   // RTSP
    3389,  // RDP
    5000,  // Synology/UPnP
    5001,  // Synology SSL
    8080,  // Alt HTTP
    8443,  // Alt HTTPS
    9100,  // Printer
    62078, // Apple iDevice
    8008,  // Chromecast
    8009,  // Chromecast
    // AI Agent ports
    3000,  // Dev servers / Claude Code
    3001,
    8000,  // Python servers
    8001,
    11434, // Ollama
    9229,  // Node.js debug
    8501,  // Streamlit (Aider)
];
```

**Step 3: Create mod.rs to export types**

```rust
// src/network_map/mod.rs
mod types;

pub use types::*;
```

**Step 4: Add module to lib.rs**

In `src/lib.rs`, add after line 6 (after `pub mod ip;`):

```rust
pub mod network_map;
```

**Step 5: Verify compilation**

Run: `cargo check`
Expected: Compiles without errors

**Step 6: Commit**

```bash
git add src/network_map/ src/lib.rs
git commit -m "feat: add network_map types for device discovery"
```

---

## Task 3: Implement Device Discovery

**Files:**
- Create: `src/network_map/discovery.rs`
- Modify: `src/network_map/mod.rs`

**Step 1: Create discovery.rs**

```rust
// src/network_map/discovery.rs
use crate::network_map::{Device, ScanPhase, ScanProgress};
use color_eyre::Result;
use ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;
use tokio::sync::mpsc;

/// Discover devices on the local network using ARP cache
pub async fn discover_devices(
    progress_tx: Option<mpsc::Sender<ScanProgress>>,
) -> Result<Vec<Device>> {
    // Send initial progress
    if let Some(ref tx) = progress_tx {
        let _ = tx.send(ScanProgress {
            phase: ScanPhase::Discovery,
            devices_found: 0,
            current_device: None,
            ports_scanned: 0,
            total_ports: 0,
        }).await;
    }

    // Get local network info
    let (local_ip, _subnet) = get_local_network_info()?;

    // Parse ARP cache
    let mut devices = parse_arp_cache()?;

    // Add gateway if not in ARP cache
    if let Some(gateway) = get_default_gateway()? {
        if !devices.iter().any(|d| d.ip_address == gateway) {
            let gateway_mac = get_mac_for_ip(&gateway).unwrap_or_else(|| "00:00:00:00:00:00".to_string());
            let mut gw_device = Device::new(gateway_mac, gateway);
            gw_device.device_type = crate::network_map::DeviceType::Router;
            devices.push(gw_device);
        }
    }

    // Mark this device
    for device in &mut devices {
        if device.ip_address == local_ip {
            device.hostname = Some("This device".to_string());
        }
    }

    // Update progress
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

/// Get local IP and subnet
fn get_local_network_info() -> Result<(String, IpNetwork)> {
    let local_ip = local_ip_address::local_ip()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to get local IP: {}", e))?;

    let ip_str = local_ip.to_string();

    // Assume /24 subnet for simplicity (covers most home/office networks)
    let network: IpNetwork = format!("{}/24", ip_str).parse()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to parse network: {}", e))?;

    Ok((ip_str, network))
}

/// Parse the system ARP cache
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
            // Skip incomplete entries and duplicates
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

/// Parse a single ARP line
/// Format varies by OS:
/// macOS: "hostname (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
/// Linux: "hostname (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0"
fn parse_arp_line(line: &str) -> Option<(String, String)> {
    // Find IP in parentheses
    let ip_start = line.find('(')? + 1;
    let ip_end = line.find(')')?;
    let ip = line[ip_start..ip_end].to_string();

    // Find MAC after "at "
    let at_pos = line.find(" at ")?;
    let after_at = &line[at_pos + 4..];
    let mac_end = after_at.find(' ').unwrap_or(after_at.len());
    let mac = after_at[..mac_end].to_string();

    // Validate IP format
    if ip.parse::<IpAddr>().is_err() {
        return None;
    }

    Some((ip, mac))
}

/// Get the default gateway IP
fn get_default_gateway() -> Result<Option<String>> {
    // macOS: netstat -nr | grep default
    let output = Command::new("netstat")
        .args(["-nr"])
        .output()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to run netstat: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[0] == "default" {
            let gateway = parts[1].to_string();
            // Validate it's an IP address
            if gateway.parse::<IpAddr>().is_ok() {
                return Ok(Some(gateway));
            }
        }
    }

    Ok(None)
}

/// Get MAC address for an IP (from ARP cache)
fn get_mac_for_ip(ip: &str) -> Option<String> {
    let output = Command::new("arp")
        .arg("-n")
        .arg(ip)
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_arp_line(&stdout).map(|(_, mac)| mac)
}

/// Ping sweep to populate ARP cache (optional, for more thorough discovery)
pub async fn ping_sweep(subnet: &IpNetwork) -> Result<()> {
    use tokio::process::Command as TokioCommand;
    use tokio::time::{timeout, Duration};

    let mut handles = Vec::new();

    for ip in subnet.iter() {
        if ip.is_loopback() {
            continue;
        }

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

        // Limit concurrency
        if handles.len() >= 50 {
            for h in handles.drain(..) {
                let _ = h.await;
            }
        }
    }

    // Wait for remaining
    for h in handles {
        let _ = h.await;
    }

    Ok(())
}
```

**Step 2: Update mod.rs**

```rust
// src/network_map/mod.rs
mod discovery;
mod types;

pub use discovery::*;
pub use types::*;
```

**Step 3: Verify compilation**

Run: `cargo check`
Expected: Compiles without errors

**Step 4: Commit**

```bash
git add src/network_map/
git commit -m "feat: implement device discovery via ARP cache"
```

---

## Task 4: Implement Port Scanner

**Files:**
- Create: `src/network_map/port_scan.rs`
- Modify: `src/network_map/mod.rs`

**Step 1: Create port_scan.rs**

```rust
// src/network_map/port_scan.rs
use crate::network_map::{Device, PortState, Protocol, ScanPhase, ScanProgress, Service, COMMON_PORTS};
use color_eyre::Result;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const BANNER_TIMEOUT: Duration = Duration::from_millis(1000);
const MAX_CONCURRENT_PORTS: usize = 50;
const MAX_CONCURRENT_DEVICES: usize = 10;

/// Scan common ports on all devices
pub async fn scan_devices_ports(
    devices: &mut [Device],
    progress_tx: Option<mpsc::Sender<ScanProgress>>,
) -> Result<()> {
    let total_ports = COMMON_PORTS.len() * devices.len();
    let mut scanned = 0;

    // Process devices in batches
    for chunk in devices.chunks_mut(MAX_CONCURRENT_DEVICES) {
        let mut handles = Vec::new();

        for device in chunk.iter() {
            let ip = device.ip_address.clone();
            let handle = tokio::spawn(async move {
                scan_device_ports(&ip, COMMON_PORTS).await
            });
            handles.push((device.mac_address.clone(), handle));
        }

        for (mac, handle) in handles {
            if let Ok(Ok(services)) = handle.await {
                if let Some(device) = chunk.iter_mut().find(|d| d.mac_address == mac) {
                    device.services = services;
                }
            }

            scanned += COMMON_PORTS.len();
            if let Some(ref tx) = progress_tx {
                let _ = tx.send(ScanProgress {
                    phase: ScanPhase::PortScan,
                    devices_found: devices.len(),
                    current_device: Some(mac),
                    ports_scanned: scanned,
                    total_ports,
                }).await;
            }
        }
    }

    Ok(())
}

/// Scan specific ports on a single device
async fn scan_device_ports(ip: &str, ports: &[u16]) -> Result<Vec<Service>> {
    let mut services = Vec::new();

    // Scan ports in parallel batches
    for chunk in ports.chunks(MAX_CONCURRENT_PORTS) {
        let mut handles = Vec::new();

        for &port in chunk {
            let ip = ip.to_string();
            let handle = tokio::spawn(async move {
                scan_port(&ip, port).await
            });
            handles.push((port, handle));
        }

        for (port, handle) in handles {
            if let Ok(Ok(Some(service))) = handle.await {
                services.push(service);
            }
        }
    }

    Ok(services)
}

/// Scan a single port
async fn scan_port(ip: &str, port: u16) -> Result<Option<Service>> {
    let addr: SocketAddr = format!("{}:{}", ip, port).parse()?;

    // Try to connect
    let connect_result = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await;

    match connect_result {
        Ok(Ok(mut stream)) => {
            // Port is open - try to grab banner
            let banner = grab_banner(&mut stream, port).await.ok().flatten();

            let service_name = identify_service(port, banner.as_deref());
            let detected_agent = detect_agent(port, banner.as_deref());

            Ok(Some(Service {
                port,
                protocol: Protocol::Tcp,
                state: PortState::Open,
                service_name,
                banner,
                detected_agent,
            }))
        }
        Ok(Err(_)) => Ok(None), // Connection refused = closed
        Err(_) => Ok(None),     // Timeout = filtered/closed
    }
}

/// Try to grab a banner from an open port
async fn grab_banner(stream: &mut TcpStream, port: u16) -> Result<Option<String>> {
    let mut buf = [0u8; 256];

    // Some services need a prompt
    let probe = match port {
        80 | 8080 | 8000 | 8001 | 3000 | 3001 | 8008 | 11434 => {
            Some("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        }
        _ => None,
    };

    if let Some(probe) = probe {
        let _ = stream.write_all(probe.as_bytes()).await;
    }

    match timeout(BANNER_TIMEOUT, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let banner = String::from_utf8_lossy(&buf[..n])
                .chars()
                .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                .take(200)
                .collect::<String>()
                .trim()
                .to_string();

            if banner.is_empty() {
                Ok(None)
            } else {
                Ok(Some(banner))
            }
        }
        _ => Ok(None),
    }
}

/// Identify service from port number and banner
fn identify_service(port: u16, banner: Option<&str>) -> Option<String> {
    // Check banner first
    if let Some(banner) = banner {
        let banner_lower = banner.to_lowercase();

        if banner_lower.contains("ssh") {
            return Some("SSH".to_string());
        }
        if banner_lower.contains("http") || banner_lower.contains("html") {
            return Some("HTTP".to_string());
        }
        if banner_lower.contains("ftp") {
            return Some("FTP".to_string());
        }
        if banner_lower.contains("smtp") {
            return Some("SMTP".to_string());
        }
        if banner_lower.contains("ollama") {
            return Some("Ollama API".to_string());
        }
    }

    // Fall back to well-known ports
    match port {
        21 => Some("FTP".to_string()),
        22 => Some("SSH".to_string()),
        23 => Some("Telnet".to_string()),
        25 => Some("SMTP".to_string()),
        53 => Some("DNS".to_string()),
        80 => Some("HTTP".to_string()),
        443 => Some("HTTPS".to_string()),
        139 | 445 => Some("SMB".to_string()),
        548 => Some("AFP".to_string()),
        554 => Some("RTSP".to_string()),
        3389 => Some("RDP".to_string()),
        5000 | 5001 => Some("Synology".to_string()),
        8080 | 8443 => Some("HTTP Alt".to_string()),
        9100 => Some("Printer".to_string()),
        62078 => Some("Apple Device".to_string()),
        8008 | 8009 => Some("Chromecast".to_string()),
        11434 => Some("Ollama".to_string()),
        9229 => Some("Node Debug".to_string()),
        8501 => Some("Streamlit".to_string()),
        3000 | 3001 => Some("Dev Server".to_string()),
        8000 | 8001 => Some("Python Server".to_string()),
        _ => None,
    }
}

/// Detect AI coding agents from port/banner
fn detect_agent(port: u16, banner: Option<&str>) -> Option<String> {
    if let Some(banner) = banner {
        let banner_lower = banner.to_lowercase();

        if banner_lower.contains("claude") || banner_lower.contains("anthropic") {
            return Some("Claude Code".to_string());
        }
        if banner_lower.contains("ollama") {
            return Some("Ollama".to_string());
        }
        if banner_lower.contains("cursor") {
            return Some("Cursor".to_string());
        }
        if banner_lower.contains("aider") {
            return Some("Aider".to_string());
        }
        if banner_lower.contains("openai") {
            return Some("OpenAI".to_string());
        }
        if banner_lower.contains("llama") {
            return Some("Llama.cpp".to_string());
        }
    }

    // Port-based detection (less reliable)
    match port {
        11434 => Some("Ollama".to_string()),
        8501 => Some("Aider (Streamlit)".to_string()),
        _ => None,
    }
}

/// Deep scan: scan all 65535 ports on a single device
pub async fn deep_scan_device(
    device: &mut Device,
    progress_tx: Option<mpsc::Sender<ScanProgress>>,
) -> Result<()> {
    let all_ports: Vec<u16> = (1..=65535).collect();
    let total_ports = all_ports.len();
    let mut scanned = 0;

    let mut services = Vec::new();

    // Scan in larger batches for deep scan
    for chunk in all_ports.chunks(2000) {
        let chunk_services = scan_device_ports(&device.ip_address, chunk).await?;
        services.extend(chunk_services);

        scanned += chunk.len();
        if let Some(ref tx) = progress_tx {
            let _ = tx.send(ScanProgress {
                phase: ScanPhase::PortScan,
                devices_found: 1,
                current_device: Some(device.ip_address.clone()),
                ports_scanned: scanned,
                total_ports,
            }).await;
        }
    }

    device.services = services;
    Ok(())
}
```

**Step 2: Update mod.rs**

```rust
// src/network_map/mod.rs
mod discovery;
mod port_scan;
mod types;

pub use discovery::*;
pub use port_scan::*;
pub use types::*;
```

**Step 3: Verify compilation**

Run: `cargo check`
Expected: Compiles without errors

**Step 4: Commit**

```bash
git add src/network_map/
git commit -m "feat: implement async TCP port scanner with banner grabbing"
```

---

## Task 5: Implement OUI Vendor Lookup

**Files:**
- Create: `src/network_map/oui.rs`
- Modify: `src/network_map/mod.rs`

**Step 1: Create oui.rs with embedded vendor database**

```rust
// src/network_map/oui.rs
use std::collections::HashMap;
use std::sync::OnceLock;

/// Lookup vendor name from MAC address prefix (OUI)
pub fn lookup_vendor(mac: &str) -> Option<&'static str> {
    let oui = get_oui_database();

    // Normalize MAC: remove separators and take first 6 chars (3 bytes)
    let normalized: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(6)
        .collect::<String>()
        .to_uppercase();

    if normalized.len() < 6 {
        return None;
    }

    oui.get(normalized.as_str()).copied()
}

/// Get or initialize the OUI database
fn get_oui_database() -> &'static HashMap<&'static str, &'static str> {
    static OUI_DB: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();

    OUI_DB.get_or_init(|| {
        let mut map = HashMap::with_capacity(500);

        // Common vendors (abbreviated list - expand as needed)
        // Apple
        map.insert("000A27", "Apple");
        map.insert("000A95", "Apple");
        map.insert("000D93", "Apple");
        map.insert("0010FA", "Apple");
        map.insert("001124", "Apple");
        map.insert("001451", "Apple");
        map.insert("0016CB", "Apple");
        map.insert("0017F2", "Apple");
        map.insert("0019E3", "Apple");
        map.insert("001B63", "Apple");
        map.insert("001CB3", "Apple");
        map.insert("001D4F", "Apple");
        map.insert("001E52", "Apple");
        map.insert("001EC2", "Apple");
        map.insert("001F5B", "Apple");
        map.insert("001FF3", "Apple");
        map.insert("002241", "Apple");
        map.insert("002312", "Apple");
        map.insert("002332", "Apple");
        map.insert("002436", "Apple");
        map.insert("00254B", "Apple");
        map.insert("002608", "Apple");
        map.insert("00264A", "Apple");
        map.insert("0026B0", "Apple");
        map.insert("0026BB", "Apple");
        map.insert("003065", "Apple");
        map.insert("003EE1", "Apple");
        map.insert("0050E4", "Apple");
        map.insert("00A040", "Apple");
        map.insert("041552", "Apple");
        map.insert("042665", "Apple");
        map.insert("044BED", "Apple");
        map.insert("0452F3", "Apple");
        map.insert("045453", "Apple");
        map.insert("046C59", "Apple");
        map.insert("047D7B", "Apple");
        map.insert("04D3CF", "Apple");
        map.insert("04DB56", "Apple");
        map.insert("04E536", "Apple");
        map.insert("04F13E", "Apple");
        map.insert("04F7E4", "Apple");
        map.insert("086698", "Apple");
        map.insert("086D41", "Apple");
        map.insert("087045", "Apple");
        map.insert("0C74C2", "Apple");
        map.insert("0C771A", "Apple");
        map.insert("10DDB1", "Apple");
        map.insert("14109F", "Apple");
        map.insert("183451", "Apple");
        map.insert("18AF61", "Apple");
        map.insert("1C36BB", "Apple");
        map.insert("20AB37", "Apple");
        map.insert("24A074", "Apple");
        map.insert("28E02C", "Apple");
        map.insert("2C200B", "Apple");
        map.insert("34C059", "Apple");
        map.insert("3C0754", "Apple");
        map.insert("403004", "Apple");
        map.insert("442A60", "Apple");
        map.insert("483B38", "Apple");
        map.insert("4C3275", "Apple");
        map.insert("4C57CA", "Apple");
        map.insert("4C8D79", "Apple");
        map.insert("503237", "Apple");
        map.insert("54724F", "Apple");
        map.insert("54E43A", "Apple");
        map.insert("58B035", "Apple");
        map.insert("5C5948", "Apple");
        map.insert("5C969D", "Apple");
        map.insert("5CADCF", "Apple");
        map.insert("60C547", "Apple");
        map.insert("60FACD", "Apple");
        map.insert("64200C", "Apple");
        map.insert("649ABE", "Apple");
        map.insert("64A3CB", "Apple");
        map.insert("64E682", "Apple");
        map.insert("68644B", "Apple");
        map.insert("68967B", "Apple");
        map.insert("68A86D", "Apple");
        map.insert("6C3E6D", "Apple");
        map.insert("6C709F", "Apple");
        map.insert("6CC26B", "Apple");
        map.insert("70CD60", "Apple");
        map.insert("70DEE2", "Apple");
        map.insert("74E1B6", "Apple");
        map.insert("78886D", "Apple");
        map.insert("78A3E4", "Apple");
        map.insert("7C11BE", "Apple");
        map.insert("7CC3A1", "Apple");
        map.insert("7CC537", "Apple");
        map.insert("7CD1C3", "Apple");
        map.insert("803F5D", "Apple");
        map.insert("804971", "Apple");
        map.insert("80E650", "Apple");
        map.insert("8489AD", "Apple");
        map.insert("848506", "Apple");
        map.insert("84788B", "Apple");
        map.insert("8866A5", "Apple");
        map.insert("886B6E", "Apple");
        map.insert("88C663", "Apple");
        map.insert("88E87F", "Apple");
        map.insert("8C006D", "Apple");
        map.insert("8C2937", "Apple");
        map.insert("8C2DAA", "Apple");
        map.insert("8C5877", "Apple");
        map.insert("8C7B9D", "Apple");
        map.insert("8C8590", "Apple");
        map.insert("8C8FE9", "Apple");
        map.insert("9027E4", "Apple");
        map.insert("90840D", "Apple");
        map.insert("90B21F", "Apple");
        map.insert("90B931", "Apple");
        map.insert("9803D8", "Apple");
        map.insert("9810E8", "Apple");
        map.insert("9C20A3", "Apple");
        map.insert("9CFC01", "Apple");
        map.insert("A0999B", "Apple");
        map.insert("A43135", "Apple");
        map.insert("A45E60", "Apple");
        map.insert("A4B197", "Apple");
        map.insert("A4C361", "Apple");
        map.insert("A4D1D2", "Apple");
        map.insert("A82066", "Apple");
        map.insert("A85B78", "Apple");
        map.insert("A860B6", "Apple");
        map.insert("A88808", "Apple");
        map.insert("A88E24", "Apple");
        map.insert("AC293A", "Apple");
        map.insert("ACBC32", "Apple");
        map.insert("ACFDCE", "Apple");
        map.insert("B03495", "Apple");
        map.insert("B418D1", "Apple");
        map.insert("B48B19", "Apple");
        map.insert("B4F0AB", "Apple");
        map.insert("B844D9", "Apple");
        map.insert("B8C75D", "Apple");
        map.insert("B8E856", "Apple");
        map.insert("B8F6B1", "Apple");
        map.insert("BC3BAF", "Apple");
        map.insert("BC5436", "Apple");
        map.insert("BC6778", "Apple");
        map.insert("BC9FEF", "Apple");
        map.insert("C06394", "Apple");
        map.insert("C0847A", "Apple");
        map.insert("C42C03", "Apple");
        map.insert("C82A14", "Apple");
        map.insert("C8334B", "Apple");
        map.insert("C869CD", "Apple");
        map.insert("C8B5B7", "Apple");
        map.insert("CC29F5", "Apple");
        map.insert("D023DB", "Apple");
        map.insert("D02598", "Apple");
        map.insert("D0A637", "Apple");
        map.insert("D4619D", "Apple");
        map.insert("D4F46F", "Apple");
        map.insert("D89695", "Apple");
        map.insert("D8A25E", "Apple");
        map.insert("D8BB2C", "Apple");
        map.insert("DC2B2A", "Apple");
        map.insert("DC2B61", "Apple");
        map.insert("DC86D8", "Apple");
        map.insert("DCA4CA", "Apple");
        map.insert("E05F45", "Apple");
        map.insert("E0ACCB", "Apple");
        map.insert("E0B52D", "Apple");
        map.insert("E0C767", "Apple");
        map.insert("E0F5C6", "Apple");
        map.insert("E80688", "Apple");
        map.insert("E8040B", "Apple");
        map.insert("E8802E", "Apple");
        map.insert("E8B4C8", "Apple");
        map.insert("F02475", "Apple");
        map.insert("F0B479", "Apple");
        map.insert("F0C1F1", "Apple");
        map.insert("F0D1A9", "Apple");
        map.insert("F0DCE2", "Apple");
        map.insert("F0F61C", "Apple");
        map.insert("F4310D", "Apple");
        map.insert("F437B7", "Apple");
        map.insert("F8E079", "Apple");

        // Samsung
        map.insert("00125A", "Samsung");
        map.insert("0015B9", "Samsung");
        map.insert("001A8A", "Samsung");
        map.insert("001EE1", "Samsung");
        map.insert("002119", "Samsung");
        map.insert("0026E4", "Samsung");
        map.insert("1C62B8", "Samsung");
        map.insert("2C4401", "Samsung");
        map.insert("34145F", "Samsung");
        map.insert("50A4C8", "Samsung");
        map.insert("50FC9F", "Samsung");
        map.insert("5C497D", "Samsung");
        map.insert("6C2F2C", "Samsung");
        map.insert("78BD9D", "Samsung");
        map.insert("84119E", "Samsung");
        map.insert("8C71F8", "Samsung");
        map.insert("9463D1", "Samsung");
        map.insert("9852B1", "Samsung");
        map.insert("A0B4A5", "Samsung");
        map.insert("ACE4B5", "Samsung");
        map.insert("BC8CCD", "Samsung");
        map.insert("C44619", "Samsung");
        map.insert("E4F8EF", "Samsung");
        map.insert("F0E77E", "Samsung");

        // Google
        map.insert("001A11", "Google");
        map.insert("3C5AB4", "Google");
        map.insert("54608C", "Google");
        map.insert("94EB2C", "Google");
        map.insert("F4F5D8", "Google");
        map.insert("F4F5E8", "Google");

        // Intel
        map.insert("001111", "Intel");
        map.insert("001302", "Intel");
        map.insert("001500", "Intel");
        map.insert("0016EA", "Intel");
        map.insert("001B21", "Intel");
        map.insert("001E64", "Intel");
        map.insert("001E67", "Intel");
        map.insert("001F3B", "Intel");
        map.insert("002314", "Intel");
        map.insert("0024D6", "Intel");
        map.insert("0024D7", "Intel");
        map.insert("3C970E", "Intel");
        map.insert("485B39", "Intel");
        map.insert("4CEB42", "Intel");
        map.insert("5CE0C5", "Intel");
        map.insert("606720", "Intel");
        map.insert("64D4DA", "Intel");
        map.insert("7C7A91", "Intel");
        map.insert("8086F2", "Intel");
        map.insert("84A6C8", "Intel");
        map.insert("8C8D28", "Intel");
        map.insert("9C4E36", "Intel");
        map.insert("A4C494", "Intel");
        map.insert("B4B686", "Intel");
        map.insert("C80838", "Intel");
        map.insert("F81654", "Intel");

        // Espressif (ESP32/ESP8266)
        map.insert("240AC4", "Espressif");
        map.insert("24B2DE", "Espressif");
        map.insert("2C3AE8", "Espressif");
        map.insert("30AEA4", "Espressif");
        map.insert("3C61E0", "Espressif");
        map.insert("3C71BF", "Espressif");
        map.insert("480FD2", "Espressif");
        map.insert("4C11AE", "Espressif");
        map.insert("5CCF7F", "Espressif");
        map.insert("600194", "Espressif");
        map.insert("68C63A", "Espressif");
        map.insert("84CCA8", "Espressif");
        map.insert("84F3EB", "Espressif");
        map.insert("8CAAB5", "Espressif");
        map.insert("98CDAC", "Espressif");
        map.insert("A020A6", "Espressif");
        map.insert("A4CF12", "Espressif");
        map.insert("AC67B2", "Espressif");
        map.insert("B4E62D", "Espressif");
        map.insert("BC:DD:C2", "Espressif");
        map.insert("C44F33", "Espressif");
        map.insert("CC50E3", "Espressif");
        map.insert("D8BFC0", "Espressif");
        map.insert("DC4F22", "Espressif");
        map.insert("E868E7", "Espressif");
        map.insert("ECFABC", "Espressif");

        // Amazon
        map.insert("0C47C9", "Amazon");
        map.insert("18B4A6", "Amazon");
        map.insert("34D270", "Amazon");
        map.insert("40B4CD", "Amazon");
        map.insert("50DCE7", "Amazon");
        map.insert("687D6B", "Amazon");
        map.insert("68547A", "Amazon");
        map.insert("6854FD", "Amazon");
        map.insert("74C246", "Amazon");
        map.insert("747548", "Amazon");
        map.insert("84D6D0", "Amazon");
        map.insert("A002DC", "Amazon");
        map.insert("F0272D", "Amazon");
        map.insert("FC65DE", "Amazon");
        map.insert("FCA183", "Amazon");

        // Microsoft
        map.insert("001DD8", "Microsoft");
        map.insert("0050F2", "Microsoft");
        map.insert("28186D", "Microsoft");
        map.insert("50579C", "Microsoft");
        map.insert("7CB27D", "Microsoft");
        map.insert("B483E7", "Microsoft");
        map.insert("C83DD4", "Microsoft");

        // TP-Link
        map.insert("001470", "TP-Link");
        map.insert("0019E0", "TP-Link");
        map.insert("00275A", "TP-Link");
        map.insert("14CC20", "TP-Link");
        map.insert("1C3BF3", "TP-Link");
        map.insert("30B5C2", "TP-Link");
        map.insert("503EAA", "TP-Link");
        map.insert("54E6FC", "TP-Link");
        map.insert("64566D", "TP-Link");
        map.insert("6C5AB0", "TP-Link");
        map.insert("90F652", "TP-Link");
        map.insert("98254A", "TP-Link");
        map.insert("ACE215", "TP-Link");
        map.insert("B0A7B9", "TP-Link");
        map.insert("C025E9", "TP-Link");
        map.insert("D80D17", "TP-Link");
        map.insert("EC086B", "TP-Link");
        map.insert("F4EC38", "TP-Link");

        // Netgear
        map.insert("0024B2", "Netgear");
        map.insert("00265A", "Netgear");
        map.insert("000FB5", "Netgear");
        map.insert("001B2F", "Netgear");
        map.insert("001E2A", "Netgear");
        map.insert("002275", "Netgear");
        map.insert("20E52A", "Netgear");
        map.insert("28C68E", "Netgear");
        map.insert("2CB05D", "Netgear");
        map.insert("4494FC", "Netgear");
        map.insert("6038E0", "Netgear");
        map.insert("6CB0CE", "Netgear");
        map.insert("744401", "Netgear");
        map.insert("84D47E", "Netgear");
        map.insert("9C3DCF", "Netgear");
        map.insert("A42B8C", "Netgear");
        map.insert("B03956", "Netgear");
        map.insert("C03F0E", "Netgear");
        map.insert("C0FFD4", "Netgear");
        map.insert("E0469A", "Netgear");
        map.insert("E4F4C6", "Netgear");

        // ASUS
        map.insert("001731", "ASUS");
        map.insert("001A92", "ASUS");
        map.insert("001FC6", "ASUS");
        map.insert("002354", "ASUS");
        map.insert("0025D3", "ASUS");
        map.insert("04421A", "ASUS");
        map.insert("08606E", "ASUS");
        map.insert("107B44", "ASUS");
        map.insert("14DAE9", "ASUS");
        map.insert("1C872C", "ASUS");
        map.insert("2C4D54", "ASUS");
        map.insert("2CFDA1", "ASUS");
        map.insert("3085A9", "ASUS");
        map.insert("3497F6", "ASUS");
        map.insert("485B39", "ASUS");
        map.insert("50465D", "ASUS");
        map.insert("54A050", "ASUS");
        map.insert("6045CB", "ASUS");
        map.insert("74D02B", "ASUS");
        map.insert("88D7F6", "ASUS");
        map.insert("90E6BA", "ASUS");
        map.insert("ACDE48", "ASUS");
        map.insert("B06EBF", "ASUS");
        map.insert("BC5FF4", "ASUS");
        map.insert("D45D64", "ASUS");
        map.insert("D850E6", "ASUS");
        map.insert("E03F49", "ASUS");
        map.insert("F07959", "ASUS");
        map.insert("F46D04", "ASUS");

        // Dell
        map.insert("001422", "Dell");
        map.insert("001C23", "Dell");
        map.insert("002219", "Dell");
        map.insert("0023AE", "Dell");
        map.insert("00B0D0", "Dell");
        map.insert("14187D", "Dell");
        map.insert("149182", "Dell");
        map.insert("14B31F", "Dell");
        map.insert("18A99B", "Dell");
        map.insert("18DB24", "Dell");
        map.insert("246E96", "Dell");
        map.insert("28F10E", "Dell");
        map.insert("34E6D7", "Dell");
        map.insert("5C260A", "Dell");
        map.insert("6C2B59", "Dell");
        map.insert("74E6E2", "Dell");
        map.insert("782BCB", "Dell");
        map.insert("78E7D1", "Dell");
        map.insert("84FD2B", "Dell");
        map.insert("88AE1D", "Dell");
        map.insert("98902D", "Dell");
        map.insert("B083FE", "Dell");
        map.insert("B8CA3A", "Dell");
        map.insert("D481D7", "Dell");
        map.insert("D89EF3", "Dell");
        map.insert("E0DB55", "Dell");
        map.insert("F04DA2", "Dell");
        map.insert("F48E38", "Dell");
        map.insert("F8DB88", "Dell");

        // HP
        map.insert("001083", "HP");
        map.insert("001185", "HP");
        map.insert("0014C2", "HP");
        map.insert("001635", "HP");
        map.insert("001708", "HP");
        map.insert("001A4B", "HP");
        map.insert("001CC4", "HP");
        map.insert("001E0B", "HP");
        map.insert("002128", "HP");
        map.insert("00215A", "HP");
        map.insert("0022B0", "HP");
        map.insert("0023B7", "HP");
        map.insert("002481", "HP");
        map.insert("002564", "HP");
        map.insert("003048", "HP");
        map.insert("0030C1", "HP");
        map.insert("040E3C", "HP");
        map.insert("10604B", "HP");
        map.insert("10E68A", "HP");
        map.insert("1458D0", "HP");
        map.insert("28924A", "HP");
        map.insert("3024A9", "HP");
        map.insert("308D99", "HP");
        map.insert("3863BB", "HP");
        map.insert("3CA82A", "HP");
        map.insert("3CD92B", "HP");
        map.insert("64517E", "HP");
        map.insert("6CC217", "HP");
        map.insert("802689", "HP");
        map.insert("84345C", "HP");
        map.insert("8851FB", "HP");
        map.insert("94B862", "HP");
        map.insert("98E7F4", "HP");
        map.insert("A02BB8", "HP");
        map.insert("A45D36", "HP");
        map.insert("A4DB30", "HP");
        map.insert("B00594", "HP");
        map.insert("B8B81E", "HP");
        map.insert("C8D9D2", "HP");
        map.insert("D42C44", "HP");
        map.insert("D4C9EF", "HP");
        map.insert("E4115B", "HP");
        map.insert("EC8EB5", "HP");
        map.insert("F0921C", "HP");
        map.insert("F4CE46", "HP");
        map.insert("F8D111", "HP");

        // Lenovo
        map.insert("002482", "Lenovo");
        map.insert("00249B", "Lenovo");
        map.insert("002558", "Lenovo");
        map.insert("0026E8", "Lenovo");
        map.insert("347083", "Lenovo");
        map.insert("384312", "Lenovo");
        map.insert("4C5262", "Lenovo");
        map.insert("5470E6", "Lenovo");
        map.insert("60D819", "Lenovo");
        map.insert("6C0B84", "Lenovo");
        map.insert("6CDC1A", "Lenovo");
        map.insert("C4D0E3", "Lenovo");
        map.insert("E83934", "Lenovo");
        map.insert("EC5C68", "Lenovo");
        map.insert("F82FA8", "Lenovo");

        // Synology
        map.insert("0011A0", "Synology");
        map.insert("001132", "Synology");
        map.insert("0011A1", "Synology");
        map.insert("0011A2", "Synology");

        // Raspberry Pi
        map.insert("B827EB", "Raspberry Pi");
        map.insert("DC:A6:32", "Raspberry Pi");
        map.insert("E45F01", "Raspberry Pi");

        // Sony
        map.insert("000AD9", "Sony");
        map.insert("001315", "Sony");
        map.insert("001A80", "Sony");
        map.insert("001D0D", "Sony");
        map.insert("001FA7", "Sony");
        map.insert("0024EF", "Sony");
        map.insert("1C1B0D", "Sony");
        map.insert("28A02B", "Sony");
        map.insert("30F9ED", "Sony");
        map.insert("40B837", "Sony");
        map.insert("54426F", "Sony");
        map.insert("78843C", "Sony");
        map.insert("8C4909", "Sony");
        map.insert("A85B61", "Sony");
        map.insert("AC7A42", "Sony");
        map.insert("B4527E", "Sony");
        map.insert("BC60A7", "Sony");
        map.insert("E8B2AC", "Sony");
        map.insert("F8DA0C", "Sony");

        // LG
        map.insert("001256", "LG");
        map.insert("001E75", "LG");
        map.insert("00E091", "LG");
        map.insert("10F96F", "LG");
        map.insert("1C5A6B", "LG");
        map.insert("1C6262", "LG");
        map.insert("340804", "LG");
        map.insert("3C8BFE", "LG");
        map.insert("64899A", "LG");
        map.insert("6C5C14", "LG");
        map.insert("6CD032", "LG");
        map.insert("78F882", "LG");
        map.insert("88074B", "LG");
        map.insert("9C02D7", "LG");
        map.insert("9CA39B", "LG");
        map.insert("A8F274", "LG");
        map.insert("B8C68E", "LG");
        map.insert("C83870", "LG");
        map.insert("CC2D8C", "LG");
        map.insert("D0D2B0", "LG");
        map.insert("EC1F72", "LG");
        map.insert("F8B156", "LG");

        // Nintendo
        map.insert("001656", "Nintendo");
        map.insert("001AE9", "Nintendo");
        map.insert("001BEA", "Nintendo");
        map.insert("001CBE", "Nintendo");
        map.insert("001DBC", "Nintendo");
        map.insert("001E35", "Nintendo");
        map.insert("001F32", "Nintendo");
        map.insert("001FC5", "Nintendo");
        map.insert("0022D7", "Nintendo");
        map.insert("0022AA", "Nintendo");
        map.insert("002331", "Nintendo");
        map.insert("002403", "Nintendo");
        map.insert("0024F3", "Nintendo");
        map.insert("0025A0", "Nintendo");
        map.insert("002709", "Nintendo");
        map.insert("182A7B", "Nintendo");
        map.insert("2C10C1", "Nintendo");
        map.insert("34AF2C", "Nintendo");
        map.insert("40D28A", "Nintendo");
        map.insert("40F407", "Nintendo");
        map.insert("582F40", "Nintendo");
        map.insert("58BDA3", "Nintendo");
        map.insert("5C521E", "Nintendo");
        map.insert("606BFF", "Nintendo");
        map.insert("7048F7", "Nintendo");
        map.insert("78A2A0", "Nintendo");
        map.insert("7CBB8A", "Nintendo");
        map.insert("8CCDE8", "Nintendo");
        map.insert("98415C", "Nintendo");
        map.insert("98B6E9", "Nintendo");
        map.insert("9CE635", "Nintendo");
        map.insert("A438CC", "Nintendo");
        map.insert("A45C27", "Nintendo");
        map.insert("A4C0E1", "Nintendo");
        map.insert("B87826", "Nintendo");
        map.insert("B88AEC", "Nintendo");
        map.insert("B8AE6E", "Nintendo");
        map.insert("CC9E00", "Nintendo");
        map.insert("D8CEE6", "Nintendo");
        map.insert("DC68EB", "Nintendo");
        map.insert("E00C7F", "Nintendo");
        map.insert("E0E751", "Nintendo");
        map.insert("E84ECE", "Nintendo");

        // Ubiquiti
        map.insert("00156D", "Ubiquiti");
        map.insert("002722", "Ubiquiti");
        map.insert("04E2F6", "Ubiquiti");
        map.insert("0418D6", "Ubiquiti");
        map.insert("18E829", "Ubiquiti");
        map.insert("24A43C", "Ubiquiti");
        map.insert("44D9E7", "Ubiquiti");
        map.insert("60229C", "Ubiquiti");
        map.insert("687251", "Ubiquiti");
        map.insert("68D79A", "Ubiquiti");
        map.insert("6C19E8", "Ubiquiti");
        map.insert("788A20", "Ubiquiti");
        map.insert("802AA8", "Ubiquiti");
        map.insert("ACE6AB", "Ubiquiti");
        map.insert("B4FBE4", "Ubiquiti");
        map.insert("D021F9", "Ubiquiti");
        map.insert("DC9FDB", "Ubiquiti");
        map.insert("E063DA", "Ubiquiti");
        map.insert("E42283", "Ubiquiti");
        map.insert("F09FC2", "Ubiquiti");
        map.insert("FC2277", "Ubiquiti");
        map.insert("FC72F1", "Ubiquiti");
        map.insert("FCFFD4", "Ubiquiti");

        // Xiaomi
        map.insert("0C1DAF", "Xiaomi");
        map.insert("0DDB6B", "Xiaomi");
        map.insert("1C5A37", "Xiaomi");
        map.insert("286C07", "Xiaomi");
        map.insert("28E31F", "Xiaomi");
        map.insert("34CE00", "Xiaomi");
        map.insert("38A4ED", "Xiaomi");
        map.insert("3C91FB", "Xiaomi");
        map.insert("50647B", "Xiaomi");
        map.insert("54E61B", "Xiaomi");
        map.insert("584498", "Xiaomi");
        map.insert("5C0A5B", "Xiaomi");
        map.insert("640980", "Xiaomi");
        map.insert("64B473", "Xiaomi");
        map.insert("6889A2", "Xiaomi");
        map.insert("68DFDD", "Xiaomi");
        map.insert("74234A", "Xiaomi");
        map.insert("74A3D1", "Xiaomi");
        map.insert("78020F", "Xiaomi");
        map.insert("7C1DD9", "Xiaomi");
        map.insert("8C376F", "Xiaomi");
        map.insert("98FAE3", "Xiaomi");
        map.insert("A4D388", "Xiaomi");
        map.insert("AC1E92", "Xiaomi");
        map.insert("ACF7F3", "Xiaomi");
        map.insert("B0D59D", "Xiaomi");
        map.insert("C40BC2", "Xiaomi");
        map.insert("D472DC", "Xiaomi");
        map.insert("E8AB54", "Xiaomi");
        map.insert("F0B429", "Xiaomi");
        map.insert("F48B32", "Xiaomi");

        map
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_apple() {
        assert_eq!(lookup_vendor("00:26:BB:12:34:56"), Some("Apple"));
        assert_eq!(lookup_vendor("0026bb123456"), Some("Apple"));
        assert_eq!(lookup_vendor("00-26-BB-12-34-56"), Some("Apple"));
    }

    #[test]
    fn test_lookup_unknown() {
        assert_eq!(lookup_vendor("FF:FF:FF:FF:FF:FF"), None);
    }

    #[test]
    fn test_lookup_espressif() {
        assert_eq!(lookup_vendor("5C:CF:7F:12:34:56"), Some("Espressif"));
    }
}
```

**Step 2: Update mod.rs**

```rust
// src/network_map/mod.rs
mod discovery;
mod oui;
mod port_scan;
mod types;

pub use discovery::*;
pub use oui::lookup_vendor;
pub use port_scan::*;
pub use types::*;
```

**Step 3: Verify compilation**

Run: `cargo check`
Expected: Compiles without errors

**Step 4: Run tests**

Run: `cargo test oui`
Expected: All tests pass

**Step 5: Commit**

```bash
git add src/network_map/
git commit -m "feat: add OUI vendor database for MAC address lookup"
```

---

## Task 6: Implement Device Identification

**Files:**
- Create: `src/network_map/identify.rs`
- Modify: `src/network_map/mod.rs`

**Step 1: Create identify.rs**

```rust
// src/network_map/identify.rs
use crate::network_map::{lookup_vendor, Device, DeviceType};

/// Identify device type and vendor information
pub fn identify_device(device: &mut Device) {
    // Lookup vendor from MAC
    if device.vendor.is_none() {
        device.vendor = lookup_vendor(&device.mac_address).map(String::from);
    }

    // Infer device type from ports and vendor
    device.device_type = infer_device_type(device);

    // Collect detected agents
    device.detected_agents = device.services
        .iter()
        .filter_map(|s| s.detected_agent.clone())
        .collect();
}

/// Infer device type from open ports and vendor
fn infer_device_type(device: &Device) -> DeviceType {
    let ports: Vec<u16> = device.services.iter().map(|s| s.port).collect();
    let vendor = device.vendor.as_deref().unwrap_or("");
    let vendor_lower = vendor.to_lowercase();

    // Router detection: DNS + HTTP/HTTPS management
    if ports.contains(&53) && (ports.contains(&80) || ports.contains(&443)) {
        return DeviceType::Router;
    }

    // Apple iPhone/iPad detection
    if ports.contains(&62078) && vendor_lower.contains("apple") {
        return DeviceType::Phone;
    }

    // Apple devices without iPhone port
    if vendor_lower.contains("apple") {
        if ports.contains(&22) || ports.contains(&548) {
            return DeviceType::Computer;
        }
        return DeviceType::Phone; // Default Apple to phone
    }

    // Smart TV detection
    if ports.contains(&8008) || ports.contains(&8009) || ports.contains(&9197) {
        return DeviceType::SmartTV;
    }
    if vendor_lower.contains("samsung") && !ports.contains(&22) {
        return DeviceType::SmartTV; // Samsung without SSH is likely a TV
    }
    if vendor_lower.contains("lg") && !ports.contains(&22) {
        return DeviceType::SmartTV;
    }

    // Game console detection
    if vendor_lower.contains("nintendo") || vendor_lower.contains("sony") && !ports.contains(&22) {
        return DeviceType::GameConsole;
    }

    // NAS detection
    if (ports.contains(&22) || ports.contains(&23))
        && (ports.contains(&445) || ports.contains(&548))
        && (ports.contains(&5000) || ports.contains(&5001))
    {
        return DeviceType::NAS;
    }
    if vendor_lower.contains("synology") || vendor_lower.contains("qnap") {
        return DeviceType::NAS;
    }

    // Printer detection
    if ports.contains(&9100) || ports.contains(&631) {
        return DeviceType::Printer;
    }
    if vendor_lower.contains("hp") && ports.contains(&80) && !ports.contains(&22) {
        return DeviceType::Printer;
    }

    // Computer/Laptop detection (SSH or RDP)
    if ports.contains(&22) || ports.contains(&3389) {
        if vendor_lower.contains("dell") || vendor_lower.contains("lenovo")
            || vendor_lower.contains("hp") {
            return DeviceType::Laptop;
        }
        return DeviceType::Computer;
    }

    // IoT detection
    if vendor_lower.contains("espressif") || vendor_lower.contains("amazon") {
        return DeviceType::IoT;
    }

    // Network equipment
    if vendor_lower.contains("tp-link") || vendor_lower.contains("netgear")
        || vendor_lower.contains("asus") || vendor_lower.contains("ubiquiti")
    {
        if ports.contains(&80) || ports.contains(&443) {
            return DeviceType::Router;
        }
    }

    // Phone detection by vendor
    if vendor_lower.contains("samsung") || vendor_lower.contains("xiaomi")
        || vendor_lower.contains("google")
    {
        return DeviceType::Phone;
    }

    DeviceType::Unknown
}

/// Identify all devices in a list
pub fn identify_all_devices(devices: &mut [Device]) {
    for device in devices {
        identify_device(device);
    }
}
```

**Step 2: Update mod.rs**

```rust
// src/network_map/mod.rs
mod discovery;
mod identify;
mod oui;
mod port_scan;
mod types;

pub use discovery::*;
pub use identify::*;
pub use oui::lookup_vendor;
pub use port_scan::*;
pub use types::*;
```

**Step 3: Verify compilation**

Run: `cargo check`
Expected: Compiles without errors

**Step 4: Commit**

```bash
git add src/network_map/
git commit -m "feat: add device type identification from ports and vendor"
```

---

## Task 7: Add Database Schema for Devices

**Files:**
- Modify: `src/db.rs`

**Step 1: Add device-related sequences and tables to initialize_schema**

In `src/db.rs`, find the `initialize_schema` function and add after the existing `CREATE SEQUENCE` statements (around line 67):

```rust
            CREATE SEQUENCE IF NOT EXISTS seq_devices_id START 1;
            CREATE SEQUENCE IF NOT EXISTS seq_device_services_id START 1;
            CREATE SEQUENCE IF NOT EXISTS seq_device_scans_id START 1;
```

Then add the new tables after the `known_networks` table (before the closing `"#`):

```rust
            -- Devices: discovered network devices
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY DEFAULT nextval('seq_devices_id'),
                mac_address TEXT NOT NULL UNIQUE,
                ip_address TEXT,
                hostname TEXT,
                vendor TEXT,
                device_type TEXT,
                custom_name TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                network_bssid TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);

            -- Device services: open ports on devices
            CREATE TABLE IF NOT EXISTS device_services (
                id INTEGER PRIMARY KEY DEFAULT nextval('seq_device_services_id'),
                device_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                service_name TEXT,
                banner TEXT,
                detected_agent TEXT,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(device_id, port, protocol)
            );
            CREATE INDEX IF NOT EXISTS idx_device_services_device ON device_services(device_id);

            -- Device scan history
            CREATE TABLE IF NOT EXISTS device_scans (
                id INTEGER PRIMARY KEY DEFAULT nextval('seq_device_scans_id'),
                network_bssid TEXT,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                devices_found INTEGER,
                scan_type TEXT
            );
```

**Step 2: Add device database methods**

Add these methods to the `impl Database` block (at the end, before the closing `}`):

```rust
    // ========== Device Management ==========

    /// Insert or update a device
    pub fn upsert_device(
        &self,
        mac_address: &str,
        ip_address: &str,
        hostname: Option<&str>,
        vendor: Option<&str>,
        device_type: &str,
        custom_name: Option<&str>,
        network_bssid: Option<&str>,
    ) -> Result<i64> {
        let mac_upper = mac_address.to_uppercase();

        // Try to get existing device
        let mut stmt = self.conn.prepare("SELECT id FROM devices WHERE mac_address = ?")?;
        let mut rows = stmt.query(params![mac_upper])?;

        if let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            // Update existing device
            self.conn.execute(
                r#"
                UPDATE devices SET
                    ip_address = ?,
                    hostname = COALESCE(?, hostname),
                    vendor = COALESCE(?, vendor),
                    device_type = ?,
                    custom_name = COALESCE(?, custom_name),
                    network_bssid = COALESCE(?, network_bssid),
                    last_seen = CURRENT_TIMESTAMP
                WHERE id = ?
                "#,
                params![ip_address, hostname, vendor, device_type, custom_name, network_bssid, id],
            )?;
            return Ok(id);
        }

        // Insert new device
        self.conn.execute(
            r#"
            INSERT INTO devices (mac_address, ip_address, hostname, vendor, device_type, custom_name, network_bssid)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
            params![mac_upper, ip_address, hostname, vendor, device_type, custom_name, network_bssid],
        )?;

        // Get the inserted ID
        let mut stmt = self.conn.prepare("SELECT id FROM devices WHERE mac_address = ?")?;
        let mut rows = stmt.query(params![mac_upper])?;
        let row = rows.next()?.ok_or_else(|| {
            color_eyre::eyre::eyre!("Failed to retrieve inserted device")
        })?;
        Ok(row.get(0)?)
    }

    /// Update device custom name
    pub fn update_device_name(&self, mac_address: &str, custom_name: &str) -> Result<()> {
        let mac_upper = mac_address.to_uppercase();
        self.conn.execute(
            "UPDATE devices SET custom_name = ? WHERE mac_address = ?",
            params![custom_name, mac_upper],
        )?;
        Ok(())
    }

    /// Insert or update a service for a device
    pub fn upsert_device_service(
        &self,
        device_id: i64,
        port: u16,
        protocol: &str,
        service_name: Option<&str>,
        banner: Option<&str>,
        detected_agent: Option<&str>,
    ) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO device_services (device_id, port, protocol, service_name, banner, detected_agent)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (device_id, port, protocol) DO UPDATE SET
                service_name = COALESCE(EXCLUDED.service_name, device_services.service_name),
                banner = COALESCE(EXCLUDED.banner, device_services.banner),
                detected_agent = COALESCE(EXCLUDED.detected_agent, device_services.detected_agent),
                last_seen = CURRENT_TIMESTAMP
            "#,
            params![device_id, port as i32, protocol, service_name, banner, detected_agent],
        )?;
        Ok(())
    }

    /// Get all devices for a network
    pub fn get_devices_for_network(&self, network_bssid: Option<&str>) -> Result<Vec<DeviceRecord>> {
        let query = if network_bssid.is_some() {
            r#"
            SELECT
                id, mac_address, ip_address, hostname, vendor, device_type, custom_name,
                CAST(first_seen AS VARCHAR), CAST(last_seen AS VARCHAR), network_bssid
            FROM devices
            WHERE network_bssid = ?
            ORDER BY last_seen DESC
            "#
        } else {
            r#"
            SELECT
                id, mac_address, ip_address, hostname, vendor, device_type, custom_name,
                CAST(first_seen AS VARCHAR), CAST(last_seen AS VARCHAR), network_bssid
            FROM devices
            ORDER BY last_seen DESC
            "#
        };

        let mut stmt = self.conn.prepare(query)?;
        let mut rows = if let Some(bssid) = network_bssid {
            stmt.query(params![bssid])?
        } else {
            stmt.query([])?
        };

        let mut devices = Vec::new();
        while let Some(row) = rows.next()? {
            let first_seen_str: String = row.get(7)?;
            let last_seen_str: String = row.get(8)?;

            devices.push(DeviceRecord {
                id: row.get(0)?,
                mac_address: row.get(1)?,
                ip_address: row.get(2)?,
                hostname: row.get(3)?,
                vendor: row.get(4)?,
                device_type: row.get(5)?,
                custom_name: row.get(6)?,
                first_seen: parse_timestamp(&first_seen_str),
                last_seen: parse_timestamp(&last_seen_str),
                network_bssid: row.get(9)?,
            });
        }

        Ok(devices)
    }

    /// Get services for a device
    pub fn get_device_services(&self, device_id: i64) -> Result<Vec<ServiceRecord>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, port, protocol, service_name, banner, detected_agent
            FROM device_services
            WHERE device_id = ?
            ORDER BY port
            "#,
        )?;
        let mut rows = stmt.query(params![device_id])?;

        let mut services = Vec::new();
        while let Some(row) = rows.next()? {
            services.push(ServiceRecord {
                id: row.get(0)?,
                port: row.get::<_, i32>(1)? as u16,
                protocol: row.get(2)?,
                service_name: row.get(3)?,
                banner: row.get(4)?,
                detected_agent: row.get(5)?,
            });
        }

        Ok(services)
    }

    /// Create a device scan record
    pub fn create_device_scan(&self, network_bssid: Option<&str>, scan_type: &str) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO device_scans (network_bssid, scan_type) VALUES (?, ?)",
            params![network_bssid, scan_type],
        )?;

        let mut stmt = self.conn.prepare(
            "SELECT id FROM device_scans ORDER BY id DESC LIMIT 1",
        )?;
        let mut rows = stmt.query([])?;
        let row = rows.next()?.ok_or_else(|| {
            color_eyre::eyre::eyre!("Failed to retrieve inserted device scan")
        })?;
        Ok(row.get(0)?)
    }

    /// Complete a device scan
    pub fn complete_device_scan(&self, scan_id: i64, devices_found: usize) -> Result<()> {
        self.conn.execute(
            r#"
            UPDATE device_scans SET
                completed_at = CURRENT_TIMESTAMP,
                devices_found = ?
            WHERE id = ?
            "#,
            params![devices_found as i32, scan_id],
        )?;
        Ok(())
    }
```

**Step 3: Add the new record types**

Add these structs after `KnownNetwork` struct (around line 676):

```rust
/// Device record from the database
#[derive(Debug, Clone)]
pub struct DeviceRecord {
    pub id: i64,
    pub mac_address: String,
    pub ip_address: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub device_type: Option<String>,
    pub custom_name: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub network_bssid: Option<String>,
}

/// Service record from the database
#[derive(Debug, Clone)]
pub struct ServiceRecord {
    pub id: i64,
    pub port: u16,
    pub protocol: String,
    pub service_name: Option<String>,
    pub banner: Option<String>,
    pub detected_agent: Option<String>,
}
```

**Step 4: Verify compilation**

Run: `cargo check`
Expected: Compiles without errors

**Step 5: Commit**

```bash
git add src/db.rs
git commit -m "feat: add database schema for device discovery persistence"
```

---

## Task 8: Add App State for Device View

**Files:**
- Modify: `src/app.rs`

**Step 1: Add AppView enum and device state fields**

In `src/app.rs`, add after `SortField` enum (around line 28):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AppView {
    #[default]
    WifiNetworks,
    NetworkDevices,
}
```

**Step 2: Add device-related fields to App struct**

Add these fields to the `App` struct (after `speedtest_receiver` around line 72):

```rust
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
```

**Step 3: Initialize new fields in App::new**

In the `App::new` function, add these initializations (after `speedtest_receiver: None,`):

```rust
            current_view: AppView::default(),
            devices: Vec::new(),
            selected_device_index: 0,
            device_scan_progress: None,
            device_scan_receiver: None,
            show_device_detail: false,
            show_rename_dialog: false,
            rename_input: String::new(),
```

**Step 4: Add device navigation methods**

Add these methods to the `impl App` block (after `quit` method):

```rust
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
```

**Step 5: Verify compilation**

Run: `cargo check`
Expected: Compiles without errors

**Step 6: Commit**

```bash
git add src/app.rs
git commit -m "feat: add app state for device view and navigation"
```

---

## Task 9: Create Device Table Component

**Files:**
- Create: `src/components/device_table.rs`
- Modify: `src/components/mod.rs`

**Step 1: Create device_table.rs**

```rust
// src/components/device_table.rs
use crate::app::App;
use crate::components::Component;
use crate::theme::Theme;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Row, Table, TableState};
use ratatui::Frame;

pub struct DeviceTable;

impl Component for DeviceTable {
    fn render(&self, frame: &mut Frame, area: Rect, app: &App) {
        let header_cells = [
            Cell::from(Span::styled("Status", Theme::header_style())),
            Cell::from(Span::styled("Device", Theme::header_style())),
            Cell::from(Span::styled("IP Address", Theme::header_style())),
            Cell::from(Span::styled("Vendor", Theme::header_style())),
            Cell::from(Span::styled("AI", Theme::header_style())),
        ];

        let header = Row::new(header_cells).style(Theme::header_style()).height(1);

        let rows = app.devices.iter().enumerate().map(|(idx, device)| {
            let is_selected = idx == app.selected_device_index;

            // Selection indicator
            let select_indicator = if is_selected { "\u{25b6}" } else { " " };

            // Online status indicator
            let (status_icon, status_style) = if device.is_online {
                ("\u{25cf}", Theme::connected_style()) // Green dot
            } else {
                ("\u{25cb}", Style::default()) // Empty circle
            };

            // Status cell with selection and online indicator
            let status_cell = Cell::from(Line::from(vec![
                Span::raw(format!("{} ", select_indicator)),
                Span::styled(status_icon, status_style),
            ]));

            // Device name
            let name = device.display_name();
            let name_with_type = if device.custom_name.is_some() {
                name
            } else {
                format!("{} ({})", truncate(&name, 16), device.device_type)
            };
            let device_cell = Cell::from(truncate(&name_with_type, 24));

            // IP address
            let ip_cell = Cell::from(device.ip_address.clone());

            // Vendor
            let vendor = device.vendor.as_deref().unwrap_or("Unknown");
            let vendor_cell = Cell::from(truncate(vendor, 12));

            // AI agent indicator
            let ai_cell = if !device.detected_agents.is_empty() {
                Cell::from(Span::styled(
                    "[AI]",
                    Style::default().fg(ratatui::style::Color::Magenta),
                ))
            } else {
                Cell::from("")
            };

            let row = Row::new([status_cell, device_cell, ip_cell, vendor_cell, ai_cell]);

            if is_selected {
                row.style(Theme::selected_style())
            } else {
                row
            }
        });

        let device_count = app.devices.len();
        let scan_status = if app.device_scan_progress.is_some() {
            " - Scanning..."
        } else {
            ""
        };
        let title = format!(" Network Devices ({} found){} ", device_count, scan_status);

        let table = Table::new(
            rows,
            [
                Constraint::Length(4),   // Status
                Constraint::Min(20),     // Device name
                Constraint::Length(15),  // IP
                Constraint::Length(12),  // Vendor
                Constraint::Length(5),   // AI
            ],
        )
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .style(Theme::border_style())
                .title(Span::styled(title, Theme::title_style())),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

        let mut table_state = TableState::default();
        table_state.select(Some(app.selected_device_index));

        frame.render_stateful_widget(table, area, &mut table_state);
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    } else {
        s.to_string()
    }
}
```

**Step 2: Update mod.rs**

```rust
// src/components/mod.rs
mod detail_panel;
mod device_table;
mod network_table;
mod signal_chart;
mod status_bar;

pub use detail_panel::DetailPanel;
pub use device_table::DeviceTable;
pub use network_table::NetworkTable;
pub use signal_chart::SignalChart;
pub use status_bar::StatusBar;

use crate::app::App;
use ratatui::layout::Rect;
use ratatui::Frame;

pub trait Component {
    fn render(&self, frame: &mut Frame, area: Rect, app: &App);
}
```

**Step 3: Verify compilation**

Run: `cargo check`
Expected: Compiles without errors

**Step 4: Commit**

```bash
git add src/components/
git commit -m "feat: add device table component for network devices view"
```

---

## Task 10: Create Device Detail Component

**Files:**
- Create: `src/components/device_detail.rs`
- Modify: `src/components/mod.rs`

**Step 1: Create device_detail.rs**

```rust
// src/components/device_detail.rs
use crate::app::App;
use crate::components::Component;
use crate::network_map::PortState;
use crate::theme::Theme;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use ratatui::Frame;

pub struct DeviceDetail;

impl Component for DeviceDetail {
    fn render(&self, frame: &mut Frame, area: Rect, app: &App) {
        if app.devices.is_empty() {
            let empty = Paragraph::new("No device selected")
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .style(Theme::border_style())
                        .title(Span::styled(" Device Details ", Theme::title_style())),
                );
            frame.render_widget(empty, area);
            return;
        }

        let device = &app.devices[app.selected_device_index];

        // Build info lines
        let mut lines = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("Name: ", Style::default().fg(Color::Gray)),
                Span::raw(device.display_name()),
            ]),
            Line::from(vec![
                Span::styled("MAC:  ", Style::default().fg(Color::Gray)),
                Span::raw(&device.mac_address),
            ]),
            Line::from(vec![
                Span::styled("IP:   ", Style::default().fg(Color::Gray)),
                Span::raw(&device.ip_address),
            ]),
            Line::from(vec![
                Span::styled("Type: ", Style::default().fg(Color::Gray)),
                Span::raw(format!("{}", device.device_type)),
            ]),
        ];

        if let Some(ref vendor) = device.vendor {
            lines.push(Line::from(vec![
                Span::styled("Vendor: ", Style::default().fg(Color::Gray)),
                Span::raw(vendor),
            ]));
        }

        if let Some(ref hostname) = device.hostname {
            lines.push(Line::from(vec![
                Span::styled("Hostname: ", Style::default().fg(Color::Gray)),
                Span::raw(hostname),
            ]));
        }

        // AI Agents
        if !device.detected_agents.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Detected AI Agents:",
                Style::default().fg(Color::Magenta),
            )));
            for agent in &device.detected_agents {
                lines.push(Line::from(format!("  \u{2022} {}", agent)));
            }
        }

        // Open services
        let open_services: Vec<_> = device.services
            .iter()
            .filter(|s| s.state == PortState::Open)
            .collect();

        if !open_services.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Open Services:",
                Style::default().fg(Color::Cyan),
            )));

            for service in open_services.iter().take(10) {
                let service_name = service.service_name.as_deref().unwrap_or("Unknown");
                let agent_info = service.detected_agent
                    .as_ref()
                    .map(|a| format!(" [{}]", a))
                    .unwrap_or_default();

                lines.push(Line::from(format!(
                    "  {:5} {} {}{}",
                    service.port,
                    service.protocol,
                    service_name,
                    agent_info
                )));
            }

            if open_services.len() > 10 {
                lines.push(Line::from(format!(
                    "  ... and {} more",
                    open_services.len() - 10
                )));
            }
        }

        // Timestamps
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("First seen: ", Style::default().fg(Color::Gray)),
            Span::raw(device.first_seen.format("%Y-%m-%d %H:%M").to_string()),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Last seen:  ", Style::default().fg(Color::Gray)),
            Span::raw(device.last_seen.format("%Y-%m-%d %H:%M").to_string()),
        ]));

        let paragraph = Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .style(Theme::border_style())
                .title(Span::styled(" Device Details ", Theme::title_style())),
        );

        frame.render_widget(paragraph, area);
    }
}
```

**Step 2: Update mod.rs to export DeviceDetail**

```rust
// src/components/mod.rs
mod detail_panel;
mod device_detail;
mod device_table;
mod network_table;
mod signal_chart;
mod status_bar;

pub use detail_panel::DetailPanel;
pub use device_detail::DeviceDetail;
pub use device_table::DeviceTable;
pub use network_table::NetworkTable;
pub use signal_chart::SignalChart;
pub use status_bar::StatusBar;

use crate::app::App;
use ratatui::layout::Rect;
use ratatui::Frame;

pub trait Component {
    fn render(&self, frame: &mut Frame, area: Rect, app: &App);
}
```

**Step 3: Verify compilation**

Run: `cargo check`
Expected: Compiles without errors

**Step 4: Commit**

```bash
git add src/components/
git commit -m "feat: add device detail component showing services and info"
```

---

## Task 11: Integrate Device View into App Rendering

**Files:**
- Modify: `src/app.rs`

**Step 1: Add imports for device components**

At the top of `src/app.rs`, update the components import line to include DeviceDetail and DeviceTable:

```rust
use crate::components::{Component, DetailPanel, DeviceDetail, DeviceTable, NetworkTable, SignalChart, StatusBar};
```

**Step 2: Update the render method**

Replace the `render` method in the `impl App` block with:

```rust
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
                // Original WiFi networks view
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
                // Network devices view
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

        // Overlays (help, popups, etc.)
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

        // Scan progress overlay
        if let Some(ref progress) = self.device_scan_progress {
            self.render_scan_progress_overlay(frame, progress);
        }

        if let Some(ref error) = self.error_message {
            self.render_error_overlay(frame, error);
        }
    }

    fn render_header_with_tabs(&self, frame: &mut Frame, area: Rect) {
        use ratatui::style::{Color, Style};
        use ratatui::text::{Line, Span};
        use ratatui::widgets::Paragraph;

        let wifi_style = if matches!(self.current_view, AppView::WifiNetworks) {
            Style::default().fg(Color::Cyan).add_modifier(ratatui::style::Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };

        let devices_style = if matches!(self.current_view, AppView::NetworkDevices) {
            Style::default().fg(Color::Cyan).add_modifier(ratatui::style::Modifier::BOLD)
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
        use ratatui::style::{Color, Style};
        use ratatui::text::{Line, Span};
        use ratatui::widgets::{Block, Borders, Clear, Paragraph};

        let area = centered_rect(40, 20, frame.area());

        let phase_str = format!("{}", progress.phase);
        let device_str = progress.current_device.as_deref().unwrap_or("");
        let progress_bar = if progress.total_ports > 0 {
            let pct = (progress.ports_scanned * 100) / progress.total_ports;
            let filled = pct / 5;
            let empty = 20 - filled;
            format!("[{}{}] {}%", "█".repeat(filled), "░".repeat(empty), pct)
        } else {
            "[░░░░░░░░░░░░░░░░░░░░]".to_string()
        };

        let lines = vec![
            Line::from(""),
            Line::from(Span::styled(&phase_str, Style::default().fg(Color::Cyan))),
            Line::from(""),
            Line::from(progress_bar),
            Line::from(""),
            Line::from(format!("Devices found: {}", progress.devices_found)),
            Line::from(device_str.to_string()),
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
```

**Step 3: Remove the old render_header method**

Find and remove the `render_header` method (it's replaced by `render_header_with_tabs`).

**Step 4: Verify compilation**

Run: `cargo check`
Expected: Compiles without errors

**Step 5: Commit**

```bash
git add src/app.rs
git commit -m "feat: integrate device view into app rendering with tab navigation"
```

---

## Task 12: Add Device Scan Functionality

**Files:**
- Modify: `src/app.rs`

**Step 1: Add async device scan method**

Add this method to the `impl App` block:

```rust
    /// Start a network device scan
    pub fn start_device_scan(&mut self) {
        if self.device_scan_progress.is_some() {
            return; // Already scanning
        }

        let (tx, rx) = std::sync::mpsc::channel();
        self.device_scan_receiver = Some(rx);

        // Get current network BSSID
        let network_bssid = self.connected_bssid.clone();
        let db_clone = self.db.as_ref().map(|db| {
            // We can't clone Database, so we'll persist after scan completes
            ()
        });

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

                // Send complete signal with devices
                let _ = progress_tx.send(ScanProgress {
                    phase: ScanPhase::Complete,
                    devices_found: devices.len(),
                    current_device: None,
                    ports_scanned: 0,
                    total_ports: 0,
                }).await;

                // Store devices in a static for the main thread to pick up
                // This is a bit hacky but avoids complex channel serialization
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
            // Drain all available progress updates
            while let Ok(progress) = rx.try_recv() {
                if matches!(progress.phase, crate::network_map::ScanPhase::Complete) {
                    // Scan complete - get devices
                    if let Some(devices) = SCANNED_DEVICES.lock().unwrap().take() {
                        self.devices = devices;
                        self.persist_devices();
                    }
                    self.device_scan_progress = None;
                    self.device_scan_receiver = None;
                    self.status_message = Some(format!("Found {} devices", self.devices.len()));
                    return;
                }
                self.device_scan_progress = Some(progress);
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

            // Persist services
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
                device.is_online = false; // Will be updated on scan
                device
            })
            .collect();
    }
```

**Step 2: Add the global device storage and helper**

Add at the top of the file, after the imports:

```rust
use std::sync::Mutex;

static SCANNED_DEVICES: Mutex<Option<Vec<crate::network_map::Device>>> = Mutex::new(None);

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
```

**Step 3: Verify compilation**

Run: `cargo check`
Expected: Compiles without errors

**Step 4: Commit**

```bash
git add src/app.rs
git commit -m "feat: add device scan functionality with background scanning"
```

---

## Task 13: Add Keyboard Handling for Device View

**Files:**
- Modify: `src/main.rs`

**Step 1: Update the key handling section**

In `src/main.rs`, find the key handling section (around line 157) and update it to handle both views:

```rust
                } else {
                    // Normal key handling based on current view
                    match app.current_view {
                        wifi_analyzer::app::AppView::WifiNetworks => {
                            // WiFi Networks view keys
                            match key.code {
                                KeyCode::Char('q') | KeyCode::Esc => app.quit(),
                                KeyCode::Tab => app.switch_view(),
                                KeyCode::Up | KeyCode::Char('k') => app.navigate_up(),
                                KeyCode::Down | KeyCode::Char('j') => app.navigate_down(),
                                KeyCode::Enter => {
                                    app.show_connect_dialog();
                                }
                                KeyCode::Char('r') => {
                                    app.trigger_scan();
                                    match app.perform_scan().await {
                                        Ok(()) => {
                                            app.clear_error();
                                            let _ = app.refresh_current_connection();
                                        }
                                        Err(e) => app.set_error(format!("{}", e)),
                                    }
                                }
                                KeyCode::Char('d') => {
                                    enable_demo_mode();
                                    app.clear_error();
                                    let _ = app.perform_scan().await;
                                }
                                KeyCode::Char('a') => app.toggle_scan_mode(),
                                KeyCode::Char('s') => app.cycle_sort(),
                                KeyCode::Char('?') => app.toggle_help(),
                                _ => {}
                            }
                        }
                        wifi_analyzer::app::AppView::NetworkDevices => {
                            // Network Devices view keys
                            if app.show_rename_dialog {
                                match key.code {
                                    KeyCode::Enter => app.confirm_rename(),
                                    KeyCode::Esc => app.cancel_rename(),
                                    KeyCode::Backspace => app.rename_input_backspace(),
                                    KeyCode::Char(c) => app.rename_input_char(c),
                                    _ => {}
                                }
                            } else if app.device_scan_progress.is_some() {
                                match key.code {
                                    KeyCode::Esc => app.cancel_device_scan(),
                                    _ => {}
                                }
                            } else {
                                match key.code {
                                    KeyCode::Char('q') | KeyCode::Esc => app.quit(),
                                    KeyCode::Tab => app.switch_view(),
                                    KeyCode::Up | KeyCode::Char('k') => app.device_navigate_up(),
                                    KeyCode::Down | KeyCode::Char('j') => app.device_navigate_down(),
                                    KeyCode::Enter => app.toggle_device_detail(),
                                    KeyCode::Char('s') | KeyCode::Char('S') => app.start_device_scan(),
                                    KeyCode::Char('r') | KeyCode::Char('R') => app.start_rename_device(),
                                    KeyCode::Char('?') => app.toggle_help(),
                                    _ => {}
                                }
                            }
                        }
                    }
                }
```

**Step 2: Update the tick handler**

In the `Event::Tick` handler, add device scan progress checking:

```rust
            Event::Tick => {
                // Check for background speed test completion
                app.check_speedtest_result();

                // Check for device scan progress
                app.check_device_scan_progress();

                // Check for auto-scan
                if app.should_scan() {
                    match app.perform_scan().await {
                        Ok(()) => {
                            app.clear_error();
                            let _ = app.refresh_current_connection();
                        }
                        Err(e) => app.set_error(format!("{}", e)),
                    }
                }
            }
```

**Step 3: Verify compilation**

Run: `cargo check`
Expected: Compiles without errors

**Step 4: Commit**

```bash
git add src/main.rs
git commit -m "feat: add keyboard handling for device view navigation and scanning"
```

---

## Task 14: Update Status Bar for Device View

**Files:**
- Modify: `src/components/status_bar.rs`

**Step 1: Read current file**

Run: Read `src/components/status_bar.rs`

**Step 2: Update render to show view-appropriate shortcuts**

Update the status bar to show different key hints based on current view:

```rust
// Add this at the top of render method after getting app state
        let shortcuts = match app.current_view {
            crate::app::AppView::WifiNetworks => {
                vec![
                    ("Tab", "Devices"),
                    ("r", "Scan"),
                    ("a", "Mode"),
                    ("s", "Sort"),
                    ("Enter", "Connect"),
                    ("?", "Help"),
                    ("q", "Quit"),
                ]
            }
            crate::app::AppView::NetworkDevices => {
                vec![
                    ("Tab", "WiFi"),
                    ("s", "Scan"),
                    ("r", "Rename"),
                    ("Enter", "Details"),
                    ("?", "Help"),
                    ("q", "Quit"),
                ]
            }
        };
```

Then use this `shortcuts` vec to build the status line.

**Step 3: Verify compilation**

Run: `cargo check`
Expected: Compiles without errors

**Step 4: Commit**

```bash
git add src/components/status_bar.rs
git commit -m "feat: update status bar with view-specific shortcuts"
```

---

## Task 15: Integration Test - Manual Testing

**Step 1: Build and run the application**

Run: `cargo build --release`
Expected: Builds without errors

**Step 2: Test WiFi view**

Run: `cargo run -- --demo`

1. Verify WiFi networks tab loads
2. Navigate with j/k
3. Press Tab to switch views

**Step 3: Test Device view**

1. In Network Devices view, press 's' to start scan
2. Verify progress overlay appears
3. Wait for scan to complete
4. Verify devices appear in list
5. Navigate with j/k
6. Press 'r' to rename a device
7. Press Tab to return to WiFi view

**Step 4: Test persistence**

1. Exit and restart app
2. Switch to Device view
3. Verify previously scanned devices appear

**Step 5: Commit final changes**

```bash
git add -A
git commit -m "feat: complete network device mapper feature

- Add network device discovery via ARP cache
- Implement async TCP port scanning with banner grabbing
- Add OUI vendor database for device identification
- Implement AI coding agent detection
- Add tabbed UI with WiFi Networks and Network Devices views
- Persist device data to DuckDB
- Support device renaming with custom labels

Closes: network-device-mapper feature"
```

---

## Summary

This implementation plan covers:

1. **Dependencies**: ipnetwork crate for subnet calculations
2. **Data Types**: Device, Service, ScanProgress structures
3. **Discovery**: ARP cache parsing for device enumeration
4. **Port Scanning**: Async TCP scanner with banner grabbing
5. **Identification**: OUI lookup + port-based device type inference
6. **AI Detection**: Pattern matching for Claude, Ollama, and other agents
7. **Database**: Schema and methods for device/service persistence
8. **UI**: DeviceTable and DeviceDetail components
9. **Integration**: Tab-based navigation, keyboard handling, status bar updates

Each task is designed to be completed in 2-5 minutes with clear verification steps.
