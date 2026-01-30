# Network Device Mapper Design

## Overview

Add a Fing-like network device discovery feature to the WiFi Analyzer TUI. Users can scan the local network to discover all connected devices, identify them by vendor/type, enumerate open services, and detect AI coding agents.

## Requirements

- **Use cases**: Security auditing, network inventory, troubleshooting
- **Scanning**: On-demand only (user-triggered)
- **Service detection**: Smart scan (quick common ports, optional deep scan per device)
- **Device identification**: OUI vendor lookup + hostname + port heuristics for device type
- **UI integration**: New "Network Devices" tab (Tab key to switch)
- **Persistence**: Store all data in DuckDB

## Data Model

### Device Table

```sql
CREATE TABLE devices (
    mac_address TEXT PRIMARY KEY,
    ip_address TEXT,
    hostname TEXT,
    vendor TEXT,
    device_type TEXT,  -- Router, Phone, TV, NAS, Printer, Unknown
    custom_name TEXT,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    network_bssid TEXT  -- Which WiFi network this device was seen on
);
```

### Service Table

```sql
CREATE TABLE services (
    id INTEGER PRIMARY KEY,
    device_mac TEXT REFERENCES devices(mac_address),
    port INTEGER,
    protocol TEXT,  -- TCP/UDP
    state TEXT,     -- Open/Filtered/Closed
    service_name TEXT,
    banner TEXT,
    detected_agent TEXT,  -- AI agent name if detected
    last_seen TIMESTAMP
);
```

### Device Scan History

```sql
CREATE TABLE device_scans (
    scan_id INTEGER PRIMARY KEY,
    network_bssid TEXT,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    devices_found INTEGER,
    scan_type TEXT  -- Quick/Deep
);
```

### Device Type Inference Rules

| Condition | Inferred Type |
|-----------|---------------|
| Port 80/443 + port 53 open | Router/Gateway |
| Port 22 + port 445/548 | NAS |
| Port 62078 + vendor "Apple" | iPhone/iPad |
| Port 8008/8009 | Smart TV/Chromecast |
| Port 9100 | Printer |
| Port 3389 | Windows PC |
| Vendor-based fallback | Per vendor heuristics |

## Scanning Architecture

### Phase 1: Device Discovery

1. Get local IP and subnet mask to determine scan range (e.g., 192.168.1.0/24)
2. Parse system ARP cache (`arp -a`) for known devices
3. Optionally send ARP probes to discover new devices
4. Timeout: 3 seconds

### Phase 2: Quick Port Scan

Common ports scanned in parallel per device:

- 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP)
- 53 (DNS), 80 (HTTP), 443 (HTTPS)
- 139/445 (SMB), 548 (AFP), 3389 (RDP)
- 5000/5001 (Synology), 8080 (Alt HTTP)
- 62078 (Apple), 8008/8009 (Chromecast)
- 9100 (Printer), 554 (RTSP)
- 3000-3999 (Dev servers/agents), 8000-8999 (Alt servers)
- 11434 (Ollama), 9229 (Node debug)

**Technique**: Async TCP connect with 500ms timeout
**Parallelism**: 50 concurrent connections per device, 10 devices simultaneously

### Phase 3: Deep Scan (On-Demand)

- Scan all 65535 ports in batches of 2000
- Banner grabbing on open ports (read first 256 bytes)
- Duration: 30-60 seconds per device

### Progress Reporting

```rust
pub struct ScanProgress {
    pub phase: ScanPhase,      // Discovery, QuickScan, DeepScan
    pub devices_found: usize,
    pub current_device: Option<String>,
    pub ports_scanned: usize,
    pub total_ports: usize,
}
```

## AI Agent Detection

### Known Agent Signatures

| Agent | Detection Method |
|-------|------------------|
| Claude Code / Clawdbot | Port 3000-3999 + "claude" in banner/hostname |
| Moldbot | Port 8000-8999 + "mold" in banner |
| Cursor Agent | Port 3000 + "cursor" in banner |
| Aider | Port 8501 (Streamlit) + "aider" in banner |
| Continue.dev | Port 65432 or VS Code extension ports |
| OpenHands | Ports 3000, 8000 + sandbox indicators |
| Cline | Port 9229 (VS Code debug) |
| Ollama | Port 11434 + "ollama" in response |
| llama.cpp | Port 8080 + "llama" in response |

### Detection Method

1. Check common agent ports during quick scan
2. Banner grab on open ports - search for keywords
3. HTTP GET on web ports - check response headers/body
4. Flag devices with detected agents in UI

## UI Design

### Tab Navigation

```
┌─────────────────────────────────────────────────────────────┐
│ [WiFi Networks]  [Network Devices]              Tab to switch│
└─────────────────────────────────────────────────────────────┘
```

### Device List View

```
┌─ Network Devices (12 found) ─ Quick Scan ──────────────────┐
│                                                             │
│  Status   Device              IP             Vendor    AI   │
│  ──────────────────────────────────────────────────────────│
│  ● Online  Router (Gateway)   192.168.1.1    ASUS          │
│  ● Online  Living Room TV     192.168.1.42   Samsung       │
│  ● Online  My iPhone          192.168.1.101  Apple         │
│  ● Online  Dev MacBook        192.168.1.88   Apple     [AI]│
│  ○ Offline Printer            192.168.1.200  HP            │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│ [S]can  [D]eep scan  [R]ename  [↑↓]Navigate  [Enter]Details │
└─────────────────────────────────────────────────────────────┘
```

### Device Detail Panel

```
┌─ Device Details ────────────────────────────────────────────┐
│  Name: Dev MacBook (custom: "Work Laptop")                  │
│  MAC:  a8:23:fe:xx:xx:xx                                    │
│  IP:   192.168.1.88                                         │
│  Type: MacBook                                              │
│                                                             │
│  ┌─ Open Services ─────────────────────────────────────┐   │
│  │  Port   Service      State   Agent                  │   │
│  │  22     SSH          Open                           │   │
│  │  3000   HTTP         Open    Claude Code            │   │
│  │  11434  Ollama API   Open    Ollama                 │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  First seen: 2025-01-15 14:30                              │
│  Last seen:  2025-01-30 10:45                              │
│                                                             │
│  [D]eep scan  [R]ename  [Esc]Back                          │
└─────────────────────────────────────────────────────────────┘
```

### Scanning Progress Overlay

```
┌─ Scanning Network ──────────────────┐
│  ████████░░░░░░░░  Phase 2/2       │
│  Scanning ports: 192.168.1.42      │
│  Devices found: 8                   │
│  [Esc] Cancel                       │
└─────────────────────────────────────┘
```

## Module Structure

```
src/
├── network_map/
│   ├── mod.rs              # Public API, Device/Service structs
│   ├── discovery.rs        # ARP scan, device enumeration
│   ├── port_scan.rs        # Async TCP port scanning
│   ├── identify.rs         # OUI lookup, device type inference, agent detection
│   └── oui_db.rs           # Embedded MAC vendor database
├── components/
│   ├── device_table.rs     # Device list view (new)
│   └── device_detail.rs    # Device detail panel (new)
└── db.rs                   # Extended with device/service tables
```

## Dependencies

```toml
# New dependencies
mac_address = "1.1"          # MAC address parsing
ipnetwork = "0.20"           # Subnet/CIDR calculations
# Existing tokio already has required features
```

## OUI Database

Embed a compressed IEEE OUI database (~500KB) at compile time using `include_bytes!`. The database maps MAC address prefixes (first 3 bytes) to vendor names. Covers ~30,000 vendor prefixes.

Source: IEEE MA-L registry (https://standards-oui.ieee.org/)

## Implementation Notes

- Use `arp -a` for device discovery on macOS (avoids raw socket complexity)
- Async TCP connect for port scanning (tokio::net::TcpStream)
- Channel-based progress updates to keep UI responsive
- Store scan results in DuckDB for history and persistence
- Support demo mode with simulated devices for testing
