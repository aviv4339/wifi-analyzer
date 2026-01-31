# WiFi Analyzer

A terminal-based WiFi analyzer with a beautiful TUI, designed to help you find and connect to the best public WiFi networks. Built with Rust and [Ratatui](https://ratatui.rs/).

![Rust](https://img.shields.io/badge/rust-1.85+-orange.svg)
![Platform](https://img.shields.io/badge/platform-macOS-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Features

- **Real-time WiFi Scanning** - Discover all nearby WiFi networks with multi-pass scanning
- **Multi-factor Scoring** - Intelligent scoring to find the best public WiFi
- **Beautiful TUI** - Dashboard interface with network table, details panel, and signal charts
- **Connection Tracking** - Track connection history, timestamps, and connection counts
- **Speed Test** - Measure download/upload speeds using Cloudflare's speed test servers
- **IP Tracking** - View current and historical local/public IP addresses
- **Database Persistence** - Store network data and history with DuckDB
- **Location Support** - Organize scans by location (e.g., "office", "cafe")
- **Auto/Manual Modes** - Auto-refresh with countdown timer or scan on demand
- **Connect to Networks** - Quick connect via Enter key (opens System WiFi Settings)
- **Network Map** - Discover all devices on your network with port scanning and service detection
- **AI Agent Detection** - Identify running AI services (Ollama, Claude Code, LM Studio, etc.)

## Screenshot

```
┌─────────────────────────────────────────────────────────────────────────┐
│  WiFi Analyzer                    [Auto] next scan in 12s │ ? Help │ q Quit │
├────────────────────────────────────────────┬────────────────────────────┤
│  Networks (12 found)           Score ▼     │  Selected: CoffeeShop      │
│ ─────────────────────────────────────────  │ ──────────────────────────  │
│ ● CoffeeShop_Free      ▓▓▓▓▓░  92  OPEN   │  MAC: AA:BB:CC:DD:EE       │
│   Airport_WiFi         ▓▓▓▓░░  78  OPEN   │  Channel: 6 (2.4GHz)       │
│   Starbucks            ▓▓▓░░░  65  WPA2   │  Signal: -42 dBm           │
│   Hotel_Guest          ▓▓░░░░  51  OPEN   │  Security: Open            │
│   WeakNet              ▓░░░░░  23  WPA3   │  Status: ● Connected       │
│                                            │                            │
│                                            │  ─── Connection History ─── │
│                                            │  Last: 2h ago              │
│                                            │  Times connected: 12       │
│                                            │                            │
│                                            │  ─── Speed Test ───        │
│                                            │  ↓ 45.2 Mbps  ↑ 12.8 Mbps │
│                                            │                            │
│                                            │  ─── IP Addresses ───      │
│                                            │  Local: 192.168.1.42       │
│                                            │  Public: 73.162.89.201     │
├────────────────────────────────────────────┴────────────────────────────┤
│ ↑↓ Nav │ Enter Connect │ r Scan │ s Sort │ ? Help │ q Quit              │
└─────────────────────────────────────────────────────────────────────────┘
```

## Requirements

- **macOS Sonoma (14.0)** or later (Sequoia, Tahoe)
- **Rust 1.85+** (2024 edition)
- **Swift** (included with Xcode or Command Line Tools)

> **Note**: The WiFi scanner uses Apple's CoreWLAN framework via a Swift helper script, which requires macOS. Linux and Windows support is available through the `wifiscanner` crate fallback, but may have limited functionality.

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/aviv4339/wifi-analyzer.git
cd wifi-analyzer

# Build and run
cargo run --release
```

### Quick Start

```bash
# Run with default settings (auto-refresh every 15 seconds)
cargo run --release

# Run in manual mode (scan only when pressing 'r')
cargo run --release -- --manual

# Run with custom refresh interval
cargo run --release -- --interval 30

# Run with a specific location name
cargo run --release -- --location office

# Run in demo mode (simulated networks for testing)
cargo run --release -- --demo

# Run without database persistence (memory only)
cargo run --release -- --no-persist
```

## Usage

### Keyboard Controls

| Key | Action |
|-----|--------|
| `↑` / `k` | Navigate up |
| `↓` / `j` | Navigate down |
| `Enter` | Connect to network (or run speed test if already connected) |
| `r` | Manual refresh/scan |
| `a` | Toggle auto/manual mode |
| `s` | Cycle sort order (Score → Signal → Name) |
| `d` | Switch to demo mode |
| `?` | Toggle help overlay |
| `q` / `Esc` | Quit |

### Connection Dialog

When pressing Enter on a network:
- **Not connected**: Shows "Connect to [network]?" dialog (Y/N)
- **Already connected**: Shows "Run speed test?" dialog (Y/N)

### Command Line Options

```
wifi-analyzer [OPTIONS]

Options:
  -i, --interval <SECONDS>  Auto-refresh interval in seconds [default: 15]
  -m, --manual              Start in manual mode (no auto-refresh)
  -d, --demo                Run with simulated WiFi networks
  -l, --location <NAME>     Location name for this session (e.g., "office")
      --db-path <PATH>      Database file path [default: wifi_analyzer.duckdb]
      --no-persist          Run without database persistence
  -h, --help                Print help
  -V, --version             Print version
```

## Network Map (CLI)

Discover devices on your local network with port scanning and AI agent detection:

```bash
# Quick device discovery (ARP cache only)
cargo run --release -- discover

# Full network sweep (ping all IPs, slower but thorough)
cargo run --release -- discover --full

# Full scan: discover + port scan + service detection
cargo run --release -- scan-devices

# Full scan with ping sweep
cargo run --release -- scan-devices --full --verbose

# Scan ports on a specific IP
cargo run --release -- scan-ports 192.168.1.100
```

### What It Detects

- **Device identification** via MAC address vendor lookup
- **Hostname resolution** from ARP cache
- **Open ports** on common services (SSH, HTTP, databases, etc.)
- **AI/LLM agents** running on the network:
  - Ollama, LM Studio, Llama.cpp
  - Claude Code, Aider
  - OpenClaw, Clawdbot, Moldbot
  - GPT4All, Text Generation WebUI

## Scoring System

WiFi networks are scored from 0-100 based on multiple factors, optimized for finding the best public WiFi:

| Factor | Weight | Description |
|--------|--------|-------------|
| **Signal Strength** | 40% | Stronger signal = higher score |
| **Channel Congestion** | 25% | Less crowded channels score higher |
| **Security** | 20% | Open networks preferred for public WiFi |
| **Frequency Band** | 15% | 5GHz preferred for speed |

### Score Legend

- **80-100** (Green): Excellent - Best choice
- **60-79** (Yellow): Good - Reliable option
- **40-59** (Orange): Fair - Usable but not ideal
- **0-39** (Red): Poor - Avoid if possible

## Architecture

```
src/
├── main.rs              # Entry point, CLI parsing, event loop
├── app.rs               # Application state and logic
├── lib.rs               # Library exports
├── tui.rs               # Terminal setup/teardown
├── event.rs             # Keyboard and tick event handling
├── theme.rs             # Colors and styling
├── db.rs                # DuckDB database persistence
├── connection.rs        # WiFi connection management
├── speedtest.rs         # Download/upload speed measurement
├── ip.rs                # Local and public IP detection
├── scanner/
│   ├── mod.rs           # Network types and exports
│   └── platform.rs      # Platform-specific WiFi scanning
├── scoring/
│   ├── mod.rs           # Score calculation
│   └── factors.rs       # Individual scoring factors
├── network_map/
│   ├── mod.rs           # Device discovery and exports
│   ├── types.rs         # Device, Service, and scan types
│   ├── port_scan.rs     # Port scanning and service detection
│   └── vendor.rs        # MAC address vendor lookup
└── components/
    ├── mod.rs           # Component trait
    ├── network_table.rs # Network list widget
    ├── detail_panel.rs  # Selected network details
    ├── signal_chart.rs  # Signal history sparkline
    ├── status_bar.rs    # Mode, timers, and keybind hints
    ├── popup.rs         # Modal dialog component
    └── help_overlay.rs  # Help screen

scripts/
├── wifi_scan.swift      # CoreWLAN WiFi scanner
└── wifi_connect.swift   # CoreWLAN WiFi connector
```

## How It Works

### WiFi Scanning (macOS)

On modern macOS (Sonoma+), the app uses Swift helper scripts that leverage Apple's CoreWLAN framework for WiFi scanning. This provides:

- Full network discovery with multi-pass scanning
- Accurate signal strength in dBm
- Security type detection (Open, WEP, WPA, WPA2, WPA3)
- Channel and frequency band information
- Current connection detection

### Connection Management

Connecting to WiFi networks on modern macOS requires special app entitlements. The app:
1. First attempts connection via CoreWLAN/networksetup
2. If that fails (common on macOS Sonoma+), opens System WiFi Settings for manual connection

### Speed Test

Speed tests use Cloudflare's speed test servers:
- Downloads for ~5 seconds to measure download speed
- Uploads for ~5 seconds to measure upload speed
- Results stored in database for history tracking

### Database

Network data is persisted using DuckDB:
- **networks**: Discovered networks with signal history
- **connections**: Connection events with timestamps and IPs
- **locations**: Named scanning locations
- **known_networks**: Imported from macOS keychain

## Troubleshooting

### "No WiFi interface found"

Ensure your Mac has a WiFi adapter and it's enabled. The app requires WiFi to be turned on.

### "Swift scanner failed"

Make sure you have Swift installed (comes with Xcode or Command Line Tools):
```bash
xcode-select --install
```

### Connection fails / Opens System Settings

On modern macOS (Sonoma+), command-line WiFi connection is restricted. The app will open System WiFi Settings for you to connect manually.

### Empty network list

Try running with `--demo` flag to verify the TUI works:
```bash
cargo run --release -- --demo
```

If demo mode works but real scanning doesn't, check your macOS privacy settings for Location Services (required for WiFi scanning on some versions).

## Development

```bash
# Run tests
cargo test

# Run with debug output
RUST_BACKTRACE=1 cargo run

# Check for issues
cargo clippy

# Format code
cargo fmt
```

## Dependencies

- [ratatui](https://crates.io/crates/ratatui) - Terminal UI framework
- [crossterm](https://crates.io/crates/crossterm) - Cross-platform terminal manipulation
- [tokio](https://crates.io/crates/tokio) - Async runtime
- [clap](https://crates.io/crates/clap) - Command line argument parsing
- [color-eyre](https://crates.io/crates/color-eyre) - Error handling
- [duckdb](https://crates.io/crates/duckdb) - Embedded analytics database
- [reqwest](https://crates.io/crates/reqwest) - HTTP client for speed tests
- [local-ip-address](https://crates.io/crates/local-ip-address) - Local IP detection
- [wifiscanner](https://crates.io/crates/wifiscanner) - WiFi scanning (fallback)

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Acknowledgments

- [Ratatui](https://ratatui.rs/) for the excellent TUI framework
- Apple's CoreWLAN framework for WiFi scanning capabilities
- [Cloudflare](https://speed.cloudflare.com/) for speed test infrastructure
