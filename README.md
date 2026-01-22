# WiFi Analyzer

A terminal-based WiFi analyzer with a beautiful TUI, designed to help you find the best public WiFi networks. Built with Rust and [Ratatui](https://ratatui.rs/).

![Rust](https://img.shields.io/badge/rust-1.85+-orange.svg)
![Platform](https://img.shields.io/badge/platform-macOS-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Features

- **Real-time WiFi Scanning** - Discover all nearby WiFi networks
- **Multi-factor Scoring** - Intelligent scoring to find the best public WiFi
- **Beautiful TUI** - Dashboard interface with network table, details panel, and signal charts
- **Signal History** - Track signal strength over time with sparkline charts
- **Auto/Manual Modes** - Auto-refresh or scan on demand
- **Sortable Views** - Sort by score, signal strength, or network name

## Screenshot

```
┌─────────────────────────────────────────────────────────────────────┐
│  WiFi Analyzer                           [Auto] ⟳ 5s │ ? Help │ q Quit │
├────────────────────────────────────────────┬────────────────────────┤
│  Networks (12 found)           Score ▼     │  Selected: CoffeeShop  │
│ ─────────────────────────────────────────  │ ──────────────────────  │
│ ▶ CoffeeShop_Free      ▓▓▓▓▓░  92  OPEN   │  MAC: AA:BB:CC:DD:EE   │
│   Airport_WiFi         ▓▓▓▓░░  78  OPEN   │  Channel: 6 (2.4GHz)   │
│   Starbucks            ▓▓▓░░░  65  WPA2   │  Signal: -42 dBm       │
│   Hotel_Guest          ▓▓░░░░  51  OPEN   │  Security: Open        │
│   WeakNet              ▓░░░░░  23  WPA3   │                        │
│                                            │  Signal History:       │
│                                            │  ▁▂▃▄▅▆▇█▇▆▅▄ (-42)   │
├────────────────────────────────────────────┴────────────────────────┤
│ ↑↓ Navigate │ r Refresh │ a Auto-toggle │ s Sort │ ? Help │ q Quit │
└─────────────────────────────────────────────────────────────────────┘
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
git clone https://github.com/yourusername/wifi-analyzer.git
cd wifi-analyzer

# Build and run
cargo run --release
```

### Quick Start

```bash
# Run with default settings (auto-refresh every 5 seconds)
cargo run

# Run in manual mode (scan only when pressing 'r')
cargo run -- --manual

# Run with custom refresh interval
cargo run -- --interval 10

# Run in demo mode (simulated networks for testing)
cargo run -- --demo
```

## Usage

### Keyboard Controls

| Key | Action |
|-----|--------|
| `↑` / `k` | Navigate up |
| `↓` / `j` | Navigate down |
| `r` | Manual refresh/scan |
| `a` | Toggle auto/manual mode |
| `s` | Cycle sort order (Score → Signal → Name) |
| `d` | Switch to demo mode |
| `?` | Toggle help overlay |
| `q` / `Esc` | Quit |

### Command Line Options

```
wifi-analyzer [OPTIONS]

Options:
  -i, --interval <SECONDS>  Auto-refresh interval in seconds [default: 5]
  -m, --manual              Start in manual mode (no auto-refresh)
  -d, --demo                Run with simulated WiFi networks
  -h, --help                Print help
  -V, --version             Print version
```

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
├── main.rs              # Entry point, CLI parsing
├── app.rs               # Application state and logic
├── tui.rs               # Terminal setup/teardown
├── event.rs             # Keyboard and tick event handling
├── theme.rs             # Colors and styling
├── scanner/
│   ├── mod.rs           # Network types and exports
│   └── platform.rs      # Platform-specific WiFi scanning
├── scoring/
│   ├── mod.rs           # Score calculation
│   └── factors.rs       # Individual scoring factors
└── components/
    ├── mod.rs           # Component trait
    ├── network_table.rs # Network list widget
    ├── detail_panel.rs  # Selected network details
    ├── signal_chart.rs  # Signal history sparkline
    └── status_bar.rs    # Mode and keybind hints
```

## How It Works

### WiFi Scanning (macOS)

On modern macOS (Sonoma+), the app uses a Swift helper script (`scripts/wifi_scan.swift`) that leverages Apple's CoreWLAN framework for WiFi scanning. This provides:

- Full network discovery (not just the connected network)
- Accurate signal strength in dBm
- Security type detection (Open, WEP, WPA, WPA2, WPA3)
- Channel and frequency band information

### Fallback Scanning

On older macOS versions or other platforms, the app falls back to the `wifiscanner` crate, which may have platform-specific limitations.

## Troubleshooting

### "No WiFi interface found"

Ensure your Mac has a WiFi adapter and it's enabled. The app requires WiFi to be turned on.

### "Swift scanner failed"

Make sure you have Swift installed (comes with Xcode or Command Line Tools):
```bash
xcode-select --install
```

### Empty network list

Try running with `--demo` flag to verify the TUI works:
```bash
cargo run -- --demo
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
