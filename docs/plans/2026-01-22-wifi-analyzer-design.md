# WiFi Analyzer Design Document

**Date**: 2026-01-22
**Status**: Approved

## Overview

A terminal-based WiFi analyzer built with Rust and Ratatui, designed to help users find the best public WiFi networks at locations like cafes, airports, and hotels.

## Goals

1. Scan and display all nearby WiFi networks
2. Score networks using multiple factors for "best public WiFi" use case
3. Provide a beautiful, informative dashboard interface
4. Track signal strength over time
5. Support both auto-refresh and manual scan modes

## Non-Goals

- Security auditing or penetration testing features
- Network connection management (this is analysis only)
- Historical data persistence across sessions
- Network speed testing

## User Experience

### Primary Flow

1. User launches `wifi-analyzer` in terminal
2. App immediately scans and displays nearby networks
3. Networks sorted by score (best for public use at top)
4. User navigates list to see detailed analysis
5. Auto-refresh keeps data current, or user manually refreshes

### Key Interactions

| Key | Action |
|-----|--------|
| `↑`/`↓` | Navigate network list |
| `r` | Manual refresh scan |
| `a` | Toggle auto-refresh mode |
| `s` | Cycle sort order |
| `?` | Show help overlay |
| `q`/`Esc` | Quit |

## Scoring System

### Factors and Weights

| Factor | Weight | Rationale |
|--------|--------|-----------|
| Signal Strength | 40% | Primary indicator of connection quality |
| Channel Congestion | 25% | Fewer networks = less interference |
| Security Type | 20% | Open networks preferred for public WiFi |
| Frequency Band | 15% | 5GHz typically less congested |

### Score Calculation

```
Signal Score: Linear scale from -90dBm (0) to -30dBm (100)
Congestion Score: 100 - (networks_on_channel * 15), min 0
Security Score: Open=100, WPA2=80, WPA3=70, WEP=30
Band Score: 5GHz=100, 2.4GHz=60

Final = (Signal * 0.40) + (Congestion * 0.25) + (Security * 0.20) + (Band * 0.15)
```

### Score Interpretation

- **80-100** (Green): Excellent - strong signal, minimal interference
- **60-79** (Yellow): Good - reliable for most tasks
- **40-59** (Orange): Fair - may struggle with video/large downloads
- **0-39** (Red): Poor - expect connectivity issues

## Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                        main.rs                               │
│                    (CLI + bootstrap)                         │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                        app.rs                                │
│              (State + Business Logic)                        │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐    │
│  │  networks   │  │ signal_hist  │  │   scan_mode     │    │
│  │  selected   │  │   sort_by    │  │   is_scanning   │    │
│  └─────────────┘  └──────────────┘  └─────────────────┘    │
└───────┬─────────────────┬───────────────────┬───────────────┘
        │                 │                   │
┌───────▼───────┐ ┌───────▼───────┐ ┌────────▼────────┐
│   scanner/    │ │   scoring/    │ │   components/   │
│  (WiFi scan)  │ │  (Calculate)  │ │  (UI widgets)   │
└───────────────┘ └───────────────┘ └─────────────────┘
```

### Event Loop

```
┌──────────┐     ┌──────────┐     ┌──────────┐
│ Crossterm│     │  Tokio   │     │  Async   │
│   Keys   │────►│  Select  │◄────│  Scan    │
└──────────┘     └────┬─────┘     └──────────┘
                      │
                      ▼
               ┌─────────────┐
               │ Update App  │
               │   State     │
               └──────┬──────┘
                      │
                      ▼
               ┌─────────────┐
               │  Render UI  │
               │  (60 fps)   │
               └─────────────┘
```

## Data Structures

### Network

```rust
pub struct Network {
    pub ssid: String,
    pub mac: String,
    pub channel: u8,
    pub signal_dbm: i32,
    pub security: SecurityType,
    pub frequency_band: FrequencyBand,
    pub score: u8,  // Calculated
}

pub enum SecurityType {
    Open,
    WEP,
    WPA,
    WPA2,
    WPA3,
    Unknown,
}

pub enum FrequencyBand {
    Band2_4GHz,
    Band5GHz,
    Band6GHz,
    Unknown,
}
```

### Application State

```rust
pub struct App {
    pub networks: Vec<Network>,
    pub selected_index: usize,
    pub signal_history: HashMap<String, VecDeque<i32>>,
    pub scan_mode: ScanMode,
    pub auto_interval: Duration,
    pub last_scan: Instant,
    pub is_scanning: bool,
    pub sort_by: SortField,
    pub should_quit: bool,
}
```

## UI Layout

```
┌─────────────────────────────────────────────────────────────────────┐
│  Header: Title + Mode Indicator + Help/Quit                         │ 3 rows
├────────────────────────────────────────────┬────────────────────────┤
│                                            │                        │
│           Network Table (60%)              │   Detail Panel (40%)   │
│                                            │                        │
│  - SSID                                    │  - All properties      │
│  - Signal bar                              │  - Score breakdown     │
│  - Score (colored)                         │  - Signal sparkline    │
│  - Security type                           │  - Channel congestion  │
│                                            │                        │
├────────────────────────────────────────────┴────────────────────────┤
│  Footer: Keybindings                                                │ 3 rows
└─────────────────────────────────────────────────────────────────────┘
```

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| ratatui | 0.29 | TUI framework |
| crossterm | 0.28 | Terminal backend |
| tokio | 1.x | Async runtime |
| wifiscanner | 0.5 | WiFi scanning |
| clap | 4.x | CLI parsing |
| color-eyre | 0.6 | Error handling |

## Platform Considerations

### macOS
- Uses `airport` command from Apple80211 framework
- No special permissions required for scanning
- Full feature support

### Linux
- Uses `iw` command
- May require `sudo` for scan operations
- Security field may be empty (known limitation)

### Windows
- Supported by wifiscanner crate
- Not primary development target

## Future Enhancements (Out of Scope)

- Network connection functionality
- Historical data with SQLite
- Export to JSON/CSV
- Custom scoring weights via config
- Network speed estimation
