mod platform;

pub use platform::{enable_demo_mode, is_demo_mode, scan_networks};

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum SecurityType {
    Open,
    WEP,
    WPA,
    WPA2,
    WPA3,
    Unknown,
}

impl fmt::Display for SecurityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityType::Open => write!(f, "Open"),
            SecurityType::WEP => write!(f, "WEP"),
            SecurityType::WPA => write!(f, "WPA"),
            SecurityType::WPA2 => write!(f, "WPA2"),
            SecurityType::WPA3 => write!(f, "WPA3"),
            SecurityType::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrequencyBand {
    Band2_4GHz,
    Band5GHz,
    #[allow(dead_code)]
    Band6GHz,
    Unknown,
}

impl fmt::Display for FrequencyBand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrequencyBand::Band2_4GHz => write!(f, "2.4 GHz"),
            FrequencyBand::Band5GHz => write!(f, "5 GHz"),
            FrequencyBand::Band6GHz => write!(f, "6 GHz"),
            FrequencyBand::Unknown => write!(f, "Unknown"),
        }
    }
}

impl FrequencyBand {
    pub fn from_channel(channel: u8) -> Self {
        match channel {
            1..=14 => FrequencyBand::Band2_4GHz,
            36..=177 => FrequencyBand::Band5GHz,
            _ => FrequencyBand::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Network {
    pub ssid: String,
    pub mac: String,
    pub channel: u8,
    pub signal_dbm: i32,
    pub security: SecurityType,
    pub frequency_band: FrequencyBand,
    pub score: u8,
}

impl Network {
    pub fn signal_bars(&self) -> String {
        let bars = match self.signal_dbm {
            s if s >= -50 => 5,
            s if s >= -60 => 4,
            s if s >= -70 => 3,
            s if s >= -80 => 2,
            _ => 1,
        };
        let filled = "\u{2593}".repeat(bars);
        let empty = "\u{2591}".repeat(5 - bars);
        format!("{}{}", filled, empty)
    }
}
