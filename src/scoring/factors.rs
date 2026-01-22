use crate::scanner::{FrequencyBand, Network, SecurityType};

/// Score signal strength (40% weight)
/// -30 dBm = 100 (excellent), -90 dBm = 0 (terrible)
pub fn score_signal(dbm: i32) -> f32 {
    // Linear scale from -90 (0) to -30 (100)
    let clamped = dbm.clamp(-90, -30);
    let normalized = (clamped + 90) as f32 / 60.0;
    normalized * 100.0
}

/// Score channel congestion (25% weight)
/// Fewer networks on same channel = higher score
pub fn score_congestion(channel: u8, all_networks: &[Network]) -> f32 {
    if channel == 0 {
        return 50.0; // Unknown channel, neutral score
    }

    let networks_on_channel = all_networks.iter().filter(|n| n.channel == channel).count();

    // 1 network (just us) = 100, each additional network subtracts 15
    let score = 100.0 - ((networks_on_channel.saturating_sub(1)) as f32 * 15.0);
    score.max(0.0)
}

/// Score security type (20% weight)
/// For public WiFi use case: Open is preferred (easier to connect)
pub fn score_security(security: &SecurityType) -> f32 {
    match security {
        SecurityType::Open => 100.0,
        SecurityType::WPA2 => 80.0,
        SecurityType::WPA3 => 70.0, // Newer but less compatible
        SecurityType::WPA => 60.0,
        SecurityType::WEP => 30.0, // Insecure
        SecurityType::Unknown => 50.0,
    }
}

/// Score frequency band (15% weight)
/// 5GHz typically has less congestion and higher speeds
pub fn score_band(band: FrequencyBand) -> f32 {
    match band {
        FrequencyBand::Band5GHz => 100.0,
        FrequencyBand::Band6GHz => 90.0, // Newest, but less device support
        FrequencyBand::Band2_4GHz => 60.0,
        FrequencyBand::Unknown => 50.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_scoring() {
        assert_eq!(score_signal(-30), 100.0);
        assert_eq!(score_signal(-90), 0.0);
        assert_eq!(score_signal(-60), 50.0);
        // Out of range values should clamp
        assert_eq!(score_signal(-20), 100.0);
        assert_eq!(score_signal(-100), 0.0);
    }

    #[test]
    fn test_security_scoring() {
        assert_eq!(score_security(&SecurityType::Open), 100.0);
        assert_eq!(score_security(&SecurityType::WPA2), 80.0);
        assert_eq!(score_security(&SecurityType::WEP), 30.0);
    }

    #[test]
    fn test_band_scoring() {
        assert_eq!(score_band(FrequencyBand::Band5GHz), 100.0);
        assert_eq!(score_band(FrequencyBand::Band2_4GHz), 60.0);
    }
}
