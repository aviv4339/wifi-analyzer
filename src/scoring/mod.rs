mod factors;

use crate::scanner::Network;
pub use factors::*;

/// Calculate the overall score for a network (0-100)
/// Weights: Signal 40%, Congestion 25%, Security 20%, Band 15%
pub fn calculate_score(network: &Network, all_networks: &[Network]) -> u8 {
    let signal_score = score_signal(network.signal_dbm);
    let congestion_score = score_congestion(network.channel, all_networks);
    let security_score = score_security(&network.security);
    let band_score = score_band(network.frequency_band);

    let weighted_score = (signal_score * 0.40)
        + (congestion_score * 0.25)
        + (security_score * 0.20)
        + (band_score * 0.15);

    weighted_score.round().clamp(0.0, 100.0) as u8
}

/// Calculate scores for all networks
pub fn calculate_all_scores(networks: &mut [Network]) {
    // Need to clone for the borrow checker since we're reading and writing
    let networks_ref: Vec<Network> = networks.to_vec();

    for network in networks.iter_mut() {
        network.score = calculate_score(network, &networks_ref);
    }
}
