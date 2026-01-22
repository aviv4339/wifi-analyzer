//! Quick test for the real WiFi scanner

use wifi_analyzer::scanner::scan_networks;

#[tokio::main]
async fn main() {
    println!("Testing real WiFi scanner (no demo mode)...\n");

    match scan_networks().await {
        Ok(networks) => {
            println!("SUCCESS! Found {} networks:\n", networks.len());
            for (i, net) in networks.iter().enumerate() {
                println!(
                    "{}. {} \n   Channel: {} ({}) | Signal: {} dBm | Security: {}",
                    i + 1,
                    net.ssid,
                    net.channel,
                    net.frequency_band,
                    net.signal_dbm,
                    net.security
                );
            }
        }
        Err(e) => {
            println!("FAILED: {}", e);
        }
    }
}
