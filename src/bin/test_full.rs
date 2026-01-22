//! Full integration test: scanner + database

use wifi_analyzer::db::{Database, ScanResultRecord};
use wifi_analyzer::scanner::scan_networks;
use wifi_analyzer::scoring::calculate_all_scores;

#[tokio::main]
async fn main() {
    // Clean up any existing test database
    let _ = std::fs::remove_file("test_full.duckdb");
    let _ = std::fs::remove_file("test_full.duckdb.wal");

    println!("=== Full Integration Test ===\n");

    // 1. Open database and create location
    println!("1. Setting up database...");
    let db = Database::open("test_full.duckdb").expect("Failed to open db");
    let location_id = db.create_or_get_location("test_room").expect("Failed to create location");
    println!("   Location 'test_room' created with id={}\n", location_id);

    // 2. Scan networks (real scan, not demo)
    println!("2. Scanning WiFi networks (this takes ~3 seconds)...");
    let mut networks = scan_networks().await.expect("Failed to scan networks");
    println!("   Found {} networks\n", networks.len());

    // 3. Calculate scores
    println!("3. Calculating scores...");
    calculate_all_scores(&mut networks);
    println!("   Scores calculated\n");

    // 4. Persist to database
    println!("4. Persisting scan results...");
    let scan_id = db.create_scan(location_id).expect("Failed to create scan");

    let records: Vec<ScanResultRecord> = networks
        .iter()
        .map(|n| ScanResultRecord {
            bssid: n.mac.clone(),
            ssid: n.ssid.clone(),
            channel: n.channel,
            signal_dbm: n.signal_dbm,
            security: format!("{:?}", n.security),
            frequency_band: format!("{:?}", n.frequency_band),
            score: n.score,
        })
        .collect();

    db.record_scan_results(scan_id, &records).expect("Failed to record results");
    println!("   Persisted {} networks to scan_id={}\n", records.len(), scan_id);

    // 5. Display results
    println!("5. Networks found:");
    println!("   {:<30} {:>8} {:>6} {:>5}", "SSID", "Signal", "Ch", "Score");
    println!("   {}", "-".repeat(55));
    for net in &networks {
        println!(
            "   {:<30} {:>5} dBm {:>6} {:>5}",
            if net.ssid.len() > 28 { format!("{}...", &net.ssid[..25]) } else { net.ssid.clone() },
            net.signal_dbm,
            net.channel,
            net.score
        );
    }

    println!("\n=== All tests passed! ===");

    // Cleanup
    let _ = std::fs::remove_file("test_full.duckdb");
    let _ = std::fs::remove_file("test_full.duckdb.wal");
}
