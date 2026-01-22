//! Test FK constraints with repeated networks across scans

use wifi_analyzer::db::{Database, ScanResultRecord};

fn main() {
    let _ = std::fs::remove_file("test_fk.duckdb");
    let _ = std::fs::remove_file("test_fk.duckdb.wal");

    let db = Database::open("test_fk.duckdb").expect("open");
    let loc_id = db.create_or_get_location("room1").expect("loc");
    println!("Location id: {}", loc_id);

    // Same networks seen in every scan (like real WiFi)
    let networks = vec![
        ("AA:BB:CC:DD:EE:01", "Network1", 6),
        ("AA:BB:CC:DD:EE:02", "Network2", 11),
        ("AA:BB:CC:DD:EE:03", "Network3", 36),
    ];

    for scan_num in 1..=10 {
        println!("\nScan {}:", scan_num);

        let scan_id = match db.create_scan(loc_id) {
            Ok(id) => { println!("  scan_id: {}", id); id }
            Err(e) => { println!("  FAILED create_scan: {}", e); return; }
        };

        let results: Vec<ScanResultRecord> = networks.iter().map(|(bssid, ssid, ch)| {
            ScanResultRecord {
                bssid: bssid.to_string(),
                ssid: ssid.to_string(),
                channel: *ch,
                signal_dbm: -50 - (scan_num as i32),
                security: "WPA2".to_string(),
                frequency_band: "2.4GHz".to_string(),
                score: 80,
            }
        }).collect();

        match db.record_scan_results(scan_id, &results) {
            Ok(()) => println!("  recorded {} networks OK", results.len()),
            Err(e) => { println!("  FAILED record_scan_results: {}", e); return; }
        }
    }

    // Try with a different location
    println!("\n--- Testing second location ---");
    let loc2_id = db.create_or_get_location("room2").expect("loc2");
    println!("Location 2 id: {}", loc2_id);

    for scan_num in 1..=3 {
        println!("\nScan {} (room2):", scan_num);

        let scan_id = match db.create_scan(loc2_id) {
            Ok(id) => { println!("  scan_id: {}", id); id }
            Err(e) => { println!("  FAILED create_scan: {}", e); return; }
        };

        let results: Vec<ScanResultRecord> = networks.iter().map(|(bssid, ssid, ch)| {
            ScanResultRecord {
                bssid: bssid.to_string(),
                ssid: ssid.to_string(),
                channel: *ch,
                signal_dbm: -60,
                security: "WPA2".to_string(),
                frequency_band: "2.4GHz".to_string(),
                score: 70,
            }
        }).collect();

        match db.record_scan_results(scan_id, &results) {
            Ok(()) => println!("  recorded {} networks OK", results.len()),
            Err(e) => { println!("  FAILED record_scan_results: {}", e); return; }
        }
    }

    println!("\n=== All tests passed! ===");
    let _ = std::fs::remove_file("test_fk.duckdb");
    let _ = std::fs::remove_file("test_fk.duckdb.wal");
}
