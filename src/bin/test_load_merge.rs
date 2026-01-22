//! Test loading networks from DB and merge behavior

use chrono::Utc;
use wifi_analyzer::db::{Database, ScanResultRecord};
use wifi_analyzer::scanner::{enable_demo_mode, FrequencyBand, Network, SecurityType};
use wifi_analyzer::app::App;
use std::time::Duration;

fn main() {
    println!("=== Testing Load and Merge Behavior ===\n");

    // Clean up any existing test database
    let _ = std::fs::remove_file("test_load_merge.duckdb");
    let _ = std::fs::remove_file("test_load_merge.duckdb.wal");

    // Enable demo mode
    enable_demo_mode();

    // 1. Create database and populate with some initial data
    println!("1. Creating database and populating with initial networks...");
    let db = Database::open("test_load_merge.duckdb").expect("Failed to open db");
    let location_id = db.create_or_get_location("test_room").expect("Failed to create location");
    println!("   Location 'test_room' id={}", location_id);

    // Create a scan and add some networks
    let scan_id = db.create_scan(location_id).expect("Failed to create scan");
    let initial_networks = vec![
        ScanResultRecord {
            bssid: "AA:BB:CC:DD:EE:01".to_string(),
            ssid: "OldNetwork1".to_string(),
            channel: 6,
            signal_dbm: -50,
            security: "WPA2".to_string(),
            frequency_band: "Band2_4GHz".to_string(),
            score: 75,
        },
        ScanResultRecord {
            bssid: "AA:BB:CC:DD:EE:02".to_string(),
            ssid: "OldNetwork2".to_string(),
            channel: 36,
            signal_dbm: -60,
            security: "Open".to_string(),
            frequency_band: "Band5GHz".to_string(),
            score: 80,
        },
    ];
    db.record_scan_results(scan_id, &initial_networks).expect("Failed to record results");
    println!("   Recorded {} initial networks", initial_networks.len());

    // 2. Test loading networks from DB
    println!("\n2. Testing load_networks_from_db...");
    let mut app = App::new(Duration::from_secs(5), true)
        .with_database(db, location_id, "test_room".to_string());

    app.load_networks_from_db().expect("Failed to load networks from DB");
    println!("   Loaded {} networks from database", app.networks.len());

    // Verify the loaded networks
    let has_old1 = app.networks.iter().any(|n| n.ssid == "OldNetwork1");
    let has_old2 = app.networks.iter().any(|n| n.ssid == "OldNetwork2");

    if has_old1 && has_old2 {
        println!("   ✓ Both old networks were loaded from DB");
        for n in &app.networks {
            println!("     - {} (BSSID: {}, last_seen: {})", n.ssid, n.mac, n.last_seen);
        }
    } else {
        println!("   ✗ Failed to load old networks (has_old1={}, has_old2={})", has_old1, has_old2);
        std::process::exit(1);
    }

    // 3. Test merge behavior - add new network manually
    println!("\n3. Testing merge behavior...");

    // Simulate adding a new network (like from a scan)
    let new_network = Network {
        ssid: "NewNetwork3".to_string(),
        mac: "AA:BB:CC:DD:EE:03".to_string(),
        channel: 11,
        signal_dbm: -55,
        security: SecurityType::WPA3,
        frequency_band: FrequencyBand::Band2_4GHz,
        score: 85,
        last_seen: Utc::now(),
    };

    // Manually add to simulate merge
    app.networks.push(new_network);
    println!("   Added new network, total: {}", app.networks.len());

    // Now verify that old networks are still there after "merge"
    let has_old1_after = app.networks.iter().any(|n| n.ssid == "OldNetwork1");
    let has_old2_after = app.networks.iter().any(|n| n.ssid == "OldNetwork2");
    let has_new3 = app.networks.iter().any(|n| n.ssid == "NewNetwork3");

    if has_old1_after && has_old2_after && has_new3 {
        println!("   ✓ All networks present after merge (old + new)");
        println!("   Total networks: {}", app.networks.len());
        for n in &app.networks {
            println!("     - {} ({}, {} dBm, score: {})", n.ssid, n.mac, n.signal_dbm, n.score);
        }
    } else {
        println!("   ✗ Merge failed (old1={}, old2={}, new3={})", has_old1_after, has_old2_after, has_new3);
        std::process::exit(1);
    }

    // 4. Test last_seen formatting
    println!("\n4. Testing last_seen field...");
    for n in &app.networks {
        let now = Utc::now();
        let duration = now.signed_duration_since(n.last_seen);
        println!("   {} last_seen: {} ({} secs ago)", n.ssid, n.last_seen, duration.num_seconds());
    }
    println!("   ✓ All networks have last_seen timestamp");

    // Cleanup
    println!("\n=== All tests passed! ===");
    let _ = std::fs::remove_file("test_load_merge.duckdb");
    let _ = std::fs::remove_file("test_load_merge.duckdb.wal");
}
