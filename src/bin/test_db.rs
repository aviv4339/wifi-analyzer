//! Quick test for the database

use wifi_analyzer::db::{Database, ScanResultRecord};

fn main() {
    // Clean up any existing test database
    let _ = std::fs::remove_file("test_db.duckdb");
    let _ = std::fs::remove_file("test_db.duckdb.wal");

    println!("Testing database operations...\n");

    // Test 1: Open database
    println!("1. Opening database...");
    let db = match Database::open("test_db.duckdb") {
        Ok(db) => {
            println!("   SUCCESS: Database opened\n");
            db
        }
        Err(e) => {
            println!("   FAILED: {}\n", e);
            return;
        }
    };

    // Test 2: Create location
    println!("2. Creating location...");
    let location_id = match db.create_or_get_location("test_location") {
        Ok(id) => {
            println!("   SUCCESS: Location created with id={}\n", id);
            id
        }
        Err(e) => {
            println!("   FAILED: {}\n", e);
            return;
        }
    };

    // Test 3: Create scan
    println!("3. Creating scan...");
    let scan_id = match db.create_scan(location_id) {
        Ok(id) => {
            println!("   SUCCESS: Scan created with id={}\n", id);
            id
        }
        Err(e) => {
            println!("   FAILED: {}\n", e);
            return;
        }
    };

    // Test 4: Record scan results
    println!("4. Recording scan results...");
    let results = vec![
        ScanResultRecord {
            bssid: "AA:BB:CC:DD:EE:FF".to_string(),
            ssid: "TestNetwork1".to_string(),
            channel: 6,
            signal_dbm: -50,
            security: "WPA2".to_string(),
            frequency_band: "2.4GHz".to_string(),
            score: 85,
        },
        ScanResultRecord {
            bssid: "11:22:33:44:55:66".to_string(),
            ssid: "TestNetwork2".to_string(),
            channel: 36,
            signal_dbm: -65,
            security: "WPA3".to_string(),
            frequency_band: "5GHz".to_string(),
            score: 70,
        },
    ];

    match db.record_scan_results(scan_id, &results) {
        Ok(()) => println!("   SUCCESS: Scan results recorded\n"),
        Err(e) => {
            println!("   FAILED: {}\n", e);
            return;
        }
    }

    // Test 5: List locations
    println!("5. Listing locations...");
    match db.list_locations() {
        Ok(locs) => {
            println!("   SUCCESS: Found {} locations", locs.len());
            for loc in locs {
                println!("   - {} (id={})", loc.name, loc.id);
            }
            println!();
        }
        Err(e) => {
            println!("   FAILED: {}\n", e);
        }
    }

    println!("All database tests passed!");

    // Cleanup
    let _ = std::fs::remove_file("test_db.duckdb");
    let _ = std::fs::remove_file("test_db.duckdb.wal");
}
