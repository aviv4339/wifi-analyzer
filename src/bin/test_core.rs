//! Test binary to verify core functionality without TUI

use chrono::Utc;
use std::time::Duration;
use wifi_analyzer::app::{App, ScanMode, SortField};
use wifi_analyzer::scanner::{enable_demo_mode, scan_networks, FrequencyBand, Network, SecurityType};
use wifi_analyzer::scoring::calculate_all_scores;

#[tokio::main]
async fn main() {
    println!("=== WiFi Analyzer Core Tests ===\n");

    let mut all_passed = true;

    // Test 1: Demo Mode Scanner
    println!("1. Testing Demo Mode Scanner...");
    enable_demo_mode();
    match scan_networks().await {
        Ok(networks) => {
            if networks.len() >= 10 {
                println!("   ✓ Demo scanner works! Found {} networks", networks.len());
                for (i, net) in networks.iter().take(3).enumerate() {
                    println!(
                        "     Network {}: {} ({} dBm, Ch {}, {})",
                        i + 1,
                        net.ssid,
                        net.signal_dbm,
                        net.channel,
                        net.security
                    );
                }
                println!("     ... and {} more", networks.len() - 3);
            } else {
                println!("   ✗ Expected at least 10 demo networks, got {}", networks.len());
                all_passed = false;
            }
        }
        Err(e) => {
            println!("   ✗ Demo scanner error: {}", e);
            all_passed = false;
        }
    }
    println!();

    // Test 2: Scoring System
    println!("2. Testing Scoring System...");
    let mut test_networks = vec![
        Network {
            ssid: "StrongOpen5G".to_string(),
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            channel: 36,
            signal_dbm: -40,
            security: SecurityType::Open,
            frequency_band: FrequencyBand::Band5GHz,
            score: 0,
            last_seen: Utc::now(),
        },
        Network {
            ssid: "WeakSecured24".to_string(),
            mac: "11:22:33:44:55:66".to_string(),
            channel: 6,
            signal_dbm: -85,
            security: SecurityType::WPA2,
            frequency_band: FrequencyBand::Band2_4GHz,
            score: 0,
            last_seen: Utc::now(),
        },
        Network {
            ssid: "MediumOpen".to_string(),
            mac: "AA:11:BB:22:CC:33".to_string(),
            channel: 6,
            signal_dbm: -60,
            security: SecurityType::Open,
            frequency_band: FrequencyBand::Band2_4GHz,
            score: 0,
            last_seen: Utc::now(),
        },
    ];

    calculate_all_scores(&mut test_networks);

    // StrongOpen5G should have highest score, WeakSecured24 lowest
    let strong = test_networks.iter().find(|n| n.ssid == "StrongOpen5G").unwrap();
    let weak = test_networks.iter().find(|n| n.ssid == "WeakSecured24").unwrap();
    let medium = test_networks.iter().find(|n| n.ssid == "MediumOpen").unwrap();

    let score_order_correct = strong.score > medium.score && medium.score > weak.score;
    if score_order_correct {
        println!("   ✓ Score ordering correct:");
        println!("     Strong5G: {} > Medium: {} > Weak24: {}", strong.score, medium.score, weak.score);
    } else {
        println!("   ✗ Score ordering wrong!");
        println!("     Strong5G: {}, Medium: {}, Weak24: {}", strong.score, medium.score, weak.score);
        all_passed = false;
    }
    println!();

    // Test 3: Security Type Display
    println!("3. Testing Security Type Display...");
    let types = vec![
        (SecurityType::Open, "Open"),
        (SecurityType::WEP, "WEP"),
        (SecurityType::WPA, "WPA"),
        (SecurityType::WPA2, "WPA2"),
        (SecurityType::WPA3, "WPA3"),
        (SecurityType::Unknown, "Unknown"),
    ];
    let mut display_pass = true;
    for (t, expected) in types {
        let display = t.to_string();
        if display == expected {
            println!("   ✓ {:?} -> \"{}\"", t, display);
        } else {
            println!("   ✗ {:?} -> \"{}\" (expected \"{}\")", t, display, expected);
            display_pass = false;
        }
    }
    if !display_pass {
        all_passed = false;
    }
    println!();

    // Test 4: Frequency Band Detection
    println!("4. Testing Frequency Band Detection...");
    let test_cases = vec![
        (1, FrequencyBand::Band2_4GHz),
        (6, FrequencyBand::Band2_4GHz),
        (11, FrequencyBand::Band2_4GHz),
        (14, FrequencyBand::Band2_4GHz),
        (36, FrequencyBand::Band5GHz),
        (149, FrequencyBand::Band5GHz),
        (177, FrequencyBand::Band5GHz),
        (0, FrequencyBand::Unknown),
    ];
    let mut band_pass = true;
    for (channel, expected) in test_cases {
        let actual = FrequencyBand::from_channel(channel);
        if actual == expected {
            println!("   ✓ Channel {} -> {}", channel, actual);
        } else {
            println!("   ✗ Channel {} -> {} (expected {})", channel, actual, expected);
            band_pass = false;
        }
    }
    if !band_pass {
        all_passed = false;
    }
    println!();

    // Test 5: Signal Bars
    println!("5. Testing Signal Bars...");
    let signal_tests = vec![
        (-40, 5), // Excellent
        (-50, 5), // Excellent (boundary)
        (-55, 4), // Good
        (-60, 4), // Good (boundary)
        (-65, 3), // Fair
        (-70, 3), // Fair (boundary)
        (-75, 2), // Weak
        (-80, 2), // Weak (boundary)
        (-85, 1), // Very weak
        (-90, 1), // Very weak
    ];
    let mut bars_pass = true;
    for (dbm, expected_bars) in signal_tests {
        let net = Network {
            ssid: "test".to_string(),
            mac: String::new(),
            channel: 1,
            signal_dbm: dbm,
            security: SecurityType::Open,
            frequency_band: FrequencyBand::Band2_4GHz,
            score: 0,
            last_seen: Utc::now(),
        };
        let bars = net.signal_bars();
        let filled_count = bars.chars().filter(|c| *c == '▓').count();
        if filled_count == expected_bars {
            println!("   ✓ {} dBm -> {} ({} bars)", dbm, bars, filled_count);
        } else {
            println!(
                "   ✗ {} dBm -> {} ({} bars, expected {})",
                dbm, bars, filled_count, expected_bars
            );
            bars_pass = false;
        }
    }
    if !bars_pass {
        all_passed = false;
    }
    println!();

    // Test 6: App State Management
    println!("6. Testing App State Management...");
    let mut app = App::new(Duration::from_secs(5), true);

    // Test initial state
    let init_mode = matches!(app.scan_mode, ScanMode::Auto);
    let init_sort = matches!(app.sort_by, SortField::Score);
    let init_quit = !app.should_quit;
    if init_mode && init_sort && init_quit {
        println!("   ✓ Initial state correct (Auto mode, Sort by Score)");
    } else {
        println!("   ✗ Initial state incorrect");
        all_passed = false;
    }

    // Test mode toggle
    app.toggle_scan_mode();
    let toggled_manual = matches!(app.scan_mode, ScanMode::Manual);
    app.toggle_scan_mode();
    let toggled_back = matches!(app.scan_mode, ScanMode::Auto);
    if toggled_manual && toggled_back {
        println!("   ✓ Mode toggle works (Auto <-> Manual)");
    } else {
        println!("   ✗ Mode toggle failed");
        all_passed = false;
    }

    // Test sort cycling
    app.cycle_sort();
    let sort1 = matches!(app.sort_by, SortField::Signal);
    app.cycle_sort();
    let sort2 = matches!(app.sort_by, SortField::Name);
    app.cycle_sort();
    let sort3 = matches!(app.sort_by, SortField::Score);
    if sort1 && sort2 && sort3 {
        println!("   ✓ Sort cycling works (Score -> Signal -> Name -> Score)");
    } else {
        println!("   ✗ Sort cycling failed");
        all_passed = false;
    }

    // Test navigation
    app.perform_scan().await.unwrap();
    let initial_idx = app.selected_index;
    app.navigate_down();
    let after_down = app.selected_index;
    app.navigate_up();
    let after_up = app.selected_index;
    if after_down == initial_idx + 1 && after_up == initial_idx {
        println!("   ✓ Navigation works (down/up)");
    } else {
        println!("   ✗ Navigation failed");
        all_passed = false;
    }

    // Test quit
    app.quit();
    if app.should_quit {
        println!("   ✓ Quit flag works");
    } else {
        println!("   ✗ Quit flag failed");
        all_passed = false;
    }
    println!();

    // Test 7: Full scan with scoring
    println!("7. Testing Full Scan with Scoring...");
    let mut app2 = App::new(Duration::from_secs(5), true);
    match app2.perform_scan().await {
        Ok(()) => {
            let networks_have_scores = app2.networks.iter().all(|n| n.score > 0);
            let sorted_by_score = app2
                .networks
                .windows(2)
                .all(|w| w[0].score >= w[1].score);
            if networks_have_scores && sorted_by_score {
                println!("   ✓ Full scan works ({} networks, all scored, sorted)", app2.networks.len());
                println!("     Top network: {} (score: {})", app2.networks[0].ssid, app2.networks[0].score);
            } else {
                println!("   ✗ Scan issues: scores={}, sorted={}", networks_have_scores, sorted_by_score);
                all_passed = false;
            }
        }
        Err(e) => {
            println!("   ✗ Scan failed: {}", e);
            all_passed = false;
        }
    }
    println!();

    // Final result
    println!("=== Test Summary ===");
    if all_passed {
        println!("✓ All tests PASSED!");
    } else {
        println!("✗ Some tests FAILED");
        std::process::exit(1);
    }
}
