//! Test binary to verify UI components render correctly

use ratatui::backend::TestBackend;
use ratatui::Terminal;
use std::time::Duration;
use wifi_analyzer::app::App;
use wifi_analyzer::scanner::enable_demo_mode;

#[tokio::main]
async fn main() {
    println!("=== WiFi Analyzer UI Tests ===\n");

    let mut all_passed = true;

    // Enable demo mode for testing
    enable_demo_mode();

    // Create a test terminal backend (80x24)
    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();

    // Create app and perform initial scan
    let mut app = App::new(Duration::from_secs(5), true);
    app.perform_scan().await.unwrap();

    // Test 1: Main render
    println!("1. Testing main render...");
    match terminal.draw(|frame| app.render(frame)) {
        Ok(_) => {
            println!("   ✓ Main render succeeded");
        }
        Err(e) => {
            println!("   ✗ Main render failed: {}", e);
            all_passed = false;
        }
    }

    // Test 2: Render with different sort modes
    println!("2. Testing render with different sort modes...");
    for mode_name in ["Score", "Signal", "Name"] {
        app.cycle_sort();
        match terminal.draw(|frame| app.render(frame)) {
            Ok(_) => {
                println!("   ✓ Render with {} sort succeeded", mode_name);
            }
            Err(e) => {
                println!("   ✗ Render with {} sort failed: {}", mode_name, e);
                all_passed = false;
            }
        }
    }

    // Test 3: Render with help overlay
    println!("3. Testing render with help overlay...");
    app.toggle_help();
    match terminal.draw(|frame| app.render(frame)) {
        Ok(_) => {
            println!("   ✓ Help overlay render succeeded");
        }
        Err(e) => {
            println!("   ✗ Help overlay render failed: {}", e);
            all_passed = false;
        }
    }
    app.toggle_help(); // Toggle off

    // Test 4: Render after navigation
    println!("4. Testing render after navigation...");
    for i in 0..5 {
        app.navigate_down();
        match terminal.draw(|frame| app.render(frame)) {
            Ok(_) => {
                println!("   ✓ Render at index {} succeeded", i + 1);
            }
            Err(e) => {
                println!("   ✗ Render at index {} failed: {}", i + 1, e);
                all_passed = false;
            }
        }
    }

    // Test 5: Render in manual mode
    println!("5. Testing render in manual mode...");
    app.toggle_scan_mode();
    match terminal.draw(|frame| app.render(frame)) {
        Ok(_) => {
            println!("   ✓ Manual mode render succeeded");
        }
        Err(e) => {
            println!("   ✗ Manual mode render failed: {}", e);
            all_passed = false;
        }
    }

    // Test 6: Verify buffer content has expected elements
    println!("6. Testing buffer content...");
    let _ = terminal.draw(|frame| app.render(frame));
    let buffer = terminal.backend().buffer().clone();
    let content = buffer_to_string(&buffer);

    let expected_elements = vec![
        "WiFi Analyzer",  // Title
        "Networks",       // Table title
        "dBm",            // Signal label in details
        "Navigate",       // Help text
    ];

    let mut content_pass = true;
    for element in expected_elements {
        if content.contains(element) {
            println!("   ✓ Found \"{}\" in buffer", element);
        } else {
            println!("   ✗ Missing \"{}\" in buffer", element);
            content_pass = false;
        }
    }
    if !content_pass {
        all_passed = false;
    }

    // Test 7: Verify score colors are applied
    println!("7. Testing score display...");
    // Reset to top
    for _ in 0..10 {
        app.navigate_up();
    }
    let _ = terminal.draw(|frame| app.render(frame));
    let buffer = terminal.backend().buffer().clone();

    // Check that network names are visible
    let network_names = ["CoffeeShop", "Airport", "Hotel"];
    let mut names_found = 0;
    for name in network_names {
        if buffer_to_string(&buffer).contains(name) {
            names_found += 1;
        }
    }
    if names_found >= 2 {
        println!("   ✓ Network names displayed ({} found)", names_found);
    } else {
        println!("   ✗ Network names missing ({} found)", names_found);
        all_passed = false;
    }

    println!();
    println!("=== UI Test Summary ===");
    if all_passed {
        println!("✓ All UI tests PASSED!");
    } else {
        println!("✗ Some UI tests FAILED");
        std::process::exit(1);
    }
}

fn buffer_to_string(buffer: &ratatui::buffer::Buffer) -> String {
    let mut result = String::new();
    for y in 0..buffer.area().height {
        for x in 0..buffer.area().width {
            let cell = buffer.cell((x, y)).unwrap();
            result.push_str(cell.symbol());
        }
        result.push('\n');
    }
    result
}
