use clap::Parser;
use color_eyre::Result;
use crossterm::event::{KeyCode, KeyModifiers};
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;
use wifi_analyzer::app::App;
use wifi_analyzer::db::Database;
use wifi_analyzer::event::{Event, EventHandler};
use wifi_analyzer::scanner::enable_demo_mode;
use wifi_analyzer::tui;

#[derive(Parser, Debug)]
#[command(name = "wifi-analyzer")]
#[command(author = "Aviv E")]
#[command(version = "0.1.0")]
#[command(about = "A terminal-based WiFi analyzer for finding the best public WiFi")]
struct Args {
    /// Auto-refresh interval in seconds
    #[arg(short, long, default_value = "15")]
    interval: u64,

    /// Start in manual mode (no auto-refresh)
    #[arg(short = 'm', long)]
    manual: bool,

    /// Run with simulated WiFi networks (for testing/demo)
    #[arg(short, long)]
    demo: bool,

    /// Location name for this scanning session (e.g., "livingroom", "office")
    #[arg(short, long)]
    location: Option<String>,

    /// Database file path for persistence
    #[arg(long, default_value = "wifi_analyzer.duckdb")]
    db_path: PathBuf,

    /// Disable database persistence (run in memory-only mode)
    #[arg(long)]
    no_persist: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let args = Args::parse();
    let interval = Duration::from_secs(args.interval);

    // Enable demo mode if requested
    if args.demo {
        enable_demo_mode();
    }

    // Initialize database and get location (before TUI starts)
    let mut app = App::new(interval, !args.manual);

    // Initialize persistence (location prompt happens here, before TUI)
    let db_info = if !args.no_persist {
        match initialize_persistence(&args) {
            Ok(info) => Some(info),
            Err(e) => {
                eprintln!("Warning: Failed to initialize database: {}", e);
                eprintln!("Running in memory-only mode.\n");
                None
            }
        }
    } else {
        None
    };

    // Start TUI immediately - show GUI first!
    let mut terminal = tui::init()?;
    let mut events = EventHandler::new(Duration::from_millis(100));

    // Show GUI immediately with "Loading..." status
    app.status_message = Some("Loading...".to_string());
    terminal.draw(|frame| app.render(frame))?;

    // Now configure database (after GUI is visible)
    if let Some((db, location_id, location_name)) = db_info {
        app = app.with_database(db, location_id, location_name);
        // Load existing networks for this location from DB
        if let Err(e) = app.load_networks_from_db() {
            app.status_message = Some(format!("DB load warning: {}", e));
        }
        terminal.draw(|frame| app.render(frame))?;
    }

    // Scan networks
    app.status_message = Some("Scanning networks...".to_string());
    terminal.draw(|frame| app.render(frame))?;

    app.trigger_scan();
    if let Err(e) = app.perform_scan().await {
        app.set_error(format!("{}", e));
    }

    // Initialize connection state (fast - no network calls now)
    if let Err(e) = app.init_connection_state() {
        app.status_message = Some(format!("Warning: {}", e));
    } else {
        app.status_message = None;
    }

    // Track previous selection to update cache when it changes
    let mut prev_selected_idx = app.selected_index;
    let mut prev_selected_mac = app.networks.get(app.selected_index).map(|n| n.mac.clone());

    loop {
        // Render
        terminal.draw(|frame| app.render(frame))?;

        // Handle events
        match events.next().await? {
            Event::Key(key) => {
                // Handle Ctrl+C
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c')
                {
                    app.quit();
                }

                // Handle popup keys first
                if app.show_connect_popup {
                    match key.code {
                        KeyCode::Char('y') | KeyCode::Char('Y') => {
                            // Dismiss dialog immediately and render
                            app.show_connect_popup = false;
                            app.status_message = Some("Connecting...".to_string());
                            terminal.draw(|frame| app.render(frame))?;

                            // Now attempt connection
                            if let Err(e) = app.do_connect() {
                                app.set_error(format!("Connection failed: {}", e));
                            }
                        }
                        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                            app.cancel_connect_dialog();
                        }
                        _ => {}
                    }
                } else if app.show_speedtest_popup {
                    match key.code {
                        KeyCode::Char('y') | KeyCode::Char('Y') => {
                            // Render immediately to show "Running speed test..." message
                            terminal.draw(|frame| app.render(frame))?;
                            if let Err(e) = app.confirm_speedtest() {
                                app.set_error(format!("Speed test failed: {}", e));
                            }
                        }
                        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                            app.cancel_speedtest_dialog();
                        }
                        _ => {}
                    }
                } else {
                    // Normal key handling based on current view
                    match app.current_view {
                        wifi_analyzer::app::AppView::WifiNetworks => {
                            // WiFi Networks view keys
                            match key.code {
                                KeyCode::Char('q') | KeyCode::Esc => app.quit(),
                                KeyCode::Tab => app.switch_view(),
                                KeyCode::Up | KeyCode::Char('k') => app.navigate_up(),
                                KeyCode::Down | KeyCode::Char('j') => app.navigate_down(),
                                KeyCode::Enter => {
                                    app.show_connect_dialog();
                                }
                                KeyCode::Char('r') => {
                                    app.trigger_scan();
                                    match app.perform_scan().await {
                                        Ok(()) => {
                                            app.clear_error();
                                            let _ = app.refresh_current_connection();
                                        }
                                        Err(e) => app.set_error(format!("{}", e)),
                                    }
                                }
                                KeyCode::Char('d') => {
                                    enable_demo_mode();
                                    app.clear_error();
                                    let _ = app.perform_scan().await;
                                }
                                KeyCode::Char('a') => app.toggle_scan_mode(),
                                KeyCode::Char('s') => app.cycle_sort(),
                                KeyCode::Char('?') => app.toggle_help(),
                                _ => {}
                            }
                        }
                        wifi_analyzer::app::AppView::NetworkDevices => {
                            // Network Devices view keys
                            if app.show_rename_dialog {
                                match key.code {
                                    KeyCode::Enter => app.confirm_rename(),
                                    KeyCode::Esc => app.cancel_rename(),
                                    KeyCode::Backspace => app.rename_input_backspace(),
                                    KeyCode::Char(c) => app.rename_input_char(c),
                                    _ => {}
                                }
                            } else if app.device_scan_progress.is_some() {
                                match key.code {
                                    KeyCode::Esc => app.cancel_device_scan(),
                                    _ => {}
                                }
                            } else {
                                match key.code {
                                    KeyCode::Char('q') | KeyCode::Esc => app.quit(),
                                    KeyCode::Tab => app.switch_view(),
                                    KeyCode::Up | KeyCode::Char('k') => app.device_navigate_up(),
                                    KeyCode::Down | KeyCode::Char('j') => app.device_navigate_down(),
                                    KeyCode::Enter => app.toggle_device_detail(),
                                    KeyCode::Char('s') | KeyCode::Char('S') => app.start_device_scan(),
                                    KeyCode::Char('r') | KeyCode::Char('R') => app.start_rename_device(),
                                    KeyCode::Char('?') => app.toggle_help(),
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
            Event::Tick => {
                // Check for background speed test completion
                app.check_speedtest_result();

                // Check for device scan progress
                app.check_device_scan_progress();

                // Check for auto-scan
                if app.should_scan() {
                    match app.perform_scan().await {
                        Ok(()) => {
                            app.clear_error();
                            let _ = app.refresh_current_connection();
                        }
                        Err(e) => app.set_error(format!("{}", e)),
                    }
                }
            }
            Event::Resize(_, _) => {
                // Terminal will handle resize on next draw
            }
        }

        // Update connection data cache if selection changed
        let current_mac = app.networks.get(app.selected_index).map(|n| n.mac.clone());
        if app.selected_index != prev_selected_idx || current_mac != prev_selected_mac {
            app.clear_connection_cache();

            // Load connection data for newly selected network
            if let Some(ref mac) = current_mac {
                let _ = app.get_connection_history(mac);
                let _ = app.get_recent_ips(mac);
            }

            prev_selected_idx = app.selected_index;
            prev_selected_mac = current_mac;
        }

        if app.should_quit {
            break;
        }
    }

    tui::restore()?;
    Ok(())
}

/// Initialize database persistence and get location
fn initialize_persistence(args: &Args) -> Result<(Database, i64, String)> {
    let db = Database::open(&args.db_path)?;

    // Get location name from CLI arg or prompt user
    let location_name = if let Some(ref name) = args.location {
        name.clone()
    } else {
        prompt_for_location(&db)?
    };

    let location_id = db.create_or_get_location(&location_name)?;

    Ok((db, location_id, location_name))
}

/// Prompt user for location name (before TUI starts)
fn prompt_for_location(db: &Database) -> Result<String> {
    println!("\n=== WiFi Analyzer - Location Setup ===\n");

    // Show existing locations if any
    let locations = db.list_locations().unwrap_or_default();
    if !locations.is_empty() {
        println!("Existing locations:");
        for (i, loc) in locations.iter().enumerate() {
            println!("  {}. {}", i + 1, loc.name);
        }
        println!();
    }

    print!("Enter location name (e.g., 'livingroom', 'office'): ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    let location = input.trim();

    if location.is_empty() {
        return Err(color_eyre::eyre::eyre!("Location name cannot be empty"));
    }

    println!("Using location: {}\n", location);

    Ok(location.to_string())
}
