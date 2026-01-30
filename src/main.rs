use clap::{Parser, Subcommand};
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

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Scan network devices (CLI mode, no TUI)
    ScanDevices {
        /// Show verbose output
        #[arg(short, long)]
        verbose: bool,
        /// Do full ping sweep to discover all devices (slower but more thorough)
        #[arg(short, long)]
        full: bool,
    },
    /// Discover devices on the network (ARP only, no port scan)
    Discover {
        /// Do full ping sweep to discover all devices
        #[arg(short, long)]
        full: bool,
    },
    /// Test port scanning on a specific IP
    ScanPorts {
        /// IP address to scan
        ip: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let args = Args::parse();

    // Handle subcommands (CLI mode)
    if let Some(cmd) = args.command {
        return run_cli_command(cmd).await;
    }

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

/// Run CLI commands (non-TUI mode)
async fn run_cli_command(cmd: Command) -> Result<()> {
    use wifi_analyzer::network_map::{
        discover_devices, discover_devices_with_options, identify_device, scan_devices_ports,
        Device, ScanPhase, ScanProgress, COMMON_PORTS,
    };

    match cmd {
        Command::ScanDevices { verbose, full } => {
            println!("=== Network Device Scanner{} ===\n", if full { " (Full)" } else { "" });

            // Phase 1: Discovery
            println!("[1/3] Discovering devices{}...", if full { " (with ping sweep)" } else { "" });
            let (progress_tx, mut progress_rx) = tokio::sync::mpsc::channel::<ScanProgress>(10);

            // Spawn progress printer
            let verbose_clone = verbose;
            let progress_handle = tokio::spawn(async move {
                while let Some(progress) = progress_rx.recv().await {
                    if verbose_clone {
                        match progress.phase {
                            ScanPhase::Discovery => {
                                println!("  Discovery: {} devices found", progress.devices_found);
                            }
                            ScanPhase::PortScan => {
                                if let Some(ref dev) = progress.current_device {
                                    println!(
                                        "  Port scan: {} ({}/{})",
                                        dev, progress.ports_scanned, progress.total_ports
                                    );
                                }
                            }
                            ScanPhase::Identification => {
                                println!("  Identifying {} devices...", progress.devices_found);
                            }
                            ScanPhase::Complete => {
                                println!("  Complete!");
                            }
                        }
                    }
                }
            });

            let mut devices = match discover_devices_with_options(Some(progress_tx.clone()), full).await {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Discovery error: {}", e);
                    return Ok(());
                }
            };
            println!("  Found {} devices\n", devices.len());

            if devices.is_empty() {
                println!("No devices found. Make sure you're connected to a network.");
                return Ok(());
            }

            // Phase 2: Port scanning
            println!("[2/3] Scanning ports on {} devices...", devices.len());
            if let Err(e) = scan_devices_ports(&mut devices, Some(progress_tx.clone())).await {
                eprintln!("Port scan error: {}", e);
            }
            println!("  Port scan complete\n");

            // Phase 3: Identification
            println!("[3/3] Identifying devices...");
            let _ = progress_tx
                .send(ScanProgress {
                    phase: ScanPhase::Identification,
                    devices_found: devices.len(),
                    current_device: None,
                    ports_scanned: 0,
                    total_ports: 0,
                })
                .await;

            let device_count = devices.len();
            for (i, device) in devices.iter_mut().enumerate() {
                if verbose {
                    println!("  Identifying device {}/{}: {}", i + 1, device_count, device.ip_address);
                }
                identify_device(device);
            }
            println!("  Identification complete\n");

            // Close progress channel
            drop(progress_tx);
            let _ = progress_handle.await;

            // Print results
            println!("=== Results ===\n");
            for device in &devices {
                // Show hostname or display name
                let name = device.hostname.as_deref()
                    .unwrap_or_else(|| device.vendor.as_deref().unwrap_or("Unknown"));
                let name_truncated = if name.len() > 24 {
                    format!("{}...", &name[..21])
                } else {
                    name.to_string()
                };

                println!(
                    "{:<16} {:<25} {:<12} {}",
                    device.ip_address,
                    name_truncated,
                    format!("{}", device.device_type),
                    device.vendor.as_deref().unwrap_or("-")
                );

                if !device.services.is_empty() {
                    for svc in &device.services {
                        let agent_str = svc
                            .detected_agent
                            .as_ref()
                            .map(|a| format!(" [AI: {}]", a))
                            .unwrap_or_default();
                        println!(
                            "  └─ :{:<5} {}{}",
                            svc.port,
                            svc.service_name.as_deref().unwrap_or("unknown"),
                            agent_str
                        );
                    }
                }
            }

            let ai_devices: Vec<_> = devices.iter().filter(|d| !d.detected_agents.is_empty()).collect();
            if !ai_devices.is_empty() {
                println!("\n=== AI Agents Detected ===");
                for device in ai_devices {
                    println!(
                        "  {} ({}): {:?}",
                        device.ip_address,
                        device.display_name(),
                        device.detected_agents
                    );
                }
            }

            println!("\nTotal: {} devices", devices.len());
        }

        Command::Discover { full } => {
            println!("=== Device Discovery{} ===\n", if full { " (Full Sweep)" } else { " (ARP only)" });

            let devices = match discover_devices_with_options(None, full).await {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Discovery error: {}", e);
                    return Ok(());
                }
            };

            println!("Found {} devices:\n", devices.len());
            for device in &devices {
                let name = device.hostname.as_deref().unwrap_or("-");
                println!(
                    "  {:<16} {:<18} {}",
                    device.ip_address,
                    device.mac_address,
                    name
                );
            }
        }

        Command::ScanPorts { ip } => {
            println!("=== Port Scan: {} ===\n", ip);

            let mut device = Device::new("00:00:00:00:00:00".to_string(), ip.clone());

            println!("Scanning {} common ports...", COMMON_PORTS.len());

            // Create a single-device vec for scanning
            let mut devices = vec![device];
            if let Err(e) = scan_devices_ports(&mut devices, None).await {
                eprintln!("Port scan error: {}", e);
                return Ok(());
            }
            device = devices.into_iter().next().unwrap();

            // Identify the device
            identify_device(&mut device);

            println!("\nDevice type: {}", device.device_type);
            if let Some(ref vendor) = device.vendor {
                println!("Vendor: {}", vendor);
            }

            if device.services.is_empty() {
                println!("\nNo open ports found.");
            } else {
                println!("\nOpen ports:");
                for svc in &device.services {
                    let agent_str = svc
                        .detected_agent
                        .as_ref()
                        .map(|a| format!(" [AI Agent: {}]", a))
                        .unwrap_or_default();
                    let banner_str = svc
                        .banner
                        .as_ref()
                        .map(|b| format!(" \"{}\"", b.chars().take(50).collect::<String>()))
                        .unwrap_or_default();
                    println!(
                        "  :{:<5} {} {}{}{}",
                        svc.port,
                        svc.protocol,
                        svc.service_name.as_deref().unwrap_or("unknown"),
                        agent_str,
                        banner_str
                    );
                }
            }

            if !device.detected_agents.is_empty() {
                println!("\nAI Agents detected: {:?}", device.detected_agents);
            }
        }
    }

    Ok(())
}
