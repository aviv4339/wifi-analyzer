use clap::Parser;
use color_eyre::Result;
use crossterm::event::{KeyCode, KeyModifiers};
use std::time::Duration;
use wifi_analyzer::app::App;
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
    #[arg(short, long, default_value = "5")]
    interval: u64,

    /// Start in manual mode (no auto-refresh)
    #[arg(short = 'm', long)]
    manual: bool,

    /// Run with simulated WiFi networks (for testing/demo)
    #[arg(short, long)]
    demo: bool,
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

    let mut terminal = tui::init()?;
    let mut events = EventHandler::new(Duration::from_millis(100));
    let mut app = App::new(interval, !args.manual);

    // Initial scan
    if let Err(e) = app.perform_scan().await {
        app.set_error(format!("{}", e));
    }

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

                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => app.quit(),
                    KeyCode::Up | KeyCode::Char('k') => app.navigate_up(),
                    KeyCode::Down | KeyCode::Char('j') => app.navigate_down(),
                    KeyCode::Char('r') => {
                        app.trigger_scan();
                        match app.perform_scan().await {
                            Ok(()) => app.clear_error(),
                            Err(e) => app.set_error(format!("{}", e)),
                        }
                    }
                    KeyCode::Char('d') => {
                        // Switch to demo mode
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
            Event::Tick => {
                // Check for auto-scan
                if app.should_scan() {
                    match app.perform_scan().await {
                        Ok(()) => app.clear_error(),
                        Err(e) => app.set_error(format!("{}", e)),
                    }
                }
            }
            Event::Resize(_, _) => {
                // Terminal will handle resize on next draw
            }
        }

        if app.should_quit {
            break;
        }
    }

    tui::restore()?;
    Ok(())
}
