use crate::components::{Component, DetailPanel, NetworkTable, SignalChart, StatusBar};
use crate::scanner::{scan_networks, Network};
use crate::scoring::calculate_all_scores;
use color_eyre::Result;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::Frame;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

const SIGNAL_HISTORY_SIZE: usize = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    Auto,
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortField {
    Score,
    Signal,
    Name,
}

pub struct App {
    pub networks: Vec<Network>,
    pub selected_index: usize,
    pub signal_history: HashMap<String, VecDeque<i32>>,
    pub scan_mode: ScanMode,
    pub auto_interval: Duration,
    pub last_scan: Instant,
    pub is_scanning: bool,
    pub sort_by: SortField,
    pub should_quit: bool,
    pub show_help: bool,
    pub error_message: Option<String>,
}

impl App {
    pub fn new(auto_interval: Duration, start_auto: bool) -> Self {
        Self {
            networks: Vec::new(),
            selected_index: 0,
            signal_history: HashMap::new(),
            scan_mode: if start_auto {
                ScanMode::Auto
            } else {
                ScanMode::Manual
            },
            auto_interval,
            last_scan: Instant::now() - auto_interval, // Trigger immediate scan
            is_scanning: false,
            sort_by: SortField::Score,
            should_quit: false,
            show_help: false,
            error_message: None,
        }
    }

    pub fn set_error(&mut self, msg: String) {
        self.error_message = Some(msg);
    }

    pub fn clear_error(&mut self) {
        self.error_message = None;
    }

    pub fn navigate_up(&mut self) {
        if !self.networks.is_empty() && self.selected_index > 0 {
            self.selected_index -= 1;
        }
    }

    pub fn navigate_down(&mut self) {
        if !self.networks.is_empty() && self.selected_index < self.networks.len() - 1 {
            self.selected_index += 1;
        }
    }

    pub fn toggle_scan_mode(&mut self) {
        self.scan_mode = match self.scan_mode {
            ScanMode::Auto => ScanMode::Manual,
            ScanMode::Manual => ScanMode::Auto,
        };
    }

    pub fn cycle_sort(&mut self) {
        self.sort_by = match self.sort_by {
            SortField::Score => SortField::Signal,
            SortField::Signal => SortField::Name,
            SortField::Name => SortField::Score,
        };
        self.sort_networks();
    }

    pub fn toggle_help(&mut self) {
        self.show_help = !self.show_help;
    }

    pub fn quit(&mut self) {
        self.should_quit = true;
    }

    pub fn should_scan(&self) -> bool {
        if self.is_scanning {
            return false;
        }
        match self.scan_mode {
            ScanMode::Auto => self.last_scan.elapsed() >= self.auto_interval,
            ScanMode::Manual => false,
        }
    }

    pub fn trigger_scan(&mut self) {
        if !self.is_scanning {
            self.is_scanning = true;
        }
    }

    pub async fn perform_scan(&mut self) -> Result<()> {
        self.is_scanning = true;
        let mut networks = scan_networks().await?;
        calculate_all_scores(&mut networks);

        // Update signal history
        for network in &networks {
            let history = self
                .signal_history
                .entry(network.ssid.clone())
                .or_default();
            history.push_back(network.signal_dbm);
            while history.len() > SIGNAL_HISTORY_SIZE {
                history.pop_front();
            }
        }

        // Preserve selection if possible
        let selected_ssid = self.networks.get(self.selected_index).map(|n| n.ssid.clone());

        self.networks = networks;
        self.sort_networks();

        // Try to maintain selection
        if let Some(ssid) = selected_ssid
            && let Some(idx) = self.networks.iter().position(|n| n.ssid == ssid)
        {
            self.selected_index = idx;
        }

        // Clamp selection index
        if !self.networks.is_empty() {
            self.selected_index = self.selected_index.min(self.networks.len() - 1);
        } else {
            self.selected_index = 0;
        }

        self.last_scan = Instant::now();
        self.is_scanning = false;

        Ok(())
    }

    fn sort_networks(&mut self) {
        match self.sort_by {
            SortField::Score => self.networks.sort_by(|a, b| b.score.cmp(&a.score)),
            SortField::Signal => self.networks.sort_by(|a, b| b.signal_dbm.cmp(&a.signal_dbm)),
            SortField::Name => self.networks.sort_by(|a, b| a.ssid.cmp(&b.ssid)),
        }
    }

    pub fn render(&self, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),  // Header/title
                Constraint::Min(10),    // Main content
                Constraint::Length(1),  // Status bar
            ])
            .split(frame.area());

        // Header
        self.render_header(frame, chunks[0]);

        // Main content: table (60%) + detail panel (40%)
        let main_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(chunks[1]);

        // Network table
        NetworkTable.render(frame, main_chunks[0], self);

        // Detail panel with signal chart
        let detail_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(10), Constraint::Length(5)])
            .split(main_chunks[1]);

        DetailPanel.render(frame, detail_chunks[0], self);
        SignalChart.render(frame, detail_chunks[1], self);

        // Status bar
        StatusBar.render(frame, chunks[2], self);

        // Help overlay
        if self.show_help {
            self.render_help_overlay(frame);
        }

        // Error overlay
        if let Some(ref error) = self.error_message {
            self.render_error_overlay(frame, error);
        }
    }

    fn render_error_overlay(&self, frame: &mut Frame, error: &str) {
        use ratatui::style::{Color, Style};
        use ratatui::text::{Line, Span};
        use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

        let area = centered_rect(70, 50, frame.area());

        let error_text = vec![
            Line::from(""),
            Line::from(Span::styled(
                "WiFi Scan Failed",
                Style::default().fg(Color::Red),
            )),
            Line::from(""),
            Line::from(error.to_string()),
            Line::from(""),
            Line::from(""),
            Line::from(Span::styled(
                "Tip: Run with --demo flag to see the app with simulated networks:",
                Style::default().fg(Color::Yellow),
            )),
            Line::from(""),
            Line::from("  cargo run -- --demo"),
            Line::from(""),
            Line::from(""),
            Line::from("Press 'd' to switch to demo mode, or 'q' to quit"),
        ];

        let paragraph = Paragraph::new(error_text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Red))
                    .title(Span::styled(
                        " Error ",
                        Style::default().fg(Color::Red),
                    )),
            )
            .wrap(Wrap { trim: true });

        frame.render_widget(Clear, area);
        frame.render_widget(paragraph, area);
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        use ratatui::text::{Line, Span};
        use ratatui::widgets::Paragraph;
        use crate::theme::Theme;

        let title = Span::styled(" WiFi Analyzer ", Theme::title_style());
        let line = Line::from(vec![title]);
        let paragraph = Paragraph::new(line);
        frame.render_widget(paragraph, area);
    }

    fn render_help_overlay(&self, frame: &mut Frame) {
        use ratatui::text::{Line, Span};
        use ratatui::widgets::{Block, Borders, Clear, Paragraph};
        use crate::theme::Theme;

        let area = centered_rect(50, 60, frame.area());

        let help_text = vec![
            Line::from(""),
            Line::from(Span::styled("Keyboard Shortcuts", Theme::title_style())),
            Line::from(""),
            Line::from("\u{2191}/\u{2193} or j/k   Navigate networks"),
            Line::from("r              Refresh scan"),
            Line::from("a              Toggle auto/manual mode"),
            Line::from("s              Cycle sort order"),
            Line::from("?              Toggle this help"),
            Line::from("q / Esc        Quit"),
            Line::from(""),
            Line::from(Span::styled("Score Legend", Theme::title_style())),
            Line::from(""),
            Line::from(vec![
                Span::styled("80-100", Theme::score_style(90)),
                Span::raw("  Excellent"),
            ]),
            Line::from(vec![
                Span::styled("60-79 ", Theme::score_style(70)),
                Span::raw("  Good"),
            ]),
            Line::from(vec![
                Span::styled("40-59 ", Theme::score_style(50)),
                Span::raw("  Fair"),
            ]),
            Line::from(vec![
                Span::styled("0-39  ", Theme::score_style(20)),
                Span::raw("  Poor"),
            ]),
            Line::from(""),
            Line::from("Press ? to close"),
        ];

        let paragraph = Paragraph::new(help_text).block(
            Block::default()
                .borders(Borders::ALL)
                .style(Theme::border_style())
                .title(Span::styled(" Help ", Theme::title_style())),
        );

        frame.render_widget(Clear, area);
        frame.render_widget(paragraph, area);
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
