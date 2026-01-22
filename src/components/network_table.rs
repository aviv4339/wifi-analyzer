use crate::app::{App, SortField};
use crate::components::Component;
use crate::scanner::SecurityType;
use crate::theme::Theme;
use chrono::Utc;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Row, Table, TableState};
use ratatui::Frame;

pub struct NetworkTable;

impl Component for NetworkTable {
    fn render(&self, frame: &mut Frame, area: Rect, app: &App) {
        let header_cells = [
            header_cell("SSID", app.sort_by == SortField::Name),
            header_cell("Signal", app.sort_by == SortField::Signal),
            header_cell("Score", app.sort_by == SortField::Score),
            header_cell("Security", false),
            header_cell("Channel", false),
            header_cell("Last Seen", false),
        ];

        let header = Row::new(header_cells).style(Theme::header_style()).height(1);

        let rows = app.networks.iter().enumerate().map(|(idx, network)| {
            let is_selected = idx == app.selected_index;
            let is_connected = app.is_connected(network);

            // Selection indicator
            let select_indicator = if is_selected { "\u{25b6}" } else { " " };

            // Connection indicator: green dot for connected
            let (connect_indicator, connect_style) = if is_connected {
                ("\u{25cf}", Theme::connected_style())
            } else {
                (" ", Style::default())
            };

            // Build SSID cell with both indicators
            let ssid_text = truncate(&network.ssid, 16);
            let ssid_cell = Cell::from(Line::from(vec![
                Span::raw(format!("{} ", select_indicator)),
                Span::styled(connect_indicator, connect_style),
                Span::raw(format!(" {}", ssid_text)),
            ]));

            let signal_cell = Cell::from(Span::styled(
                network.signal_bars(),
                Theme::signal_style(network.signal_dbm),
            ));

            let score_cell =
                Cell::from(Span::styled(format!("{:3}", network.score), Theme::score_style(network.score)));

            let security_style = match network.security {
                SecurityType::Open => Theme::security_open_style(),
                _ => Theme::security_secured_style(),
            };
            let security_cell = Cell::from(Span::styled(network.security.to_string(), security_style));

            let channel_cell = Cell::from(format!(
                "{} ({})",
                network.channel, network.frequency_band
            ));

            let last_seen_cell = Cell::from(format_relative_time(network.last_seen));

            let row = Row::new([ssid_cell, signal_cell, score_cell, security_cell, channel_cell, last_seen_cell]);

            if is_selected {
                row.style(Theme::selected_style())
            } else {
                row
            }
        });

        let network_count = app.networks.len();
        let title = format!(" Networks ({} found) ", network_count);

        let table = Table::new(
            rows,
            [
                Constraint::Min(22),       // SSID
                Constraint::Length(7),     // Signal bars
                Constraint::Length(5),     // Score
                Constraint::Length(8),     // Security
                Constraint::Length(14),    // Channel
                Constraint::Length(10),    // Last Seen
            ],
        )
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .style(Theme::border_style())
                .title(Span::styled(title, Theme::title_style())),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

        let mut table_state = TableState::default();
        table_state.select(Some(app.selected_index));

        frame.render_stateful_widget(table, area, &mut table_state);
    }
}

fn header_cell(name: &str, is_sorted: bool) -> Cell<'static> {
    let indicator = if is_sorted { " \u{25bc}" } else { "" };
    Cell::from(Line::from(vec![
        Span::styled(name.to_string(), Theme::header_style()),
        Span::raw(indicator.to_string()),
    ]))
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len - 3])
    } else {
        s.to_string()
    }
}

/// Format a timestamp as relative time (e.g., "2m ago", "1h ago")
fn format_relative_time(time: chrono::DateTime<Utc>) -> String {
    let now = Utc::now();
    let duration = now.signed_duration_since(time);

    if duration.num_seconds() < 0 {
        return "now".to_string();
    }

    let secs = duration.num_seconds();
    if secs < 60 {
        format!("{}s ago", secs)
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}
