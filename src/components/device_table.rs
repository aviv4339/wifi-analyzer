use crate::app::App;
use crate::components::Component;
use crate::theme::Theme;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Row, Table, TableState};
use ratatui::Frame;

pub struct DeviceTable;

impl Component for DeviceTable {
    fn render(&self, frame: &mut Frame, area: Rect, app: &App) {
        let header_cells = [
            Cell::from(Span::styled("Status", Theme::header_style())),
            Cell::from(Span::styled("Device", Theme::header_style())),
            Cell::from(Span::styled("IP Address", Theme::header_style())),
            Cell::from(Span::styled("Vendor", Theme::header_style())),
            Cell::from(Span::styled("AI", Theme::header_style())),
        ];

        let header = Row::new(header_cells).style(Theme::header_style()).height(1);

        let rows = app.devices.iter().enumerate().map(|(idx, device)| {
            let is_selected = idx == app.selected_device_index;

            // Selection indicator
            let select_indicator = if is_selected { "\u{25b6}" } else { " " };

            // Online status indicator
            let (status_icon, status_style) = if device.is_online {
                ("\u{25cf}", Theme::connected_style()) // Green dot
            } else {
                ("\u{25cb}", Style::default()) // Empty circle
            };

            // Status cell with selection and online indicator
            let status_cell = Cell::from(Line::from(vec![
                Span::raw(format!("{} ", select_indicator)),
                Span::styled(status_icon, status_style),
            ]));

            // Device name
            let name = device.display_name();
            let name_with_type = if device.custom_name.is_some() {
                name
            } else {
                format!("{} ({})", truncate(&name, 16), device.device_type)
            };
            let device_cell = Cell::from(truncate(&name_with_type, 24));

            // IP address
            let ip_cell = Cell::from(device.ip_address.clone());

            // Vendor
            let vendor = device.vendor.as_deref().unwrap_or("Unknown");
            let vendor_cell = Cell::from(truncate(vendor, 12));

            // AI agent indicator
            let ai_cell = if !device.detected_agents.is_empty() {
                Cell::from(Span::styled(
                    "[AI]",
                    Style::default().fg(ratatui::style::Color::Magenta),
                ))
            } else {
                Cell::from("")
            };

            let row = Row::new([status_cell, device_cell, ip_cell, vendor_cell, ai_cell]);

            if is_selected {
                row.style(Theme::selected_style())
            } else {
                row
            }
        });

        let device_count = app.devices.len();
        let scan_status = if app.device_scan_progress.is_some() {
            " - Scanning..."
        } else {
            ""
        };
        let title = format!(" Network Devices ({} found){} ", device_count, scan_status);

        let table = Table::new(
            rows,
            [
                Constraint::Length(4),   // Status
                Constraint::Min(20),     // Device name
                Constraint::Length(15),  // IP
                Constraint::Length(12),  // Vendor
                Constraint::Length(5),   // AI
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
        table_state.select(Some(app.selected_device_index));

        frame.render_stateful_widget(table, area, &mut table_state);
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    } else {
        s.to_string()
    }
}
