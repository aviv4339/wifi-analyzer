use crate::app::App;
use crate::components::Component;
use crate::network_map::PortState;
use crate::theme::Theme;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

pub struct DeviceDetail;

impl Component for DeviceDetail {
    fn render(&self, frame: &mut Frame, area: Rect, app: &App) {
        if app.devices.is_empty() {
            let empty = Paragraph::new("No device selected")
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .style(Theme::border_style())
                        .title(Span::styled(" Device Details ", Theme::title_style())),
                );
            frame.render_widget(empty, area);
            return;
        }

        let device = &app.devices[app.selected_device_index];

        // Build info lines
        let mut lines = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("Name: ", Style::default().fg(Color::Gray)),
                Span::raw(device.display_name()),
            ]),
            Line::from(vec![
                Span::styled("MAC:  ", Style::default().fg(Color::Gray)),
                Span::raw(&device.mac_address),
            ]),
            Line::from(vec![
                Span::styled("IP:   ", Style::default().fg(Color::Gray)),
                Span::raw(&device.ip_address),
            ]),
            Line::from(vec![
                Span::styled("Type: ", Style::default().fg(Color::Gray)),
                Span::raw(format!("{}", device.device_type)),
            ]),
        ];

        if let Some(ref vendor) = device.vendor {
            lines.push(Line::from(vec![
                Span::styled("Vendor: ", Style::default().fg(Color::Gray)),
                Span::raw(vendor),
            ]));
        }

        if let Some(ref hostname) = device.hostname {
            lines.push(Line::from(vec![
                Span::styled("Hostname: ", Style::default().fg(Color::Gray)),
                Span::raw(hostname),
            ]));
        }

        // AI Agents
        if !device.detected_agents.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Detected AI Agents:",
                Style::default().fg(Color::Magenta),
            )));
            for agent in &device.detected_agents {
                lines.push(Line::from(format!("  \u{2022} {}", agent)));
            }
        }

        // Open services
        let open_services: Vec<_> = device.services
            .iter()
            .filter(|s| s.state == PortState::Open)
            .collect();

        if !open_services.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Open Services:",
                Style::default().fg(Color::Cyan),
            )));

            for service in open_services.iter().take(10) {
                let service_name = service.service_name.as_deref().unwrap_or("Unknown");
                let agent_info = service.detected_agent
                    .as_ref()
                    .map(|a| format!(" [{}]", a))
                    .unwrap_or_default();

                lines.push(Line::from(format!(
                    "  {:5} {} {}{}",
                    service.port,
                    service.protocol,
                    service_name,
                    agent_info
                )));
            }

            if open_services.len() > 10 {
                lines.push(Line::from(format!(
                    "  ... and {} more",
                    open_services.len() - 10
                )));
            }
        }

        // Timestamps
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("First seen: ", Style::default().fg(Color::Gray)),
            Span::raw(device.first_seen.format("%Y-%m-%d %H:%M").to_string()),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Last seen:  ", Style::default().fg(Color::Gray)),
            Span::raw(device.last_seen.format("%Y-%m-%d %H:%M").to_string()),
        ]));

        let paragraph = Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .style(Theme::border_style())
                .title(Span::styled(" Device Details ", Theme::title_style())),
        );

        frame.render_widget(paragraph, area);
    }
}
