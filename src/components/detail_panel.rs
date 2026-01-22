use crate::app::App;
use crate::components::Component;
use crate::theme::Theme;
use chrono::Utc;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

pub struct DetailPanel;

impl Component for DetailPanel {
    fn render(&self, frame: &mut Frame, area: Rect, app: &App) {
        let content = if let Some(network) = app.networks.get(app.selected_index) {
            let score_style = Theme::score_style(network.score);
            let is_connected = app.is_connected(network);
            let is_known = app.is_known_network(&network.ssid);

            let mut lines = vec![
                Line::from(vec![
                    Span::raw("SSID: "),
                    Span::styled(&network.ssid, Theme::title_style()),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::raw("MAC: "),
                    Span::raw(&network.mac),
                ]),
            ];

            // Connection status
            let status_line = if is_connected {
                Line::from(vec![
                    Span::raw("Status: "),
                    Span::styled("● Connected", Style::default().fg(Color::Green)),
                ])
            } else if is_known {
                Line::from(vec![
                    Span::raw("Status: "),
                    Span::styled("Known Network", Style::default().fg(Color::Yellow)),
                ])
            } else {
                Line::from(vec![
                    Span::raw("Status: "),
                    Span::raw("New Network"),
                ])
            };
            lines.push(status_line);
            lines.push(Line::from(""));

            // Basic network info
            lines.push(Line::from(vec![
                Span::raw("Channel: "),
                Span::raw(format!("{} ({})", network.channel, network.frequency_band)),
            ]));
            lines.push(Line::from(vec![
                Span::raw("Signal: "),
                Span::styled(
                    format!("{} dBm", network.signal_dbm),
                    Theme::signal_style(network.signal_dbm),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::raw("Security: "),
                Span::raw(network.security.to_string()),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::raw("Score: "),
                Span::styled(format!("{}/100", network.score), score_style),
            ]));

            // Connection History section (if we have cached data)
            if let Some((cached_bssid, history)) = &app.cached_connection_history {
                if cached_bssid == &network.mac && !history.is_empty() {
                    lines.push(Line::from(""));
                    lines.push(Line::from(Span::styled(
                        "─── Connection History ───",
                        Style::default().fg(Color::Cyan),
                    )));

                    // Last connected
                    if let Some(last) = history.first() {
                        let relative = format_relative_time(last.connected_at);
                        lines.push(Line::from(format!("Last connected: {}", relative)));
                    }

                    // Connection count
                    if let Some(count) = app.get_connection_count(&network.mac) {
                        lines.push(Line::from(format!("Times connected: {}", count)));
                    }
                }
            }

            // Speed Test section (if we have cached data)
            if let Some((cached_bssid, speed)) = &app.cached_speed_test {
                if cached_bssid == &network.mac {
                    lines.push(Line::from(""));
                    lines.push(Line::from(Span::styled(
                        "─── Speed Test ───",
                        Style::default().fg(Color::Cyan),
                    )));
                    lines.push(Line::from(format!(
                        "↓ {:.1} Mbps  ↑ {:.1} Mbps",
                        speed.download_mbps, speed.upload_mbps
                    )));
                }
            } else if is_connected || is_known {
                // Show last speed test from connection history if available
                if let Some((cached_bssid, history)) = &app.cached_connection_history {
                    if cached_bssid == &network.mac {
                        // Find a connection with speed data
                        if let Some(conn) = history.iter().find(|c| c.download_mbps.is_some()) {
                            lines.push(Line::from(""));
                            lines.push(Line::from(Span::styled(
                                "─── Last Speed Test ───",
                                Style::default().fg(Color::Cyan),
                            )));
                            lines.push(Line::from(format!(
                                "↓ {:.1} Mbps  ↑ {:.1} Mbps",
                                conn.download_mbps.unwrap_or(0.0),
                                conn.upload_mbps.unwrap_or(0.0)
                            )));
                        }
                    }
                }
            }

            // IP Addresses section
            let mut show_ip_section = false;
            let mut ip_lines: Vec<Line> = Vec::new();

            // If this is the connected network, show current IPs
            if is_connected {
                if app.current_local_ip.is_some() || app.current_public_ip.is_some() {
                    show_ip_section = true;
                    if let Some(ref local) = app.current_local_ip {
                        ip_lines.push(Line::from(format!("Local:  {}", local)));
                    }
                    if let Some(ref public) = app.current_public_ip {
                        ip_lines.push(Line::from(format!("Public: {}", public)));
                    }
                }
            }

            // Also show historical IPs if available
            if let Some((cached_bssid, ips)) = &app.cached_recent_ips {
                if cached_bssid == &network.mac && !ips.is_empty() {
                    show_ip_section = true;

                    // If not connected (showing history only)
                    if !is_connected {
                        if let Some(current) = ips.first() {
                            ip_lines.push(Line::from(format!("Last Local: {}", current)));
                        }
                    }

                    // Previous IPs (if more than one)
                    if ips.len() > 1 {
                        let previous: Vec<&str> = ips.iter().skip(1).take(4).map(|s| s.as_str()).collect();
                        ip_lines.push(Line::from(format!("Previous: {}", previous.join(", "))));
                    }
                }
            }

            if show_ip_section {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "─── IP Addresses ───",
                    Style::default().fg(Color::Cyan),
                )));
                lines.extend(ip_lines);
            }

            lines
        } else {
            vec![Line::from("No network selected")]
        };

        let title = if let Some(network) = app.networks.get(app.selected_index) {
            format!(" {} ", network.ssid)
        } else {
            " Details ".to_string()
        };

        let paragraph = Paragraph::new(content).block(
            Block::default()
                .borders(Borders::ALL)
                .style(Theme::border_style())
                .title(Span::styled(title, Theme::title_style())),
        );

        frame.render_widget(paragraph, area);
    }
}

/// Format a timestamp as relative time (e.g., "2m ago", "1h ago")
fn format_relative_time(time: chrono::DateTime<Utc>) -> String {
    let now = Utc::now();
    let duration = now.signed_duration_since(time);

    if duration.num_seconds() < 0 {
        return "just now".to_string();
    }

    let secs = duration.num_seconds();
    if secs < 60 {
        "just now".to_string()
    } else if secs < 3600 {
        format!("{} min ago", secs / 60)
    } else if secs < 86400 {
        format!("{} hours ago", secs / 3600)
    } else if secs < 604800 {
        format!("{} days ago", secs / 86400)
    } else {
        format!("{} weeks ago", secs / 604800)
    }
}
