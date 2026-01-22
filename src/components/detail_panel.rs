use crate::app::App;
use crate::components::Component;
use crate::theme::Theme;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

pub struct DetailPanel;

impl Component for DetailPanel {
    fn render(&self, frame: &mut Frame, area: Rect, app: &App) {
        let content = if let Some(network) = app.networks.get(app.selected_index) {
            let score_style = Theme::score_style(network.score);

            vec![
                Line::from(vec![
                    Span::raw("SSID: "),
                    Span::styled(&network.ssid, Theme::title_style()),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::raw("MAC: "),
                    Span::raw(&network.mac),
                ]),
                Line::from(vec![
                    Span::raw("Channel: "),
                    Span::raw(format!("{} ({})", network.channel, network.frequency_band)),
                ]),
                Line::from(vec![
                    Span::raw("Signal: "),
                    Span::styled(
                        format!("{} dBm", network.signal_dbm),
                        Theme::signal_style(network.signal_dbm),
                    ),
                ]),
                Line::from(vec![
                    Span::raw("Security: "),
                    Span::raw(network.security.to_string()),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::raw("Score: "),
                    Span::styled(format!("{}/100", network.score), score_style),
                ]),
                Line::from(""),
                Line::from("Score Breakdown:"),
                Line::from(format!(
                    "  Signal (40%): {} dBm",
                    network.signal_dbm
                )),
                Line::from(format!(
                    "  Congestion (25%): Ch {}",
                    network.channel
                )),
                Line::from(format!(
                    "  Security (20%): {}",
                    network.security
                )),
                Line::from(format!(
                    "  Band (15%): {}",
                    network.frequency_band
                )),
            ]
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
