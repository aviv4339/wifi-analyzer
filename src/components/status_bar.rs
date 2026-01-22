use crate::app::{App, ScanMode};
use crate::components::Component;
use crate::theme::Theme;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

pub struct StatusBar;

impl Component for StatusBar {
    fn render(&self, frame: &mut Frame, area: Rect, app: &App) {
        // Mode indicator with countdown for auto mode
        let mode_span = match app.scan_mode {
            ScanMode::Auto => {
                if let Some(secs) = app.get_next_refresh_secs() {
                    Span::styled(
                        format!("[Auto] next scan in {}s", secs),
                        Theme::auto_mode_style(),
                    )
                } else {
                    Span::styled("[Auto]", Theme::auto_mode_style())
                }
            }
            ScanMode::Manual => Span::styled("[Manual]", Theme::manual_mode_style()),
        };

        // Status message - prioritize speed test progress
        let status_span = if let Some(speedtest_status) = app.get_speedtest_status() {
            Span::styled(format!(" {}", speedtest_status), Style::default().fg(Color::Yellow))
        } else if app.is_scanning {
            Span::raw(" Scanning...")
        } else if let Some(ref msg) = app.status_message {
            Span::styled(format!(" {}", msg), Theme::status_style())
        } else {
            Span::raw("")
        };

        let help_text = Span::styled(
            " | ↑↓ Nav | Enter Connect | r Scan | s Sort | ? Help | q Quit",
            Theme::help_style(),
        );

        let line = Line::from(vec![mode_span, status_span, help_text]);

        let paragraph = Paragraph::new(line);
        frame.render_widget(paragraph, area);
    }
}
