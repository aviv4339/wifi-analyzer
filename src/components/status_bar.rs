use crate::app::{App, ScanMode};
use crate::components::Component;
use crate::theme::Theme;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

pub struct StatusBar;

impl Component for StatusBar {
    fn render(&self, frame: &mut Frame, area: Rect, app: &App) {
        let mode_span = match app.scan_mode {
            ScanMode::Auto => Span::styled(
                format!("[Auto] \u{21bb} {}s", app.auto_interval.as_secs()),
                Theme::auto_mode_style(),
            ),
            ScanMode::Manual => Span::styled("[Manual]", Theme::manual_mode_style()),
        };

        let scanning_indicator = if app.is_scanning {
            Span::raw(" Scanning...")
        } else {
            Span::raw("")
        };

        let help_text = Span::styled(
            " | \u{2191}\u{2193} Navigate | r Refresh | a Auto-toggle | s Sort | ? Help | q Quit",
            Theme::help_style(),
        );

        let line = Line::from(vec![mode_span, scanning_indicator, help_text]);

        let paragraph = Paragraph::new(line);
        frame.render_widget(paragraph, area);
    }
}
