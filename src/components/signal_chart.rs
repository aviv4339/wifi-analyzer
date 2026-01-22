use crate::app::App;
use crate::components::Component;
use crate::theme::Theme;
use ratatui::layout::Rect;
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Sparkline};
use ratatui::Frame;

pub struct SignalChart;

impl Component for SignalChart {
    fn render(&self, frame: &mut Frame, area: Rect, app: &App) {
        let data: Vec<u64> = if let Some(network) = app.networks.get(app.selected_index) {
            if let Some(history) = app.signal_history.get(&network.ssid) {
                // Convert dBm to positive values for sparkline (0-100 scale)
                // -30 dBm = 100, -90 dBm = 0
                history
                    .iter()
                    .map(|&dbm| {
                        let clamped = dbm.clamp(-90, -30);
                        ((clamped + 90) as f32 / 60.0 * 100.0) as u64
                    })
                    .collect()
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        let current_dbm = app
            .networks
            .get(app.selected_index)
            .map(|n| n.signal_dbm)
            .unwrap_or(-100);

        let title = format!(" Signal History ({} dBm) ", current_dbm);

        let sparkline = Sparkline::default()
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .style(Theme::border_style())
                    .title(Span::styled(title, Theme::title_style())),
            )
            .data(&data)
            .style(Theme::signal_style(current_dbm));

        frame.render_widget(sparkline, area);
    }
}
