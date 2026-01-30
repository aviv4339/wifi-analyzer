mod detail_panel;
mod device_table;
mod network_table;
mod signal_chart;
mod status_bar;

pub use detail_panel::DetailPanel;
pub use device_table::DeviceTable;
pub use network_table::NetworkTable;
pub use signal_chart::SignalChart;
pub use status_bar::StatusBar;

use crate::app::App;
use ratatui::layout::Rect;
use ratatui::Frame;

pub trait Component {
    fn render(&self, frame: &mut Frame, area: Rect, app: &App);
}
