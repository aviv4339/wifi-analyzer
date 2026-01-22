use ratatui::style::{Color, Modifier, Style};

pub struct Theme;

impl Theme {
    /// Get color for score value
    pub fn score_color(score: u8) -> Color {
        match score {
            80..=100 => Color::Green,
            60..=79 => Color::Yellow,
            40..=59 => Color::Rgb(255, 165, 0), // Orange
            _ => Color::Red,
        }
    }

    /// Style for score display
    pub fn score_style(score: u8) -> Style {
        Style::default()
            .fg(Self::score_color(score))
            .add_modifier(Modifier::BOLD)
    }

    /// Style for selected row
    pub fn selected_style() -> Style {
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD)
    }

    /// Style for header
    pub fn header_style() -> Style {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    }

    /// Style for borders
    pub fn border_style() -> Style {
        Style::default().fg(Color::Gray)
    }

    /// Style for title
    pub fn title_style() -> Style {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    }

    /// Style for help text
    pub fn help_style() -> Style {
        Style::default().fg(Color::DarkGray)
    }

    /// Style for auto mode indicator
    pub fn auto_mode_style() -> Style {
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD)
    }

    /// Style for manual mode indicator
    pub fn manual_mode_style() -> Style {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    }

    /// Style for security type: Open
    pub fn security_open_style() -> Style {
        Style::default().fg(Color::Green)
    }

    /// Style for security type: Secured
    pub fn security_secured_style() -> Style {
        Style::default().fg(Color::Yellow)
    }

    /// Style for signal bars
    pub fn signal_style(dbm: i32) -> Style {
        let color = match dbm {
            s if s >= -50 => Color::Green,
            s if s >= -70 => Color::Yellow,
            _ => Color::Red,
        };
        Style::default().fg(color)
    }
}
