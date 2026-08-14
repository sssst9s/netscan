use std::io::{IsTerminal, Write};
use std::time::{Duration, Instant};

use netscan_core::Progress;

const REDRAW_INTERVAL: Duration = Duration::from_millis(120);

pub struct ProgressLine {
    enabled: bool,
    last_draw: Option<Instant>,
    last_width: usize,
}

impl ProgressLine {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled: enabled && std::io::stderr().is_terminal(),
            last_draw: None,
            last_width: 0,
        }
    }

    pub fn disabled() -> Self {
        Self {
            enabled: false,
            last_draw: None,
            last_width: 0,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn update(&mut self, progress: &Progress) {
        if !self.enabled {
            return;
        }
        let now = Instant::now();
        if let Some(last) = self.last_draw {
            if now.duration_since(last) < REDRAW_INTERVAL {
                return;
            }
        }
        self.last_draw = Some(now);
        self.draw(&format(progress, terminal_width()));
    }

    pub fn force_update(&mut self, progress: &Progress) {
        if !self.enabled {
            return;
        }
        self.last_draw = Some(Instant::now());
        self.draw(&format(progress, terminal_width()));
    }

    pub fn note(&mut self, message: &str) {
        if !self.enabled {
            return;
        }
        self.clear();
        let mut stderr = std::io::stderr();
        let _ = writeln!(stderr, "{message}");
        let _ = stderr.flush();
    }

    pub fn clear(&mut self) {
        if !self.enabled || self.last_width == 0 {
            return;
        }
        let mut stderr = std::io::stderr();
        let _ = write!(stderr, "\r{}\r", " ".repeat(self.last_width));
        let _ = stderr.flush();
        self.last_width = 0;
    }

    pub fn finish(&mut self) {
        self.clear();
        self.enabled = false;
    }

    fn draw(&mut self, text: &str) {
        let mut stderr = std::io::stderr();

        let padding = self.last_width.saturating_sub(text.chars().count());
        let _ = write!(stderr, "\r{text}{}", " ".repeat(padding));
        let _ = stderr.flush();
        self.last_width = text.chars().count();
    }
}

impl Drop for ProgressLine {
    fn drop(&mut self) {
        self.clear();
    }
}

pub fn format(progress: &Progress, width: usize) -> String {
    let mut fields: Vec<String> = Vec::with_capacity(8);

    fields.push(format!("{:>3}%", progress.percent()));

    if progress.hosts_total > 0 {
        fields.push(format!(
            "hosts {}/{}",
            progress.hosts_completed.min(progress.hosts_total),
            progress.hosts_total
        ));
    }
    if progress.hosts_up > 0 {
        fields.push(format!("up {}", progress.hosts_up));
    }
    if progress.probes_total > 0 {
        fields.push(format!(
            "ports {}/{}",
            thousands(progress.probes_completed),
            thousands(progress.probes_total)
        ));
    } else if progress.probes_completed > 0 {
        fields.push(format!("ports {}", thousands(progress.probes_completed)));
    }
    if progress.open_ports > 0 {
        fields.push(format!("open {}", progress.open_ports));
    }
    if progress.rate > 0.0 {
        fields.push(format!("{}/s", thousands(progress.rate as u64)));
    }
    fields.push(format!("{}", HumanDuration(progress.elapsed)));
    if let Some(eta) = progress.eta() {
        fields.push(format!("eta {}", HumanDuration(eta)));
    }

    let mut line = fields.join("  ");
    while line.chars().count() > width && fields.len() > 1 {
        fields.pop();
        line = fields.join("  ");
    }
    line
}

fn thousands(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

pub struct HumanDuration(pub Duration);

impl std::fmt::Display for HumanDuration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let seconds = self.0.as_secs();
        match seconds {
            0..=9 => write!(f, "{:.1}s", self.0.as_secs_f64()),
            10..=59 => write!(f, "{seconds}s"),
            60..=3599 => write!(f, "{}m{:02}s", seconds / 60, seconds % 60),
            _ => write!(f, "{}h{:02}m", seconds / 3600, (seconds % 3600) / 60),
        }
    }
}

fn terminal_width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|w| *w >= 20)
        .unwrap_or(80)
        .saturating_sub(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn progress() -> Progress {
        Progress {
            hosts_total: 254,
            hosts_completed: 100,
            hosts_up: 42,
            probes_total: 25_400,
            probes_completed: 12_700,
            open_ports: 73,
            elapsed: Duration::from_secs(8),
            rate: 1500.0,
            concurrency: 512,
            timeout: Duration::from_millis(800),
        }
    }

    #[test]
    fn the_line_reports_what_is_known() {
        let line = format(&progress(), 200);
        assert!(line.contains("50%"), "line was: {line}");
        assert!(line.contains("hosts 100/254"), "line was: {line}");
        assert!(line.contains("up 42"), "line was: {line}");
        assert!(line.contains("ports 12,700/25,400"), "line was: {line}");
        assert!(line.contains("open 73"), "line was: {line}");
        assert!(line.contains("eta"), "line was: {line}");
    }

    #[test]
    fn the_line_never_exceeds_the_terminal_width() {
        for width in [20, 40, 60, 80, 120, 200] {
            let line = format(&progress(), width);
            assert!(
                line.chars().count() <= width,
                "width {width} produced {} chars: {line}",
                line.chars().count()
            );
        }
    }

    #[test]
    fn the_percentage_always_survives_truncation() {
        let line = format(&progress(), 4);
        assert!(line.contains('%'), "line was: {line}");
    }

    #[test]
    fn unknown_values_are_omitted_rather_than_shown_as_zero() {
        let early = Progress {
            hosts_total: 10,
            ..Default::default()
        };
        let line = format(&early, 200);
        assert!(!line.contains("open"), "line was: {line}");
        assert!(!line.contains("eta"), "an ETA needs data first: {line}");
        assert!(!line.contains("ports"), "line was: {line}");
    }

    #[test]
    fn thousands_separators_are_inserted() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000), "1,000");
        assert_eq!(thousands(12_700), "12,700");
        assert_eq!(thousands(1_234_567), "1,234,567");
    }

    #[test]
    fn durations_are_readable_at_every_scale() {
        assert_eq!(
            HumanDuration(Duration::from_millis(1200)).to_string(),
            "1.2s"
        );
        assert_eq!(HumanDuration(Duration::from_secs(45)).to_string(), "45s");
        assert_eq!(HumanDuration(Duration::from_secs(200)).to_string(), "3m20s");
        assert_eq!(
            HumanDuration(Duration::from_secs(3900)).to_string(),
            "1h05m"
        );
    }

    #[test]
    fn a_disabled_line_draws_nothing() {
        let mut line = ProgressLine::disabled();
        assert!(!line.is_enabled());

        line.update(&progress());
        line.force_update(&progress());
        line.note("hello");
        line.clear();
        line.finish();
    }

    #[test]
    fn progress_is_disabled_when_stderr_is_not_a_terminal() {
        let line = ProgressLine::new(true);
        if !std::io::stderr().is_terminal() {
            assert!(!line.is_enabled());
        }
    }
}
