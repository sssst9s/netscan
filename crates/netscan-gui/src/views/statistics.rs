use egui::{Align2, Color32, FontId, Rect, RichText, Rounding, Sense, Ui, Vec2};
use netscan_core::HostReport;

use crate::session::LiveResults;
use crate::theme;
use crate::widgets::{self, muted, palette};

#[derive(Debug, Clone, PartialEq)]
pub struct Ranked {
    pub label: String,
    pub count: u64,
    pub action: Option<StatAction>,
}

impl Ranked {
    fn plain(label: impl Into<String>, count: u64) -> Ranked {
        Ranked {
            label: label.into(),
            count,
            action: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatAction {
    Filter(String),
    Show(std::net::IpAddr),
}

#[derive(Debug, Default, PartialEq)]
pub struct Aggregates {
    pub services: Vec<(String, u64)>,
    pub busiest_hosts: Vec<(String, u64, std::net::IpAddr)>,
    pub port_states: Vec<(String, u64)>,
    pub latencies: Vec<f64>,
    pub hosts_up: u64,
    pub hosts_total: u64,
    pub open_ports: u64,
}

impl Aggregates {
    pub fn compute(results: &LiveResults) -> Self {
        let mut services: std::collections::BTreeMap<String, u64> = Default::default();
        let mut port_states: std::collections::BTreeMap<String, u64> = Default::default();
        let mut busiest: Vec<(String, u64, std::net::IpAddr)> = Vec::new();
        let mut latencies: Vec<f64> = Vec::new();
        let mut hosts_up = 0u64;
        let mut open_ports = 0u64;

        for host in results.hosts.values() {
            if host.status == netscan_core::HostStatus::Up {
                hosts_up += 1;
            }
            if let Some(rtt) = host.rtt_ms {
                latencies.push(rtt);
            }

            let open = host.open_port_count() as u64;
            open_ports += open;
            if open > 0 {
                busiest.push((display_name(host), open, host.address));
            }

            for port in &host.ports {
                *port_states
                    .entry(port.state.as_str().to_string())
                    .or_default() += 1;
                if port.state.is_open_ish() {
                    *services.entry(port.service_name().to_string()).or_default() += 1;
                }
            }
            for (state, count) in &host.other_ports.counts {
                *port_states.entry(state.clone()).or_default() += count;
            }
        }

        let mut services: Vec<(String, u64)> = services.into_iter().collect();
        services.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        busiest.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        let mut port_states: Vec<(String, u64)> = port_states.into_iter().collect();
        port_states.sort_by_key(|(_, count)| std::cmp::Reverse(*count));

        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        Self {
            services,
            busiest_hosts: busiest,
            port_states,
            latencies,
            hosts_up,
            hosts_total: results.hosts.len() as u64,
            open_ports,
        }
    }

    pub fn median_latency(&self) -> Option<f64> {
        if self.latencies.is_empty() {
            return None;
        }
        let middle = self.latencies.len() / 2;
        Some(if self.latencies.len() % 2 == 0 {
            (self.latencies[middle - 1] + self.latencies[middle]) / 2.0
        } else {
            self.latencies[middle]
        })
    }

    pub fn p95_latency(&self) -> Option<f64> {
        if self.latencies.is_empty() {
            return None;
        }
        let index = ((self.latencies.len() as f64 * 0.95).ceil() as usize)
            .saturating_sub(1)
            .min(self.latencies.len() - 1);
        Some(self.latencies[index])
    }

    pub fn is_empty(&self) -> bool {
        self.hosts_total == 0
    }
}

fn display_name(host: &HostReport) -> String {
    match host.primary_hostname() {
        Some(name) => format!("{} ({})", host.address, widgets::ellipsise(name, 24)),
        None => host.address.to_string(),
    }
}

const SHORT_LIST: usize = 10;

pub fn show(ui: &mut Ui, results: &LiveResults) -> Option<StatAction> {
    let aggregates = Aggregates::compute(results);

    if aggregates.is_empty() {
        super::results::empty(
            ui,
            "Nothing to summarise yet.",
            "Run a scan and its statistics appear here as results arrive.",
        );
        return None;
    }

    let mut chosen = None;
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            headline_numbers(ui, results, &aggregates);

            panel(ui, "Services by frequency", |ui| {
                if aggregates.services.is_empty() {
                    ui.label(muted("No open ports yet."));
                } else {
                    let rows: Vec<Ranked> = aggregates
                        .services
                        .iter()
                        .map(|(name, count)| Ranked {
                            label: name.clone(),
                            count: *count,
                            action: Some(StatAction::Filter(format!("service:{name}"))),
                        })
                        .collect();
                    chosen = ranked_bars(ui, "services", &rows, None).or(chosen.take());
                }
            });

            panel(ui, "Hosts with the most open ports", |ui| {
                if aggregates.busiest_hosts.is_empty() {
                    ui.label(muted("No open ports yet."));
                } else {
                    let rows: Vec<Ranked> = aggregates
                        .busiest_hosts
                        .iter()
                        .map(|(label, count, address)| Ranked {
                            label: label.clone(),
                            count: *count,
                            action: Some(StatAction::Show(*address)),
                        })
                        .collect();
                    chosen = ranked_bars(ui, "hosts", &rows, Some(theme::current().accent))
                        .or(chosen.take());
                }
            });

            panel(ui, "Port states", |ui| {
                if aggregates.port_states.is_empty() {
                    ui.label(muted("No ports tested yet."));
                } else {
                    let segments: Vec<(String, u64, Color32)> = aggregates
                        .port_states
                        .iter()
                        .map(|(state, count)| (state.clone(), *count, state_colour_by_name(state)))
                        .collect();
                    chosen = stacked_bar(ui, &segments).or(chosen.take());
                }
            });

            panel(ui, "Host latency", |ui| {
                match (aggregates.median_latency(), aggregates.p95_latency()) {
                    (Some(median), Some(p95)) => {
                        readouts(
                            ui,
                            &[
                                ("Median", format!("{median:.2} ms"), None),
                                ("95th percentile", format!("{p95:.2} ms"), None),
                                ("Samples", aggregates.latencies.len().to_string(), None),
                            ],
                        );
                        ui.add_space(crate::theme::UNIT);
                        let rows: Vec<Ranked> = latency_buckets(&aggregates.latencies)
                            .into_iter()
                            .map(|(label, count)| Ranked::plain(label, count))
                            .collect();
                        chosen = ranked_bars(ui, "latency", &rows, Some(theme::current().info))
                            .or(chosen.take());
                    }
                    _ => {
                        ui.label(muted("No latency measurements yet."));
                    }
                }
            });
        });
    chosen
}

fn panel(ui: &mut Ui, title: &str, contents: impl FnOnce(&mut Ui)) {
    ui.add_space(crate::theme::UNIT * 3.0);
    ui.label(widgets::micro_label(title));
    ui.add_space(crate::theme::UNIT);
    let line = ui.available_rect_before_wrap();
    ui.painter().hline(
        line.x_range(),
        line.top(),
        egui::Stroke::new(1.0_f32, theme::current().line),
    );
    ui.add_space(crate::theme::UNIT * 1.5);
    contents(ui);
}

fn readouts(ui: &mut Ui, values: &[(&str, String, Option<Color32>)]) {
    let palette = theme::current();
    ui.horizontal_wrapped(|ui| {
        for (index, (label, value, colour)) in values.iter().enumerate() {
            if index > 0 {
                ui.add_space(crate::theme::UNIT * 2.0);
                let (rect, _) = ui.allocate_exact_size(Vec2::new(1.0, 30.0), Sense::hover());
                ui.painter().rect_filled(rect, 0.0, palette.line);
                ui.add_space(crate::theme::UNIT * 2.0);
            }
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 1.0;
                ui.label(
                    RichText::new(value)
                        .font(FontId::new(
                            19.0,
                            crate::fonts::family(crate::fonts::MEDIUM),
                        ))
                        .color(colour.unwrap_or(palette.text)),
                );
                ui.label(widgets::micro_label(label));
            });
        }
    });
}

fn headline_numbers(ui: &mut Ui, results: &LiveResults, aggregates: &Aggregates) {
    let progress = &results.progress;
    let palette = theme::current();
    readouts(
        ui,
        &[
            (
                "Hosts up",
                format!(
                    "{} / {}",
                    aggregates.hosts_up,
                    progress.hosts_total.max(aggregates.hosts_total)
                ),
                Some(palette.success),
            ),
            (
                "Open ports",
                widgets::count(aggregates.open_ports),
                Some(palette.success),
            ),
            (
                "Ports tested",
                widgets::count(progress.probes_completed),
                None,
            ),
            ("Elapsed", widgets::duration(progress.elapsed), None),
            (
                "Rate",
                format!("{}/s", widgets::count(progress.rate as u64)),
                None,
            ),
        ],
    );

    if let Some(report) = &results.report {
        ui.add_space(crate::theme::UNIT * 2.0);
        let mut values = vec![
            (
                "Probes sent",
                widgets::count(report.stats.probes_sent),
                None,
            ),
            ("Retries", widgets::count(report.stats.retries), None),
            (
                "Retry rate",
                format!("{:.1}%", report.stats.retry_rate() * 100.0),
                (report.stats.retry_rate() > 0.25).then_some(palette.warning),
            ),
        ];
        if report.stats.errors > 0 {
            values.push((
                "Errors",
                widgets::count(report.stats.errors),
                Some(palette.danger),
            ));
        }
        readouts(ui, &values);
    }
}

fn state_colour_by_name(name: &str) -> egui::Color32 {
    match name {
        "open" => palette::open(),
        "closed" => palette::closed(),
        "filtered" | "open|filtered" => palette::filtered(),
        _ => palette::unknown(),
    }
}

const LABEL_WIDTH: f32 = 150.0;

const BAR_ROW: f32 = 18.0;

fn ranked_bars(
    ui: &mut Ui,
    id: &str,
    data: &[Ranked],
    colour: Option<Color32>,
) -> Option<StatAction> {
    let palette = theme::current();
    let dark = ui.visuals().dark_mode;

    let expanded_id = egui::Id::new(("statistics-expanded", id));
    let mut expanded: bool = ui.data(|data| data.get_temp(expanded_id)).unwrap_or(false);
    let limit = if expanded { data.len() } else { SHORT_LIST };
    let shown: Vec<&Ranked> = data.iter().take(limit).collect();
    let largest = shown.iter().map(|row| row.count).max().unwrap_or(1).max(1);

    let mut chosen = None;
    for (index, row) in shown.iter().enumerate() {
        let clickable = row.action.is_some();
        let sense = if clickable {
            Sense::click()
        } else {
            Sense::hover()
        };
        let (rect, response) =
            ui.allocate_exact_size(Vec2::new(ui.available_width(), BAR_ROW), sense);
        if !ui.is_rect_visible(rect) {
            continue;
        }
        let hovered = response.hovered();
        let painter = ui.painter();

        if hovered && clickable {
            painter.rect_filled(
                rect.expand2(Vec2::new(2.0, 0.0)),
                Rounding::same(2.0),
                palette.hover,
            );
        }

        painter.text(
            egui::pos2(rect.left() + LABEL_WIDTH, rect.center().y),
            Align2::RIGHT_CENTER,
            widgets::ellipsise(&row.label, 26),
            FontId::proportional(11.0),
            if hovered { palette.text } else { palette.muted },
        );

        let track = Rect::from_min_max(
            egui::pos2(rect.left() + LABEL_WIDTH + 8.0, rect.top() + 4.0),
            egui::pos2(
                (rect.right() - 52.0).max(rect.left() + LABEL_WIDTH + 9.0),
                rect.bottom() - 4.0,
            ),
        );

        painter.rect_filled(track, Rounding::same(2.0), palette.sunken);

        let fraction = row.count as f32 / largest as f32;
        let filled = Rect::from_min_size(
            track.min,
            Vec2::new((track.width() * fraction).max(2.0), track.height()),
        );
        let mut fill = colour.unwrap_or_else(|| palette.categorical(index, dark));
        if hovered && clickable {
            fill = fill.gamma_multiply(1.3);
        }
        painter.rect_filled(filled, Rounding::same(2.0), fill);

        painter.text(
            egui::pos2(rect.right(), rect.center().y),
            Align2::RIGHT_CENTER,
            widgets::count(row.count),
            FontId::monospace(11.0),
            palette.text,
        );

        let response = response.on_hover_text(match &row.action {
            Some(StatAction::Filter(expression)) => format!(
                "{}: {} — click to show only {expression}",
                row.label,
                widgets::count(row.count)
            ),
            Some(StatAction::Show(address)) => format!(
                "{}: {} open — click to open {address}",
                row.label,
                widgets::count(row.count)
            ),
            None => format!("{}: {}", row.label, widgets::count(row.count)),
        });
        if clickable {
            if response.hovered() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
            }
            if response.clicked() {
                chosen = row.action.clone();
            }
        }
    }

    if data.len() > SHORT_LIST {
        ui.add_space(2.0);
        let label = if expanded {
            format!("Show the top {SHORT_LIST}")
        } else {
            format!("Show all {}", data.len())
        };
        if ui.small_button(label).clicked() {
            expanded = !expanded;
            ui.data_mut(|data| data.insert_temp(expanded_id, expanded));
        }
    }
    chosen
}

fn stacked_bar(ui: &mut Ui, segments: &[(String, u64, Color32)]) -> Option<StatAction> {
    let total: u64 = segments.iter().map(|(_, count, _)| count).sum();
    if total == 0 {
        ui.label(muted("No ports tested yet."));
        return None;
    }

    let mut chosen = None;
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 14.0), Sense::click());
    let pointer = response.hover_pos();
    let mut x = rect.left();
    for (name, count, colour) in segments {
        let width = rect.width() * (*count as f32 / total as f32);
        if width <= 0.0 {
            continue;
        }
        let piece = Rect::from_min_size(egui::pos2(x, rect.top()), Vec2::new(width, rect.height()));
        let hovered = pointer.is_some_and(|p| piece.contains(p));
        ui.painter().rect_filled(
            if hovered {
                piece.expand2(Vec2::new(0.0, 2.0))
            } else {
                piece
            },
            Rounding::ZERO,
            *colour,
        );
        if hovered {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
            if response.clicked() {
                chosen = Some(StatAction::Filter(state_filter(name)));
            }
        }
        x += width;
    }

    ui.painter().rect_stroke(
        rect,
        Rounding::same(2.0),
        egui::Stroke::new(1.0_f32, theme::current().sunken_border),
    );
    if let Some(position) = pointer {
        if let Some((name, count, _)) = segment_at(segments, rect, position, total) {
            response.clone().on_hover_text(format!(
                "{name}: {} of {} ports ({:.1}%) — click to show only these",
                widgets::count(count),
                widgets::count(total),
                count as f32 / total as f32 * 100.0
            ));
        }
    }

    ui.add_space(crate::theme::UNIT);
    ui.horizontal_wrapped(|ui| {
        for (name, count, colour) in segments {
            let text = RichText::new(format!(
                "{name} {}  ({:.0}%)",
                widgets::count(*count),
                *count as f32 / total as f32 * 100.0
            ))
            .size(11.0)
            .color(theme::current().muted);
            let (swatch, _) = ui.allocate_exact_size(Vec2::splat(9.0), Sense::hover());
            ui.painter()
                .rect_filled(swatch, Rounding::same(2.0), *colour);
            if ui
                .add(egui::Label::new(text).sense(Sense::click()))
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .clicked()
            {
                chosen = Some(StatAction::Filter(state_filter(name)));
            }
            ui.add_space(crate::theme::UNIT * 2.0);
        }
    });
    chosen
}

pub fn state_filter(state: &str) -> String {
    format!("state:{state}")
}

fn segment_at(
    segments: &[(String, u64, Color32)],
    rect: Rect,
    position: egui::Pos2,
    total: u64,
) -> Option<(String, u64, Color32)> {
    let mut x = rect.left();
    for (name, count, colour) in segments {
        let width = rect.width() * (*count as f32 / total as f32);
        if position.x >= x && position.x <= x + width {
            return Some((name.clone(), *count, *colour));
        }
        x += width;
    }
    None
}

pub fn latency_buckets(latencies: &[f64]) -> Vec<(String, u64)> {
    const EDGES: &[(f64, &str)] = &[
        (1.0, "<1 ms"),
        (5.0, "1-5"),
        (20.0, "5-20"),
        (50.0, "20-50"),
        (100.0, "50-100"),
        (250.0, "100-250"),
        (f64::MAX, ">250"),
    ];

    let mut counts = vec![0u64; EDGES.len()];
    for value in latencies {
        let index = EDGES
            .iter()
            .position(|(edge, _)| *value < *edge)
            .unwrap_or(EDGES.len() - 1);
        counts[index] += 1;
    }

    EDGES
        .iter()
        .zip(counts)
        .map(|((_, label), count)| ((*label).to_string(), count))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use netscan_core::{HostStatus, PortReason, PortReport, PortState, Transport};

    fn results() -> LiveResults {
        let mut results = LiveResults::default();
        for (address, ports, rtt) in [
            ("10.0.0.1", vec![22u16, 80], 2.0),
            ("10.0.0.2", vec![22, 443, 3306], 30.0),
            ("10.0.0.3", vec![80], 120.0),
        ] {
            let mut host = HostReport::new(address.parse().unwrap());
            host.status = HostStatus::Up;
            host.rtt_ms = Some(rtt);
            for port in ports {
                host.ports.push(PortReport::new(
                    port,
                    Transport::Tcp,
                    PortState::Open,
                    PortReason::ConnectionEstablished,
                ));
            }
            host.other_ports.record(PortState::Closed);
            results.hosts.insert(host.address, host);
        }
        results
    }

    #[test]
    fn aggregates_count_services_by_frequency() {
        let aggregates = Aggregates::compute(&results());

        assert_eq!(aggregates.services[0], ("http".to_string(), 2));
        assert_eq!(aggregates.services[1], ("ssh".to_string(), 2));
        assert_eq!(
            aggregates.services.last().unwrap(),
            &("mysql".to_string(), 1)
        );
    }

    #[test]
    fn aggregates_rank_the_busiest_hosts_first() {
        let aggregates = Aggregates::compute(&results());
        assert!(aggregates.busiest_hosts[0].0.contains("10.0.0.2"));
        assert_eq!(aggregates.busiest_hosts[0].1, 3);
    }

    #[test]
    fn a_ranked_host_carries_the_address_that_clicking_it_should_open() {
        let aggregates = Aggregates::compute(&results());
        let (label, _, address) = &aggregates.busiest_hosts[0];
        assert_eq!(address.to_string(), "10.0.0.2");
        assert!(label.starts_with("10.0.0.2"));
    }

    #[test]
    fn every_bar_asks_for_something_the_filter_understands() {
        let aggregates = Aggregates::compute(&results());
        let mut expressions: Vec<String> = aggregates
            .services
            .iter()
            .map(|(name, _)| format!("service:{name}"))
            .collect();
        expressions.extend(
            aggregates
                .port_states
                .iter()
                .map(|(state, _)| state_filter(state)),
        );

        assert!(!expressions.is_empty());
        for expression in expressions {
            let filter = crate::filter::Filter::parse(&expression);
            assert!(
                filter.errors.is_empty(),
                "{expression:?} did not parse: {:?}",
                filter.errors
            );
            assert!(!filter.is_empty(), "{expression:?} filtered nothing");
        }
    }

    #[test]
    fn a_state_filter_names_the_state_it_came_from() {
        assert_eq!(state_filter("open"), "state:open");

        let filter = crate::filter::Filter::parse(&state_filter("open|filtered"));
        assert!(filter.errors.is_empty(), "{:?}", filter.errors);
    }

    #[test]
    fn aggregates_include_summarised_ports_in_the_state_counts() {
        let aggregates = Aggregates::compute(&results());
        let closed = aggregates
            .port_states
            .iter()
            .find(|(state, _)| state == "closed");
        assert_eq!(
            closed.map(|(_, n)| *n),
            Some(3),
            "one summarised closed port per host"
        );
    }

    #[test]
    fn the_median_is_robust_to_an_outlier() {
        let aggregates = Aggregates::compute(&results());
        assert_eq!(aggregates.median_latency(), Some(30.0));
        assert_eq!(aggregates.p95_latency(), Some(120.0));
    }

    #[test]
    fn medians_handle_even_sample_counts() {
        let aggregates = Aggregates {
            latencies: vec![1.0, 2.0, 3.0, 4.0],
            ..Default::default()
        };
        assert_eq!(aggregates.median_latency(), Some(2.5));
    }

    #[test]
    fn empty_results_produce_no_statistics() {
        let aggregates = Aggregates::compute(&LiveResults::default());
        assert!(aggregates.is_empty());
        assert_eq!(aggregates.median_latency(), None);
        assert_eq!(aggregates.p95_latency(), None);
    }

    #[test]
    fn latency_buckets_cover_every_sample() {
        let latencies = vec![0.5, 3.0, 10.0, 30.0, 75.0, 200.0, 900.0];
        let buckets = latency_buckets(&latencies);
        let total: u64 = buckets.iter().map(|(_, count)| count).sum();
        assert_eq!(
            total,
            latencies.len() as u64,
            "every sample must land in a bucket"
        );
        assert_eq!(buckets[0].1, 1, "0.5 ms belongs in the first bucket");
        assert_eq!(
            buckets.last().unwrap().1,
            1,
            "900 ms belongs in the last bucket"
        );
    }

    #[test]
    fn latency_buckets_handle_no_samples() {
        let buckets = latency_buckets(&[]);
        assert!(buckets.iter().all(|(_, count)| *count == 0));
        assert!(
            !buckets.is_empty(),
            "the buckets themselves should still be described"
        );
    }
}
