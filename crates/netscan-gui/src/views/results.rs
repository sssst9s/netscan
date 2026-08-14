use egui::{RichText, Ui};
use egui_extras::{Column, TableBuilder};
use netscan_core::{HostReport, HostStatus, PortReport};

use super::table;
use crate::filter::Filter;
use crate::theme;
use crate::widgets::{self, muted, palette};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HostSort {
    #[default]
    Address,
    Hostname,
    Status,
    Role,
    OpenPorts,
    Tested,
    Latency,
    Mac,
    Vendor,
    Os,
    Services,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DetailTab {
    #[default]
    Ports,
    Host,
    Detection,
    Tls,
}

impl DetailTab {
    pub const ALL: &'static [DetailTab] = &[
        DetailTab::Ports,
        DetailTab::Host,
        DetailTab::Detection,
        DetailTab::Tls,
    ];

    pub fn label(self) -> &'static str {
        match self {
            DetailTab::Ports => "Ports",
            DetailTab::Host => "Host",
            DetailTab::Detection => "Detection",
            DetailTab::Tls => "TLS",
        }
    }
}

#[derive(Debug, Default)]
pub struct ResultsState {
    pub selected: Option<std::net::IpAddr>,
    pub sort: HostSort,
    pub descending: bool,
    pub tab: DetailTab,
    pub show_down: bool,
    pub layout_ready: bool,
    pub last_available: f32,
    pub selected_port: Option<(u16, netscan_core::Transport)>,
    pub hovered_host: Option<usize>,
    pub hovered_port: Option<usize>,
}

impl ResultsState {
    pub fn settle(&mut self, available: f32, minimum: f32) -> bool {
        let steady = (available - self.last_available).abs() < 1.0;
        self.last_available = available;
        if steady && available >= minimum {
            self.layout_ready = true;
        }
        self.layout_ready
    }
}

pub fn visible_hosts<'a>(
    hosts: impl Iterator<Item = &'a HostReport>,
    filter: &Filter,
    state: &ResultsState,
) -> Vec<&'a HostReport> {
    let mut visible: Vec<&HostReport> = hosts
        .filter(|host| state.show_down || host.status == HostStatus::Up)
        .filter(|host| filter.matches_host(host))
        .collect();

    let by_text = |value: fn(&HostReport) -> String| {
        move |a: &&HostReport, b: &&HostReport| {
            let key = |host: &HostReport| {
                let text = value(host);
                (text.is_empty(), text.to_lowercase())
            };
            key(a).cmp(&key(b)).then_with(|| a.address.cmp(&b.address))
        }
    };

    match state.sort {
        HostSort::Address => visible.sort_by_key(|host| host.address),
        HostSort::Hostname => {
            visible.sort_by(by_text(|host| {
                host.primary_hostname().unwrap_or("").to_string()
            }));
        }
        HostSort::Status => visible.sort_by(by_text(|host| host.status.to_string())),
        HostSort::Role => {
            visible.sort_by(by_text(|host| {
                super::topology::infer_role(host).label().to_string()
            }));
        }
        HostSort::Vendor => {
            visible.sort_by(by_text(|host| host.vendor.clone().unwrap_or_default()));
        }
        HostSort::Os => visible.sort_by(by_text(os_summary)),
        HostSort::Mac => {
            visible.sort_by(by_text(|host| {
                host.mac.map(|mac| mac.to_string()).unwrap_or_default()
            }));
        }
        HostSort::Services => visible.sort_by(by_text(service_summary)),
        HostSort::OpenPorts => visible.sort_by(|a, b| {
            b.open_port_count()
                .cmp(&a.open_port_count())
                .then_with(|| a.address.cmp(&b.address))
        }),
        HostSort::Tested => visible.sort_by(|a, b| {
            b.ports_tested()
                .cmp(&a.ports_tested())
                .then_with(|| a.address.cmp(&b.address))
        }),
        HostSort::Latency => visible.sort_by(|a, b| {
            let left = a.rtt_ms.unwrap_or(f64::MAX);
            let right = b.rtt_ms.unwrap_or(f64::MAX);
            left.partial_cmp(&right)
                .unwrap_or(std::cmp::Ordering::Equal)
        }),
    }

    if state.descending {
        visible.reverse();
    }
    visible
}

pub fn visible_ports<'a>(host: &'a HostReport, filter: &Filter) -> Vec<&'a PortReport> {
    host.ports
        .iter()
        .filter(|port| filter.matches_port(host, port))
        .collect()
}

pub fn empty(ui: &mut Ui, headline: &str, hint: &str) {
    empty_in(ui, theme::current().faint, headline, hint);
}

pub fn empty_in(ui: &mut Ui, colour: egui::Color32, headline: &str, hint: &str) {
    let size = ui.available_size();
    ui.allocate_ui_with_layout(
        size,
        egui::Layout::centered_and_justified(egui::Direction::TopDown),
        |ui| {
            ui.label(
                RichText::new(format!("{headline}\n{hint}"))
                    .color(colour)
                    .size(12.0),
            );
        },
    );
}

#[derive(Debug, Default)]
pub struct TableOutcome {
    pub selected: Option<std::net::IpAddr>,
    pub action: Option<table::RowAction>,
}

pub fn host_table(ui: &mut Ui, hosts: &[&HostReport], state: &mut ResultsState) -> TableOutcome {
    let mut outcome = TableOutcome::default();
    let skin = table::Skin::hosts(&theme::current());

    if hosts.is_empty() {
        empty(
            ui,
            "No hosts match.",
            "Adjust the filter, or enable \"show hosts that are down\".",
        );
        return outcome;
    }

    skin.prepare(ui);
    let row_height = table::row_height(ui);

    let available = ui.available_height().max(row_height);

    let hovered = state.hovered_host.take();
    let mut next_hovered = None;

    TableBuilder::new(ui)
        .id_salt("host-table")
        .striped(false)
        .resizable(true)
        .vscroll(true)
        .sense(egui::Sense::click())
        .auto_shrink([false, false])
        .min_scrolled_height(0.0)
        .max_scroll_height(available)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::initial(126.0).at_least(100.0).clip(true))
        .column(Column::initial(140.0).at_least(70.0).clip(true))
        .column(Column::initial(62.0).at_least(50.0).clip(true))
        .column(Column::initial(72.0).at_least(56.0).clip(true))
        .column(Column::initial(52.0).at_least(42.0).clip(true))
        .column(Column::initial(60.0).at_least(46.0).clip(true))
        .column(Column::initial(74.0).at_least(58.0).clip(true))
        .column(Column::initial(126.0).at_least(64.0).clip(true))
        .column(Column::initial(116.0).at_least(64.0).clip(true))
        .column(Column::initial(116.0).at_least(64.0).clip(true))
        .column(Column::remainder().at_least(110.0).clip(true))
        .header(row_height, |mut header| {
            let mut sort_button =
                |header: &mut egui_extras::TableRow, label: &str, sort: HostSort| {
                    header.col(|ui| {
                        table::begin_cell(ui, egui::Color32::TRANSPARENT);
                        let mark = if state.sort != sort {
                            table::SortMark::None
                        } else if state.descending {
                            table::SortMark::Descending
                        } else {
                            table::SortMark::Ascending
                        };
                        if table::sort_heading(ui, label, mark, &skin.header_ink).clicked() {
                            if mark == table::SortMark::None {
                                state.sort = sort;
                                state.descending = false;
                            } else {
                                state.descending = !state.descending;
                            }
                        }
                    });
                };

            sort_button(&mut header, "Address", HostSort::Address);
            sort_button(&mut header, "Hostname", HostSort::Hostname);
            sort_button(&mut header, "Status", HostSort::Status);
            sort_button(&mut header, "Role", HostSort::Role);
            sort_button(&mut header, "Open", HostSort::OpenPorts);
            sort_button(&mut header, "Tested", HostSort::Tested);
            sort_button(&mut header, "Latency", HostSort::Latency);
            sort_button(&mut header, "MAC", HostSort::Mac);
            sort_button(&mut header, "Vendor", HostSort::Vendor);
            sort_button(&mut header, "OS", HostSort::Os);
            sort_button(&mut header, "Services", HostSort::Services);
        })
        .body(|body| {
            body.rows(row_height, hosts.len(), |mut row| {
                let index = row.index();
                let host = hosts[index];
                let is_selected = state.selected == Some(host.address);
                row.set_selected(is_selected);
                row.set_hovered(hovered == Some(index));

                let ink = skin.row_ink(is_selected);
                let cell = skin.cell(is_selected, hovered == Some(index));

                row.col(|ui| {
                    table::begin_cell(ui, cell);
                    ui.label(table::code(host.address.to_string(), ink.text));
                });
                row.col(|ui| {
                    table::begin_cell(ui, cell);
                    ui.label(
                        RichText::new(widgets::ellipsise(
                            host.primary_hostname().unwrap_or("—"),
                            40,
                        ))
                        .color(ink.text),
                    );
                });
                row.col(|ui| {
                    table::begin_cell(ui, cell);
                    ui.label(
                        RichText::new(host.status.to_string())
                            .color(widgets::status_ink(&ink, host.status))
                            .strong(),
                    );
                });
                row.col(|ui| {
                    table::begin_cell(ui, cell);

                    let role = super::topology::infer_role(host);
                    ui.label(RichText::new(role.label()).color(ink.muted));
                });
                row.col(|ui| {
                    table::begin_cell(ui, cell);
                    let open = host.open_port_count();
                    let colour = if open > 0 { ink.success } else { ink.faint };
                    table::number(ui, RichText::new(open.to_string()).color(colour).strong());
                });
                row.col(|ui| {
                    table::begin_cell(ui, cell);
                    table::number(
                        ui,
                        RichText::new(widgets::count(host.ports_tested())).color(ink.muted),
                    );
                });
                row.col(|ui| {
                    table::begin_cell(ui, cell);
                    table::number(ui, table::code(widgets::rtt(host.rtt_ms), ink.muted));
                });
                row.col(|ui| {
                    table::begin_cell(ui, cell);
                    ui.label(table::code(
                        host.mac.map(|mac| mac.to_string()).unwrap_or_default(),
                        ink.muted,
                    ));
                });
                row.col(|ui| {
                    table::begin_cell(ui, cell);
                    ui.label(
                        RichText::new(widgets::ellipsise(host.vendor.as_deref().unwrap_or(""), 28))
                            .color(ink.muted),
                    );
                });
                row.col(|ui| {
                    table::begin_cell(ui, cell);

                    ui.label(
                        RichText::new(widgets::ellipsise(&os_summary(host), 28)).color(ink.muted),
                    );
                });
                row.col(|ui| {
                    table::begin_cell(ui, cell);
                    ui.label(RichText::new(service_summary(host)).color(ink.muted));
                });

                let response = row.response();
                if response.hovered() {
                    next_hovered = Some(index);
                }

                let response = response.on_hover_text(host_summary(host));
                if response.clicked() {
                    outcome.selected = Some(host.address);
                }

                if response.secondary_clicked() {
                    outcome.selected = Some(host.address);
                }
                if let Some(action) = table::row_menu(&response, &table::host_entries(host, hosts))
                {
                    outcome.action = Some(action);
                }
            });
        });

    state.hovered_host = next_hovered;
    outcome
}

pub fn os_summary(host: &HostReport) -> String {
    host.os
        .as_ref()
        .filter(|os| !os.is_empty())
        .map(|os| os.summary())
        .unwrap_or_default()
}

pub fn host_summary(host: &HostReport) -> String {
    let mut lines = vec![host.address.to_string()];
    for name in &host.hostnames {
        lines.push(format!("{} ({:?})", name.name, name.source).to_lowercase());
    }
    lines.push(format!("status: {}", host.status));
    if let Some(reason) = &host.status_reason {
        lines.push(format!("reason: {reason}"));
    }
    lines.push(format!(
        "role: {} (inferred)",
        super::topology::infer_role(host).label()
    ));
    lines.push(format!("latency: {}", widgets::rtt(host.rtt_ms)));
    lines.push(format!(
        "ports: {} open of {} tested",
        host.open_port_count(),
        widgets::count(host.ports_tested())
    ));
    if host.not_scanned > 0 {
        lines.push(format!("{} port(s) never tested", host.not_scanned));
    }
    if let Some(mac) = host.mac {
        lines.push(format!("MAC: {mac}"));
    }
    if let Some(vendor) = &host.vendor {
        lines.push(format!("vendor: {vendor}"));
    }
    let os = os_summary(host);
    if !os.is_empty() {
        lines.push(format!("OS: {os} (inferred)"));
    }
    if let Some(duration) = host.duration() {
        lines.push(format!(
            "scanned in {} ms",
            duration.num_milliseconds().max(0)
        ));
    }
    lines.join("\n")
}

pub fn identity(host: &HostReport) -> String {
    let vendor = host.vendor.as_deref().unwrap_or_default().trim();
    let os = host
        .os
        .as_ref()
        .filter(|os| !os.is_empty())
        .map(|os| os.summary())
        .unwrap_or_default();
    match (vendor.is_empty(), os.is_empty()) {
        (true, true) => String::new(),
        (false, true) => vendor.to_string(),
        (true, false) => os,
        (false, false) => format!("{vendor} · {os}"),
    }
}

pub fn service_summary(host: &HostReport) -> String {
    let mut names: Vec<&str> = host.open_ports().map(PortReport::service_name).collect();
    names.sort_unstable();
    names.dedup();
    if names.is_empty() {
        return String::new();
    }
    let shown: Vec<&str> = names.iter().copied().take(5).collect();
    if names.len() > shown.len() {
        format!("{}, +{}", shown.join(", "), names.len() - shown.len())
    } else {
        shown.join(", ")
    }
}

pub fn host_details(
    ui: &mut Ui,
    host: &HostReport,
    filter: &Filter,
    state: &mut ResultsState,
) -> Option<table::RowAction> {
    ui.separator();
    ui.horizontal(|ui| {
        ui.heading(host.address.to_string());
        if let Some(name) = host.primary_hostname() {
            ui.label(muted(name));
        }
        ui.label(widgets::status_badge(host.status));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            for tab in DetailTab::ALL.iter().rev() {
                if widgets::tab(ui, state.tab == *tab, tab.label()).clicked() {
                    state.tab = *tab;
                }
            }
        });
    });
    ui.separator();

    match state.tab {
        DetailTab::Ports => port_table(ui, host, filter, state),
        _ => {
            egui::ScrollArea::vertical()
                .id_salt("host-detail")
                .auto_shrink([false, false])
                .show(ui, |ui| match state.tab {
                    DetailTab::Host => host_facts(ui, host),
                    DetailTab::Detection => detection_details(ui, host),
                    DetailTab::Tls => tls_details(ui, host),
                    DetailTab::Ports => {}
                });
            None
        }
    }
}

fn port_table(
    ui: &mut Ui,
    host: &HostReport,
    filter: &Filter,
    state: &mut ResultsState,
) -> Option<table::RowAction> {
    let ports = visible_ports(host, filter);
    if ports.is_empty() {
        summarise_other_ports(ui, host);
        empty(
            ui,
            if host.ports.is_empty() {
                "No open ports were found on this host."
            } else {
                "No ports match the current filter."
            },
            "",
        );
        return None;
    }

    let mut action = None;

    let skin = table::Skin::ports(&theme::current());
    skin.prepare(ui);
    let row_height = table::row_height(ui);

    let reserve = if host.other_ports.is_empty() && host.not_scanned == 0 {
        0.0
    } else {
        row_height
    };
    let available = (ui.available_height() - reserve).max(row_height);

    let hovered = state.hovered_port.take();
    let mut next_hovered = None;

    TableBuilder::new(ui)
        .id_salt("port-table")
        .striped(false)
        .resizable(true)
        .vscroll(true)
        .sense(egui::Sense::click())
        .auto_shrink([false, false])
        .min_scrolled_height(0.0)
        .max_scroll_height(available)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::initial(84.0).at_least(70.0).clip(true))
        .column(Column::initial(84.0).at_least(70.0).clip(true))
        .column(Column::initial(110.0).at_least(80.0).clip(true))
        .column(Column::initial(180.0).at_least(100.0).clip(true))
        .column(Column::initial(84.0).at_least(60.0).clip(true))
        .column(Column::remainder().at_least(140.0).clip(true))
        .header(row_height, |mut header| {
            for (label, numeric) in [
                ("Port", false),
                ("State", false),
                ("Service", false),
                ("Product / version", false),
                ("Latency", true),
                ("Detail", false),
            ] {
                header.col(|ui| {
                    table::begin_cell(ui, egui::Color32::TRANSPARENT);
                    if numeric {
                        table::number(ui, table::heading(label, &skin.header_ink));
                    } else {
                        ui.label(table::heading(label, &skin.header_ink));
                    }
                });
            }
        })
        .body(|body| {
            body.rows(row_height, ports.len(), |mut row| {
                let index = row.index();
                let port = ports[index];
                let key = (port.port, port.transport);
                let is_selected = state.selected_port == Some(key);
                row.set_selected(is_selected);
                row.set_hovered(hovered == Some(index));

                let ink = skin.row_ink(is_selected);
                let cell = skin.cell(is_selected, hovered == Some(index));

                row.col(|ui| {
                    table::begin_cell(ui, cell);
                    ui.label(table::code(port.label(), ink.text));
                });
                row.col(|ui| {
                    table::begin_cell(ui, cell);
                    ui.label(
                        RichText::new(port.state.as_str())
                            .color(widgets::state_ink(&ink, port.state))
                            .strong(),
                    );
                });
                row.col(|ui| {
                    table::begin_cell(ui, cell);
                    ui.label(RichText::new(port.service_name()).color(ink.text));
                });
                row.col(|ui| {
                    table::begin_cell(ui, cell);
                    let text = port
                        .service
                        .as_ref()
                        .and_then(|s| s.product_version())
                        .unwrap_or_else(|| "—".to_string());
                    ui.label(RichText::new(widgets::ellipsise(&text, 40)).color(ink.muted));
                });
                row.col(|ui| {
                    table::begin_cell(ui, cell);
                    table::number(ui, table::code(widgets::rtt(port.rtt_ms), ink.muted));
                });
                row.col(|ui| {
                    table::begin_cell(ui, cell);
                    ui.horizontal(|ui| {
                        if let Some(service) = &port.service {
                            ui.label(
                                widgets::confidence_badge(service.confidence)
                                    .color(widgets::confidence_ink(&ink, service.confidence)),
                            )
                            .on_hover_text(format!("identified by {}", service.source));
                            if service.tls {
                                ui.label(RichText::new("TLS").color(ink.accent));
                            }
                        }
                        if let Some(banner) = &port.banner {
                            ui.label(
                                RichText::new(widgets::ellipsise(banner, 60)).color(ink.muted),
                            )
                            .on_hover_text(banner);
                        }
                        if let Some(error) = &port.error {
                            ui.label(RichText::new(error.to_string()).color(ink.danger));
                        }
                    });
                });

                let response = row.response();
                if response.hovered() {
                    next_hovered = Some(index);
                }
                if response.clicked() || response.secondary_clicked() {
                    state.selected_port = Some(key);
                }
                if let Some(chosen) =
                    table::row_menu(&response, &table::port_entries(host, port, &ports))
                {
                    action = Some(chosen);
                }
            });
        });

    state.hovered_port = next_hovered;
    summarise_other_ports(ui, host);
    action
}

fn summarise_other_ports(ui: &mut Ui, host: &HostReport) {
    if host.other_ports.is_empty() && host.not_scanned == 0 {
        return;
    }
    ui.add_space(6.0);
    let mut parts: Vec<String> = host
        .other_ports
        .counts
        .iter()
        .map(|(state, count)| format!("{count} {state}"))
        .collect();
    if host.not_scanned > 0 {
        parts.push(format!("{} not tested", host.not_scanned));
    }
    ui.label(muted(format!("Not listed: {}", parts.join(", "))));
}

fn host_facts(ui: &mut Ui, host: &HostReport) {
    ui.add_space(4.0);
    widgets::field(ui, "Address", host.address.to_string());
    widgets::optional_field(ui, "Status reason", host.status_reason.clone());
    widgets::field(ui, "Latency", widgets::rtt(host.rtt_ms));
    widgets::optional_field(ui, "MAC address", host.mac.map(|m| m.to_string()));
    widgets::optional_field(ui, "Vendor", host.vendor.clone());

    if !host.hostnames.is_empty() {
        widgets::section(ui, "Names");
        for hostname in &host.hostnames {
            ui.horizontal(|ui| {
                ui.label(&hostname.name);
                ui.label(muted(format!("({:?})", hostname.source).to_lowercase()));
            });
        }
    }

    widgets::section(ui, "Timing");
    widgets::field(
        ui,
        "Started",
        host.started_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
    );
    if let Some(finished) = host.finished_at {
        widgets::field(
            ui,
            "Finished",
            finished.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        );
        if let Some(duration) = host.duration() {
            widgets::field(
                ui,
                "Took",
                format!("{} ms", duration.num_milliseconds().max(0)),
            );
        }
    }

    widgets::section(ui, "Ports");
    widgets::field(ui, "Tested", widgets::count(host.ports_tested()));
    widgets::field(ui, "Open", host.open_port_count().to_string());
    if host.not_scanned > 0 {
        ui.label(
            RichText::new(format!("{} port(s) were never tested", host.not_scanned))
                .color(palette::filtered()),
        );
    }
}

fn detection_details(ui: &mut Ui, host: &HostReport) {
    ui.add_space(4.0);
    let Some(os) = host.os.as_ref().filter(|os| !os.is_empty()) else {
        ui.label(muted(
            "No operating system inference is available for this host.",
        ));
        ui.label(muted(
            "Enable OS detection in the scan configuration to collect one.",
        ));
        return;
    };

    ui.horizontal(|ui| {
        ui.label(RichText::new(os.summary()).strong());
        ui.label(muted("inferred, not measured"));
    });

    widgets::optional_field(ui, "Family", os.family.clone());
    widgets::optional_field(ui, "Name", os.name.clone());
    widgets::optional_field(ui, "Device type", os.device_type.clone());

    widgets::section(ui, "Evidence");
    if os.evidence.is_empty() {
        ui.label(muted("No individual observations were recorded."));
    }
    for evidence in &os.evidence {
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(&evidence.kind)
                    .monospace()
                    .color(palette::muted()),
            );
            ui.label(&evidence.detail);
            ui.label(muted(format!("→ {}", evidence.suggests)));
        });
    }

    widgets::section(ui, "Identified services");
    let identified: Vec<&PortReport> = host.ports.iter().filter(|p| p.service.is_some()).collect();
    if identified.is_empty() {
        ui.label(muted("No services were identified."));
    }
    for port in identified {
        if let Some(service) = &port.service {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(port.label()).monospace());
                ui.label(service.summary());
                ui.label(widgets::confidence_badge(service.confidence));
                ui.label(muted(format!("via {}", service.source)));
            });
        }
    }
}

fn tls_details(ui: &mut Ui, host: &HostReport) {
    ui.add_space(4.0);
    let with_tls: Vec<&PortReport> = host.ports.iter().filter(|p| p.tls.is_some()).collect();
    if with_tls.is_empty() {
        ui.label(muted("No TLS endpoints were inspected on this host."));
        ui.label(muted(
            "Enable TLS inspection in the scan configuration to collect certificates.",
        ));
        return;
    }

    for port in with_tls {
        let Some(tls) = &port.tls else { continue };
        widgets::section(ui, &format!("{} ", port.label()));
        widgets::optional_field(ui, "Protocol", tls.version.clone());
        widgets::optional_field(ui, "Cipher", tls.cipher.clone());
        widgets::optional_field(ui, "Subject", tls.subject.clone());
        widgets::optional_field(ui, "Issuer", tls.issuer.clone());

        if let Some(not_after) = tls.not_after {
            ui.horizontal(|ui| {
                ui.label(muted("Expires:"));
                let text = not_after.format("%Y-%m-%d").to_string();
                if tls.expired {
                    ui.label(RichText::new(format!("{text} (expired)")).color(palette::unknown()));
                } else {
                    ui.label(text);
                }
            });
        }
        if tls.self_signed {
            ui.label(muted("Self-signed"));
        }
        if !tls.subject_alt_names.is_empty() {
            ui.label(muted("Subject alternative names:"));
            for name in &tls.subject_alt_names {
                ui.label(format!("    {name}"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netscan_core::{PortReason, PortState, ServiceInfo, Transport};

    fn host(address: &str, name: Option<&str>, open: &[u16], rtt: Option<f64>) -> HostReport {
        let mut host = HostReport::new(address.parse().unwrap());
        host.status = HostStatus::Up;
        host.rtt_ms = rtt;
        if let Some(name) = name {
            host.add_hostname(
                name,
                netscan_core::scanner::result::HostnameSource::ReverseDns,
            );
        }
        for port in open {
            let mut report = PortReport::new(
                *port,
                Transport::Tcp,
                PortState::Open,
                PortReason::ConnectionEstablished,
            );
            report.service = Some(ServiceInfo::from_port_number(
                netscan_core::detection::service::name_for_port(Transport::Tcp, *port)
                    .unwrap_or("unknown"),
            ));
            host.ports.push(report);
        }
        host
    }

    fn hosts() -> Vec<HostReport> {
        let mut down = HostReport::new("10.0.0.9".parse().unwrap());
        down.status = HostStatus::Down;
        vec![
            host("10.0.0.2", Some("beta.example"), &[22, 80], Some(5.0)),
            host("10.0.0.1", Some("alpha.example"), &[443], Some(20.0)),
            host("10.0.0.3", None, &[22, 80, 443, 3306], Some(1.0)),
            down,
        ]
    }

    fn state() -> ResultsState {
        ResultsState::default()
    }

    #[test]
    fn hosts_that_are_down_are_hidden_by_default() {
        let hosts = hosts();
        let visible = visible_hosts(hosts.iter(), &Filter::default(), &state());
        assert_eq!(visible.len(), 3);
        assert!(visible.iter().all(|h| h.status == HostStatus::Up));

        let showing = ResultsState {
            show_down: true,
            ..state()
        };
        assert_eq!(
            visible_hosts(hosts.iter(), &Filter::default(), &showing).len(),
            4
        );
    }

    #[test]
    fn sorting_by_address_is_numeric() {
        let hosts = hosts();
        let visible = visible_hosts(hosts.iter(), &Filter::default(), &state());
        let addresses: Vec<String> = visible.iter().map(|h| h.address.to_string()).collect();
        assert_eq!(addresses, vec!["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
    }

    #[test]
    fn sorting_by_open_ports_puts_the_busiest_host_first() {
        let hosts = hosts();
        let state = ResultsState {
            sort: HostSort::OpenPorts,
            ..state()
        };
        let visible = visible_hosts(hosts.iter(), &Filter::default(), &state);
        assert_eq!(visible[0].address.to_string(), "10.0.0.3");
        assert_eq!(visible[0].open_port_count(), 4);
    }

    #[test]
    fn sorting_by_latency_puts_the_fastest_first_and_unmeasured_last() {
        let mut hosts = hosts();
        hosts.push(host("10.0.0.4", None, &[80], None));
        let state = ResultsState {
            sort: HostSort::Latency,
            ..state()
        };
        let visible = visible_hosts(hosts.iter(), &Filter::default(), &state);
        assert_eq!(
            visible[0].address.to_string(),
            "10.0.0.3",
            "1 ms is fastest"
        );
        assert_eq!(
            visible.last().unwrap().address.to_string(),
            "10.0.0.4",
            "a host with no measurement should sort last"
        );
    }

    #[test]
    fn sorting_by_hostname_is_alphabetical() {
        let hosts = hosts();
        let state = ResultsState {
            sort: HostSort::Hostname,
            ..state()
        };
        let visible = visible_hosts(hosts.iter(), &Filter::default(), &state);
        assert_eq!(visible[0].primary_hostname(), Some("alpha.example"));
        assert_eq!(visible[1].primary_hostname(), Some("beta.example"));
        assert_eq!(
            visible.last().unwrap().primary_hostname(),
            None,
            "unnamed hosts sort last"
        );
    }

    #[test]
    fn reversing_the_sort_reverses_the_order() {
        let hosts = hosts();
        let ascending = visible_hosts(hosts.iter(), &Filter::default(), &state());
        let state = ResultsState {
            descending: true,
            ..state()
        };
        let descending = visible_hosts(hosts.iter(), &Filter::default(), &state);
        assert_eq!(ascending[0].address, descending.last().unwrap().address);
    }

    #[test]
    fn the_filter_narrows_the_host_list() {
        let hosts = hosts();
        let filter = Filter::parse("port:3306");
        let visible = visible_hosts(hosts.iter(), &filter, &state());
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].address.to_string(), "10.0.0.3");
    }

    #[test]
    fn a_port_level_filter_narrows_the_port_table_too() {
        let host = host("10.0.0.3", None, &[22, 80, 443], None);
        let ports = visible_ports(&host, &Filter::parse("port:80"));
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 80);
    }

    #[test]
    fn a_host_level_filter_keeps_every_port_row() {
        let host = host("10.0.0.3", None, &[22, 80, 443], None);
        let ports = visible_ports(&host, &Filter::parse("status:up"));
        assert_eq!(ports.len(), 3);
    }

    #[test]
    fn the_service_summary_lists_and_truncates() {
        let simple = host("10.0.0.1", None, &[22, 80], None);
        let summary = service_summary(&simple);
        assert!(summary.contains("ssh"));
        assert!(summary.contains("http"));

        let busy = host("10.0.0.2", None, &[21, 22, 23, 25, 53, 80, 110, 143], None);
        let summary = service_summary(&busy);
        assert!(
            summary.contains('+'),
            "a long list should be truncated: {summary}"
        );
    }

    #[test]
    fn a_host_with_no_services_has_an_empty_summary() {
        let bare = HostReport::new("10.0.0.1".parse().unwrap());
        assert_eq!(service_summary(&bare), "");
    }

    #[test]
    fn the_split_waits_for_the_pane_to_stop_moving() {
        let mut state = state();

        assert!(!state.settle(0.0, 240.0), "nothing has been measured yet");
        assert!(!state.settle(300.0, 240.0), "one reading proves nothing");
        assert!(
            !state.settle(700.0, 240.0),
            "a height that jumped is not settled, however roomy"
        );

        assert!(state.settle(700.0, 240.0));
    }

    #[test]
    fn a_pane_too_small_to_divide_never_becomes_ready() {
        let mut state = state();
        for _ in 0..10 {
            assert!(
                !state.settle(180.0, 240.0),
                "a steady but tiny pane must not be split"
            );
        }

        assert!(!state.settle(600.0, 240.0));
        assert!(state.settle(600.0, 240.0));
    }

    #[test]
    fn a_settled_layout_survives_a_later_resize() {
        let mut state = state();
        state.settle(600.0, 240.0);
        assert!(state.settle(600.0, 240.0));
        assert!(state.settle(576.0, 240.0), "a resize is not a reset");
    }

    #[test]
    fn every_column_can_be_sorted_by_and_blanks_go_last() {
        let mut rich = host("10.0.0.5", Some("rich.example"), &[80], Some(2.0));
        rich.vendor = Some("Zebra Technologies".to_string());
        rich.mac = Some("aa:bb:cc:00:00:01".parse().unwrap());
        rich.os = Some(netscan_core::OsGuess {
            family: Some("Linux".to_string()),
            ..Default::default()
        });
        let bare = host("10.0.0.1", None, &[], Some(1.0));

        for sort in [
            HostSort::Vendor,
            HostSort::Os,
            HostSort::Mac,
            HostSort::Hostname,
            HostSort::Services,
        ] {
            let hosts = [bare.clone(), rich.clone()];
            let state = ResultsState {
                sort,
                show_down: true,
                ..state()
            };
            let visible = visible_hosts(hosts.iter(), &Filter::default(), &state);
            assert_eq!(
                visible[0].address.to_string(),
                "10.0.0.5",
                "{sort:?} put the blank host first"
            );
        }
    }

    #[test]
    fn sorting_by_ports_tested_puts_the_most_thoroughly_scanned_first() {
        let mut few = host("10.0.0.1", None, &[80], None);
        few.not_scanned = 0;
        let many = host("10.0.0.2", None, &[22, 80, 443, 8080], None);
        let hosts = [few, many];
        let state = ResultsState {
            sort: HostSort::Tested,
            ..state()
        };
        let visible = visible_hosts(hosts.iter(), &Filter::default(), &state);
        assert_eq!(visible[0].address.to_string(), "10.0.0.2");
    }

    #[test]
    fn sorting_by_role_groups_the_same_kind_of_thing_together() {
        let printer = host("10.0.0.7", None, &[9100], None);
        let server = host("10.0.0.8", None, &[22, 443], None);
        let hosts = [printer, server];
        let state = ResultsState {
            sort: HostSort::Role,
            ..state()
        };
        let visible = visible_hosts(hosts.iter(), &Filter::default(), &state);
        let roles: Vec<&str> = visible
            .iter()
            .map(|host| super::super::topology::infer_role(host).label())
            .collect();
        assert_eq!(roles, vec!["printer", "server"], "alphabetical by role");
    }

    #[test]
    fn the_row_tooltip_carries_what_the_columns_could_not() {
        let mut host = host("10.0.0.3", Some("nas.example"), &[22, 445], Some(3.5));
        host.status_reason = Some("echo reply".to_string());
        host.mac = Some("aa:bb:cc:dd:ee:ff".parse().unwrap());
        host.vendor = Some("Synology".to_string());
        host.not_scanned = 12;

        let summary = host_summary(&host);
        for expected in [
            "10.0.0.3",
            "nas.example",
            "echo reply",
            "role:",
            "latency: 3.5 ms",
            "2 open",
            "12 port(s) never tested",
            "aa:bb:cc:dd:ee:ff",
            "Synology",
        ] {
            assert!(
                summary.contains(expected),
                "{expected:?} is missing from:\n{summary}"
            );
        }
    }

    #[test]
    fn a_host_with_nothing_known_still_has_a_usable_tooltip() {
        let bare = HostReport::new("10.0.0.9".parse().unwrap());
        let summary = host_summary(&bare);
        assert!(summary.starts_with("10.0.0.9"));

        for line in summary.lines() {
            assert!(
                !line.trim_end().ends_with(':'),
                "{line:?} promises a value it does not have"
            );
        }
        assert_eq!(os_summary(&bare), "");
    }

    #[test]
    fn every_detail_tab_has_a_label() {
        for tab in DetailTab::ALL {
            assert!(!tab.label().is_empty());
        }
        assert_eq!(DetailTab::default(), DetailTab::Ports);
    }
}
