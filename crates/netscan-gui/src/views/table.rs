use egui::{Color32, Response, RichText, Stroke, Ui};
use netscan_core::{HostReport, PortReport, PortState, Transport};

use crate::theme::{Ink, Palette};
use crate::widgets;

const ROW_PADDING: f32 = 4.0;

const CELL_GAP: f32 = 0.0;

pub fn row_height(ui: &Ui) -> f32 {
    ui.text_style_height(&egui::TextStyle::Body) + ROW_PADDING
}

pub const RADIUS: f32 = 4.0;

pub const INSET: f32 = 8.0;

fn margin() -> egui::Margin {
    egui::Margin {
        left: INSET,
        right: INSET,
        top: crate::theme::UNIT,
        bottom: crate::theme::UNIT,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Skin {
    pub fill: Color32,
    pub container: Color32,
    pub border: Color32,
    pub ink: Ink,
    pub header_ink: Ink,
    pub hover: Color32,
    pub selected: Color32,
    pub selected_ink: Ink,
}

impl Skin {
    pub fn hosts(palette: &Palette) -> Skin {
        Skin {
            fill: palette.table,
            container: palette.sunken,
            border: palette.sunken_border,
            ink: crate::theme::TABLE_INK,
            header_ink: palette.ink(),
            hover: Color32::from_rgb(0xCF, 0xCE, 0xEC),
            selected: palette.selected,
            selected_ink: crate::theme::SELECTED_INK,
        }
    }

    pub fn ports(palette: &Palette) -> Skin {
        Skin {
            fill: palette.sunken,
            container: palette.sunken,
            border: palette.sunken_border,
            ink: palette.ink(),
            header_ink: palette.ink(),
            hover: palette.hover,
            selected: palette.selected,
            selected_ink: crate::theme::SELECTED_INK,
        }
    }

    pub fn row_ink(&self, selected: bool) -> Ink {
        if selected {
            self.selected_ink
        } else {
            self.ink
        }
    }

    pub fn frame(&self) -> egui::Frame {
        egui::Frame::none()
            .fill(self.container)
            .stroke(Stroke::new(1.0_f32, self.border))
            .rounding(egui::Rounding::same(RADIUS))
            .inner_margin(margin())
    }

    pub fn cell(&self, selected: bool, hovered: bool) -> Color32 {
        if selected {
            self.selected
        } else if hovered {
            self.hover
        } else {
            self.fill
        }
    }

    pub fn prepare(&self, ui: &mut Ui) {
        ui.visuals_mut().selection.bg_fill = Color32::TRANSPARENT;
        ui.visuals_mut().selection.stroke.color = self.selected_ink.text;
        ui.visuals_mut().widgets.hovered.bg_fill = Color32::TRANSPARENT;

        ui.visuals_mut().widgets.noninteractive.bg_stroke = Stroke::NONE;

        ui.visuals_mut().widgets.hovered.bg_stroke = Stroke::new(1.0_f32, self.ink.faint);
        ui.visuals_mut().widgets.active.bg_stroke = Stroke::new(1.0_f32, self.ink.muted);
        ui.spacing_mut().item_spacing = egui::vec2(CELL_GAP, CELL_GAP);

        let (track, handle, dragging) = if is_light(self.fill) {
            (
                Color32::from_rgb(0xD3, 0xD2, 0xEA),
                Color32::from_rgb(0x9C, 0x9B, 0xC0),
                Color32::from_rgb(0x6F, 0x6E, 0xA0),
            )
        } else {
            (
                Color32::from_white_alpha(14),
                Color32::from_white_alpha(48),
                Color32::from_white_alpha(90),
            )
        };
        ui.visuals_mut().extreme_bg_color = track;
        ui.visuals_mut().widgets.inactive.bg_fill = handle;
        ui.visuals_mut().widgets.active.bg_fill = dragging;
    }
}

fn is_light(colour: Color32) -> bool {
    let [r, g, b, _] = colour.to_array();
    (u32::from(r) + u32::from(g) + u32::from(b)) / 3 > 127
}

const CELL_PAD: f32 = 6.0;

pub fn begin_cell(ui: &mut Ui, colour: Color32) {
    if colour != Color32::TRANSPARENT {
        ui.painter()
            .rect_filled(ui.max_rect(), egui::Rounding::ZERO, colour);
    }
    ui.add_space(CELL_PAD);
}

pub fn heading(text: &str, ink: &Ink) -> RichText {
    RichText::new(text).size(11.0).color(ink.muted)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortMark {
    None,
    Ascending,
    Descending,
}

impl SortMark {
    pub fn icon(self) -> Option<crate::icons::Icon> {
        match self {
            SortMark::None => None,
            SortMark::Ascending => Some(crate::icons::Icon::CaretUp),
            SortMark::Descending => Some(crate::icons::Icon::CaretDown),
        }
    }
}

pub fn sort_heading(ui: &mut Ui, label: &str, mark: SortMark, ink: &Ink) -> Response {
    let active = mark != SortMark::None;
    let colour = if active { ink.accent } else { ink.muted };
    let text = RichText::new(label).size(11.0).color(colour);

    let full = ui.available_rect_before_wrap();
    let response = ui
        .add(egui::Label::new(text).sense(egui::Sense::click()))
        .on_hover_cursor(egui::CursorIcon::PointingHand);

    if let Some(icon) = mark.icon() {
        let size = 11.0;
        let box_ = egui::Rect::from_center_size(
            egui::pos2(full.right() - CELL_PAD - size / 2.0, full.center().y),
            egui::Vec2::splat(size),
        );
        let ctx = ui.ctx().clone();
        crate::icons::paint(&ctx, ui.painter(), box_, icon, colour);
    }
    response
}

pub fn code(text: impl Into<String>, colour: egui::Color32) -> RichText {
    RichText::new(text.into()).monospace().color(colour)
}

pub fn number(ui: &mut Ui, text: RichText) {
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        ui.add_space(CELL_PAD);
        ui.label(text);
    });
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowAction {
    Copy(String),
    Filter(String),
    Refine(String),
    Rescan {
        host: std::net::IpAddr,
        port: Option<(u16, Transport)>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Item(String, RowAction),
    Separator,
}

impl Entry {
    fn item(label: impl Into<String>, action: RowAction) -> Entry {
        Entry::Item(label.into(), action)
    }
}

pub fn host_entries(host: &HostReport, listed: &[&HostReport]) -> Vec<Entry> {
    let address = host.address.to_string();
    let mut entries = vec![Entry::item(
        "Copy address",
        RowAction::Copy(address.clone()),
    )];

    if let Some(name) = host.primary_hostname() {
        entries.push(Entry::item("Copy hostname", RowAction::Copy(name.into())));
    }
    entries.push(Entry::item("Copy row", RowAction::Copy(host_row(host))));
    entries.push(Entry::item(
        format!("Copy all {} listed", listed.len()),
        RowAction::Copy(host_table_text(listed)),
    ));

    entries.push(Entry::Separator);
    entries.push(Entry::item(
        "Show only this host",
        RowAction::Filter(format!("host:{address}")),
    ));
    entries.push(Entry::item(
        "Hide this host",
        RowAction::Refine(format!("!host:{address}")),
    ));

    let mut services: Vec<&str> = host.open_ports().map(PortReport::service_name).collect();
    services.sort_unstable();
    services.dedup();
    if let Some(service) = services.first() {
        entries.push(Entry::item(
            format!("Show only {service} hosts"),
            RowAction::Filter(format!("service:{service}")),
        ));
    }

    entries.push(Entry::Separator);
    entries.push(Entry::item(
        "Scan this host again",
        RowAction::Rescan {
            host: host.address,
            port: None,
        },
    ));
    entries
}

pub fn port_entries(host: &HostReport, port: &PortReport, listed: &[&PortReport]) -> Vec<Entry> {
    let address = host.address.to_string();
    let label = port.label();

    let socket = if host.address.is_ipv6() {
        format!("[{address}]:{}", port.port)
    } else {
        format!("{address}:{}", port.port)
    };

    let mut entries = vec![
        Entry::item("Copy port", RowAction::Copy(label.clone())),
        Entry::item("Copy address and port", RowAction::Copy(socket.clone())),
    ];

    if let Some(scheme) = web_scheme(port) {
        entries.push(Entry::item(
            "Copy URL",
            RowAction::Copy(format!("{scheme}://{socket}/")),
        ));
    }
    if let Some(banner) = &port.banner {
        entries.push(Entry::item(
            "Copy banner",
            RowAction::Copy(banner.to_string()),
        ));
    }
    entries.push(Entry::item("Copy row", RowAction::Copy(port_row(port))));
    entries.push(Entry::item(
        format!("Copy all {} listed", listed.len()),
        RowAction::Copy(port_table_text(listed)),
    ));

    entries.push(Entry::Separator);
    entries.push(Entry::item(
        format!("Show only port {}", port.port),
        RowAction::Filter(format!("port:{}", port.port)),
    ));
    let service = port.service_name();
    if service != "unknown" {
        entries.push(Entry::item(
            format!("Show only {service}"),
            RowAction::Filter(format!("service:{service}")),
        ));
    }

    entries.push(Entry::Separator);
    entries.push(Entry::item(
        format!("Scan {label} again"),
        RowAction::Rescan {
            host: host.address,
            port: Some((port.port, port.transport)),
        },
    ));
    entries
}

fn web_scheme(port: &PortReport) -> Option<&'static str> {
    if port.state != PortState::Open || port.transport != Transport::Tcp {
        return None;
    }
    let tls = port.service.as_ref().is_some_and(|service| service.tls) || port.tls.is_some();
    let service = port.service_name();
    let webbish = service.contains("http") || matches!(port.port, 80 | 443 | 8080 | 8443 | 8000);
    if !webbish {
        return None;
    }
    Some(if tls || matches!(port.port, 443 | 8443) {
        "https"
    } else {
        "http"
    })
}

fn host_row(host: &HostReport) -> String {
    let columns = HOST_COLUMNS.map(|(_, value)| value(host));
    columns.join("\t")
}

type HostColumn = (&'static str, fn(&HostReport) -> String);

pub const HOST_COLUMNS: [HostColumn; 11] = [
    ("address", |host| host.address.to_string()),
    ("hostname", |host| {
        host.primary_hostname().unwrap_or("").to_string()
    }),
    ("status", |host| host.status.to_string()),
    ("role", |host| {
        super::topology::infer_role(host).label().to_string()
    }),
    ("open", |host| host.open_port_count().to_string()),
    ("tested", |host| host.ports_tested().to_string()),
    ("latency", |host| widgets::rtt(host.rtt_ms)),
    ("mac", |host| {
        host.mac.map(|mac| mac.to_string()).unwrap_or_default()
    }),
    ("vendor", |host| host.vendor.clone().unwrap_or_default()),
    ("os", |host| {
        host.os
            .as_ref()
            .filter(|os| !os.is_empty())
            .map(|os| os.summary())
            .unwrap_or_default()
    }),
    ("services", super::results::service_summary),
];

fn host_table_text(hosts: &[&HostReport]) -> String {
    let headings: Vec<&str> = HOST_COLUMNS.iter().map(|(name, _)| *name).collect();
    let mut out = headings.join("\t");
    out.push('\n');
    for host in hosts {
        out.push_str(&host_row(host));
        out.push('\n');
    }
    out
}

fn port_row(port: &PortReport) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}",
        port.label(),
        port.state.as_str(),
        port.service_name(),
        port.service
            .as_ref()
            .and_then(|service| service.product_version())
            .unwrap_or_default(),
        widgets::rtt(port.rtt_ms),
    )
}

fn port_table_text(ports: &[&PortReport]) -> String {
    let mut out = String::from("port\tstate\tservice\tproduct\tlatency\n");
    for port in ports {
        out.push_str(&port_row(port));
        out.push('\n');
    }
    out
}

pub fn menu(ui: &mut Ui, entries: &[Entry]) -> Option<RowAction> {
    let mut chosen = None;
    ui.set_min_width(180.0);
    for entry in entries {
        match entry {
            Entry::Separator => {
                ui.separator();
            }
            Entry::Item(label, action) => {
                if ui.button(label).clicked() {
                    chosen = Some(action.clone());
                    ui.close_menu();
                }
            }
        }
    }
    chosen
}

pub fn row_menu(response: &Response, entries: &[Entry]) -> Option<RowAction> {
    let mut chosen = None;
    response.context_menu(|ui| {
        chosen = menu(ui, entries);
    });
    chosen
}

#[cfg(test)]
mod tests {
    use super::*;
    use netscan_core::{HostStatus, PortReason, ServiceInfo};

    fn host() -> HostReport {
        let mut host = HostReport::new("192.168.1.10".parse().unwrap());
        host.status = HostStatus::Up;
        host.rtt_ms = Some(4.0);
        host.add_hostname(
            "printer.local",
            netscan_core::scanner::result::HostnameSource::ReverseDns,
        );
        host.ports.push(port(80, PortState::Open, "http"));
        host.ports.push(port(631, PortState::Open, "ipp"));
        host
    }

    fn port(number: u16, state: PortState, service: &str) -> PortReport {
        let mut report = PortReport::new(
            number,
            Transport::Tcp,
            state,
            PortReason::ConnectionEstablished,
        );
        report.service = Some(ServiceInfo::from_port_number(service));
        report
    }

    fn labels(entries: &[Entry]) -> Vec<String> {
        entries
            .iter()
            .filter_map(|entry| match entry {
                Entry::Item(label, _) => Some(label.clone()),
                Entry::Separator => None,
            })
            .collect()
    }

    fn action_for(entries: &[Entry], label: &str) -> RowAction {
        entries
            .iter()
            .find_map(|entry| match entry {
                Entry::Item(name, action) if name == label => Some(action.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no entry called {label:?} in {:?}", labels(entries)))
    }

    #[test]
    fn the_host_menu_copies_what_it_says_it_copies() {
        let host = host();
        let listed = vec![&host];
        let entries = host_entries(&host, &listed);

        assert_eq!(
            action_for(&entries, "Copy address"),
            RowAction::Copy("192.168.1.10".to_string())
        );
        assert_eq!(
            action_for(&entries, "Copy hostname"),
            RowAction::Copy("printer.local".to_string())
        );
        let RowAction::Copy(row) = action_for(&entries, "Copy row") else {
            panic!("copying a row should copy text");
        };
        let fields: Vec<&str> = row.split('\t').collect();
        assert_eq!(
            fields.len(),
            HOST_COLUMNS.len(),
            "a row must have exactly one field per column: {row:?}"
        );
        assert_eq!(fields[0], "192.168.1.10");
        assert_eq!(fields[1], "printer.local");
        assert_eq!(fields[2], "up");
        assert!(row.contains("http"), "the row should carry its services");
    }

    #[test]
    fn a_copied_row_says_everything_the_table_shows() {
        let mut host = host();
        host.vendor = Some("Example Networks".to_string());
        host.mac = Some("aa:bb:cc:dd:ee:ff".parse().unwrap());
        let fields: Vec<String> = HOST_COLUMNS.iter().map(|(_, value)| value(&host)).collect();
        for (index, (name, _)) in HOST_COLUMNS.iter().enumerate() {
            if *name == "os" {
                continue;
            }
            assert!(
                !fields[index].is_empty(),
                "the {name} column came out empty"
            );
        }

        assert!(fields.iter().all(|field| !field.contains('\t')));
    }

    #[test]
    fn a_host_with_no_name_offers_nothing_to_copy() {
        let mut bare = HostReport::new("10.0.0.1".parse().unwrap());
        bare.status = HostStatus::Up;
        let listed = vec![&bare];
        let entries = host_entries(&bare, &listed);
        assert!(!labels(&entries).contains(&"Copy hostname".to_string()));

        assert!(!labels(&entries)
            .iter()
            .any(|l| l.starts_with("Show only h")));
    }

    #[test]
    fn copying_every_listed_host_copies_the_list_that_is_shown() {
        let first = host();
        let mut second = HostReport::new("192.168.1.11".parse().unwrap());
        second.status = HostStatus::Up;
        let listed = vec![&first, &second];
        let entries = host_entries(&first, &listed);

        let RowAction::Copy(text) = action_for(&entries, "Copy all 2 listed") else {
            panic!("expected a copy");
        };
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "a header and two rows: {text:?}");
        assert!(lines[0].starts_with("address\thostname"));
        assert!(lines[1].starts_with("192.168.1.10"));
        assert!(lines[2].starts_with("192.168.1.11"));

        let expected = HOST_COLUMNS.len() - 1;
        for line in &lines {
            assert_eq!(line.matches('\t').count(), expected, "in {line:?}");
        }
    }

    #[test]
    fn the_host_menu_filters_by_the_row_it_was_opened_on() {
        let host = host();
        let listed = vec![&host];
        let entries = host_entries(&host, &listed);
        assert_eq!(
            action_for(&entries, "Show only this host"),
            RowAction::Filter("host:192.168.1.10".to_string())
        );
        assert_eq!(
            action_for(&entries, "Hide this host"),
            RowAction::Refine("!host:192.168.1.10".to_string())
        );
        assert_eq!(
            action_for(&entries, "Show only http hosts"),
            RowAction::Filter("service:http".to_string())
        );
    }

    #[test]
    fn the_host_menu_can_rescan_just_that_host() {
        let host = host();
        let listed = vec![&host];
        assert_eq!(
            action_for(&host_entries(&host, &listed), "Scan this host again"),
            RowAction::Rescan {
                host: "192.168.1.10".parse().unwrap(),
                port: None
            }
        );
    }

    #[test]
    fn the_port_menu_writes_an_address_and_port_the_way_they_are_written() {
        let host = host();
        let ports: Vec<&PortReport> = host.ports.iter().collect();
        let entries = port_entries(&host, ports[0], &ports);
        assert_eq!(
            action_for(&entries, "Copy port"),
            RowAction::Copy("80/tcp".to_string())
        );
        assert_eq!(
            action_for(&entries, "Copy address and port"),
            RowAction::Copy("192.168.1.10:80".to_string())
        );
    }

    #[test]
    fn an_ipv6_address_and_port_are_bracketed() {
        let mut host = HostReport::new("fe80::1".parse().unwrap());
        host.status = HostStatus::Up;
        host.ports.push(port(443, PortState::Open, "https"));
        let ports: Vec<&PortReport> = host.ports.iter().collect();
        let entries = port_entries(&host, ports[0], &ports);
        assert_eq!(
            action_for(&entries, "Copy address and port"),
            RowAction::Copy("[fe80::1]:443".to_string())
        );
        assert_eq!(
            action_for(&entries, "Copy URL"),
            RowAction::Copy("https://[fe80::1]:443/".to_string())
        );
    }

    #[test]
    fn only_ports_that_would_answer_a_browser_offer_a_url() {
        let host = host();
        let http = port(80, PortState::Open, "http");
        let https = port(443, PortState::Open, "https");
        let ssh = port(22, PortState::Open, "ssh");
        let closed_web = port(80, PortState::Closed, "http");
        let udp = {
            let mut report =
                PortReport::new(80, Transport::Udp, PortState::Open, PortReason::UdpResponse);
            report.service = Some(ServiceInfo::from_port_number("http"));
            report
        };

        assert_eq!(web_scheme(&http), Some("http"));
        assert_eq!(web_scheme(&https), Some("https"));
        assert_eq!(web_scheme(&ssh), None, "ssh is not a web service");
        assert_eq!(
            web_scheme(&closed_web),
            None,
            "a closed port answers nobody"
        );
        assert_eq!(web_scheme(&udp), None, "there is no http over udp here");

        let listed: Vec<&PortReport> = vec![&ssh];
        assert!(!labels(&port_entries(&host, &ssh, &listed)).contains(&"Copy URL".to_string()));
    }

    #[test]
    fn a_port_with_a_banner_offers_it_and_one_without_does_not() {
        let host = host();
        let mut with_banner = port(22, PortState::Open, "ssh");
        with_banner.banner = Some("SSH-2.0-OpenSSH_9.6".to_string());
        let listed = vec![&with_banner];
        assert_eq!(
            action_for(&port_entries(&host, &with_banner, &listed), "Copy banner"),
            RowAction::Copy("SSH-2.0-OpenSSH_9.6".to_string())
        );

        let plain = port(22, PortState::Open, "ssh");
        let listed = vec![&plain];
        assert!(!labels(&port_entries(&host, &plain, &listed)).contains(&"Copy banner".to_string()));
    }

    #[test]
    fn the_port_menu_can_rescan_exactly_that_port() {
        let host = host();
        let ports: Vec<&PortReport> = host.ports.iter().collect();
        assert_eq!(
            action_for(&port_entries(&host, ports[0], &ports), "Scan 80/tcp again"),
            RowAction::Rescan {
                host: "192.168.1.10".parse().unwrap(),
                port: Some((80, Transport::Tcp)),
            }
        );
    }

    #[test]
    fn an_unidentified_service_is_not_offered_as_a_filter() {
        let host = host();
        let mystery = PortReport::new(
            9999,
            Transport::Tcp,
            PortState::Open,
            PortReason::ConnectionEstablished,
        );
        let listed = vec![&mystery];
        let labels = labels(&port_entries(&host, &mystery, &listed));
        assert!(labels.contains(&"Show only port 9999".to_string()));
        assert!(!labels.iter().any(|label| label.contains("unknown")));
    }

    #[test]
    fn every_menu_has_entries_and_no_empty_labels() {
        let host = host();
        let hosts = vec![&host];
        let ports: Vec<&PortReport> = host.ports.iter().collect();
        for entries in [
            host_entries(&host, &hosts),
            port_entries(&host, ports[0], &ports),
        ] {
            assert!(!entries.is_empty());

            assert!(matches!(entries.first(), Some(Entry::Item(..))));
            assert!(matches!(entries.last(), Some(Entry::Item(..))));
            for entry in &entries {
                if let Entry::Item(label, _) = entry {
                    assert!(!label.trim().is_empty(), "an entry has no label");
                }
            }
        }
    }

    #[test]
    fn the_two_lists_share_everything_except_their_ground() {
        let hosts = Skin::hosts(&crate::theme::DARK);
        let ports = Skin::ports(&crate::theme::DARK);

        assert_eq!(hosts.fill, crate::theme::DARK.table, "the light band");
        assert_eq!(
            ports.fill,
            crate::theme::DARK.sunken,
            "no colour of its own"
        );
        assert_ne!(hosts.fill, ports.fill);
        assert_ne!(
            hosts.ink.text, ports.ink.text,
            "different ground, different ink"
        );

        assert_eq!(hosts.selected, ports.selected);
        assert_eq!(hosts.selected_ink.text, ports.selected_ink.text);
        assert_eq!(hosts.border, ports.border);
    }

    #[test]
    fn a_cell_is_its_own_tile_and_turns_blue_when_its_row_is_picked() {
        let hosts = Skin::hosts(&crate::theme::DARK);
        assert_eq!(hosts.cell(false, false), crate::theme::DARK.table);
        assert_eq!(hosts.cell(true, false), crate::theme::DARK.selected);

        assert_eq!(hosts.cell(true, true), crate::theme::DARK.selected);
        assert_eq!(hosts.cell(false, true), hosts.hover);

        let ports = Skin::ports(&crate::theme::DARK);
        assert_eq!(ports.cell(false, false), ports.container);
        assert_eq!(ports.cell(true, false), hosts.cell(true, false));
    }

    #[test]
    fn column_headings_are_drawn_for_the_container_not_for_the_cells() {
        let hosts = Skin::hosts(&crate::theme::DARK);
        assert_eq!(hosts.header_ink, crate::theme::DARK.ink());
        assert_ne!(
            hosts.header_ink.text, hosts.ink.text,
            "the heading and the data are on different grounds here"
        );

        let ports = Skin::ports(&crate::theme::DARK);
        assert_eq!(ports.header_ink.text, ports.ink.text);
    }

    #[test]
    fn cells_meet_with_nothing_showing_between_them() {
        assert_eq!(CELL_GAP, 0.0);
    }

    #[test]
    fn a_row_takes_its_ink_from_the_ground_it_is_on() {
        for skin in [
            Skin::hosts(&crate::theme::DARK),
            Skin::ports(&crate::theme::DARK),
        ] {
            assert_eq!(skin.row_ink(false), skin.ink);
            assert_eq!(skin.row_ink(true), skin.selected_ink);

            assert_ne!(skin.row_ink(true).text, skin.ink.text);
        }
    }

    #[test]
    fn the_light_band_is_recognised_as_light_and_the_recess_as_dark() {
        assert!(is_light(crate::theme::DARK.table));
        assert!(!is_light(crate::theme::DARK.sunken));
        assert!(!is_light(crate::theme::DARK.selected));
    }

    #[test]
    fn headings_are_written_the_way_they_are_read() {
        let ink = crate::theme::TABLE_INK;
        let text = heading("Hostname", &ink);
        assert_eq!(text.text(), "Hostname");
        assert!(!text.text().contains('\u{2009}'));
    }

    #[test]
    fn rows_are_no_taller_than_the_text_needs() {
        let ctx = egui::Context::default();
        crate::theme::apply(&ctx);
        let mut height = 0.0;
        let mut once = Some(());
        let _ = ctx.run(Default::default(), |ctx| {
            if once.take().is_some() {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let text = ui.text_style_height(&egui::TextStyle::Body);
                    height = row_height(ui) / text;
                });
            }
        });
        assert!(
            height > 1.0 && height < 1.4,
            "a row is {height:.2}× its text, which is not dense"
        );
    }

    #[test]
    fn no_two_entries_in_a_menu_share_a_label() {
        let host = host();
        let hosts = vec![&host];
        let ports: Vec<&PortReport> = host.ports.iter().collect();
        for entries in [
            host_entries(&host, &hosts),
            port_entries(&host, ports[0], &ports),
        ] {
            let mut seen = labels(&entries);
            let before = seen.len();
            seen.sort();
            seen.dedup();
            assert_eq!(before, seen.len(), "a menu repeats a label");
        }
    }
}
