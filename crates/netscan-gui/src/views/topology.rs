use std::collections::BTreeMap;

use egui::{Color32, Pos2, Rect, Sense, Stroke, Ui, Vec2};
use ipnet::IpNet;
use netscan_core::{HostReport, HostStatus};

use crate::widgets::{self, muted, palette};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Gateway,
    Server,
    Printer,
    Endpoint,
}

impl Role {
    pub fn label(self) -> &'static str {
        match self {
            Role::Gateway => "gateway?",
            Role::Server => "server",
            Role::Printer => "printer",
            Role::Endpoint => "host",
        }
    }

    pub fn colour(self) -> Color32 {
        match self {
            Role::Gateway => palette::changed(),
            Role::Server => palette::open(),
            Role::Printer => palette::filtered(),
            Role::Endpoint => palette::muted(),
        }
    }
}

pub fn infer_role(host: &HostReport) -> Role {
    let vendor_is_network = host
        .vendor
        .as_deref()
        .and_then(netscan_core::detection::oui::device_hint)
        .is_some_and(|hint| hint == "network device");

    let device_type = host.os.as_ref().and_then(|os| os.device_type.as_deref());
    if device_type == Some("printer") {
        return Role::Printer;
    }
    if device_type == Some("network device") || vendor_is_network {
        return Role::Gateway;
    }

    let open: Vec<u16> = host.open_ports().map(|p| p.port).collect();
    if open.iter().any(|p| matches!(p, 9100 | 515 | 631)) {
        return Role::Printer;
    }

    let router_ports = open
        .iter()
        .filter(|p| matches!(**p, 53 | 67 | 80 | 443 | 8080 | 23))
        .count();
    if router_ports >= 3 && open.len() <= 6 && host.address.to_string().ends_with(".1") {
        return Role::Gateway;
    }
    if open
        .iter()
        .any(|p| matches!(p, 80 | 443 | 22 | 3306 | 5432 | 8080))
    {
        return Role::Server;
    }
    Role::Endpoint
}

#[derive(Debug, Clone, PartialEq)]
pub struct Subnet {
    pub network: IpNet,
    pub directly_attached: bool,
    pub hosts: Vec<(std::net::IpAddr, Role)>,
}

pub fn group_by_subnet(hosts: &[&HostReport], local_networks: &[IpNet]) -> Vec<Subnet> {
    let mut groups: BTreeMap<String, Subnet> = BTreeMap::new();

    for host in hosts.iter().filter(|h| h.status == HostStatus::Up) {
        let network = netscan_core::scanner::target::enclosing_block(host.address);
        let attached = local_networks
            .iter()
            .any(|local| local.contains(&host.address));
        let entry = groups.entry(network.to_string()).or_insert_with(|| Subnet {
            network,
            directly_attached: attached,
            hosts: Vec::new(),
        });
        entry.directly_attached |= attached;
        entry.hosts.push((host.address, infer_role(host)));
    }

    let mut subnets: Vec<Subnet> = groups.into_values().collect();
    for subnet in &mut subnets {
        subnet.hosts.sort_by_key(|(address, _)| *address);
    }

    subnets.sort_by(|a, b| {
        b.directly_attached
            .cmp(&a.directly_attached)
            .then_with(|| b.hosts.len().cmp(&a.hosts.len()))
            .then_with(|| a.network.to_string().cmp(&b.network.to_string()))
    });
    subnets
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Subnet,
    Host,
    Service,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub kind: NodeKind,
    pub label: String,
    pub detail: String,
    pub tooltip: String,
    pub address: Option<std::net::IpAddr>,
    pub rect: Rect,
    pub colour: Color32,
}

#[derive(Debug, Clone, Default)]
pub struct Graph {
    pub nodes: Vec<Node>,
    pub edges: Vec<(usize, usize)>,
}

impl Graph {
    pub fn bounds(&self) -> Rect {
        let mut bounds = Rect::NOTHING;
        for node in &self.nodes {
            bounds = bounds.union(node.rect);
        }
        bounds
    }
}

const SUBNET_WIDTH: f32 = 170.0;
const HOST_WIDTH: f32 = 190.0;
const SERVICE_WIDTH: f32 = 140.0;

const NODE_HEIGHT: f32 = 32.0;
const NODE_GAP: f32 = 8.0;

const COLUMN_GAP: f32 = 130.0;

pub fn layout(subnets: &[Subnet], hosts: &[&HostReport], services: bool) -> Graph {
    let mut graph = Graph::default();
    let by_address: BTreeMap<std::net::IpAddr, &&HostReport> =
        hosts.iter().map(|host| (host.address, host)).collect();

    let mut service_hosts: BTreeMap<String, Vec<std::net::IpAddr>> = BTreeMap::new();
    for subnet in subnets {
        for (address, _) in &subnet.hosts {
            if let Some(host) = by_address.get(address) {
                let mut names: Vec<&str> = host.open_ports().map(|p| p.service_name()).collect();
                names.sort_unstable();
                names.dedup();
                for name in names {
                    service_hosts
                        .entry(name.to_string())
                        .or_default()
                        .push(*address);
                }
            }
        }
    }
    let mut service_list: Vec<(String, Vec<std::net::IpAddr>)> =
        service_hosts.into_iter().collect();
    service_list.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(&b.0)));

    let mut host_index: BTreeMap<std::net::IpAddr, usize> = BTreeMap::new();
    let mut y = 0.0_f32;
    let host_x = SUBNET_WIDTH + COLUMN_GAP;

    for subnet in subnets {
        let block_top = y;
        let mut members: Vec<usize> = Vec::new();

        for (address, role) in &subnet.hosts {
            let host = by_address.get(address);
            let open = host.map(|h| h.open_port_count()).unwrap_or(0);
            let name = host.and_then(|h| h.primary_hostname()).unwrap_or("");
            let identity = host
                .map(|h| super::results::identity(h))
                .unwrap_or_default();

            let detail = if !name.is_empty() {
                widgets::ellipsise(name, 24)
            } else if !identity.is_empty() {
                widgets::ellipsise(&identity, 24)
            } else {
                role.label().to_string()
            };

            let mut tooltip = format!("{address}\n{} — inferred", role.label());
            if !name.is_empty() {
                tooltip.push_str(&format!("\nname: {name}"));
            }
            if !identity.is_empty() {
                tooltip.push_str(&format!("\n{identity}"));
            }
            if let Some(host) = host {
                tooltip.push_str(&format!("\n{open} open port(s)"));
                tooltip.push_str(&format!("\nlatency: {}", widgets::rtt(host.rtt_ms)));
                if let Some(mac) = host.mac {
                    tooltip.push_str(&format!("\nMAC: {mac}"));
                }
            }

            graph.nodes.push(Node {
                kind: NodeKind::Host,
                label: address.to_string(),
                detail,
                tooltip,
                address: Some(*address),
                rect: Rect::from_min_size(Pos2::new(host_x, y), Vec2::new(HOST_WIDTH, NODE_HEIGHT)),
                colour: role.colour(),
            });
            members.push(graph.nodes.len() - 1);
            host_index.insert(*address, graph.nodes.len() - 1);
            y += NODE_HEIGHT + NODE_GAP;
        }

        let block_bottom = (y - NODE_GAP).max(block_top + NODE_HEIGHT);
        let centre = (block_top + block_bottom) / 2.0 - NODE_HEIGHT / 2.0;
        graph.nodes.push(Node {
            kind: NodeKind::Subnet,
            label: subnet.network.to_string(),
            detail: format!(
                "{} host(s){}",
                subnet.hosts.len(),
                if subnet.directly_attached {
                    " · attached"
                } else {
                    ""
                }
            ),
            tooltip: format!(
                "{}\n{} host(s) found\n{}",
                subnet.network,
                subnet.hosts.len(),
                if subnet.directly_attached {
                    "directly attached to this machine"
                } else {
                    "not directly attached"
                }
            ),
            address: None,
            rect: Rect::from_min_size(Pos2::new(0.0, centre), Vec2::new(SUBNET_WIDTH, NODE_HEIGHT)),
            colour: if subnet.directly_attached {
                palette::open()
            } else {
                palette::muted()
            },
        });
        let subnet_index = graph.nodes.len() - 1;
        for member in members {
            graph.edges.push((subnet_index, member));
        }

        y += NODE_GAP * 2.0;
    }

    if !services {
        return graph;
    }
    let service_x = host_x + HOST_WIDTH + COLUMN_GAP;
    let mut service_y = 0.0_f32;
    for (name, offered_by) in &service_list {
        graph.nodes.push(Node {
            kind: NodeKind::Service,
            label: name.clone(),
            detail: format!("{} host(s)", offered_by.len()),
            tooltip: format!("{name}\noffered by {} host(s)", offered_by.len()),
            address: None,
            rect: Rect::from_min_size(
                Pos2::new(service_x, service_y),
                Vec2::new(SERVICE_WIDTH, NODE_HEIGHT),
            ),
            colour: palette::changed(),
        });
        let service_index = graph.nodes.len() - 1;
        for address in offered_by {
            if let Some(host) = host_index.get(address) {
                graph.edges.push((*host, service_index));
            }
        }
        service_y += NODE_HEIGHT + NODE_GAP;
    }

    graph
}

#[derive(Debug, Clone)]
pub struct Viewport {
    pub offset: Vec2,
    pub zoom: f32,
    pub placed: bool,
    pub moved: BTreeMap<String, Vec2>,
    pub dragging: Option<String>,
    pub show_services: bool,
    pub search: String,
}

impl Default for Viewport {
    fn default() -> Self {
        Self {
            offset: Vec2::ZERO,
            zoom: 1.0,
            placed: false,
            moved: BTreeMap::new(),
            dragging: None,
            show_services: true,
            search: String::new(),
        }
    }
}

impl Viewport {
    pub fn id() -> egui::Id {
        egui::Id::new("topology-viewport")
    }

    pub fn new() -> Self {
        Self::default()
    }

    fn placement(&self, node: &Node) -> Rect {
        match self.moved.get(&node.label) {
            Some(delta) => node.rect.translate(*delta),
            None => node.rect,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TopologyOutcome {
    pub selected: Option<std::net::IpAddr>,
    pub opened: Option<std::net::IpAddr>,
    pub action: Option<super::table::RowAction>,
}

pub fn show(
    ui: &mut Ui,
    hosts: &[&HostReport],
    local_networks: &[IpNet],
    selected: Option<std::net::IpAddr>,
) -> TopologyOutcome {
    let subnets = group_by_subnet(hosts, local_networks);

    if subnets.is_empty() {
        super::results::empty(
            ui,
            "Nothing to place yet.",
            "Hosts appear here, grouped by subnet, as a scan finds them.",
        );
        return TopologyOutcome::default();
    }

    let id = Viewport::id();
    let mut viewport: Viewport = ui.data(|data| data.get_temp(id)).unwrap_or_default();

    ui.horizontal(|ui| {
        for role in [Role::Gateway, Role::Server, Role::Printer, Role::Endpoint] {
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(9.0), Sense::hover());
            ui.painter()
                .rect_filled(rect, egui::Rounding::same(2.0), role.colour());
            ui.label(
                egui::RichText::new(role.label())
                    .size(11.0)
                    .color(palette::muted()),
            );
            ui.add_space(crate::theme::UNIT);
        }

        ui.separator();
        ui.checkbox(&mut viewport.show_services, "Services")
            .on_hover_text("Draw the third column: which services each host offers");

        ui.separator();
        ui.label(muted("Find"));
        ui.add(
            egui::TextEdit::singleline(&mut viewport.search)
                .hint_text("address, name or service")
                .desired_width(160.0),
        )
        .on_hover_text("Everything that does not match is dimmed");
        if !viewport.search.is_empty() && ui.small_button("✕").clicked() {
            viewport.search.clear();
        }

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .button("Fit")
                .on_hover_text("Fit the whole graph in the pane, and put back anything moved")
                .clicked()
            {
                let search = std::mem::take(&mut viewport.search);
                let services = viewport.show_services;
                viewport = Viewport::new();
                viewport.search = search;
                viewport.show_services = services;
            }
            if ui.button("+").on_hover_text("Zoom in").clicked() {
                viewport.zoom = (viewport.zoom * 1.25).clamp(ZOOM_RANGE.0, ZOOM_RANGE.1);
            }
            ui.label(
                egui::RichText::new(format!("{:.0}%", viewport.zoom * 100.0))
                    .size(11.0)
                    .color(palette::muted()),
            );
            if ui.button("−").on_hover_text("Zoom out").clicked() {
                viewport.zoom = (viewport.zoom / 1.25).clamp(ZOOM_RANGE.0, ZOOM_RANGE.1);
            }
        });
    });
    ui.label(muted(
        "Subnets → hosts → services · drag the background to pan, a node to move it, \
         scroll to zoom · click to select, double-click to open, right-click for more",
    ));
    ui.separator();

    let graph = layout(&subnets, hosts, viewport.show_services);
    let outcome = canvas(ui, &graph, hosts, selected, &mut viewport, id);
    ui.data_mut(|data| data.insert_temp(id, viewport));
    outcome
}

const ZOOM_RANGE: (f32, f32) = (0.15, 3.0);

pub fn matches(node: &Node, term: &str) -> bool {
    let term = term.trim().to_lowercase();
    if term.is_empty() {
        return true;
    }
    let haystack = format!("{} {} {}", node.label, node.detail, node.tooltip).to_lowercase();
    haystack.contains(&term)
}

fn canvas(
    ui: &mut Ui,
    graph: &Graph,
    hosts: &[&HostReport],
    selected: Option<std::net::IpAddr>,
    viewport: &mut Viewport,
    id: egui::Id,
) -> TopologyOutcome {
    let mut outcome = TopologyOutcome::default();
    let palette = crate::theme::current();
    let size = ui.available_size();
    if size.x < 1.0 || size.y < 1.0 {
        return outcome;
    }
    let response = ui.allocate_rect(
        Rect::from_min_size(ui.next_widget_position(), size),
        Sense::click_and_drag(),
    );
    ui.advance_cursor_after_rect(response.rect);
    let painter = ui.painter().with_clip_rect(response.rect);
    let view_rect = response.rect;
    painter.rect_filled(
        view_rect,
        egui::Rounding::same(super::table::RADIUS),
        palette.sunken,
    );

    let bounds = graph.bounds();
    if !viewport.placed && bounds.width() > 0.0 && bounds.height() > 0.0 {
        let margin = 24.0;
        let scale = ((view_rect.width() - margin * 2.0) / bounds.width())
            .min((view_rect.height() - margin * 2.0) / bounds.height())
            .clamp(0.2, 1.4);
        viewport.zoom = scale;
        viewport.offset = view_rect.center().to_vec2() - bounds.center().to_vec2() * scale;
        viewport.placed = true;
    }

    let to_screen = |rect: Rect, viewport: &Viewport| -> Rect {
        Rect::from_min_size(
            (rect.min.to_vec2() * viewport.zoom + viewport.offset).to_pos2(),
            rect.size() * viewport.zoom,
        )
    };
    let node_at = |position: Pos2, viewport: &Viewport| -> Option<usize> {
        graph
            .nodes
            .iter()
            .enumerate()
            .rev()
            .find(|(_, node)| to_screen(viewport.placement(node), viewport).contains(position))
            .map(|(index, _)| index)
    };

    if response.drag_started() {
        viewport.dragging = response
            .interact_pointer_pos()
            .and_then(|position| node_at(position, viewport))
            .and_then(|index| graph.nodes.get(index))
            .map(|node| node.label.clone());
    }
    if response.dragged() {
        let delta = response.drag_delta() / viewport.zoom;
        match viewport.dragging.clone() {
            Some(label) => *viewport.moved.entry(label).or_default() += delta,
            None => viewport.offset += response.drag_delta(),
        }
    }
    if response.drag_stopped() {
        viewport.dragging = None;
    }

    if response.hovered() {
        let scroll = ui.input(|i| i.smooth_scroll_delta.y);
        if scroll.abs() > 0.1 {
            let anchor = ui
                .input(|i| i.pointer.hover_pos())
                .unwrap_or(view_rect.center());
            let factor = (1.0 + scroll * 0.002).clamp(0.85, 1.15);
            let before = (anchor.to_vec2() - viewport.offset) / viewport.zoom;
            viewport.zoom = (viewport.zoom * factor).clamp(ZOOM_RANGE.0, ZOOM_RANGE.1);
            viewport.offset = anchor.to_vec2() - before * viewport.zoom;
        }
    }

    let pointer = response.hover_pos();
    let hovered = pointer.and_then(|position| node_at(position, viewport));
    let connected = |index: usize| -> bool {
        match hovered {
            None => false,
            Some(hovered) => {
                index == hovered
                    || graph.edges.iter().any(|(from, to)| {
                        (*from == hovered && *to == index) || (*to == hovered && *from == index)
                    })
            }
        }
    };

    let searching = !viewport.search.trim().is_empty();
    let lit = |index: usize| -> bool {
        if hovered.is_some() {
            return connected(index);
        }
        !searching
            || graph
                .nodes
                .get(index)
                .is_some_and(|n| matches(n, &viewport.search))
    };
    let anything_dimmed = hovered.is_some() || searching;

    painter.rect_stroke(
        view_rect,
        egui::Rounding::same(super::table::RADIUS),
        egui::Stroke::new(1.0_f32, palette.sunken_border),
    );
    let clip = painter;

    for (from, to) in &graph.edges {
        let (Some(source), Some(target)) = (graph.nodes.get(*from), graph.nodes.get(*to)) else {
            continue;
        };
        let a = to_screen(viewport.placement(source), viewport);
        let b = to_screen(viewport.placement(target), viewport);
        let both = lit(*from) && lit(*to);
        let colour = if anything_dimmed && both {
            target.colour
        } else if anything_dimmed {
            palette.line.gamma_multiply(0.35)
        } else {
            palette.line.gamma_multiply(0.8)
        };
        dotted_curve(
            &clip,
            Pos2::new(a.right(), a.center().y),
            Pos2::new(b.left(), b.center().y),
            Stroke::new(
                if anything_dimmed && both {
                    1.6_f32
                } else {
                    1.0_f32
                },
                colour,
            ),
        );
    }

    for (index, node) in graph.nodes.iter().enumerate() {
        let rect = to_screen(viewport.placement(node), viewport);
        if !view_rect.intersects(rect) {
            continue;
        }
        let is_selected = node.address.is_some() && node.address == selected;
        let dimmed = anything_dimmed && !lit(index);

        let fill = if is_selected {
            node.colour.gamma_multiply(0.30)
        } else {
            palette.window
        };
        let outline = if dimmed {
            node.colour.gamma_multiply(0.3)
        } else {
            node.colour
        };
        clip.rect_filled(rect, egui::Rounding::same(3.0), fill);
        clip.rect_stroke(
            rect,
            egui::Rounding::same(3.0),
            Stroke::new(if is_selected { 2.0_f32 } else { 1.0_f32 }, outline),
        );

        clip.rect_filled(
            Rect::from_min_size(rect.min, Vec2::new(3.0, rect.height())),
            egui::Rounding::same(1.0),
            outline,
        );

        if viewport.zoom > 0.45 {
            let ink = if dimmed { palette.faint } else { palette.text };
            clip.text(
                Pos2::new(rect.left() + 9.0, rect.center().y - 6.0),
                egui::Align2::LEFT_CENTER,
                widgets::ellipsise(&node.label, 22),
                if node.kind == NodeKind::Service {
                    egui::FontId::proportional(11.5 * viewport.zoom.clamp(0.8, 1.0))
                } else {
                    egui::FontId::monospace(11.0 * viewport.zoom.clamp(0.8, 1.0))
                },
                ink,
            );
            if !node.detail.is_empty() {
                clip.text(
                    Pos2::new(rect.left() + 9.0, rect.center().y + 7.0),
                    egui::Align2::LEFT_CENTER,
                    widgets::ellipsise(&node.detail, 24),
                    egui::FontId::proportional(9.5 * viewport.zoom.clamp(0.8, 1.0)),
                    if dimmed { palette.faint } else { palette.muted },
                );
            }
        }
    }

    if let Some(index) = hovered {
        if let Some(node) = graph.nodes.get(index) {
            if response.clicked() {
                outcome.selected = node.address;
            }
            if response.double_clicked() {
                outcome.opened = node.address;
                outcome.selected = node.address;
            }
            let hover = response.clone().on_hover_text(&node.tooltip);

            let entries = node_entries(node, hosts);
            if !entries.is_empty() {
                if let Some(action) = super::table::row_menu(&hover, &entries) {
                    outcome.action = Some(action);
                }
            }
        }
    }

    if response.dragged() {
        ui.ctx().request_repaint();
    }
    let _ = id;
    outcome
}

pub fn node_entries(node: &Node, hosts: &[&HostReport]) -> Vec<super::table::Entry> {
    use super::table::{Entry, RowAction};
    match node.kind {
        NodeKind::Host => match node
            .address
            .and_then(|address| hosts.iter().find(|host| host.address == address))
        {
            Some(host) => super::table::host_entries(host, hosts),
            None => Vec::new(),
        },
        NodeKind::Subnet => vec![
            Entry::Item(
                format!("Copy {}", node.label),
                RowAction::Copy(node.label.clone()),
            ),
            Entry::Item(
                "Show only this subnet".to_string(),
                RowAction::Filter(format!("net:{}", node.label)),
            ),
        ],
        NodeKind::Service => vec![
            Entry::Item(
                format!("Copy \"{}\"", node.label),
                RowAction::Copy(node.label.clone()),
            ),
            Entry::Item(
                format!("Show only {} hosts", node.label),
                RowAction::Filter(format!("service:{}", node.label)),
            ),
        ],
    }
}

fn dotted_curve(painter: &egui::Painter, a: Pos2, b: Pos2, stroke: Stroke) {
    let reach = ((b.x - a.x).abs() * 0.45).clamp(20.0, 140.0);
    let c1 = Pos2::new(a.x + reach, a.y);
    let c2 = Pos2::new(b.x - reach, b.y);

    const STEPS: usize = 28;
    let point = |t: f32| -> Pos2 {
        let u = 1.0 - t;
        let v = a.to_vec2() * (u * u * u)
            + c1.to_vec2() * (3.0 * u * u * t)
            + c2.to_vec2() * (3.0 * u * t * t)
            + b.to_vec2() * (t * t * t);
        v.to_pos2()
    };

    let mut previous = point(0.0);
    for step in 1..=STEPS {
        let next = point(step as f32 / STEPS as f32);
        if step % 3 != 0 {
            painter.line_segment([previous, next], stroke);
        }
        previous = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netscan_core::{OsGuess, PortReason, PortReport, PortState, Transport};

    fn host(address: &str, ports: &[u16]) -> HostReport {
        let mut host = HostReport::new(address.parse().unwrap());
        host.status = HostStatus::Up;
        for port in ports {
            host.ports.push(PortReport::new(
                *port,
                Transport::Tcp,
                PortState::Open,
                PortReason::ConnectionEstablished,
            ));
        }
        host
    }

    #[test]
    fn hosts_are_grouped_by_their_subnet() {
        let a = host("192.168.1.10", &[80]);
        let b = host("192.168.1.20", &[22]);
        let c = host("10.0.5.7", &[443]);
        let hosts = vec![&a, &b, &c];

        let subnets = group_by_subnet(&hosts, &[]);
        assert_eq!(subnets.len(), 2);
        let first = subnets
            .iter()
            .find(|s| s.network.to_string() == "192.168.1.0/24")
            .unwrap();
        assert_eq!(first.hosts.len(), 2);
    }

    #[test]
    fn hosts_that_are_down_are_not_placed() {
        let mut down = host("192.168.1.30", &[]);
        down.status = HostStatus::Down;
        let up = host("192.168.1.10", &[80]);

        let subnets = group_by_subnet(&[&up, &down], &[]);
        assert_eq!(
            subnets[0].hosts.len(),
            1,
            "a host that did not answer is not on the network map"
        );
    }

    #[test]
    fn directly_attached_networks_are_flagged_and_come_first() {
        let local: IpNet = "192.168.1.0/24".parse().unwrap();
        let a = host("10.0.0.5", &[80]);
        let b = host("10.0.0.6", &[80]);
        let c = host("192.168.1.10", &[80]);

        let subnets = group_by_subnet(&[&a, &b, &c], &[local]);
        assert!(subnets[0].directly_attached);
        assert_eq!(subnets[0].network.to_string(), "192.168.1.0/24");
        assert!(!subnets[1].directly_attached);
    }

    #[test]
    fn hosts_within_a_subnet_are_ordered_by_address() {
        let a = host("192.168.1.30", &[80]);
        let b = host("192.168.1.2", &[80]);
        let subnets = group_by_subnet(&[&a, &b], &[]);
        assert_eq!(subnets[0].hosts[0].0.to_string(), "192.168.1.2");
    }

    #[test]
    fn printers_are_recognised_by_their_ports() {
        assert_eq!(infer_role(&host("10.0.0.5", &[9100, 631])), Role::Printer);
    }

    #[test]
    fn printers_are_recognised_from_the_device_type() {
        let mut printer = host("10.0.0.5", &[80]);
        printer.os = Some(OsGuess {
            device_type: Some("printer".to_string()),
            ..Default::default()
        });
        assert_eq!(infer_role(&printer), Role::Printer);
    }

    #[test]
    fn network_hardware_vendors_suggest_a_gateway() {
        let mut router = host("10.0.0.1", &[80]);
        router.vendor = Some("Ubiquiti Networks".to_string());
        assert_eq!(infer_role(&router), Role::Gateway);
    }

    #[test]
    fn servers_are_recognised_by_their_services() {
        assert_eq!(
            infer_role(&host("10.0.0.20", &[22, 443, 5432])),
            Role::Server
        );
    }

    #[test]
    fn a_host_with_nothing_distinctive_is_not_over_claimed() {
        assert_eq!(infer_role(&host("10.0.0.99", &[])), Role::Endpoint);
        assert_eq!(infer_role(&host("10.0.0.99", &[49152])), Role::Endpoint);
    }

    #[test]
    fn the_graph_has_a_column_for_each_kind_of_thing() {
        let hosts = [host("10.0.0.1", &[80, 443]), host("10.0.0.2", &[22])];
        let refs: Vec<&HostReport> = hosts.iter().collect();
        let subnets = group_by_subnet(&refs, &[]);
        let graph = layout(&subnets, &refs, true);

        let kinds = |kind: NodeKind| -> Vec<&Node> {
            graph.nodes.iter().filter(|n| n.kind == kind).collect()
        };
        assert_eq!(kinds(NodeKind::Subnet).len(), 1);
        assert_eq!(kinds(NodeKind::Host).len(), 2);

        assert_eq!(kinds(NodeKind::Service).len(), 3);

        let column = |kind: NodeKind| kinds(kind)[0].rect.left();
        assert!(column(NodeKind::Subnet) < column(NodeKind::Host));
        assert!(column(NodeKind::Host) < column(NodeKind::Service));
    }

    #[test]
    fn every_edge_runs_left_to_right_between_real_nodes() {
        let hosts = [host("10.0.0.1", &[80]), host("192.168.1.5", &[22, 80])];
        let refs: Vec<&HostReport> = hosts.iter().collect();
        let graph = layout(&group_by_subnet(&refs, &[]), &refs, true);

        assert!(!graph.edges.is_empty());
        for (from, to) in &graph.edges {
            let source = graph.nodes.get(*from).expect("edge source exists");
            let target = graph.nodes.get(*to).expect("edge target exists");
            assert!(
                source.rect.left() < target.rect.left(),
                "an edge from {:?} to {:?} runs backwards",
                source.label,
                target.label
            );
        }
    }

    #[test]
    fn a_host_is_joined_to_its_own_subnet_and_its_own_services() {
        let hosts = [host("10.0.0.1", &[80]), host("192.168.1.5", &[22])];
        let refs: Vec<&HostReport> = hosts.iter().collect();
        let graph = layout(&group_by_subnet(&refs, &[]), &refs, true);

        let index = |label: &str| {
            graph
                .nodes
                .iter()
                .position(|node| node.label == label)
                .unwrap_or_else(|| panic!("no node called {label}"))
        };
        let joined = |a: usize, b: usize| {
            graph
                .edges
                .iter()
                .any(|(from, to)| (*from == a && *to == b) || (*from == b && *to == a))
        };

        assert!(joined(index("10.0.0.0/24"), index("10.0.0.1")));
        assert!(joined(index("10.0.0.1"), index("http")));

        assert!(!joined(index("10.0.0.0/24"), index("192.168.1.5")));
        assert!(!joined(index("10.0.0.1"), index("ssh")));
    }

    #[test]
    fn nodes_do_not_sit_on_top_of_each_other() {
        let hosts: Vec<HostReport> = (1..=12)
            .map(|n| host(&format!("10.0.0.{n}"), &[22, 80]))
            .collect();
        let refs: Vec<&HostReport> = hosts.iter().collect();
        let graph = layout(&group_by_subnet(&refs, &[]), &refs, true);

        for (i, a) in graph.nodes.iter().enumerate() {
            for b in graph.nodes.iter().skip(i + 1) {
                let overlap = a.rect.intersect(b.rect);
                assert!(
                    overlap.width() <= 0.0 || overlap.height() <= 0.0,
                    "{} overlaps {}",
                    a.label,
                    b.label
                );
            }
        }
    }

    #[test]
    fn a_subnet_node_sits_beside_the_hosts_it_owns() {
        let hosts: Vec<HostReport> = (1..=6)
            .map(|n| host(&format!("10.0.0.{n}"), &[80]))
            .collect();
        let refs: Vec<&HostReport> = hosts.iter().collect();
        let graph = layout(&group_by_subnet(&refs, &[]), &refs, true);

        let subnet = graph
            .nodes
            .iter()
            .find(|node| node.kind == NodeKind::Subnet)
            .expect("a subnet node");
        let block = graph
            .nodes
            .iter()
            .filter(|node| node.kind == NodeKind::Host)
            .fold(Rect::NOTHING, |acc, node| acc.union(node.rect));
        assert!(
            (subnet.rect.center().y - block.center().y).abs() < 1.0,
            "the subnet should be centred on its hosts: {:?} vs {:?}",
            subnet.rect.center(),
            block.center()
        );
    }

    #[test]
    fn an_empty_scan_lays_out_to_an_empty_graph() {
        let graph = layout(&[], &[], true);
        assert!(graph.nodes.is_empty());
        assert!(graph.edges.is_empty());

        let _ = graph.bounds();
    }

    #[test]
    fn services_are_ordered_with_the_most_common_first() {
        let hosts = [
            host("10.0.0.1", &[80]),
            host("10.0.0.2", &[80]),
            host("10.0.0.3", &[22]),
        ];
        let refs: Vec<&HostReport> = hosts.iter().collect();
        let graph = layout(&group_by_subnet(&refs, &[]), &refs, true);

        let services: Vec<&Node> = graph
            .nodes
            .iter()
            .filter(|node| node.kind == NodeKind::Service)
            .collect();
        assert_eq!(services[0].label, "http", "two hosts offer http");
        assert!(services[0].rect.top() < services[1].rect.top());
    }

    #[test]
    fn gateway_guesses_are_labelled_as_guesses() {
        assert!(
            Role::Gateway.label().ends_with('?'),
            "an inferred gateway must not be presented as a fact"
        );
        assert!(!Role::Server.label().is_empty());
    }

    #[test]
    fn turning_the_services_off_leaves_the_network_behind() {
        let hosts = [host("10.0.0.1", &[80, 443]), host("10.0.0.2", &[22])];
        let refs: Vec<&HostReport> = hosts.iter().collect();
        let subnets = group_by_subnet(&refs, &[]);

        let full = layout(&subnets, &refs, true);
        let plain = layout(&subnets, &refs, false);

        assert!(full.nodes.iter().any(|n| n.kind == NodeKind::Service));
        assert!(!plain.nodes.iter().any(|n| n.kind == NodeKind::Service));

        let hosts_and_subnets = |graph: &Graph| -> usize {
            graph
                .nodes
                .iter()
                .filter(|n| n.kind != NodeKind::Service)
                .count()
        };
        assert_eq!(hosts_and_subnets(&full), hosts_and_subnets(&plain));
        assert_eq!(plain.edges.len(), 2, "each host still joins its subnet");
        for (from, to) in &plain.edges {
            assert!(plain.nodes.get(*from).is_some() && plain.nodes.get(*to).is_some());
        }
    }

    #[test]
    fn find_matches_a_node_by_anything_it_knows() {
        let hosts = [host("10.0.0.1", &[80])];
        let refs: Vec<&HostReport> = hosts.iter().collect();
        let graph = layout(&group_by_subnet(&refs, &[]), &refs, true);
        let node = |label: &str| {
            graph
                .nodes
                .iter()
                .find(|n| n.label == label)
                .unwrap_or_else(|| panic!("no node called {label}"))
        };

        let host_node = node("10.0.0.1");
        assert!(matches(host_node, "10.0.0"), "by address");
        assert!(matches(host_node, "10.0.0.1"), "by whole address");
        assert!(matches(host_node, "SERVER"), "case-insensitively");
        assert!(matches(host_node, "  server  "), "ignoring stray spaces");
        assert!(!matches(host_node, "10.0.0.2"));

        assert!(matches(node("http"), "http"));
        assert!(
            matches(host_node, ""),
            "an empty search matches everything, so the box is quiet until used"
        );
    }

    #[test]
    fn a_host_node_offers_the_same_menu_as_its_row() {
        let hosts = [host("10.0.0.1", &[80])];
        let refs: Vec<&HostReport> = hosts.iter().collect();
        let graph = layout(&group_by_subnet(&refs, &[]), &refs, true);

        let host_node = graph
            .nodes
            .iter()
            .find(|n| n.kind == NodeKind::Host)
            .expect("a host node");
        assert_eq!(
            node_entries(host_node, &refs),
            super::super::table::host_entries(refs[0], &refs),
            "a host means the same thing on the map as in the list"
        );
    }

    #[test]
    fn subnet_and_service_nodes_offer_the_filter_that_narrows_to_them() {
        use super::super::table::{Entry, RowAction};
        let hosts = [host("10.0.0.1", &[80])];
        let refs: Vec<&HostReport> = hosts.iter().collect();
        let graph = layout(&group_by_subnet(&refs, &[]), &refs, true);

        let filters: Vec<String> = graph
            .nodes
            .iter()
            .filter(|n| n.kind != NodeKind::Host)
            .flat_map(|n| node_entries(n, &refs))
            .filter_map(|entry| match entry {
                Entry::Item(_, RowAction::Filter(expression)) => Some(expression),
                _ => None,
            })
            .collect();
        assert!(filters.contains(&"net:10.0.0.0/24".to_string()));
        assert!(filters.contains(&"service:http".to_string()));

        for expression in filters {
            let filter = crate::filter::Filter::parse(&expression);
            assert!(
                filter.errors.is_empty(),
                "{expression:?} did not parse: {:?}",
                filter.errors
            );
        }
    }

    #[test]
    fn a_node_with_no_host_behind_it_offers_an_empty_menu_rather_than_a_broken_one() {
        let node = Node {
            kind: NodeKind::Host,
            label: "10.0.0.1".to_string(),
            detail: String::new(),
            tooltip: String::new(),
            address: Some("10.0.0.1".parse().unwrap()),
            rect: Rect::from_min_size(Pos2::ZERO, Vec2::splat(10.0)),
            colour: Color32::WHITE,
        };
        assert!(node_entries(&node, &[]).is_empty());
    }

    #[test]
    fn ipv6_hosts_are_grouped_by_their_prefix() {
        let a = host("2001:db8::1", &[80]);
        let b = host("2001:db8::2", &[80]);
        let subnets = group_by_subnet(&[&a, &b], &[]);
        assert_eq!(subnets.len(), 1);
        assert_eq!(subnets[0].network.to_string(), "2001:db8::/64");
    }
}
