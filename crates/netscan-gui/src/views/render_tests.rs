use egui::Context;
use ipnet::IpNet;
use netscan_core::{
    HostReport, HostStatus, PortReason, PortReport, PortState, ServiceInfo, Transport,
};

use crate::filter::Filter;
use crate::session::LiveResults;
use crate::views::results::ResultsState;

fn frame(size: egui::Vec2, contents: impl FnOnce(&mut egui::Ui)) {
    let ctx = Context::default();

    crate::theme::apply(&ctx);
    let input = egui::RawInput {
        screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
        ..Default::default()
    };

    let mut contents = Some(contents);
    let _ = ctx.run(input, |ctx| {
        if let Some(contents) = contents.take() {
            egui::CentralPanel::default().show(ctx, contents);
        }
    });
}

fn host(address: &str, ports: &[(u16, PortState, &str)]) -> HostReport {
    let mut host = HostReport::new(address.parse().unwrap());
    host.status = HostStatus::Up;
    host.rtt_ms = Some(4.25);
    host.mac = Some("aa:bb:cc:dd:ee:ff".parse().unwrap());
    host.vendor = Some("Example Networks".to_string());
    host.add_hostname(
        "device.local",
        netscan_core::scanner::result::HostnameSource::ReverseDns,
    );
    for (number, state, service) in ports {
        let mut port = PortReport::new(
            *number,
            Transport::Tcp,
            *state,
            PortReason::ConnectionEstablished,
        );
        port.service = Some(ServiceInfo::from_port_number(*service));
        port.rtt_ms = Some(2.0);
        host.ports.push(port);
    }
    host
}

fn populated() -> Vec<HostReport> {
    vec![
        host(
            "192.168.1.1",
            &[
                (53, PortState::Open, "domain"),
                (80, PortState::Open, "http"),
                (443, PortState::Open, "https"),
            ],
        ),
        host("192.168.1.20", &[(22, PortState::Open, "ssh")]),
        host("192.168.1.31", &[]),
        host("10.8.0.2", &[(443, PortState::Open, "https")]),
    ]
}

fn live(hosts: &[HostReport]) -> LiveResults {
    let mut results = LiveResults::default();
    for host in hosts {
        results.hosts.insert(host.address, host.clone());
    }
    results.progress.hosts_total = hosts.len() as u64;
    results.progress.hosts_up = hosts.len() as u64;
    results.progress.probes_completed = 400;
    results.progress.elapsed = std::time::Duration::from_secs(3);
    results
}

const SIZES: &[(f32, f32)] = &[(1280.0, 800.0), (420.0, 300.0), (60.0, 40.0)];

#[test]
fn the_host_table_draws_at_every_size() {
    let hosts = populated();
    for (width, height) in SIZES {
        let refs: Vec<&HostReport> = hosts.iter().collect();
        let mut state = ResultsState::default();
        frame(egui::vec2(*width, *height), |ui| {
            crate::views::results::host_table(ui, &refs, &mut state);
        });
    }
}

#[test]
fn an_empty_host_table_draws_rather_than_collapsing() {
    for (width, height) in SIZES {
        let mut state = ResultsState::default();
        frame(egui::vec2(*width, *height), |ui| {
            crate::views::results::host_table(ui, &[], &mut state);
        });
    }
}

#[test]
fn the_host_table_draws_with_a_row_selected_and_by_every_ordering() {
    use crate::views::results::HostSort;
    let hosts = populated();
    for sort in [
        HostSort::Address,
        HostSort::Hostname,
        HostSort::Status,
        HostSort::Role,
        HostSort::OpenPorts,
        HostSort::Tested,
        HostSort::Latency,
        HostSort::Mac,
        HostSort::Vendor,
        HostSort::Os,
        HostSort::Services,
    ] {
        for descending in [false, true] {
            let mut state = ResultsState {
                sort,
                descending,
                selected: Some(hosts[0].address),
                ..Default::default()
            };
            let visible =
                crate::views::results::visible_hosts(hosts.iter(), &Filter::default(), &state);
            frame(egui::vec2(1280.0, 800.0), |ui| {
                crate::views::results::host_table(ui, &visible, &mut state);
            });
        }
    }
}

#[test]
fn the_port_table_draws_with_a_row_selected() {
    let hosts = populated();
    let mut state = ResultsState {
        selected_port: Some((80, Transport::Tcp)),
        ..Default::default()
    };
    frame(egui::vec2(900.0, 500.0), |ui| {
        crate::views::results::host_details(ui, &hosts[0], &Filter::default(), &mut state);
    });
}

#[test]
fn the_detail_pane_draws_every_tab() {
    let hosts = populated();
    for tab in crate::views::results::DetailTab::ALL {
        for host in &hosts {
            let mut state = ResultsState {
                tab: *tab,
                ..Default::default()
            };
            frame(egui::vec2(900.0, 500.0), |ui| {
                crate::views::results::host_details(ui, host, &Filter::default(), &mut state);
            });
        }
    }
}

#[test]
fn the_detail_pane_draws_a_host_with_no_ports_at_all() {
    let bare = HostReport::new("10.0.0.9".parse().unwrap());
    let mut state = ResultsState::default();
    frame(egui::vec2(900.0, 400.0), |ui| {
        crate::views::results::host_details(ui, &bare, &Filter::default(), &mut state);
    });
}

#[test]
fn statistics_draw_with_results_and_without() {
    let hosts = populated();
    for (width, height) in SIZES {
        frame(egui::vec2(*width, *height), |ui| {
            crate::views::statistics::show(ui, &live(&hosts));
        });
        frame(egui::vec2(*width, *height), |ui| {
            crate::views::statistics::show(ui, &LiveResults::default());
        });
    }
}

#[test]
fn statistics_draw_a_long_list_both_folded_and_open() {
    let hosts: Vec<HostReport> = (1..=40)
        .map(|n| {
            host(
                &format!("10.0.0.{n}"),
                &[
                    (22, PortState::Open, "ssh"),
                    (80, PortState::Open, "http"),
                    (n as u16 + 9000, PortState::Open, "unknown"),
                ],
            )
        })
        .collect();
    let results = live(&hosts);

    let ctx = Context::default();
    crate::theme::apply(&ctx);
    for expanded in [false, true] {
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1000.0, 700.0),
            )),
            ..Default::default()
        };
        let _ = ctx.run(input, |ctx| {
            ctx.data_mut(|data| {
                for list in ["services", "hosts", "latency"] {
                    data.insert_temp(egui::Id::new(("statistics-expanded", list)), expanded);
                }
            });
            egui::CentralPanel::default().show(ctx, |ui| {
                crate::views::statistics::show(ui, &results);
            });
        });
    }
}

#[test]
fn statistics_draw_when_every_count_is_the_same() {
    let hosts = vec![host("10.0.0.1", &[(80, PortState::Open, "http")])];
    frame(egui::vec2(900.0, 600.0), |ui| {
        crate::views::statistics::show(ui, &live(&hosts));
    });
}

#[test]
fn the_topology_draws_at_every_size() {
    let hosts = populated();
    let networks: Vec<IpNet> = vec!["192.168.1.0/24".parse().unwrap()];
    for (width, height) in SIZES {
        let refs: Vec<&HostReport> = hosts.iter().collect();
        frame(egui::vec2(*width, *height), |ui| {
            crate::views::topology::show(ui, &refs, &networks, Some(refs[0].address));
        });
    }
}

#[test]
fn the_topology_draws_with_nothing_and_with_one_host() {
    frame(egui::vec2(900.0, 600.0), |ui| {
        crate::views::topology::show(ui, &[], &[], None);
    });

    let one = [host("10.0.0.1", &[])];
    let refs: Vec<&HostReport> = one.iter().collect();
    frame(egui::vec2(900.0, 600.0), |ui| {
        crate::views::topology::show(ui, &refs, &[], None);
    });
}

#[test]
fn the_topology_draws_with_its_controls_in_every_position() {
    let hosts = populated();
    let refs: Vec<&HostReport> = hosts.iter().collect();
    let networks: Vec<IpNet> = vec!["192.168.1.0/24".parse().unwrap()];

    use crate::views::topology::Viewport;
    let states = [
        Viewport::new(),
        Viewport {
            show_services: false,
            ..Viewport::new()
        },
        Viewport {
            search: "ssh".to_string(),
            ..Viewport::new()
        },
        Viewport {
            search: "nothing here".to_string(),
            ..Viewport::new()
        },
        Viewport {
            zoom: 0.2,
            placed: true,
            moved: [("192.168.1.1".to_string(), egui::vec2(400.0, -900.0))]
                .into_iter()
                .collect(),
            ..Viewport::new()
        },
    ];

    let ctx = Context::default();
    crate::theme::apply(&ctx);
    for state in states {
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1000.0, 700.0),
            )),
            ..Default::default()
        };
        let refs = refs.clone();
        let networks = networks.clone();
        let state = state.clone();
        let _ = ctx.run(input, |ctx| {
            ctx.data_mut(|data| data.insert_temp(Viewport::id(), state.clone()));
            egui::CentralPanel::default().show(ctx, |ui| {
                crate::views::topology::show(ui, &refs, &networks, Some(refs[0].address));
            });
        });
    }
}

#[test]
fn the_topology_draws_a_host_with_many_services() {
    let ports: Vec<(u16, PortState, &str)> = vec![
        (21, PortState::Open, "ftp"),
        (22, PortState::Open, "ssh"),
        (23, PortState::Open, "telnet"),
        (25, PortState::Open, "smtp"),
        (53, PortState::Open, "domain"),
        (80, PortState::Open, "http"),
        (110, PortState::Open, "pop3"),
        (143, PortState::Open, "imap"),
        (443, PortState::Open, "https"),
        (3306, PortState::Open, "mysql"),
    ];
    let hosts = [host("10.0.0.1", &ports)];
    let refs: Vec<&HostReport> = hosts.iter().collect();
    frame(egui::vec2(1000.0, 700.0), |ui| {
        crate::views::topology::show(ui, &refs, &[], None);
    });
}

#[test]
fn the_comparison_and_log_views_draw() {
    let hosts = populated();
    let mut results = live(&hosts);
    results.log(crate::session::LogLevel::Info, "a line");
    results.log(crate::session::LogLevel::Warning, "another");

    let mut log_state = crate::views::logs::LogState::default();
    frame(egui::vec2(900.0, 500.0), |ui| {
        crate::views::logs::show(ui, &results.log, &mut log_state);
    });

    let compare = crate::views::compare::CompareState::default();
    frame(egui::vec2(900.0, 500.0), |ui| {
        crate::views::compare::show(ui, &compare, false);
    });
}
