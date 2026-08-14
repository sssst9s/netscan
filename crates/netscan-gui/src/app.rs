use std::path::PathBuf;

use egui::{Key, KeyboardShortcut, Modifiers, RichText};
use netscan_core::output::{Format, RenderOptions};
use netscan_core::{ProfileRegistry, ScanReport};

use crate::filter::{Filter, FILTER_HELP};
use crate::scanform::{PortMode, ScanForm};
use crate::session::{LogLevel, Session, Status};
use crate::views::{compare::CompareState, logs::LogState, results::ResultsState, View};
use crate::widgets::{self, muted, palette};

pub struct App {
    phase: Phase,
}

enum Phase {
    Booting(Box<crate::boot::Boot>),
    Ready(Box<Workspace>),
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        crate::fonts::install(&cc.egui_ctx);
        crate::theme::apply_style(&cc.egui_ctx);
        Self {
            phase: Phase::Booting(Box::default()),
        }
    }
}

pub struct Workspace {
    session: Session,
    form: ScanForm,
    registry: ProfileRegistry,
    view: View,
    results: ResultsState,
    compare: CompareState,
    log: LogState,
    filter_text: String,
    filter: Filter,
    show_filter_help: bool,
    show_about: bool,
    show_config: bool,
    focus_filter: bool,
    focus_target: bool,
    local_networks: Vec<ipnet::IpNet>,
    config_path: Option<std::path::PathBuf>,
    toast: Option<(String, LogLevel, std::time::Instant)>,
    pending_copy: Option<String>,
}

const SCAN_SHORTCUT: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::Enter);
const STOP_SHORTCUT: KeyboardShortcut = KeyboardShortcut::new(Modifiers::NONE, Key::Escape);
const FIND_SHORTCUT: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::F);
const OPEN_SHORTCUT: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::O);
const SAVE_SHORTCUT: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::S);

impl Workspace {
    pub fn new(artifacts: crate::boot::Artifacts, boot_log: Vec<String>) -> Result<Self, String> {
        let session = Session::new(artifacts.probes)?;
        let registry = artifacts.profiles;
        let local_networks = artifacts.local_networks;
        let mut form = ScanForm::default();

        if let Some(network) = local_networks
            .iter()
            .find(|net| net.addr().is_ipv4())
            .or_else(|| local_networks.first())
        {
            form.targets = network.to_string();
            if network.addr().is_ipv6() {
                form.family = netscan_core::IpFamily::V6;
            }
        }

        let mut workspace = Self {
            session,
            form,
            registry,
            view: View::default(),
            results: ResultsState::default(),
            compare: CompareState::default(),
            log: LogState::default(),
            filter_text: String::new(),
            filter: Filter::default(),
            show_filter_help: false,
            show_about: false,
            show_config: false,
            focus_filter: false,
            focus_target: false,
            local_networks,
            config_path: artifacts.config_path,
            toast: None,
            pending_copy: None,
        };

        for warning in boot_log {
            workspace.session.results.log(LogLevel::Warning, warning);
        }
        Ok(workspace)
    }

    fn start_scan(&mut self) {
        match self.form.to_config() {
            Ok(config) => {
                self.session.start(config);
                self.view = View::Results;
                self.results.selected = None;
            }
            Err(err) => self.notify(format!("Cannot start: {err}"), LogLevel::Error),
        }
    }

    fn notify(&mut self, message: impl Into<String>, level: LogLevel) {
        let message = message.into();
        self.session.results.log(level, message.clone());
        self.toast = Some((message, level, std::time::Instant::now()));
    }

    fn open_report(&mut self, as_baseline: bool) {
        let picked = rfd::FileDialog::new()
            .add_filter("netscan report", &["json", "jsonl"])
            .set_title(if as_baseline {
                "Open a baseline scan to compare against"
            } else {
                "Open a saved scan"
            })
            .pick_file();

        let Some(path) = picked else { return };
        let name = path.display().to_string();

        match load_report(&path) {
            Ok(report) => {
                if as_baseline {
                    self.compare.set_baseline(report, name.clone());
                    self.compare
                        .recompute(self.session.results.report.as_deref());
                    self.view = View::Compare;
                    self.notify(format!("Baseline: {name}"), LogLevel::Info);
                } else {
                    self.session.load_report(report);
                    self.compare
                        .recompute(self.session.results.report.as_deref());
                    self.notify(format!("Opened {name}"), LogLevel::Info);
                }
            }
            Err(err) => self.notify(err, LogLevel::Error),
        }
    }

    fn save_report(&mut self, format: Format) {
        let Some(report) = self.session.results.report.clone() else {
            return;
        };
        let suggested = format!("netscan-{}.{}", report.scan_id, format.extension());

        let picked = rfd::FileDialog::new()
            .set_file_name(&suggested)
            .set_title("Save scan results")
            .save_file();

        let Some(path) = picked else { return };
        match netscan_core::output::write_file(&report, &path, format, RenderOptions::verbose()) {
            Ok(()) => self.notify(format!("Saved {}", path.display()), LogLevel::Info),
            Err(err) => self.notify(err.to_string(), LogLevel::Error),
        }
    }

    fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        if ctx.input_mut(|i| i.consume_shortcut(&SCAN_SHORTCUT)) && !self.session.is_running() {
            self.start_scan();
        }
        if ctx.input_mut(|i| i.consume_shortcut(&STOP_SHORTCUT)) && self.session.is_running() {
            self.session.cancel();
        }
        if ctx.input_mut(|i| i.consume_shortcut(&OPEN_SHORTCUT)) {
            self.open_report(false);
        }
        if ctx.input_mut(|i| i.consume_shortcut(&SAVE_SHORTCUT)) {
            self.save_report(Format::Json);
        }
        if ctx.input_mut(|i| i.consume_shortcut(&FIND_SHORTCUT)) {
            self.view = View::Results;
        }

        for (index, view) in View::ALL.iter().enumerate() {
            let key = match index {
                0 => Key::Num1,
                1 => Key::Num2,
                2 => Key::Num3,
                3 => Key::Num4,
                _ => Key::Num5,
            };
            let shortcut = KeyboardShortcut::new(Modifiers::COMMAND, key);
            if ctx.input_mut(|i| i.consume_shortcut(&shortcut)) {
                self.view = *view;
            }
        }
    }

    fn menu_bar(&mut self, ui: &mut egui::Ui, palette: &crate::theme::Palette) {
        egui::TopBottomPanel::top("menu-bar")
            .exact_height(26.0)
            .frame(
                egui::Frame::none()
                    .fill(palette.panel)
                    .inner_margin(egui::Margin::symmetric(crate::theme::UNIT, 0.0)),
            )
            .show_inside(ui, |ui| {
                ui.horizontal_centered(|ui| self.menus(ui));
            });
    }

    fn menus(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let ctx = &ctx;
        {
            egui::menu::bar(ui, |ui| {
                ui.spacing_mut().item_spacing.x = crate::theme::UNIT * 2.5;
                ui.menu_button("File", |ui| {
                    if ui.button("Open scan…").clicked() {
                        self.open_report(false);
                        ui.close_menu();
                    }
                    if ui.button("Open baseline for comparison…").clicked() {
                        self.open_report(true);
                        ui.close_menu();
                    }
                    if ui
                        .add_enabled(
                            self.compare.baseline.is_some(),
                            egui::Button::new("Clear comparison baseline"),
                        )
                        .clicked()
                    {
                        self.compare.clear();
                        ui.close_menu();
                    }
                    ui.separator();
                    ui.add_enabled_ui(self.session.results.report.is_some(), |ui| {
                        for format in [Format::Json, Format::Jsonl, Format::Csv, Format::Xml] {
                            if ui
                                .button(format!("Export as {}…", format.name().to_uppercase()))
                                .clicked()
                            {
                                self.save_report(format);
                                ui.close_menu();
                            }
                        }
                    });
                    ui.separator();
                    if ui.button("Quit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });

                ui.menu_button("Scan", |ui| {
                    let can_start = !self.session.is_running() && self.form.is_valid();
                    if ui
                        .add_enabled(can_start, egui::Button::new("Start scan"))
                        .clicked()
                    {
                        self.start_scan();
                        ui.close_menu();
                    }
                    if ui
                        .add_enabled(self.session.is_running(), egui::Button::new("Stop scan"))
                        .clicked()
                    {
                        self.session.cancel();
                        ui.close_menu();
                    }
                    ui.separator();
                    ui.menu_button("Load profile", |ui| {
                        let names: Vec<String> = self
                            .registry
                            .names()
                            .into_iter()
                            .map(str::to_string)
                            .collect();
                        for name in names {
                            let description = self
                                .registry
                                .get(&name)
                                .map(|p| p.description.clone())
                                .unwrap_or_default();
                            if ui.button(&name).on_hover_text(description).clicked() {
                                if let Err(err) = self.form.apply_profile(&self.registry, &name) {
                                    self.notify(err, LogLevel::Error);
                                }
                                ui.close_menu();
                            }
                        }
                    });
                });

                ui.menu_button("Edit", |ui| {
                    let has_selection = self.results.selected.is_some();
                    if ui
                        .add_enabled(has_selection, egui::Button::new("Copy address"))
                        .clicked()
                    {
                        if let Some(address) = self.results.selected {
                            self.perform_row_action(crate::views::table::RowAction::Copy(
                                address.to_string(),
                            ));
                        }
                        ui.close_menu();
                    }
                    if ui
                        .add_enabled(
                            self.session.results.report.is_some(),
                            egui::Button::new("Copy all results"),
                        )
                        .clicked()
                    {
                        self.copy_all_results();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Find…").clicked() {
                        self.perform(crate::toolbar::Action::Find);
                        ui.close_menu();
                    }
                    if ui.button("Clear display filter").clicked() {
                        self.filter_text.clear();
                        self.filter = Filter::default();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Scan configuration…").clicked() {
                        self.show_config = true;
                        ui.close_menu();
                    }
                });

                ui.menu_button("View", |ui| {
                    for view in View::ALL {
                        if ui
                            .selectable_label(self.view == *view, view.label())
                            .on_hover_text(view.description())
                            .clicked()
                        {
                            self.view = *view;
                            ui.close_menu();
                        }
                    }
                    ui.separator();
                    ui.checkbox(&mut self.results.show_down, "Hosts that are down");
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.label(muted("Theme"));
                        egui::widgets::global_theme_preference_switch(ui);
                    });
                });

                ui.menu_button("Go", |ui| {
                    let has_hosts = !self.session.results.hosts.is_empty();
                    for (label, action) in [
                        ("First host", crate::toolbar::Action::First),
                        ("Previous host", crate::toolbar::Action::Previous),
                        ("Next host", crate::toolbar::Action::Next),
                        ("Last host", crate::toolbar::Action::Last),
                    ] {
                        if ui
                            .add_enabled(has_hosts, egui::Button::new(label))
                            .clicked()
                        {
                            self.perform(action);
                            ui.close_menu();
                        }
                    }
                });

                ui.menu_button("Analyse", |ui| {
                    for (label, expression) in [
                        ("Only hosts that are up", "status:up"),
                        ("Only web services", "service:http"),
                        ("Only SSH", "service:ssh"),
                        ("Only TLS ports", "tls:true"),
                        ("Only open ports", "state:open"),
                    ] {
                        if ui.button(label).clicked() {
                            self.filter_text = expression.to_string();
                            self.filter = Filter::parse(&self.filter_text);
                            self.view = View::Results;
                            ui.close_menu();
                        }
                    }
                    ui.separator();
                    if ui.button("Clear filter").clicked() {
                        self.filter_text.clear();
                        self.filter = Filter::default();
                        ui.close_menu();
                    }
                    if ui.button("Filter syntax…").clicked() {
                        self.show_filter_help = true;
                        ui.close_menu();
                    }
                });

                ui.menu_button("Statistics", |ui| {
                    if ui.button("Summary").clicked() {
                        self.view = View::Statistics;
                        ui.close_menu();
                    }
                    if ui.button("Topology").clicked() {
                        self.view = View::Topology;
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Compare with a saved scan…").clicked() {
                        self.open_report(true);
                        ui.close_menu();
                    }
                });

                ui.menu_button("Tools", |ui| {
                    if ui.button("Scan log").clicked() {
                        self.view = View::Log;
                        ui.close_menu();
                    }
                    if ui
                        .add_enabled(
                            self.session.results.report.is_some(),
                            egui::Button::new("Clear results"),
                        )
                        .clicked()
                    {
                        self.session.results.clear();
                        self.results.selected = None;
                        self.results.selected_port = None;
                        ui.close_menu();
                    }
                });

                ui.menu_button("Help", |ui| {
                    if ui.button("Filter syntax").clicked() {
                        self.show_filter_help = true;
                        ui.close_menu();
                    }
                    if ui.button("About netscan").clicked() {
                        self.show_about = true;
                        ui.close_menu();
                    }
                });
            });
        }
    }

    fn copy_all_results(&mut self) {
        let hosts = crate::views::results::visible_hosts(
            self.session.results.hosts.values(),
            &self.filter,
            &self.results,
        );
        let entries = crate::views::table::host_entries(
            match hosts.first() {
                Some(host) => host,
                None => return,
            },
            &hosts,
        );

        if let Some(action) = entries.iter().find_map(|entry| match entry {
            crate::views::table::Entry::Item(label, action) if label.starts_with("Copy all") => {
                Some(action.clone())
            }
            _ => None,
        }) {
            self.perform_row_action(action);
        }
    }

    fn banner(&mut self, ui: &mut egui::Ui, palette: &crate::theme::Palette) {
        use crate::theme::Intent;
        let (intent, headline, detail) = match self.session.status {
            Status::Running => {
                let progress = &self.session.results.progress;
                (
                    Intent::Info,
                    format!("Scanning — {}%", progress.percent()),
                    format!(
                        "{} of {} host(s) · {} open · {} tested{}",
                        progress.hosts_completed.min(progress.hosts_total),
                        progress.hosts_total,
                        widgets::count(self.session.results.open_port_count() as u64),
                        widgets::count(progress.probes_completed),
                        progress
                            .eta()
                            .map(|eta| format!(" · {} remaining", widgets::duration(eta)))
                            .unwrap_or_default(),
                    ),
                )
            }
            Status::Cancelling => (
                Intent::Warning,
                "Stopping".to_string(),
                "finishing the probes already in flight".to_string(),
            ),
            Status::Finished => {
                let report = self.session.results.report.as_ref();
                let cancelled =
                    report.is_some_and(|r| r.outcome != netscan_core::ScanOutcome::Completed);
                let stats = report.map(|r| r.stats.clone()).unwrap_or_default();
                (
                    if cancelled {
                        Intent::Warning
                    } else {
                        Intent::Success
                    },
                    if cancelled {
                        "Scan incomplete — results are partial".to_string()
                    } else {
                        "Scan complete".to_string()
                    },
                    format!(
                        "{} of {} host(s) up · {} open port(s) · {} tested in {}",
                        stats.hosts_up,
                        stats.hosts_total,
                        widgets::count(stats.ports_open),
                        widgets::count(stats.ports_tested),
                        widgets::duration(std::time::Duration::from_millis(stats.duration_ms)),
                    ),
                )
            }
            Status::Failed => (
                Intent::Danger,
                "Scan failed".to_string(),
                self.session.error.clone().unwrap_or_default(),
            ),
            Status::Idle => return,
        };

        if ui.available_height() < 80.0 {
            return;
        }

        let (fill, ink) = palette.band(intent);
        egui::TopBottomPanel::top("scan-banner")
            .exact_height(24.0)
            .frame(
                egui::Frame::none()
                    .fill(fill)
                    .inner_margin(egui::Margin::symmetric(crate::theme::UNIT * 2.0, 0.0)),
            )
            .show_inside(ui, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.label(
                        egui::RichText::new(&headline)
                            .size(11.5)
                            .strong()
                            .color(ink.text),
                    );
                    if !detail.is_empty() {
                        ui.label(egui::RichText::new(detail).size(11.5).color(ink.muted));
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.session.status == Status::Finished
                            && ui
                                .add(
                                    egui::Label::new(
                                        egui::RichText::new("✕").size(11.0).color(ink.muted),
                                    )
                                    .sense(egui::Sense::click()),
                                )
                                .on_hover_text("Dismiss")
                                .clicked()
                        {
                            self.session.status = Status::Idle;
                        }
                    });
                });
            });
    }

    fn icon_toolbar(&mut self, ui: &mut egui::Ui, palette: &crate::theme::Palette) {
        let availability = crate::toolbar::Availability::from_session(
            self.session.status,
            self.form.is_valid(),
            self.session.results.report.is_some(),
            self.session.results.hosts.len(),
            self.session.config.is_some(),
        );

        let pressed = egui::TopBottomPanel::top("icon-toolbar")
            .exact_height(crate::toolbar::BUTTON + crate::theme::UNIT * 2.0)
            .frame(
                egui::Frame::none()
                    .fill(palette.panel)
                    .inner_margin(egui::Margin::symmetric(crate::theme::UNIT, 0.0)),
            )
            .show_inside(ui, |ui| {
                crate::toolbar::show(ui, &availability, self.results.show_down, palette)
            })
            .inner;

        if let Some(action) = pressed {
            self.perform(action);
        }
    }

    fn perform(&mut self, action: crate::toolbar::Action) {
        use crate::toolbar::Action;
        match action {
            Action::Scan => self.start_scan(),
            Action::Stop => self.session.cancel(),
            Action::Rescan => {
                if let Some(config) = self.session.config.clone() {
                    self.session.start(config);
                    self.view = View::Results;
                }
            }
            Action::Options => self.show_config = true,
            Action::Open => self.open_report(false),
            Action::Save => self.save_report(Format::Json),
            Action::Find => {
                self.view = View::Results;
                self.focus_filter = true;
            }
            Action::Previous => self.step_selection(-1),
            Action::Next => self.step_selection(1),
            Action::First => self.jump_selection(true),
            Action::Last => self.jump_selection(false),
            Action::ShowDown => self.results.show_down = !self.results.show_down,
            Action::Compare => self.view = View::Compare,
        }
    }

    fn listed_hosts(&self) -> Vec<std::net::IpAddr> {
        crate::views::results::visible_hosts(
            self.session.results.hosts.values(),
            &self.filter,
            &self.results,
        )
        .into_iter()
        .map(|host| host.address)
        .collect()
    }

    fn step_selection(&mut self, delta: isize) {
        let hosts = self.listed_hosts();
        if hosts.is_empty() {
            return;
        }
        let current = self
            .results
            .selected
            .and_then(|address| hosts.iter().position(|h| *h == address))
            .unwrap_or(0) as isize;
        let next = (current + delta).clamp(0, hosts.len() as isize - 1) as usize;
        self.results.selected = Some(hosts[next]);
    }

    fn jump_selection(&mut self, first: bool) {
        let hosts = self.listed_hosts();
        self.results.selected = if first {
            hosts.first().copied()
        } else {
            hosts.last().copied()
        };
    }

    fn scan_bar(&mut self, ui: &mut egui::Ui, palette: &crate::theme::Palette) {
        egui::TopBottomPanel::top("scan-bar")
            .exact_height(30.0)
            .frame(
                egui::Frame::none()
                    .fill(palette.panel)
                    .inner_margin(egui::Margin::symmetric(crate::theme::UNIT * 2.0, 0.0)),
            )
            .show_inside(ui, |ui| {
                ui.horizontal_centered(|ui| {
                    let running = self.session.is_running();
                    ui.label(widgets::micro_label("Target"));

                    let problem = self.form.target_problem();
                    let field = egui::TextEdit::singleline(&mut self.form.targets)
                        .hint_text("192.168.1.0/24   10.0.0.1-50   example.com")
                        .desired_width(320.0)
                        .text_color(if problem.is_some() {
                            palette.danger
                        } else {
                            palette.text
                        });
                    let response = ui.add_enabled(!running, field);
                    if std::mem::take(&mut self.focus_target) {
                        response.request_focus();
                    }

                    if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        self.start_scan();
                    }

                    ui.add_space(crate::theme::UNIT);
                    ui.label(widgets::micro_label("Ports"));
                    ui.add_enabled_ui(!running, |ui| {
                        egui::ComboBox::from_id_salt("scan-bar-ports")
                            .selected_text(self.form.port_summary())
                            .width(150.0)
                            .show_ui(ui, |ui| {
                                for mode in PortMode::ALL {
                                    if ui
                                        .selectable_label(
                                            self.form.port_mode == *mode,
                                            mode.label(),
                                        )
                                        .clicked()
                                    {
                                        self.form.port_mode = *mode;
                                    }
                                }
                                ui.separator();
                                for preset in netscan_core::PortPreset::ALL {
                                    if ui
                                        .selectable_label(
                                            self.form.port_mode == PortMode::Preset
                                                && self.form.preset == *preset,
                                            preset.name(),
                                        )
                                        .on_hover_text(preset.description())
                                        .clicked()
                                    {
                                        self.form.port_mode = PortMode::Preset;
                                        self.form.preset = *preset;
                                    }
                                }
                            });
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add_enabled(!running, egui::Button::new("More…"))
                            .on_hover_text("Full scan configuration  (Cmd/Ctrl+,)")
                            .clicked()
                        {
                            self.show_config = true;
                        }
                        if let Some(problem) = problem {
                            ui.label(RichText::new(problem).color(palette.danger).size(11.0));
                        }
                    });
                });
            });
    }

    fn filter_bar(&mut self, ui: &mut egui::Ui, palette: &crate::theme::Palette) {
        egui::TopBottomPanel::top("filter-bar")
            .exact_height(28.0)
            .frame(
                egui::Frame::none()
                    .fill(palette.panel)
                    .inner_margin(egui::Margin::symmetric(crate::theme::UNIT, 0.0)),
            )
            .show_inside(ui, |ui| {
                ui.horizontal_centered(|ui| {
                    let valid = self.filter.errors.is_empty();
                    let (icon_rect, icon) =
                        ui.allocate_exact_size(egui::vec2(15.0, 15.0), egui::Sense::hover());
                    let ctx = ui.ctx().clone();
                    crate::icons::paint(
                        &ctx,
                        ui.painter(),
                        icon_rect,
                        crate::icons::Icon::Search,
                        if valid { palette.muted } else { palette.danger },
                    );
                    icon.on_hover_text("Display filter");

                    let width = ui.available_width() - 42.0;
                    let field = egui::TextEdit::singleline(&mut self.filter_text)
                        .hint_text("Apply a display filter …  port:22  service:http  status:up")
                        .desired_width(width.max(120.0));
                    let response = ui.add(field);

                    if std::mem::take(&mut self.focus_filter) {
                        response.request_focus();
                    }
                    if response.changed() {
                        self.filter = Filter::parse(&self.filter_text);
                    }
                    let (help_rect, help) =
                        ui.allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::click());
                    crate::icons::paint(
                        &ctx,
                        ui.painter(),
                        help_rect,
                        crate::icons::Icon::Help,
                        if help.hovered() {
                            palette.text
                        } else {
                            palette.muted
                        },
                    );
                    if help.on_hover_text("Filter syntax").clicked() {
                        self.show_filter_help = true;
                    }
                });
            });
    }

    fn view_tabs(&mut self, ui: &mut egui::Ui, palette: &crate::theme::Palette) {
        egui::TopBottomPanel::top("view-tabs")
            .exact_height(26.0)
            .frame(
                egui::Frame::none()
                    .fill(palette.window)
                    .inner_margin(egui::Margin::symmetric(crate::theme::UNIT, 0.0)),
            )
            .show_inside(ui, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    for view in View::ALL {
                        let hint = format!(
                            "{}  ({}{})",
                            view.description(),
                            crate::chrome::MODIFIER_SYMBOL,
                            view.shortcut_digit()
                        );
                        if widgets::tab(ui, self.view == *view, view.label())
                            .on_hover_text(hint)
                            .clicked()
                        {
                            self.view = *view;
                        }
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if let Some(config) = &self.session.config {
                            let targets = widgets::ellipsise(
                                &config
                                    .targets
                                    .iter()
                                    .map(ToString::to_string)
                                    .collect::<Vec<_>>()
                                    .join(", "),
                                28,
                            );
                            let ports = widgets::ellipsise(&config.ports.to_string(), 24);
                            ui.label(muted(format!("{targets}  ·  {ports}")))
                                .on_hover_text(format!(
                                    "{}\nports: {}",
                                    config
                                        .targets
                                        .iter()
                                        .map(ToString::to_string)
                                        .collect::<Vec<_>>()
                                        .join(", "),
                                    config.ports
                                ));
                        }
                    });
                });
            });
    }

    fn configuration_panel(&mut self, ui: &mut egui::Ui) {
        let running = self.session.is_running();
        ui.add_enabled_ui(!running, |ui| {
            widgets::section(ui, "Targets");
            ui.add(
                egui::TextEdit::multiline(&mut self.form.targets)
                    .desired_rows(2)
                    .hint_text("one or more, space separated"),
            );
            ui.collapsing("Exclusions", |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut self.form.exclusions)
                        .desired_rows(1)
                        .hint_text("addresses or blocks to leave alone"),
                );
            });
            if !self.local_networks.is_empty() && ui.small_button("Use my network").clicked() {
                self.form.targets = self
                    .local_networks
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ");
            }

            widgets::section(ui, "Ports");
            ui.horizontal(|ui| {
                for mode in PortMode::ALL {
                    if ui
                        .selectable_label(self.form.port_mode == *mode, mode.label())
                        .clicked()
                    {
                        self.form.port_mode = *mode;
                    }
                }
            });
            match self.form.port_mode {
                PortMode::Top => {
                    ui.add(
                        egui::Slider::new(&mut self.form.top_ports, 1..=1000)
                            .text("ports")
                            .logarithmic(true),
                    );
                }
                PortMode::Preset => {
                    egui::ComboBox::from_id_salt("preset")
                        .selected_text(self.form.preset.name())
                        .show_ui(ui, |ui| {
                            for preset in netscan_core::PortPreset::ALL {
                                ui.selectable_value(&mut self.form.preset, *preset, preset.name())
                                    .on_hover_text(preset.description());
                            }
                        });
                }
                PortMode::Custom => {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.form.custom_ports)
                            .hint_text("22,80,443,8000-9000"),
                    );
                }
            }

            widgets::section(ui, "Scan");
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.form.tcp, "TCP");
                ui.checkbox(&mut self.form.udp, "UDP");
            });
            egui::ComboBox::from_id_salt("tcp-mode")
                .selected_text(self.form.tcp_mode.name())
                .show_ui(ui, |ui| {
                    for mode in [
                        netscan_core::TcpScanMode::Connect,
                        netscan_core::TcpScanMode::Syn,
                        netscan_core::TcpScanMode::Auto,
                    ] {
                        ui.selectable_value(&mut self.form.tcp_mode, mode, mode.name());
                    }
                })
                .response
                .on_hover_text(
                    "SYN needs privileges and the `raw` build feature; it falls back to connect",
                );

            widgets::section(ui, "Discovery");
            ui.checkbox(&mut self.form.discovery, "Find which hosts are up first");
            ui.add_enabled_ui(self.form.discovery, |ui| {
                ui.checkbox(&mut self.form.icmp, "ICMP echo");
                ui.checkbox(&mut self.form.tcp_ping, "TCP ping");
                ui.checkbox(
                    &mut self.form.discovery_only,
                    "Discovery only, no port scan",
                );
            });

            widgets::section(ui, "Detection");
            ui.checkbox(&mut self.form.service_detection, "Services and versions");
            ui.checkbox(&mut self.form.tls_inspection, "TLS certificates");
            ui.checkbox(&mut self.form.os_detection, "Operating system (inferred)");
            ui.add(
                egui::Slider::new(&mut self.form.max_intrusiveness, 0..=9)
                    .text("probe level")
                    .clamping(egui::SliderClamping::Always),
            )
            .on_hover_text("0 reads banners only; higher levels send more specific probes");

            widgets::section(ui, "Timing");
            egui::ComboBox::from_id_salt("timing")
                .selected_text(self.form.timing.name())
                .show_ui(ui, |ui| {
                    for template in netscan_core::TimingTemplate::ALL {
                        if ui
                            .selectable_label(self.form.timing == *template, template.name())
                            .on_hover_text(template.description())
                            .clicked()
                        {
                            self.form.apply_timing_template(*template);
                        }
                    }
                });
            ui.add(
                egui::Slider::new(&mut self.form.concurrency, 1..=5000)
                    .text("concurrency")
                    .logarithmic(true),
            );
            ui.add(
                egui::Slider::new(&mut self.form.timeout_ms, 50..=10_000)
                    .text("timeout ms")
                    .logarithmic(true),
            );
            ui.add(egui::Slider::new(&mut self.form.retries, 0..=5).text("retries"));
            ui.checkbox(&mut self.form.adaptive, "Adapt timing automatically");

            widgets::section(ui, "Network");
            ui.horizontal(|ui| {
                for (family, label) in [
                    (netscan_core::IpFamily::V4, "IPv4"),
                    (netscan_core::IpFamily::V6, "IPv6"),
                    (netscan_core::IpFamily::Both, "Both"),
                ] {
                    ui.selectable_value(&mut self.form.family, family, label);
                }
            });
            ui.checkbox(&mut self.form.reverse_dns, "Resolve hostnames");
        });

        ui.add_space(8.0);
        for problem in self.form.problems() {
            ui.label(
                RichText::new(format!("• {problem}"))
                    .color(palette::filtered())
                    .small(),
            );
        }
        ui.add_space(4.0);
        ui.label(muted(self.form.summary()));
    }

    fn status_bar(&mut self, ui: &mut egui::Ui, palette: &crate::theme::Palette) {
        egui::TopBottomPanel::bottom("status")
            .frame(
                egui::Frame::none()
                    .fill(palette.panel)
                    .inner_margin(egui::Margin::symmetric(
                        crate::theme::UNIT * 2.0,
                        crate::theme::UNIT,
                    )),
            )
            .show_inside(ui, |ui| {
                ui.add_space(2.0);
                ui.horizontal(|ui| {
                    let status = self.session.status;
                    let colour = match status {
                        Status::Running => palette::open(),
                        Status::Cancelling => palette::filtered(),
                        Status::Failed => palette::unknown(),
                        _ => palette::muted(),
                    };
                    ui.label(RichText::new(status.label()).color(colour).strong());
                    ui.separator();

                    let progress = &self.session.results.progress;
                    if status.is_active() || progress.probes_completed > 0 {
                        ui.add(
                            egui::ProgressBar::new(progress.fraction() as f32)
                                .desired_width(140.0)
                                .desired_height(12.0)
                                .fill(palette.accent)
                                .text(
                                    RichText::new(format!("{}%", progress.percent()))
                                        .size(10.5)
                                        .color(palette.on_accent),
                                ),
                        );
                        ui.separator();
                    }

                    ui.label(muted(format!(
                        "{} up / {} hosts",
                        self.session.results.up_count(),
                        progress
                            .hosts_total
                            .max(self.session.results.hosts.len() as u64)
                    )));
                    ui.separator();
                    ui.label(muted(format!(
                        "{} open ports",
                        widgets::count(self.session.results.open_port_count() as u64)
                    )));
                    ui.separator();
                    ui.label(muted(format!(
                        "{} tested",
                        widgets::count(progress.probes_completed)
                    )));

                    if progress.rate > 0.0 {
                        ui.separator();
                        ui.label(muted(format!("{}/s", widgets::count(progress.rate as u64))));
                    }
                    ui.separator();

                    let elapsed = if progress.elapsed.is_zero() && status.is_active() {
                        self.session.elapsed()
                    } else {
                        progress.elapsed
                    };
                    ui.label(muted(widgets::duration(elapsed)));
                    if let Some(eta) = progress.eta() {
                        ui.separator();
                        ui.label(muted(format!("eta {}", widgets::duration(eta))));
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if let Some((message, level, at)) = &self.toast {
                            if at.elapsed() < std::time::Duration::from_secs(6) {
                                ui.label(
                                    RichText::new(widgets::ellipsise(message, 80))
                                        .color(crate::views::logs::level_colour(*level)),
                                );
                            } else {
                                self.toast = None;
                            }
                        }
                        let warnings = self.session.results.warnings.len();
                        if warnings > 0 {
                            let label = RichText::new(format!("{warnings} warning(s)"))
                                .color(palette::filtered());
                            if ui.selectable_label(false, label).clicked() {
                                self.view = View::Log;
                            }
                        }
                    });
                });
                ui.add_space(2.0);
            });
    }

    fn central(&mut self, ui: &mut egui::Ui) {
        egui::CentralPanel::default()
            .frame(egui::Frame::none().inner_margin(egui::Margin::same(crate::theme::UNIT * 2.0)))
            .show_inside(ui, |ui| {
                if !self.filter.errors.is_empty() {
                    for error in &self.filter.errors {
                        ui.label(RichText::new(error).color(palette::filtered()).small());
                    }
                }

                match self.view {
                    View::Results => self.results_view(ui),
                    View::Statistics => {
                        if let Some(action) =
                            crate::views::statistics::show(ui, &self.session.results)
                        {
                            self.apply_stat_action(action);
                        }
                    }
                    View::Topology => {
                        let hosts: Vec<&netscan_core::HostReport> =
                            self.session.results.hosts.values().collect();
                        let outcome = crate::views::topology::show(
                            ui,
                            &hosts,
                            &self.local_networks,
                            self.results.selected,
                        );

                        if let Some(selected) = outcome.selected {
                            self.results.selected = Some(selected);
                            self.results.selected_port = None;
                        }
                        if outcome.opened.is_some() {
                            self.view = View::Results;
                        }
                        if let Some(action) = outcome.action {
                            self.perform_row_action(action);
                        }
                    }
                    View::Compare => {
                        crate::views::compare::show(
                            ui,
                            &self.compare,
                            self.session.results.report.is_some(),
                        );
                    }
                    View::Log => {
                        crate::views::logs::show(ui, &self.session.results.log, &mut self.log)
                    }
                }
            });
    }

    fn results_view(&mut self, ui: &mut egui::Ui) {
        let hosts = crate::views::results::visible_hosts(
            self.session.results.hosts.values(),
            &self.filter,
            &self.results,
        );

        if let Some(selected) = self.results.selected {
            if !hosts.iter().any(|host| host.address == selected) {
                self.results.selected = None;
            }
        }
        if self.results.selected.is_none() {
            self.results.selected = hosts.first().map(|host| host.address);
        }

        let available = ui.available_height();
        const MIN_PANE: f32 = 120.0;

        let ready = self.results.settle(available, MIN_PANE * 2.0);
        if !ready || available < MIN_PANE * 2.0 {
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("{} host(s)", hosts.len())).strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.checkbox(&mut self.results.show_down, "show down");
                });
            });
            ui.separator();
            let outcome = crate::views::table::Skin::hosts(&crate::theme::current())
                .frame()
                .show(ui, |ui| {
                    crate::views::results::host_table(ui, &hosts, &mut self.results)
                })
                .inner;
            self.apply_table_outcome(outcome);
            return;
        }

        let min_height = (available * 0.25).clamp(MIN_PANE, available - MIN_PANE);
        let max_height = (available - MIN_PANE).max(min_height);

        let host_outcome = egui::TopBottomPanel::top("host-table")
            .resizable(true)
            .default_height((available * 0.45).clamp(min_height, max_height))
            .height_range(min_height..=max_height)
            .frame(egui::Frame::none().inner_margin(egui::Margin {
                left: 0.0,
                right: 0.0,
                top: 0.0,
                bottom: crate::theme::UNIT,
            }))
            .show_inside(ui, |ui| {
                ui.set_min_height(ui.available_height());

                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("{} host(s)", hosts.len())).strong());
                    if !self.filter.is_empty() {
                        ui.label(muted(format!(
                            "filtered from {}",
                            self.session.results.hosts.len()
                        )));
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.checkbox(&mut self.results.show_down, "show down");
                    });
                });
                ui.separator();

                crate::views::table::Skin::hosts(&crate::theme::current())
                    .frame()
                    .show(ui, |ui| {
                        crate::views::results::host_table(ui, &hosts, &mut self.results)
                    })
                    .inner
            })
            .inner;
        self.apply_table_outcome(host_outcome);

        let selected = self
            .results
            .selected
            .and_then(|address| self.session.results.hosts.get(&address).cloned());

        match selected {
            Some(host) => {
                let action = crate::views::table::Skin::ports(&crate::theme::current())
                    .frame()
                    .show(ui, |ui| {
                        crate::views::results::host_details(
                            ui,
                            &host,
                            &self.filter,
                            &mut self.results,
                        )
                    })
                    .inner;
                if let Some(action) = action {
                    self.perform_row_action(action);
                }
            }
            None => {
                crate::views::table::Skin::ports(&crate::theme::current())
                    .frame()
                    .show(ui, |ui| {
                        crate::views::results::empty(
                            ui,
                            "No host selected.",
                            "Pick one from the list above to see its ports and details.",
                        );
                    });
            }
        }
    }

    fn apply_stat_action(&mut self, action: crate::views::statistics::StatAction) {
        use crate::views::statistics::StatAction;
        match action {
            StatAction::Filter(expression) => {
                self.filter_text = expression;
                self.filter = Filter::parse(&self.filter_text);
                self.view = View::Results;
            }
            StatAction::Show(address) => {
                self.results.selected = Some(address);
                self.results.selected_port = None;
                self.view = View::Results;
            }
        }
    }

    fn apply_table_outcome(&mut self, outcome: crate::views::results::TableOutcome) {
        if let Some(address) = outcome.selected {
            self.results.selected = Some(address);

            self.results.selected_port = None;
        }
        if let Some(action) = outcome.action {
            self.perform_row_action(action);
        }
    }

    fn perform_row_action(&mut self, action: crate::views::table::RowAction) {
        use crate::views::table::RowAction;
        match action {
            RowAction::Copy(text) => {
                let lines = text.lines().count();
                self.pending_copy = Some(text);
                self.notify(
                    if lines > 1 {
                        format!("Copied {lines} lines")
                    } else {
                        "Copied".to_string()
                    },
                    LogLevel::Info,
                );
            }
            RowAction::Filter(expression) => {
                self.filter_text = expression;
                self.filter = Filter::parse(&self.filter_text);
            }
            RowAction::Refine(term) => {
                self.filter_text = refine(&self.filter_text, &term);
                self.filter = Filter::parse(&self.filter_text);
            }
            RowAction::Rescan { host, port } => self.rescan(host, port),
        }
    }

    fn rescan(&mut self, host: std::net::IpAddr, port: Option<(u16, netscan_core::Transport)>) {
        let base = match self.session.config.clone() {
            Some(config) => config,
            None => match self.form.to_config() {
                Ok(config) => config,
                Err(err) => return self.notify(format!("Cannot scan: {err}"), LogLevel::Error),
            },
        };

        let mut config = base;
        config.targets = match netscan_core::scanner::target::parse_target_list(&host.to_string()) {
            Ok(targets) => targets,
            Err(err) => return self.notify(format!("Cannot scan {host}: {err}"), LogLevel::Error),
        };

        config.exclusions.clear();

        if let Some((number, transport)) = port {
            let mut ports = netscan_core::PortSelection::default();
            let one = netscan_core::PortSet::from_iter_ordered([number]);
            match transport {
                netscan_core::Transport::Tcp => ports.merge(&netscan_core::PortSelection::tcp(one)),
                netscan_core::Transport::Udp => ports.merge(&netscan_core::PortSelection::udp(one)),
            }
            config.ports = ports;

            config.discovery.enabled = false;
        }

        self.session.start(config);
        self.view = View::Results;
        self.results.selected = Some(host);
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        if self.show_config {
            let mut open = true;
            dialog(ctx, "Scan configuration")
                .open(&mut open)
                .resizable(true)
                .vscroll(false)
                .default_width(430.0)
                .default_height(560.0)
                .show(ctx, |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("scan-configuration")
                        .auto_shrink([false, false])
                        .show(ui, |ui| self.configuration_panel(ui));

                    ui.separator();
                    ui.horizontal(|ui| {
                        let valid = self.form.is_valid();
                        if ui.add_enabled(valid, egui::Button::new("Start")).clicked() {
                            self.start_scan();
                            self.show_config = false;
                        }
                        if ui.button("Close").clicked() {
                            self.show_config = false;
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(muted(self.form.summary()))
                        });
                    });
                });
            if !open {
                self.show_config = false;
            }
        }

        if self.show_filter_help {
            let mut open = true;
            dialog(ctx, "Filter syntax")
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.label("Terms are separated by spaces and all must match.");
                    ui.add_space(6.0);
                    egui::Grid::new("filter-help")
                        .num_columns(2)
                        .spacing([16.0, 4.0])
                        .show(ui, |ui| {
                            for (expression, description) in FILTER_HELP {
                                ui.label(RichText::new(*expression).monospace());
                                ui.label(muted(*description));
                                ui.end_row();
                            }
                        });
                    ui.add_space(6.0);
                    ui.label(muted("Anything else is matched as free text."));
                });
            self.show_filter_help = open;
        }

        if self.show_about {
            let mut open = true;
            dialog(ctx, "About netscan")
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.heading("netscan");
                    ui.label(format!("Version {}", netscan_core::VERSION));
                    ui.label(muted("A network scanner and analyser."));
                    ui.add_space(8.0);
                    widgets::field(ui, "Author", AUTHOR);
                    ui.add_space(8.0);
                    ui.label("This application and the netscan command-line tool share one");
                    ui.label("scanning engine, so results are identical between them.");
                    ui.add_space(8.0);
                    match &self.config_path {
                        Some(path) => {
                            widgets::field(ui, "Configuration", path.display().to_string());
                        }
                        None => {
                            ui.label(muted("No configuration file; using built-in defaults."))
                                .on_hover_text(
                                    "netscan looks for netscan.toml in the working directory \
                                     and in your config directory",
                                );
                        }
                    }
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("Scan only networks you own or are authorised to test.")
                            .color(palette::filtered()),
                    );
                });
            self.show_about = open;
        }
    }
}

impl eframe::App for App {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        if crate::chrome::OWNS_WINDOW_FRAME {
            egui::Rgba::TRANSPARENT.to_array()
        } else {
            let window = crate::theme::current().window;
            egui::Rgba::from_srgba_premultiplied(window.r(), window.g(), window.b(), window.a())
                .to_array()
        }
    }

    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        crate::theme::sync(ctx);
        let palette = crate::theme::palette(ctx);
        let window = ctx.screen_rect();

        egui::CentralPanel::default()
            .frame(crate::chrome::window_frame(ctx, &palette))
            .show(ctx, |ui| match &mut self.phase {
                Phase::Booting(boot) => {
                    boot.advance(ctx);

                    let bar = egui::Rect::from_min_size(
                        window.min,
                        egui::vec2(window.width(), crate::theme::TITLE_BAR_HEIGHT),
                    );
                    let response = ui.allocate_new_ui(egui::UiBuilder::new().max_rect(bar), |ui| {
                        crate::chrome::title_bar(ui, "", &palette, |_| {})
                    });
                    if response.inner.close_requested {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }

                    crate::views::splash::show(ui, boot, &palette);

                    if boot.is_ready() {
                        let warnings = boot.warnings.clone();
                        let artifacts = boot.finish().expect("the sequence finished");
                        match Workspace::new(artifacts, warnings) {
                            Ok(workspace) => self.phase = Phase::Ready(Box::new(workspace)),
                            Err(err) => {
                                ui.centered_and_justified(|ui| {
                                    ui.label(egui::RichText::new(&err).color(palette.accent));
                                });
                            }
                        }
                    }
                    ctx.request_repaint();
                }
                Phase::Ready(workspace) => workspace.update(ctx, ui, frame, &palette),
            });

        crate::chrome::resize_handles(ctx, window);
    }
}

impl Workspace {
    fn update(
        &mut self,
        ctx: &egui::Context,
        ui: &mut egui::Ui,
        _frame: &mut eframe::Frame,
        palette: &crate::theme::Palette,
    ) {
        let changed = self.session.poll();

        if self.session.status == Status::Finished && self.compare.baseline.is_some() {
            self.compare
                .recompute(self.session.results.report.as_deref());
        }

        self.handle_shortcuts(ctx);

        let window = ui.max_rect();
        let bar = egui::Rect::from_min_size(
            window.min,
            egui::vec2(window.width(), crate::theme::TITLE_BAR_HEIGHT),
        );
        let target = self.session.config.as_ref().map(|config| {
            widgets::ellipsise(
                &config
                    .targets
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
                42,
            )
        });
        let title = window_title(self.session.status, target.as_deref());
        let chrome = ui
            .allocate_new_ui(egui::UiBuilder::new().max_rect(bar), |ui| {
                crate::chrome::title_bar(ui, &title, palette, |_| {})
            })
            .inner;
        if chrome.close_requested {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }

        let body = egui::Rect::from_min_max(
            egui::pos2(
                window.min.x,
                (window.min.y + crate::theme::TITLE_BAR_HEIGHT).min(window.max.y),
            ),
            window.max,
        );
        if body.height() < 1.0 || body.width() < 1.0 {
            return;
        }

        ui.allocate_new_ui(egui::UiBuilder::new().max_rect(body), |ui| {
            self.menu_bar(ui, palette);
            self.icon_toolbar(ui, palette);
            self.scan_bar(ui, palette);
            self.filter_bar(ui, palette);
            self.banner(ui, palette);
            self.status_bar(ui, palette);
            self.view_tabs(ui, palette);
            self.central(ui);
        });

        self.dialogs(ctx);

        if let Some(text) = self.pending_copy.take() {
            ctx.output_mut(|out| out.copied_text = text);
        }

        if self.session.is_running() || changed || self.toast.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}

const AUTHOR: &str = "cz";

fn dialog(ctx: &egui::Context, title: &'static str) -> egui::Window<'static> {
    let area = dialog_area(ctx.screen_rect());
    egui::Window::new(title)
        .collapsible(false)
        .resizable(false)
        .pivot(egui::Align2::CENTER_CENTER)
        .default_pos(area.center())
        .constrain_to(area)
        .max_height(area.height().max(1.0))
        .max_width(area.width().max(1.0))
        .vscroll(true)
}

fn dialog_area(screen: egui::Rect) -> egui::Rect {
    const EDGE: f32 = crate::theme::UNIT * 2.0;

    let top = (screen.top() + crate::theme::TITLE_BAR_HEIGHT + crate::theme::UNIT)
        .clamp(screen.top(), screen.bottom());
    let bottom = (screen.bottom() - EDGE).clamp(top, screen.bottom());
    let left = (screen.left() + EDGE).clamp(screen.left(), screen.right());
    let right = (screen.right() - EDGE).clamp(left, screen.right());
    egui::Rect::from_min_max(egui::pos2(left, top), egui::pos2(right, bottom))
}

fn refine(current: &str, term: &str) -> String {
    let current = current.trim();
    if current.is_empty() {
        return term.to_string();
    }
    if current.split_whitespace().any(|existing| existing == term) {
        return current.to_string();
    }
    format!("{current} {term}")
}

fn window_title(status: Status, target: Option<&str>) -> String {
    const NAME: &str = "netscan";
    let Some(target) = target.filter(|text| !text.is_empty()) else {
        return NAME.to_string();
    };
    match status {
        Status::Running => format!("{NAME} — scanning {target}"),
        Status::Cancelling => format!("{NAME} — stopping {target}"),
        Status::Failed => format!("{NAME} — {target} (failed)"),
        Status::Idle | Status::Finished => format!("{NAME} — {target}"),
    }
}

fn load_report(path: &PathBuf) -> Result<ScanReport, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    netscan_core::output::json::parse(&text)
        .or_else(|_| netscan_core::output::jsonl::parse(&text))
        .map_err(|e| format!("{} is not a netscan report: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use netscan_core::{HostReport, HostStatus};

    #[test]
    fn reports_load_from_json_and_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let mut report = ScanReport::empty();
        let mut host = HostReport::new("10.0.0.1".parse().unwrap());
        host.status = HostStatus::Up;
        report.hosts.push(host);
        report.recompute_stats();

        let json = dir.path().join("scan.json");
        std::fs::write(&json, netscan_core::output::json::render(&report).unwrap()).unwrap();
        assert_eq!(load_report(&json).unwrap().hosts.len(), 1);

        let jsonl = dir.path().join("scan.jsonl");
        std::fs::write(
            &jsonl,
            netscan_core::output::jsonl::render(&report).unwrap(),
        )
        .unwrap();
        assert_eq!(load_report(&jsonl).unwrap().hosts.len(), 1);
    }

    #[test]
    fn loading_a_non_report_reports_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notes.txt");
        std::fs::write(&path, "just some text").unwrap();
        let err = load_report(&path).unwrap_err();
        assert!(err.contains("notes.txt"), "message was: {err}");
    }

    #[test]
    fn a_dialog_is_never_placed_where_it_cannot_be_closed() {
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1440.0, 900.0));
        let area = dialog_area(screen);

        assert!(
            area.top() >= screen.top() + crate::theme::TITLE_BAR_HEIGHT,
            "a dialog must start below the application's own title bar"
        );
        assert!(area.bottom() <= screen.bottom());
        assert!(area.left() >= screen.left() && area.right() <= screen.right());

        assert!(area.contains(area.center()));
        assert!(area.height() < screen.height());
    }

    #[test]
    fn a_dialog_area_stays_a_real_rectangle_in_a_window_with_no_room() {
        for (width, height) in [(1440.0, 900.0), (320.0, 200.0), (60.0, 40.0), (1.0, 1.0)] {
            let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(width, height));
            let area = dialog_area(screen);
            assert!(
                area.width() >= 0.0 && area.height() >= 0.0,
                "{width}×{height} produced {area:?}"
            );
            assert!(
                area.top() >= screen.top() && area.bottom() <= screen.bottom(),
                "{width}×{height} produced {area:?}, which leaves the window"
            );
        }
    }

    #[test]
    fn narrowing_a_filter_appends_a_term_cleanly() {
        assert_eq!(refine("", "!host:10.0.0.1"), "!host:10.0.0.1");
        assert_eq!(refine("   ", "port:22"), "port:22");
        assert_eq!(refine("status:up", "port:22"), "status:up port:22");

        assert_eq!(refine("status:up ", "port:22"), "status:up port:22");
        assert_eq!(refine("  status:up  ", "port:22"), "status:up port:22");
    }

    #[test]
    fn narrowing_by_the_same_term_twice_changes_nothing() {
        let once = refine("", "!host:10.0.0.1");
        assert_eq!(refine(&once, "!host:10.0.0.1"), once);
        let mixed = refine("status:up !host:10.0.0.1", "!host:10.0.0.1");
        assert_eq!(mixed, "status:up !host:10.0.0.1");
    }

    #[test]
    fn a_narrowed_filter_still_parses() {
        for expression in [
            refine("", "host:192.168.1.1"),
            refine("status:up", "!host:192.168.1.1"),
            refine("port:80", "service:http"),
        ] {
            let filter = Filter::parse(&expression);
            assert!(
                filter.errors.is_empty(),
                "{expression:?} did not parse: {:?}",
                filter.errors
            );
        }
    }

    #[test]
    fn the_title_always_leads_with_the_application_name() {
        for status in [
            Status::Idle,
            Status::Running,
            Status::Cancelling,
            Status::Finished,
            Status::Failed,
        ] {
            for target in [None, Some("192.168.1.0/24"), Some("")] {
                let title = window_title(status, target);
                assert!(
                    title.starts_with("netscan"),
                    "{status:?}/{target:?} gave {title:?}"
                );
            }
        }
    }

    #[test]
    fn the_title_says_what_the_scan_is_doing() {
        let target = Some("192.168.1.0/24");
        assert_eq!(
            window_title(Status::Running, target),
            "netscan — scanning 192.168.1.0/24"
        );
        assert_eq!(
            window_title(Status::Cancelling, target),
            "netscan — stopping 192.168.1.0/24"
        );
        assert_eq!(
            window_title(Status::Finished, target),
            "netscan — 192.168.1.0/24"
        );
        assert!(window_title(Status::Failed, target).contains("failed"));
    }

    #[test]
    fn the_title_is_just_the_name_until_there_is_something_to_report() {
        assert_eq!(window_title(Status::Idle, None), "netscan");
        assert_eq!(window_title(Status::Idle, Some("")), "netscan");
        assert_eq!(window_title(Status::Running, None), "netscan");
    }

    #[test]
    fn loading_a_missing_file_reports_the_path() {
        let err = load_report(&PathBuf::from("/nonexistent/scan.json")).unwrap_err();
        assert!(err.contains("scan.json"));
    }
}
