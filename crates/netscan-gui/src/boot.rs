use std::time::{Duration, Instant};

use netscan_core::scanner::probe::ProbeRegistry;
use netscan_core::ProfileRegistry;

pub const MINIMUM_VISIBLE: Duration = Duration::from_millis(850);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Fonts,
    Probes,
    Ports,
    Interfaces,
    Profiles,
    Engine,
}

impl Step {
    pub const ALL: &'static [Step] = &[
        Step::Fonts,
        Step::Probes,
        Step::Ports,
        Step::Interfaces,
        Step::Profiles,
        Step::Engine,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Step::Fonts => "Loading typefaces",
            Step::Probes => "Compiling service probes",
            Step::Ports => "Reading port dataset",
            Step::Interfaces => "Enumerating interfaces",
            Step::Profiles => "Loading profiles",
            Step::Engine => "Starting scan engine",
        }
    }
}

#[derive(Debug, Clone)]
pub struct StepResult {
    pub step: Step,
    pub detail: String,
    pub took: Duration,
}

#[derive(Debug)]
pub struct Artifacts {
    pub probes: ProbeRegistry,
    pub local_networks: Vec<ipnet::IpNet>,
    pub profiles: ProfileRegistry,
    pub config_path: Option<std::path::PathBuf>,
}

#[derive(Debug)]
pub struct Boot {
    next: usize,
    started: Instant,
    pub results: Vec<StepResult>,
    pub warnings: Vec<String>,
    probes: Option<ProbeRegistry>,
    local_networks: Vec<ipnet::IpNet>,
    profiles: Option<ProfileRegistry>,
    config_path: Option<std::path::PathBuf>,
}

impl Default for Boot {
    fn default() -> Self {
        Self::new()
    }
}

impl Boot {
    pub fn new() -> Self {
        Self {
            next: 0,
            started: Instant::now(),
            results: Vec::new(),
            warnings: Vec::new(),
            probes: None,
            local_networks: Vec::new(),
            profiles: None,
            config_path: None,
        }
    }

    pub fn current(&self) -> Option<Step> {
        Step::ALL.get(self.next).copied()
    }

    pub fn progress(&self) -> f32 {
        self.next as f32 / Step::ALL.len() as f32
    }

    pub fn work_finished(&self) -> bool {
        self.next >= Step::ALL.len()
    }

    pub fn is_ready(&self) -> bool {
        self.work_finished() && self.started.elapsed() >= MINIMUM_VISIBLE
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    pub fn advance(&mut self, ctx: &egui::Context) -> Option<Step> {
        let step = self.current()?;
        let started = Instant::now();

        let detail = match step {
            Step::Fonts => {
                crate::theme::apply(ctx);
                format!("{} KB embedded", crate::fonts::embedded_bytes() / 1024)
            }
            Step::Probes => match ProbeRegistry::builtin() {
                Ok(registry) => {
                    let detail = format!("{} probes", registry.len());
                    self.probes = Some(registry);
                    detail
                }
                Err(err) => {
                    self.warnings
                        .push(format!("service probes failed to compile: {err}"));
                    self.probes = Some(ProbeRegistry::empty());
                    "unavailable".to_string()
                }
            },
            Step::Ports => {
                let tcp =
                    netscan_core::detection::service::max_top_ports(netscan_core::Transport::Tcp);
                let udp =
                    netscan_core::detection::service::max_top_ports(netscan_core::Transport::Udp);
                format!("{tcp} TCP, {udp} UDP ranked")
            }
            Step::Interfaces => match netscan_core::interfaces::local_networks() {
                Ok(networks) => {
                    let detail = match networks.len() {
                        0 => "no local networks".to_string(),
                        1 => networks[0].to_string(),
                        n => format!("{n} local networks"),
                    };
                    self.local_networks = networks;
                    detail
                }
                Err(err) => {
                    self.warnings
                        .push(format!("interfaces could not be listed: {err}"));
                    "unavailable".to_string()
                }
            },
            Step::Profiles => {
                let (registry, path) = match netscan_core::config::ConfigFile::discover() {
                    Ok(Some((path, file))) => (file.registry(), Some(path)),
                    Ok(None) => (ProfileRegistry::with_builtins(), None),
                    Err(err) => {
                        self.warnings
                            .push(format!("configuration file ignored: {err}"));
                        (ProfileRegistry::with_builtins(), None)
                    }
                };
                let detail = format!("{} profiles", registry.len());
                self.profiles = Some(registry);
                self.config_path = path;
                detail
            }
            Step::Engine => "ready".to_string(),
        };

        self.results.push(StepResult {
            step,
            detail,
            took: started.elapsed(),
        });
        self.next += 1;
        Some(step)
    }

    pub fn finish(&mut self) -> Option<Artifacts> {
        if !self.work_finished() {
            return None;
        }
        Some(Artifacts {
            probes: self.probes.take().unwrap_or_else(ProbeRegistry::empty),
            local_networks: std::mem::take(&mut self.local_networks),
            profiles: self.profiles.take().unwrap_or_default(),
            config_path: self.config_path.take(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_to_completion() -> Boot {
        let ctx = egui::Context::default();
        let mut boot = Boot::new();
        while boot.advance(&ctx).is_some() {}
        boot
    }

    #[test]
    fn every_step_has_a_label_and_they_are_distinct() {
        let mut labels: Vec<&str> = Step::ALL.iter().map(|s| s.label()).collect();
        assert!(labels.iter().all(|l| !l.is_empty()));
        let before = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(before, labels.len(), "two steps share a label");
    }

    #[test]
    fn a_fresh_sequence_has_done_nothing() {
        let boot = Boot::new();
        assert_eq!(boot.progress(), 0.0);
        assert_eq!(boot.current(), Some(Step::Fonts));
        assert!(!boot.work_finished());
        assert!(!boot.is_ready());
    }

    #[test]
    fn each_call_runs_exactly_one_step() {
        let ctx = egui::Context::default();
        let mut boot = Boot::new();
        for (index, expected) in Step::ALL.iter().enumerate() {
            assert_eq!(boot.current(), Some(*expected));
            assert_eq!(boot.advance(&ctx), Some(*expected));
            assert_eq!(boot.results.len(), index + 1);
        }
        assert!(boot.work_finished());
        assert_eq!(
            boot.advance(&ctx),
            None,
            "there should be nothing left to do"
        );
    }

    #[test]
    fn progress_rises_monotonically_to_one() {
        let ctx = egui::Context::default();
        let mut boot = Boot::new();
        let mut previous = 0.0;
        while boot.advance(&ctx).is_some() {
            assert!(boot.progress() > previous, "progress went backwards");
            previous = boot.progress();
        }
        assert_eq!(boot.progress(), 1.0);
    }

    #[test]
    fn the_work_actually_produces_what_the_session_needs() {
        let mut boot = run_to_completion();
        let artifacts = boot.finish().expect("the sequence finished");

        assert!(
            artifacts.probes.len() >= 10,
            "the probe registry should be populated"
        );
        assert!(
            artifacts.profiles.contains("quick"),
            "built-in profiles should be present"
        );

        let _ = artifacts.local_networks;
    }

    #[test]
    fn every_step_reports_what_it_produced() {
        let boot = run_to_completion();
        assert_eq!(boot.results.len(), Step::ALL.len());
        for result in &boot.results {
            assert!(
                !result.detail.is_empty(),
                "{:?} reported nothing",
                result.step
            );
        }
    }

    #[test]
    fn the_probe_step_reports_a_real_count() {
        let boot = run_to_completion();
        let probes = boot
            .results
            .iter()
            .find(|r| r.step == Step::Probes)
            .unwrap();

        let count: usize = probes
            .detail
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(count, ProbeRegistry::builtin().unwrap().len());
    }

    #[test]
    fn the_port_step_reports_the_real_dataset_size() {
        let boot = run_to_completion();
        let ports = boot.results.iter().find(|r| r.step == Step::Ports).unwrap();
        assert!(ports.detail.contains("TCP"), "detail was: {}", ports.detail);
        let count: usize = ports
            .detail
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(count >= 1000);
    }

    #[test]
    fn finishing_early_yields_nothing() {
        let ctx = egui::Context::default();
        let mut boot = Boot::new();
        boot.advance(&ctx);
        assert!(
            boot.finish().is_none(),
            "artifacts must not be taken mid-sequence"
        );
    }

    #[test]
    fn readiness_waits_for_the_minimum_visible_time() {
        let boot = run_to_completion();
        assert!(boot.work_finished());

        assert!(
            !boot.is_ready(),
            "the splash should not vanish after {:?}",
            boot.elapsed()
        );
        assert!(boot.elapsed() < MINIMUM_VISIBLE);
    }

    #[test]
    fn the_minimum_visible_time_is_short_enough_not_to_annoy() {
        assert!(MINIMUM_VISIBLE <= Duration::from_millis(1200));
    }

    #[test]
    fn startup_is_fast() {
        let boot = run_to_completion();
        let total: Duration = boot.results.iter().map(|r| r.took).sum();
        assert!(total < Duration::from_millis(500), "startup took {total:?}");
    }

    #[test]
    fn a_successful_startup_reports_no_warnings() {
        let boot = run_to_completion();
        assert!(boot.warnings.is_empty(), "warnings: {:?}", boot.warnings);
    }
}
