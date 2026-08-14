pub mod compare;
pub mod logs;
pub mod results;
pub mod splash;
pub mod statistics;
pub mod table;

#[cfg(test)]
mod render_tests;
pub mod topology;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum View {
    #[default]
    Results,
    Statistics,
    Topology,
    Compare,
    Log,
}

impl View {
    pub const ALL: &'static [View] = &[
        View::Results,
        View::Statistics,
        View::Topology,
        View::Compare,
        View::Log,
    ];

    pub fn label(self) -> &'static str {
        match self {
            View::Results => "Results",
            View::Statistics => "Statistics",
            View::Topology => "Topology",
            View::Compare => "Compare",
            View::Log => "Log",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            View::Results => "Hosts, open ports and the detail behind each one",
            View::Statistics => "Aggregates: services, port distribution and latency",
            View::Topology => "Hosts grouped by the subnets they were found in",
            View::Compare => "What changed between this scan and a saved one",
            View::Log => "Everything that happened during the scan",
        }
    }

    pub fn shortcut_digit(self) -> usize {
        Self::ALL.iter().position(|v| *v == self).unwrap_or(0) + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_view_has_a_label_a_description_and_a_shortcut() {
        for (index, view) in View::ALL.iter().enumerate() {
            assert!(!view.label().is_empty());
            assert!(!view.description().is_empty());
            assert_eq!(view.shortcut_digit(), index + 1);
        }
    }

    #[test]
    fn results_is_the_default_view() {
        assert_eq!(View::default(), View::Results);
    }

    #[test]
    fn labels_are_unique() {
        let mut labels: Vec<_> = View::ALL.iter().map(|v| v.label()).collect();
        let before = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(before, labels.len());
    }
}
