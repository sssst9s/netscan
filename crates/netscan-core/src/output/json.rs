use crate::error::{Error, Result};
use crate::scanner::result::ScanReport;

pub fn render(report: &ScanReport) -> Result<String> {
    serde_json::to_string_pretty(report)
        .map(|mut text| {
            text.push('\n');
            text
        })
        .map_err(|e| Error::Serialization(e.to_string()))
}

pub fn render_compact(report: &ScanReport) -> Result<String> {
    serde_json::to_string(report).map_err(|e| Error::Serialization(e.to_string()))
}

pub fn parse(text: &str) -> Result<ScanReport> {
    let value: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| Error::Serialization(format!("invalid JSON: {e}")))?;

    if let Some(version) = value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
    {
        if version > u64::from(crate::scanner::result::SCHEMA_VERSION) {
            return Err(Error::Serialization(format!(
                "report uses schema version {version}, but this build of netscan understands \
                 version {} and earlier; upgrade netscan to read it",
                crate::scanner::result::SCHEMA_VERSION
            )));
        }
    }

    serde_json::from_value(value)
        .map_err(|e| Error::Serialization(format!("not a netscan report: {e}")))
}

pub fn read_file(path: &std::path::Path) -> Result<ScanReport> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| Error::Serialization(format!("could not read {}: {e}", path.display())))?;
    parse(&text).map_err(|e| match e {
        Error::Serialization(msg) => Error::Serialization(format!("{}: {msg}", path.display())),
        other => other,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::tests::sample_report;

    #[test]
    fn output_is_valid_json_and_round_trips() {
        let report = sample_report();
        let text = render(&report).unwrap();
        assert!(text.ends_with('\n'), "files should end with a newline");
        let parsed = parse(&text).unwrap();
        assert_eq!(parsed, report);
    }

    #[test]
    fn compact_output_is_a_single_line() {
        let report = sample_report();
        let text = render_compact(&report).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert_eq!(parse(&text).unwrap(), report);
    }

    #[test]
    fn the_schema_version_is_recorded() {
        let text = render(&sample_report()).unwrap();
        assert!(text.contains("\"schema_version\": 1"), "output was: {text}");
    }

    #[test]
    fn newer_schema_versions_are_refused_with_an_explanation() {
        let text = render(&sample_report())
            .unwrap()
            .replace("\"schema_version\": 1", "\"schema_version\": 99");
        let err = parse(&text).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("99"), "message was: {message}");
        assert!(
            message.contains("upgrade netscan"),
            "message was: {message}"
        );
    }

    #[test]
    fn malformed_input_is_rejected_clearly() {
        assert!(parse("").is_err());
        assert!(parse("not json").is_err());
        let err = parse("{\"hello\": 1}").unwrap_err();
        assert!(
            err.to_string().contains("not a netscan report"),
            "message was: {err}"
        );
    }

    #[test]
    fn reading_a_file_names_it_on_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broken.json");
        std::fs::write(&path, "{").unwrap();
        let err = read_file(&path).unwrap_err();
        assert!(
            err.to_string().contains("broken.json"),
            "message was: {err}"
        );
    }

    #[test]
    fn absent_optional_fields_are_omitted_rather_than_null() {
        let text = render(&sample_report()).unwrap();
        assert!(!text.contains(": null"), "nulls should be omitted:\n{text}");
    }
}
