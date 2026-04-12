//! Load and validate the tamper scenario catalog JSON.
//!
//! Responsible for strict deserialization, version checking, and
//! scenario-level validation (unknown StepName variants, mutually exclusive
//! entries/entry_count, winner_count <= entry_count). Errors include the
//! scenario name so human operators can find the offending entry without
//! line numbers.

#![allow(dead_code)] // consumed by runner/selftest (added in later tasks)

use crate::StepName;
use crate::catalog::schema::{Catalog, Scenario};

/// Versions this verifier supports. Changing either of these constants is
/// a conscious, reviewable decision that gates catalog compatibility.
pub(crate) const SUPPORTED_CATALOG_SCHEMA_VERSION: &str = "1";
pub(crate) const SUPPORTED_PROTOCOL_VERSION: &str = "1";

/// Error type for catalog loading failures.
#[derive(Debug)]
pub(crate) enum LoadError {
    Parse(serde_json::Error),
    SchemaVersionMismatch {
        catalog: String,
        supported: String,
    },
    ProtocolVersionMismatch {
        catalog: String,
        supported: String,
    },
    UnknownStepName {
        scenario: String,
        step: String,
    },
    MutuallyExclusiveFields {
        scenario: String,
    },
    WinnerCountExceedsEntries {
        scenario: String,
        winner_count: u32,
        entry_count: u32,
    },
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Parse(e) => write!(f, "catalog JSON parse error: {e}"),
            LoadError::SchemaVersionMismatch { catalog, supported } => write!(
                f,
                "catalog uses schema version {catalog}, this verifier supports schema \
                 version {supported} — verifier too old or too new for this catalog"
            ),
            LoadError::ProtocolVersionMismatch { catalog, supported } => write!(
                f,
                "catalog declares protocol_version={catalog}, this verifier implements \
                 {supported} — cannot run catalog"
            ),
            LoadError::UnknownStepName { scenario, step } => write!(
                f,
                "catalog error in scenario '{scenario}': unknown step name '{step}' \
                 in expected_catch_steps"
            ),
            LoadError::MutuallyExclusiveFields { scenario } => write!(
                f,
                "catalog error in scenario '{scenario}': bundle_params has both \
                 'entries' and 'entry_count' — specify one"
            ),
            LoadError::WinnerCountExceedsEntries {
                scenario,
                winner_count,
                entry_count,
            } => write!(
                f,
                "catalog error in scenario '{scenario}': winner_count={winner_count} \
                 exceeds entry_count={entry_count}"
            ),
        }
    }
}

impl std::error::Error for LoadError {}

/// Load and validate a catalog from a JSON string.
pub(crate) fn load_catalog_from_str(json: &str) -> Result<Catalog, LoadError> {
    let catalog: Catalog = serde_json::from_str(json).map_err(LoadError::Parse)?;

    if catalog.catalog_schema_version != SUPPORTED_CATALOG_SCHEMA_VERSION {
        return Err(LoadError::SchemaVersionMismatch {
            catalog: catalog.catalog_schema_version.clone(),
            supported: SUPPORTED_CATALOG_SCHEMA_VERSION.to_string(),
        });
    }

    if catalog.protocol_version != SUPPORTED_PROTOCOL_VERSION {
        return Err(LoadError::ProtocolVersionMismatch {
            catalog: catalog.protocol_version.clone(),
            supported: SUPPORTED_PROTOCOL_VERSION.to_string(),
        });
    }

    for scenario in &catalog.scenarios {
        validate_scenario(scenario, &catalog.defaults)?;
    }

    Ok(catalog)
}

fn validate_scenario(
    scenario: &Scenario,
    defaults: &crate::catalog::schema::Defaults,
) -> Result<(), LoadError> {
    // Validate expected_catch_steps are real StepName variants
    for step_str in &scenario.expected_catch_steps {
        let step_json = format!("\"{step_str}\"");
        let parsed: Result<StepName, _> = serde_json::from_str(&step_json);
        if parsed.is_err() {
            return Err(LoadError::UnknownStepName {
                scenario: scenario.name.clone(),
                step: step_str.clone(),
            });
        }
    }

    // Check bundle_params invariants
    let params = scenario.bundle_params.as_ref();

    let has_entries = params.and_then(|p| p.entries.as_ref()).is_some();
    let has_entry_count = params.and_then(|p| p.entry_count).is_some();
    if has_entries && has_entry_count {
        return Err(LoadError::MutuallyExclusiveFields {
            scenario: scenario.name.clone(),
        });
    }

    let effective_entry_count = match params.and_then(|p| p.entries.as_ref()) {
        Some(entries) => entries.len() as u32,
        None => params
            .and_then(|p| p.entry_count)
            .unwrap_or(defaults.entry_count),
    };
    let effective_winner_count = params
        .and_then(|p| p.winner_count)
        .unwrap_or(defaults.winner_count);

    if effective_winner_count > effective_entry_count {
        return Err(LoadError::WinnerCountExceedsEntries {
            scenario: scenario.name.clone(),
            winner_count: effective_winner_count,
            entry_count: effective_entry_count,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_CATALOG: &str = r#"{
        "catalog_schema_version": "1",
        "protocol_version": "1",
        "defaults": { "entry_count": 3, "weather": "1013", "winner_count": 2 },
        "test_keypairs": {},
        "fixture_bundles": {},
        "scenarios": []
    }"#;

    #[test]
    fn minimal_catalog_loads() {
        let catalog = load_catalog_from_str(MINIMAL_CATALOG).unwrap();
        assert_eq!(catalog.catalog_schema_version, "1");
    }

    #[test]
    fn wrong_catalog_schema_version_rejected() {
        let json = MINIMAL_CATALOG.replace(
            "\"catalog_schema_version\": \"1\"",
            "\"catalog_schema_version\": \"2\"",
        );
        let err = load_catalog_from_str(&json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("schema version"),
            "error should mention schema version: {msg}"
        );
        assert!(
            msg.contains('1') && msg.contains('2'),
            "error should name both versions: {msg}"
        );
    }

    #[test]
    fn wrong_protocol_version_rejected() {
        let json = MINIMAL_CATALOG.replace(
            "\"protocol_version\": \"1\"",
            "\"protocol_version\": \"99\"",
        );
        let err = load_catalog_from_str(&json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("protocol_version"),
            "error should mention protocol_version: {msg}"
        );
    }

    #[test]
    fn malformed_json_gives_clear_error() {
        let err = load_catalog_from_str("{not valid json").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("parse") || msg.to_lowercase().contains("json"),
            "error should identify this as a JSON parse problem: {msg}"
        );
    }

    #[test]
    fn unknown_step_name_names_the_scenario() {
        let json = r#"{
            "catalog_schema_version": "1",
            "protocol_version": "1",
            "defaults": { "entry_count": 3, "weather": "1013", "winner_count": 2 },
            "test_keypairs": {},
            "fixture_bundles": {},
            "scenarios": [
                {
                    "name": "my_bad_scenario",
                    "category": "entry_set",
                    "description": "has a typo in its expected step",
                    "severity": "critical",
                    "tamper": { "kind": "field_op", "op": "byte_flip", "path": "lock_receipt.signature_hex", "offset": 0 },
                    "expected_catch_steps": ["lock_sig"]
                }
            ]
        }"#;
        let err = load_catalog_from_str(json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("my_bad_scenario"),
            "error should name the scenario: {msg}"
        );
        assert!(
            msg.contains("lock_sig"),
            "error should name the bad step: {msg}"
        );
    }

    #[test]
    fn mutually_exclusive_entries_and_entry_count_rejected() {
        let json = r#"{
            "catalog_schema_version": "1",
            "protocol_version": "1",
            "defaults": { "entry_count": 3, "weather": "1013", "winner_count": 2 },
            "test_keypairs": {},
            "fixture_bundles": {},
            "scenarios": [
                {
                    "name": "double_entry_spec",
                    "category": "entry_set",
                    "description": "has both entries and entry_count",
                    "severity": "critical",
                    "tamper": { "kind": "field_op", "op": "byte_flip", "path": "lock_receipt.signature_hex", "offset": 0 },
                    "expected_catch_steps": ["entry_hash"],
                    "bundle_params": {
                        "entries": [{ "id": "a", "weight": 1 }],
                        "entry_count": 3
                    }
                }
            ]
        }"#;
        let err = load_catalog_from_str(json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("double_entry_spec"),
            "error should name the scenario: {msg}"
        );
    }

    #[test]
    fn winner_count_exceeding_entry_count_rejected() {
        let json = r#"{
            "catalog_schema_version": "1",
            "protocol_version": "1",
            "defaults": { "entry_count": 3, "weather": "1013", "winner_count": 2 },
            "test_keypairs": {},
            "fixture_bundles": {},
            "scenarios": [
                {
                    "name": "too_many_winners",
                    "category": "entry_set",
                    "description": "asks for more winners than entries",
                    "severity": "critical",
                    "tamper": { "kind": "field_op", "op": "byte_flip", "path": "lock_receipt.signature_hex", "offset": 0 },
                    "expected_catch_steps": ["entry_hash"],
                    "bundle_params": {
                        "entry_count": 2,
                        "winner_count": 5
                    }
                }
            ]
        }"#;
        let err = load_catalog_from_str(json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("too_many_winners"),
            "error should name the scenario: {msg}"
        );
        assert!(
            msg.contains("winner_count"),
            "error should mention winner_count: {msg}"
        );
    }
}
