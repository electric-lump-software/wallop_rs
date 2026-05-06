//! Cross-language conformance check for the pre-lock proof page
//! allowlist vector (`spec/vectors/pre_lock_wide_gap_v1.json`,
//! consumed by `wallop_core`'s `proof_pre_lock_view_vector_test.exs`).
//!
//! The pre-lock proof page is a server-side rendering concern; this
//! Rust verifier does not (currently) parse HTML or reproduce the
//! projection. This test asserts the *vector file* is well-formed
//! and structurally matches the spec — every `expected_view` is a
//! subset of the documented `allowlist`, every `forensic_strings_*`
//! is absent from its corresponding `expected_view`. Drift here
//! flags before any future tool that DOES consume this vector to
//! drive a verifier-side rendering check (e.g. a proof-page scraper)
//! could pick up incorrect data.

use serde_json::Value;
use std::collections::HashSet;

const PRE_LOCK_VECTOR: &str =
    include_str!("../../vendor/wallop/spec/vectors/pre_lock_wide_gap_v1.json");

fn load() -> Value {
    serde_json::from_str(PRE_LOCK_VECTOR).expect("pre_lock_wide_gap_v1.json parse")
}

#[test]
fn vector_v1_has_expected_top_level_shape() {
    let v = load();
    assert_eq!(v["version"].as_str(), Some("1"));
    assert!(v["allowlist"].is_array(), "allowlist must be array");
    assert!(
        v["operator_allowlist"].is_array(),
        "operator_allowlist must be array"
    );
    assert!(v["vectors"].is_array(), "vectors must be array");
    assert!(
        v["negative_vectors"].is_array(),
        "negative_vectors must be array"
    );
}

#[test]
fn allowlist_matches_documented_set() {
    let v = load();
    let actual: HashSet<&str> = v["allowlist"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().expect("allowlist entry is string"))
        .collect();

    let expected: HashSet<&str> = [
        "id",
        "name",
        "status",
        "winner_count",
        "entry_count",
        "opened_at",
        "check_url",
        "operator_sequence",
        "operator",
    ]
    .into_iter()
    .collect();

    assert_eq!(
        actual, expected,
        "allowlist diverged from documented spec set"
    );
}

#[test]
fn operator_allowlist_matches_documented_set() {
    let v = load();
    let actual: HashSet<&str> = v["operator_allowlist"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect();

    let expected: HashSet<&str> = ["slug", "name"].into_iter().collect();
    assert_eq!(actual, expected, "operator_allowlist diverged");
}

#[test]
fn every_expected_view_is_a_subset_of_the_allowlist() {
    let v = load();
    let allowlist: HashSet<&str> = v["allowlist"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect();

    for case in v["vectors"].as_array().unwrap() {
        let view = case["expected_view"]
            .as_object()
            .expect("expected_view is object");
        for (key, _value) in view {
            assert!(
                allowlist.contains(key.as_str()),
                "vector '{}' expected_view contains unexpected field '{}' \
                 (not in allowlist) — vector is malformed",
                case["name"].as_str().unwrap_or("<unnamed>"),
                key
            );
        }
    }
}

#[test]
fn forensic_strings_never_appear_in_expected_view() {
    // The forensic_strings list documents substrings the projection
    // MUST drop. If any of them appear in expected_view, the vector
    // contradicts itself.
    let v = load();

    for case in v["vectors"].as_array().unwrap() {
        let serialised = serde_json::to_string(&case["expected_view"]).unwrap();

        if let Some(forbidden_arr) =
            case["forensic_strings_that_must_not_appear_in_view"].as_array()
        {
            for forbidden in forbidden_arr {
                let needle = forbidden.as_str().unwrap();
                assert!(
                    !serialised.contains(needle),
                    "vector '{}' is self-contradictory: expected_view contains \
                     forensic string '{}' which it claims must NOT appear",
                    case["name"].as_str().unwrap_or("<unnamed>"),
                    needle
                );
            }
        }
    }
}

#[test]
fn negative_vectors_have_required_fields() {
    let v = load();
    for case in v["negative_vectors"].as_array().unwrap() {
        assert!(
            case["draw_input"].is_object(),
            "negative_vector missing draw_input"
        );
        assert!(
            case["expected_error"].is_string(),
            "negative_vector missing expected_error"
        );
        // Negative vectors MUST be non-:open — the Elixir module raises
        // ArgumentError on non-:open, so any negative case here that
        // had status=:open would not exercise the guard it documents.
        assert_ne!(
            case["draw_input"]["status"].as_str(),
            Some("open"),
            "negative_vector has status='open' — would not exercise the non-:open guard"
        );
    }
}
