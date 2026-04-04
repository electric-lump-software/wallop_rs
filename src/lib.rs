pub mod protocol;
mod wasm;

pub use protocol::{compute_seed, compute_seed_drand_only, entry_hash};

// Re-export fair_pick_rs types for convenience
pub use fair_pick_rs::{Entry, Winner, draw};

/// Verify a draw result by recomputing the full pipeline.
///
/// Chains: entry_hash → compute_seed → draw → compare.
/// Returns true if the recomputed results match `expected_results` exactly.
pub fn verify(
    entries: &[Entry],
    drand_randomness: &str,
    weather_value: Option<&str>,
    count: u32,
    expected_results: &[Winner],
) -> bool {
    let (ehash, _) = entry_hash(entries);

    let (seed, _) = match weather_value {
        Some(w) => compute_seed(&ehash, drand_randomness, w),
        None => compute_seed_drand_only(&ehash, drand_randomness),
    };

    match draw(entries, &seed, count) {
        Ok(results) => results == expected_results,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_returns_true_for_matching_results() {
        let entries = vec![
            Entry {
                id: "ticket-47".into(),
                weight: 1,
            },
            Entry {
                id: "ticket-48".into(),
                weight: 1,
            },
            Entry {
                id: "ticket-49".into(),
                weight: 1,
            },
        ];
        let drand = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let weather = "1013";
        let expected = vec![
            Winner {
                position: 1,
                entry_id: "ticket-48".into(),
            },
            Winner {
                position: 2,
                entry_id: "ticket-47".into(),
            },
        ];

        assert!(verify(&entries, drand, Some(weather), 2, &expected));
    }

    #[test]
    fn verify_returns_false_for_wrong_results() {
        let entries = vec![
            Entry {
                id: "ticket-47".into(),
                weight: 1,
            },
            Entry {
                id: "ticket-48".into(),
                weight: 1,
            },
            Entry {
                id: "ticket-49".into(),
                weight: 1,
            },
        ];
        let drand = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let weather = "1013";
        let wrong = vec![
            Winner {
                position: 1,
                entry_id: "ticket-47".into(),
            },
            Winner {
                position: 2,
                entry_id: "ticket-48".into(),
            },
        ];

        assert!(!verify(&entries, drand, Some(weather), 2, &wrong));
    }

    #[test]
    fn verify_drand_only() {
        let entries = vec![
            Entry {
                id: "a".into(),
                weight: 1,
            },
            Entry {
                id: "b".into(),
                weight: 1,
            },
        ];
        let drand = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        // Compute expected results via the pipeline
        let (ehash, _) = entry_hash(&entries);
        let (seed, _) = compute_seed_drand_only(&ehash, drand);
        let expected = fair_pick_rs::draw(&entries, &seed, 2).unwrap();

        assert!(verify(&entries, drand, None, 2, &expected));
    }
}
