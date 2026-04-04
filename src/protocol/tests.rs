use super::*;
use sha2::{Digest, Sha256};

// --- entry_hash ---

#[test]
fn entry_hash_matches_vector_p1() {
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

    let (hash, jcs) = entry_hash(&entries);

    let expected_jcs = r#"{"entries":[{"id":"ticket-47","weight":1},{"id":"ticket-48","weight":1},{"id":"ticket-49","weight":1}]}"#;

    assert_eq!(jcs, expected_jcs);
    assert_eq!(
        hash,
        "6056fbb6c98a0f04404adb013192d284bfec98975e2a7975395c3bcd4ad59577"
    );
}

#[test]
fn entry_hash_sorts_by_id_regardless_of_input_order() {
    let entries_a = vec![
        Entry {
            id: "b".into(),
            weight: 1,
        },
        Entry {
            id: "a".into(),
            weight: 1,
        },
    ];
    let entries_b = vec![
        Entry {
            id: "a".into(),
            weight: 1,
        },
        Entry {
            id: "b".into(),
            weight: 1,
        },
    ];
    assert_eq!(entry_hash(&entries_a), entry_hash(&entries_b));
}

// --- compute_seed ---

#[test]
fn compute_seed_matches_vector_p2() {
    let drand = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    let entry_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let weather = "1013";

    let expected_json = r#"{"drand_randomness":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789","entry_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","weather_value":"1013"}"#;

    let (seed_bytes, seed_json) = compute_seed(entry_hash, drand, weather);

    assert_eq!(seed_json, expected_json);
    assert_eq!(seed_bytes.len(), 32);
    assert_eq!(
        hex::encode(seed_bytes),
        "4c1ae3e623dd22859d869f4d0cb34d3acaf4cf7907dbb472ea690e1400bfb0d0"
    );
}

#[test]
fn compute_seed_jcs_sorts_keys_alphabetically() {
    let (_, json) = compute_seed("zzz_entry", "aaa_drand", "mmm_weather");
    assert_eq!(
        json,
        r#"{"drand_randomness":"aaa_drand","entry_hash":"zzz_entry","weather_value":"mmm_weather"}"#
    );
}

// --- compute_seed_drand_only ---

#[test]
fn compute_seed_drand_only_produces_valid_seed() {
    let drand = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    let entry_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    let expected_json = r#"{"drand_randomness":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789","entry_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}"#;

    let (seed_bytes, seed_json) = compute_seed_drand_only(entry_hash, drand);

    assert_eq!(seed_json, expected_json);
    assert_eq!(seed_bytes.len(), 32);

    let expected_hash: [u8; 32] = Sha256::digest(expected_json.as_bytes()).into();
    assert_eq!(seed_bytes, expected_hash);
}

#[test]
fn drand_only_seed_differs_from_weather_seed() {
    let drand = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    let entry_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let weather = "1013";

    let (seed_with_weather, _) = compute_seed(entry_hash, drand, weather);
    let (seed_drand_only, _) = compute_seed_drand_only(entry_hash, drand);

    assert_ne!(seed_with_weather, seed_drand_only);
}

#[test]
fn drand_only_json_has_no_weather_key() {
    let (_, json) = compute_seed_drand_only("bbb", "aaa");
    assert!(!json.contains("weather"));
}

#[test]
fn vector_p3_end_to_end() {
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

    let (ehash, _jcs) = entry_hash(&entries);
    let (seed_bytes, _json) = compute_seed(&ehash, drand, weather);
    let result = fair_pick_rs::draw(&entries, &seed_bytes, 2).unwrap();

    assert_eq!(
        ehash,
        "6056fbb6c98a0f04404adb013192d284bfec98975e2a7975395c3bcd4ad59577"
    );
    assert_eq!(
        hex::encode(seed_bytes),
        "ced93f50d73a619701e9e865eb03fb4540a7232a588c707f85754aa41e3fb037"
    );
    assert_eq!(
        result,
        vec![
            fair_pick_rs::Winner {
                position: 1,
                entry_id: "ticket-48".into()
            },
            fair_pick_rs::Winner {
                position: 2,
                entry_id: "ticket-47".into()
            },
        ]
    );
}

#[test]
fn entry_hash_escapes_special_characters_in_id() {
    let entries = vec![Entry {
        id: r#"has"quote"#.into(),
        weight: 1,
    }];

    let (_, jcs) = entry_hash(&entries);

    // The quote in the ID must be escaped as \"
    assert_eq!(jcs, r#"{"entries":[{"id":"has\"quote","weight":1}]}"#);
}

#[test]
fn entry_hash_escapes_backslash_in_id() {
    let entries = vec![Entry {
        id: r#"back\slash"#.into(),
        weight: 1,
    }];

    let (_, jcs) = entry_hash(&entries);

    assert_eq!(jcs, r#"{"entries":[{"id":"back\\slash","weight":1}]}"#);
}
