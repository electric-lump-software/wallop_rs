use super::*;

const ENTRY_HASH_VECTORS: &str = include_str!("../../vendor/wallop/spec/vectors/entry-hash.json");
const COMPUTE_SEED_VECTORS: &str =
    include_str!("../../vendor/wallop/spec/vectors/compute-seed.json");
const END_TO_END_VECTOR: &str = include_str!("../../vendor/wallop/spec/vectors/end-to-end.json");

fn entries_from_json(arr: &[serde_json::Value]) -> Vec<Entry> {
    arr.iter()
        .map(|e| Entry {
            id: e["id"].as_str().unwrap().into(),
            weight: e["weight"].as_u64().unwrap() as u32,
        })
        .collect()
}

// --- entry_hash (from entry-hash.json) ---

#[test]
fn entry_hash_equal_weight() {
    let vectors: serde_json::Value = serde_json::from_str(ENTRY_HASH_VECTORS).unwrap();
    let v = &vectors["vectors"][0];

    let entries = entries_from_json(v["entries"].as_array().unwrap());
    let (hash, jcs) = entry_hash(&entries);

    assert_eq!(jcs, v["expected_jcs"].as_str().unwrap());
    assert_eq!(hash, v["expected_hash"].as_str().unwrap());
}

#[test]
fn entry_hash_weighted() {
    let vectors: serde_json::Value = serde_json::from_str(ENTRY_HASH_VECTORS).unwrap();
    let v = &vectors["vectors"][1];

    let entries = entries_from_json(v["entries"].as_array().unwrap());
    let (hash, _) = entry_hash(&entries);

    assert_eq!(hash, v["expected_hash"].as_str().unwrap());
}

#[test]
fn entry_hash_single() {
    let vectors: serde_json::Value = serde_json::from_str(ENTRY_HASH_VECTORS).unwrap();
    let v = &vectors["vectors"][2];

    let entries = entries_from_json(v["entries"].as_array().unwrap());
    let (hash, _) = entry_hash(&entries);

    assert_eq!(hash, v["expected_hash"].as_str().unwrap());
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

// --- compute_seed (from compute-seed.json) ---

#[test]
fn compute_seed_drand_plus_weather() {
    let vectors: serde_json::Value = serde_json::from_str(COMPUTE_SEED_VECTORS).unwrap();
    let v = &vectors["vectors"][0];

    let entry_hash_val = v["entry_hash"].as_str().unwrap();
    let drand = v["drand_randomness"].as_str().unwrap();
    let weather = v["weather_value"].as_str().unwrap();

    let (seed_bytes, seed_json) = compute_seed(entry_hash_val, drand, weather);

    assert_eq!(seed_json, v["expected_jcs"].as_str().unwrap());
    assert_eq!(seed_bytes.len(), 32);
    assert_eq!(
        hex::encode(seed_bytes),
        v["expected_seed_hex"].as_str().unwrap()
    );
}

#[test]
fn compute_seed_drand_only_from_vector() {
    let vectors: serde_json::Value = serde_json::from_str(COMPUTE_SEED_VECTORS).unwrap();
    let v = &vectors["vectors"][1];

    let entry_hash_val = v["entry_hash"].as_str().unwrap();
    let drand = v["drand_randomness"].as_str().unwrap();

    let (seed_bytes, seed_json) = compute_seed_drand_only(entry_hash_val, drand);

    assert_eq!(seed_bytes.len(), 32);
    assert_eq!(
        hex::encode(seed_bytes),
        v["expected_seed_hex"].as_str().unwrap()
    );

    // Verify weather key is omitted, not null
    assert!(!seed_json.contains("weather"));
}

#[test]
fn compute_seed_jcs_sorts_keys_alphabetically() {
    let (_, json) = compute_seed("zzz_entry", "aaa_drand", "mmm_weather");
    assert_eq!(
        json,
        r#"{"drand_randomness":"aaa_drand","entry_hash":"zzz_entry","weather_value":"mmm_weather"}"#
    );
}

#[test]
fn drand_only_seed_differs_from_weather_seed() {
    let vectors: serde_json::Value = serde_json::from_str(COMPUTE_SEED_VECTORS).unwrap();
    let v0 = &vectors["vectors"][0];
    let v1 = &vectors["vectors"][1];

    // Same entry_hash and drand, but one has weather and one doesn't
    assert_eq!(v0["entry_hash"], v1["entry_hash"]);
    assert_eq!(v0["drand_randomness"], v1["drand_randomness"]);
    assert_ne!(
        v0["expected_seed_hex"].as_str().unwrap(),
        v1["expected_seed_hex"].as_str().unwrap()
    );
}

// --- end-to-end (from end-to-end.json) ---

#[test]
fn end_to_end_pipeline() {
    let vector: serde_json::Value = serde_json::from_str(END_TO_END_VECTOR).unwrap();
    let input = &vector["input"];
    let expected = &vector["expected"];

    let entries = entries_from_json(input["entries"].as_array().unwrap());
    let drand = input["drand_randomness"].as_str().unwrap();
    let weather = input["weather_value"].as_str().unwrap();
    let count = input["winner_count"].as_u64().unwrap() as u32;

    let (ehash, _jcs) = entry_hash(&entries);
    let (seed_bytes, _json) = compute_seed(&ehash, drand, weather);
    let result = fair_pick_rs::draw(&entries, &seed_bytes, count).unwrap();

    assert_eq!(ehash, expected["entry_hash"].as_str().unwrap());
    assert_eq!(
        hex::encode(seed_bytes),
        expected["seed_hex"].as_str().unwrap()
    );

    let expected_winners: Vec<&str> = expected["winners"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let actual_winners: Vec<&str> = result.iter().map(|w| w.entry_id.as_str()).collect();
    assert_eq!(actual_winners, expected_winners);
}

// --- escaping (behavioral, no vector) ---

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
