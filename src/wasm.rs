use fair_pick_rs::{Entry, Winner};
use wasm_bindgen::prelude::*;

use crate::protocol;

/// WASM entry point for draw.
#[wasm_bindgen]
pub fn draw_wasm(entries_js: JsValue, seed_js: &[u8], count: u32) -> Result<JsValue, JsError> {
    let entries: Vec<Entry> =
        serde_wasm_bindgen::from_value(entries_js).map_err(|e| JsError::new(&e.to_string()))?;

    let seed: [u8; 32] = seed_js
        .try_into()
        .map_err(|_| JsError::new("seed must be exactly 32 bytes"))?;

    let result = fair_pick_rs::draw(&entries, &seed, count).map_err(|e| JsError::new(&e))?;
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// WASM entry point for entry_hash.
#[wasm_bindgen]
pub fn entry_hash_wasm(entries_js: JsValue) -> Result<JsValue, JsError> {
    let entries: Vec<Entry> =
        serde_wasm_bindgen::from_value(entries_js).map_err(|e| JsError::new(&e.to_string()))?;

    let (hash, jcs) = protocol::entry_hash(&entries);

    let result = serde_json::json!({ "hash": hash, "jcs": jcs });
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// WASM entry point for compute_seed.
#[wasm_bindgen]
pub fn compute_seed_wasm(
    entry_hash: &str,
    drand_randomness: &str,
    weather_value: &str,
) -> Result<JsValue, JsError> {
    let (seed_bytes, jcs) = protocol::compute_seed(entry_hash, drand_randomness, weather_value);

    let result = serde_json::json!({
        "seed": hex::encode(seed_bytes),
        "jcs": jcs,
    });
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// WASM entry point for compute_seed (drand-only).
#[wasm_bindgen]
pub fn compute_seed_drand_only_wasm(
    entry_hash: &str,
    drand_randomness: &str,
) -> Result<JsValue, JsError> {
    let (seed_bytes, jcs) = protocol::compute_seed_drand_only(entry_hash, drand_randomness);

    let result = serde_json::json!({
        "seed": hex::encode(seed_bytes),
        "jcs": jcs,
    });
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// WASM entry point for full verification pipeline.
#[wasm_bindgen]
pub fn verify_wasm(
    entries_js: JsValue,
    drand_randomness: &str,
    weather_value: Option<String>,
    count: u32,
    expected_results_js: JsValue,
) -> Result<bool, JsError> {
    let entries: Vec<Entry> =
        serde_wasm_bindgen::from_value(entries_js).map_err(|e| JsError::new(&e.to_string()))?;

    let expected: Vec<Winner> = serde_wasm_bindgen::from_value(expected_results_js)
        .map_err(|e| JsError::new(&e.to_string()))?;

    Ok(crate::verify(
        &entries,
        drand_randomness,
        weather_value.as_deref(),
        count,
        &expected,
    ))
}
