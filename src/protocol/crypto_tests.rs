use super::*;
use sha2::{Digest, Sha256};

const ED25519_VECTORS: &str = include_str!("../../vendor/wallop/spec/vectors/ed25519.json");
const KEY_ID_VECTORS: &str = include_str!("../../vendor/wallop/spec/vectors/key-id.json");

fn load_ed25519_keypair() -> (serde_json::Value, [u8; 32]) {
    let vectors: serde_json::Value = serde_json::from_str(ED25519_VECTORS).unwrap();
    let public_key_hex = vectors["keypair"]["public_key_hex"].as_str().unwrap();
    let public_key: [u8; 32] = hex::decode(public_key_hex).unwrap().try_into().unwrap();
    (vectors, public_key)
}

// V-4: Ed25519 verify — fixed key + fixed payload produces fixed signature
#[test]
fn v4_verify_receipt_valid_signature() {
    let (vectors, public_key) = load_ed25519_keypair();
    let v = &vectors["vectors"][0];

    let payload = v["payload"].as_str().unwrap();
    let signature: [u8; 64] = hex::decode(v["expected_signature_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();

    assert!(verify_receipt(payload.as_bytes(), &signature, &public_key));
}

// V-4: tampered payload does not verify
#[test]
fn v4_verify_receipt_tampered_payload() {
    let (vectors, public_key) = load_ed25519_keypair();
    let v = &vectors["vectors"][0];

    let payload = v["payload"].as_str().unwrap();
    let tampered = format!("{}x", payload);
    let signature: [u8; 64] = hex::decode(v["expected_signature_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();

    assert!(!verify_receipt(
        tampered.as_bytes(),
        &signature,
        &public_key
    ));
}

// V-4: wrong key does not verify
#[test]
fn v4_verify_receipt_wrong_key() {
    let (vectors, public_key) = load_ed25519_keypair();
    let _ = public_key; // loaded but not used — we use a zero key
    let v = &vectors["vectors"][0];

    let payload = v["payload"].as_str().unwrap();
    let signature: [u8; 64] = hex::decode(v["expected_signature_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();

    let wrong_key = [0u8; 32];
    assert!(!verify_receipt(payload.as_bytes(), &signature, &wrong_key));
}

// V-8: key_id — deterministic 8-char hex fingerprint
#[test]
fn v8_key_id_pinned() {
    let vectors: serde_json::Value = serde_json::from_str(KEY_ID_VECTORS).unwrap();
    let v = &vectors["vectors"][0];

    let public_key: [u8; 32] = hex::decode(v["public_key_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();

    assert_eq!(key_id(&public_key), v["expected_key_id"].as_str().unwrap());
}

// key_id is first 4 bytes of SHA-256(public_key) hex-encoded
#[test]
fn key_id_matches_sha256_prefix() {
    let vectors: serde_json::Value = serde_json::from_str(KEY_ID_VECTORS).unwrap();
    let v = &vectors["vectors"][0];

    let public_key: [u8; 32] = hex::decode(v["public_key_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();

    let hash = Sha256::digest(public_key);
    let full_hex = hex::encode(hash);
    assert_eq!(key_id(&public_key), &full_hex[..8]);
}
