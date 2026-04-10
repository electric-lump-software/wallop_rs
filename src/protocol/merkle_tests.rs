use super::*;
use sha2::{Digest, Sha256};

const MERKLE_VECTORS: &str = include_str!("../../vendor/wallop/spec/vectors/merkle-root.json");
const ANCHOR_VECTORS: &str = include_str!("../../vendor/wallop/spec/vectors/anchor-root.json");

// V-9: empty list sentinel
#[test]
fn v9_merkle_root_empty() {
    let expected: [u8; 32] = Sha256::digest(b"").into();
    assert_eq!(merkle_root(&[]), expected);
}

// V-9: single leaf
#[test]
fn v9_merkle_root_single_leaf() {
    let leaf = b"abc";
    let mut input = vec![0u8];
    input.extend_from_slice(leaf);
    let expected: [u8; 32] = Sha256::digest(&input).into();
    assert_eq!(merkle_root(&[leaf.as_slice()]), expected);
}

// V-9: two leaves pinned
#[test]
fn v9_merkle_root_two_leaves() {
    let vectors: serde_json::Value = serde_json::from_str(MERKLE_VECTORS).unwrap();
    let v = &vectors["vectors"][0];

    let leaves: Vec<String> = v["leaves"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap().to_string())
        .collect();
    let leaf_bytes: Vec<&[u8]> = leaves.iter().map(|s| s.as_bytes()).collect();

    let root = merkle_root(&leaf_bytes);
    assert_eq!(hex::encode(root), v["expected_root_hex"].as_str().unwrap());
}

// V-9: 16 leaves pinned
#[test]
fn v9_merkle_root_16_leaves() {
    let vectors: serde_json::Value = serde_json::from_str(MERKLE_VECTORS).unwrap();
    let v = &vectors["vectors"][1];

    let leaves: Vec<String> = v["leaves"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap().to_string())
        .collect();
    let leaf_bytes: Vec<&[u8]> = leaves.iter().map(|s| s.as_bytes()).collect();

    let root = merkle_root(&leaf_bytes);
    assert_eq!(hex::encode(root), v["expected_root_hex"].as_str().unwrap());
}

// V-10: anchor combined root pinned
#[test]
fn v10_anchor_root_pinned() {
    let vectors: serde_json::Value = serde_json::from_str(ANCHOR_VECTORS).unwrap();
    let v = &vectors["vectors"][0];

    let op_root: [u8; 32] = hex::decode(v["operator_receipts_root_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let exec_root: [u8; 32] = hex::decode(v["execution_receipts_root_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();

    let combined = anchor_root(&op_root, &exec_root);
    assert_eq!(
        hex::encode(combined),
        v["expected_combined_root_hex"].as_str().unwrap()
    );
}

// V-10: prefix is raw UTF-8 bytes, not length-prefixed
#[test]
fn v10_anchor_root_prefix_is_raw_utf8() {
    let dummy = [0u8; 32];
    let mut hasher_input = Vec::new();
    hasher_input.extend_from_slice(b"wallop-anchor-v1");
    hasher_input.extend_from_slice(&dummy);
    hasher_input.extend_from_slice(&dummy);
    let expected: [u8; 32] = Sha256::digest(&hasher_input).into();

    assert_eq!(anchor_root(&dummy, &dummy), expected);
}
