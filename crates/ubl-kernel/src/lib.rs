//! # UBL Kernel
//!
//! Core cryptographic kernel providing deterministic hashing and signing.
//!
//! ## Features
//! - Canonical JSON serialization (Json✯Atomic)
//! - BLAKE3 domain-separated hashing
//! - Ed25519 signing and verification
//! - Event domain enumeration
//!
//! ## Example
//!
//! ```
//! use ubl_kernel::{canonical_json, blake3_hash, EventDomain};
//!
//! // Serialize JSON canonically
//! let data = serde_json::json!({"key": "value", "number": 42});
//! let canonical = canonical_json(&data).unwrap();
//!
//! // Hash with domain separation
//! let hash = blake3_hash(EventDomain::Decision, canonical.as_bytes());
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::Value;

/// Event domain types for domain-separated hashing
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EventDomain {
    /// Genesis event - first event in a chain
    Genesis,
    /// Decision event - ALLOW/DENY verdict
    Decision,
    /// Permit event - authorization grant
    Permit,
    /// Receipt event - execution result
    Receipt,
    /// Root event - Merkle root
    Root,
}

impl EventDomain {
    /// Get the domain separator string
    fn as_str(&self) -> &'static str {
        match self {
            EventDomain::Genesis => "ubl.genesis.v1",
            EventDomain::Decision => "ubl.decision.v1",
            EventDomain::Permit => "ubl.permit.v1",
            EventDomain::Receipt => "ubl.receipt.v1",
            EventDomain::Root => "ubl.root.v1",
        }
    }
}

/// Error types for UBL Kernel operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// JSON serialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Signature verification failed
    #[error("Signature verification failed")]
    SignatureVerification,

    /// Invalid key format
    #[error("Invalid key format: {0}")]
    InvalidKey(String),
}

/// Result type for UBL Kernel operations
pub type Result<T> = std::result::Result<T, Error>;

/// Serialize JSON value to canonical form (Json✯Atomic)
///
/// This ensures deterministic serialization by:
/// - Sorting object keys alphabetically
/// - Using compact encoding (no whitespace)
/// - Consistent number formatting
///
/// # Example
///
/// ```
/// use ubl_kernel::canonical_json;
///
/// let data = serde_json::json!({"z": 1, "a": 2});
/// let canonical = canonical_json(&data).unwrap();
/// assert_eq!(canonical, r#"{"a":2,"z":1}"#);
/// ```
pub fn canonical_json(value: &Value) -> Result<String> {
    // Sort keys and serialize without whitespace
    let sorted = sort_json_keys(value);
    Ok(serde_json::to_string(&sorted)?)
}

/// Recursively sort JSON object keys for canonical serialization
fn sort_json_keys(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted_map = serde_json::Map::new();
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            for key in keys {
                sorted_map.insert(key.clone(), sort_json_keys(&map[key]));
            }
            Value::Object(sorted_map)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(sort_json_keys).collect()),
        _ => value.clone(),
    }
}

/// Compute BLAKE3 hash with domain separation
///
/// # Example
///
/// ```
/// use ubl_kernel::{blake3_hash, EventDomain};
///
/// let data = b"hello world";
/// let hash = blake3_hash(EventDomain::Decision, data);
/// assert_eq!(hash.len(), 32);
/// ```
pub fn blake3_hash(domain: EventDomain, data: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    // Add domain separator
    hasher.update(domain.as_str().as_bytes());
    hasher.update(b"\x00"); // Null byte separator
    hasher.update(data);
    let hash = hasher.finalize();
    *hash.as_bytes()
}

/// Sign data using Ed25519
///
/// # Example
///
/// ```
/// use ubl_kernel::ed25519_sign;
/// use ed25519_dalek::SigningKey;
/// use rand::rngs::OsRng;
///
/// let mut csprng = OsRng;
/// let signing_key = SigningKey::generate(&mut csprng);
/// let data = b"message to sign";
/// let signature = ed25519_sign(&signing_key, data);
/// assert_eq!(signature.len(), 64);
/// ```
pub fn ed25519_sign(signing_key: &SigningKey, data: &[u8]) -> Vec<u8> {
    let signature = signing_key.sign(data);
    signature.to_bytes().to_vec()
}

/// Verify Ed25519 signature
///
/// # Example
///
/// ```
/// use ubl_kernel::{ed25519_sign, ed25519_verify};
/// use ed25519_dalek::SigningKey;
/// use rand::rngs::OsRng;
///
/// let mut csprng = OsRng;
/// let signing_key = SigningKey::generate(&mut csprng);
/// let verifying_key = signing_key.verifying_key();
/// let data = b"message to sign";
///
/// let signature = ed25519_sign(&signing_key, data);
/// assert!(ed25519_verify(&verifying_key, data, &signature).is_ok());
/// ```
pub fn ed25519_verify(verifying_key: &VerifyingKey, data: &[u8], signature: &[u8]) -> Result<()> {
    let sig = Signature::from_slice(signature).map_err(|e| Error::InvalidKey(e.to_string()))?;

    verifying_key
        .verify(data, &sig)
        .map_err(|_| Error::SignatureVerification)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_canonical_json_sorts_keys() {
        let data = serde_json::json!({
            "z": 1,
            "a": 2,
            "m": 3
        });
        let canonical = canonical_json(&data).unwrap();
        assert_eq!(canonical, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn test_canonical_json_nested() {
        let data = serde_json::json!({
            "outer": {
                "z": 1,
                "a": 2
            },
            "array": [3, 2, 1]
        });
        let canonical = canonical_json(&data).unwrap();
        assert_eq!(canonical, r#"{"array":[3,2,1],"outer":{"a":2,"z":1}}"#);
    }

    #[test]
    fn test_canonical_json_deterministic() {
        let data1 = serde_json::json!({"b": 2, "a": 1});
        let data2 = serde_json::json!({"a": 1, "b": 2});

        let canonical1 = canonical_json(&data1).unwrap();
        let canonical2 = canonical_json(&data2).unwrap();

        assert_eq!(canonical1, canonical2);
    }

    #[test]
    fn test_blake3_hash_deterministic() {
        let data = b"test data";
        let hash1 = blake3_hash(EventDomain::Decision, data);
        let hash2 = blake3_hash(EventDomain::Decision, data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_blake3_hash_domain_separation() {
        let data = b"test data";
        let hash_decision = blake3_hash(EventDomain::Decision, data);
        let hash_permit = blake3_hash(EventDomain::Permit, data);
        assert_ne!(hash_decision, hash_permit);
    }

    #[test]
    fn test_blake3_hash_length() {
        let data = b"test data";
        let hash = blake3_hash(EventDomain::Decision, data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_ed25519_sign_and_verify() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let data = b"test message";

        let signature = ed25519_sign(&signing_key, data);
        assert_eq!(signature.len(), 64);

        let result = ed25519_verify(&verifying_key, data, &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ed25519_verify_wrong_data() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let data = b"test message";
        let wrong_data = b"wrong message";

        let signature = ed25519_sign(&signing_key, data);
        let result = ed25519_verify(&verifying_key, wrong_data, &signature);

        assert!(result.is_err());
    }

    #[test]
    fn test_ed25519_verify_wrong_key() {
        let mut csprng = OsRng;
        let signing_key1 = SigningKey::generate(&mut csprng);
        let signing_key2 = SigningKey::generate(&mut csprng);
        let verifying_key2 = signing_key2.verifying_key();
        let data = b"test message";

        let signature = ed25519_sign(&signing_key1, data);
        let result = ed25519_verify(&verifying_key2, data, &signature);

        assert!(result.is_err());
    }

    #[test]
    fn test_event_domain_strings() {
        assert_eq!(EventDomain::Genesis.as_str(), "ubl.genesis.v1");
        assert_eq!(EventDomain::Decision.as_str(), "ubl.decision.v1");
        assert_eq!(EventDomain::Permit.as_str(), "ubl.permit.v1");
        assert_eq!(EventDomain::Receipt.as_str(), "ubl.receipt.v1");
        assert_eq!(EventDomain::Root.as_str(), "ubl.root.v1");
    }
}

#[cfg(test)]
mod quickcheck_tests {
    use super::*;
    use quickcheck::{quickcheck, TestResult};

    quickcheck! {
        /// Property: Canonical JSON is deterministic for the same value
        fn prop_canonical_json_deterministic(a: i32, b: i32) -> bool {
            let data = serde_json::json!({"a": a, "b": b});
            let canonical1 = canonical_json(&data).unwrap();
            let canonical2 = canonical_json(&data).unwrap();
            canonical1 == canonical2
        }

        /// Property: Canonical JSON sorts keys consistently
        fn prop_canonical_json_key_order(a: i32, b: i32) -> bool {
            let data1 = serde_json::json!({"z": a, "a": b});
            let data2 = serde_json::json!({"a": b, "z": a});
            let canonical1 = canonical_json(&data1).unwrap();
            let canonical2 = canonical_json(&data2).unwrap();
            canonical1 == canonical2
        }

        /// Property: BLAKE3 hash is deterministic
        fn prop_blake3_deterministic(data: Vec<u8>) -> bool {
            let hash1 = blake3_hash(EventDomain::Decision, &data);
            let hash2 = blake3_hash(EventDomain::Decision, &data);
            hash1 == hash2
        }

        /// Property: BLAKE3 hash always produces 32 bytes
        fn prop_blake3_length(data: Vec<u8>) -> bool {
            let hash = blake3_hash(EventDomain::Decision, &data);
            hash.len() == 32
        }

        /// Property: Different domains produce different hashes for same data
        fn prop_blake3_domain_separation(data: Vec<u8>) -> TestResult {
            if data.is_empty() {
                return TestResult::discard();
            }
            let hash_decision = blake3_hash(EventDomain::Decision, &data);
            let hash_permit = blake3_hash(EventDomain::Permit, &data);
            TestResult::from_bool(hash_decision != hash_permit)
        }

        /// Property: Ed25519 signature verification succeeds for correct signature
        fn prop_ed25519_sign_verify(seed: u64, data: Vec<u8>) -> bool {
            use rand::SeedableRng;
            use rand::rngs::StdRng;

            let mut csprng = StdRng::seed_from_u64(seed);
            let signing_key = SigningKey::generate(&mut csprng);
            let verifying_key = signing_key.verifying_key();

            let signature = ed25519_sign(&signing_key, &data);
            ed25519_verify(&verifying_key, &data, &signature).is_ok()
        }

        /// Property: Ed25519 signature always produces 64 bytes
        fn prop_ed25519_signature_length(seed: u64, data: Vec<u8>) -> bool {
            use rand::SeedableRng;
            use rand::rngs::StdRng;

            let mut csprng = StdRng::seed_from_u64(seed);
            let signing_key = SigningKey::generate(&mut csprng);

            let signature = ed25519_sign(&signing_key, &data);
            signature.len() == 64
        }

        /// Property: Ed25519 verification fails with wrong data
        fn prop_ed25519_wrong_data_fails(seed: u64, data: Vec<u8>, extra_byte: u8) -> TestResult {
            if data.is_empty() {
                return TestResult::discard();
            }

            use rand::SeedableRng;
            use rand::rngs::StdRng;

            let mut csprng = StdRng::seed_from_u64(seed);
            let signing_key = SigningKey::generate(&mut csprng);
            let verifying_key = signing_key.verifying_key();

            let signature = ed25519_sign(&signing_key, &data);

            // Create wrong data by appending a byte
            let mut wrong_data = data.clone();
            wrong_data.push(extra_byte);

            TestResult::from_bool(ed25519_verify(&verifying_key, &wrong_data, &signature).is_err())
        }
    }
}
