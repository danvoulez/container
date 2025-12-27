//! # Membrana
//!
//! Fast-path ALLOW/DENY decision service with sub-millisecond latency.
//!
//! ## Features
//! - POST /verify endpoint
//! - LRU replay-cache (moka)
//! - Decision emission to Ledger
//! - p95 latency ≤ 1ms target
//!
//! ## Example
//!
//! ```no_run
//! use membrana::MembranaService;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let service = MembranaService::new("sqlite::memory:").await?;
//! let addr = "0.0.0.0:3000".parse()?;
//! service.serve(addr).await?;
//! # Ok(())
//! # }
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use ledger_engine::{LedgerEngine, LedgerEvent};
use moka::future::Cache;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use ubl_kernel::{blake3_hash, EventDomain};

/// Error types for Membrana operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Ledger engine error
    #[error("Ledger error: {0}")]
    Ledger(#[from] ledger_engine::Error),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Result type for Membrana operations
pub type Result<T> = std::result::Result<T, Error>;

/// Decision result for verification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Decision {
    /// Artifact is allowed
    Allow,
    /// Artifact is denied
    Deny,
    /// Replay detected (duplicate hash)
    DenyDuplicate,
}

/// Verification response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    /// Decision result
    pub decision: Decision,
    /// Hash of the verified data
    pub hash: String,
    /// Processing time in microseconds
    pub latency_us: u64,
}

/// Shared state for the Membrana service
#[derive(Clone)]
struct AppState {
    ledger: Arc<LedgerEngine>,
    replay_cache: Cache<Vec<u8>, Decision>,
    aggregate_id: String,
}

/// Membrana service for sub-millisecond ALLOW/DENY decisions
pub struct MembranaService {
    state: AppState,
}

impl MembranaService {
    /// Create a new Membrana service
    ///
    /// # Arguments
    ///
    /// * `database_url` - Database URL for the ledger engine
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use membrana::MembranaService;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let service = MembranaService::new("sqlite::memory:").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(database_url: &str) -> Result<Self> {
        let ledger = LedgerEngine::new(database_url).await?;
        ledger.init_schema().await?;

        // Initialize with genesis event for membrana aggregate
        let genesis = LedgerEvent::genesis("membrana-decisions".to_string(), b"genesis");
        let _ = ledger.append(genesis).await; // Ignore error if already exists

        // Create LRU cache with 10k capacity
        let replay_cache = Cache::builder()
            .max_capacity(10_000)
            .time_to_live(std::time::Duration::from_secs(300)) // 5 minutes TTL
            .build();

        let state = AppState {
            ledger: Arc::new(ledger),
            replay_cache,
            aggregate_id: "membrana-decisions".to_string(),
        };

        Ok(Self { state })
    }

    /// Create the Axum router with all routes
    fn router(&self) -> Router {
        Router::new()
            .route("/verify", post(verify_handler))
            .route("/health", axum::routing::get(health_handler))
            .with_state(self.state.clone())
    }

    /// Start the Membrana service
    ///
    /// # Arguments
    ///
    /// * `addr` - Socket address to bind to
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use membrana::MembranaService;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let service = MembranaService::new("sqlite::memory:").await?;
    /// let addr = "0.0.0.0:3000".parse()?;
    /// service.serve(addr).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn serve(self, addr: std::net::SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        axum::serve(listener, self.router()).await?;
        Ok(())
    }
}

/// Health check endpoint
async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "service": "membrana"
    }))
}

/// Verify endpoint handler
async fn verify_handler(
    State(state): State<AppState>,
    body: Bytes,
) -> std::result::Result<Json<VerifyResponse>, MembranaError> {
    let start = Instant::now();

    // Compute hash of the payload
    let hash = blake3_hash(EventDomain::Decision, &body);
    let hash_vec = hash.to_vec();

    // Check replay cache - if found, it's a duplicate (replay attack)
    if state.replay_cache.get(&hash_vec).await.is_some() {
        let latency = start.elapsed();
        return Ok(Json(VerifyResponse {
            decision: Decision::DenyDuplicate,
            hash: hex::encode(hash),
            latency_us: latency.as_micros() as u64,
        }));
    }

    // For now, simple verification: allow if not in cache
    // In a full implementation, this would check policies, signatures, etc.
    let decision = Decision::Allow;

    // Store in replay cache
    state.replay_cache.insert(hash_vec.clone(), decision).await;

    // Emit decision to ledger (async, best-effort)
    let ledger = state.ledger.clone();
    let aggregate_id = state.aggregate_id.clone();
    let decision_str = format!("{:?}", decision).to_uppercase();
    tokio::spawn(async move {
        // Note: For production, ledger appends should use a proper queue or transaction log
        // to handle concurrent requests and avoid sequence conflicts
        if let Ok(events) = ledger.get_events(&aggregate_id).await {
            let sequence = events.len() as i64;
            let previous_hash = events.last().map(|e| e.event_hash.clone());

            let decision_data = serde_json::json!({
                "decision": decision_str,
                "hash": hex::encode(hash),
                "timestamp": chrono::Utc::now().timestamp(),
            });

            let payload = serde_json::to_vec(&decision_data).unwrap_or_default();

            let event = if sequence == 0 {
                LedgerEvent::genesis(aggregate_id, &payload)
            } else {
                LedgerEvent::new(
                    aggregate_id,
                    sequence,
                    EventDomain::Decision,
                    previous_hash.unwrap_or_default(),
                    &payload,
                )
            };

            let _ = ledger.append(event).await; // Best-effort logging
        }
    });

    let latency = start.elapsed();

    Ok(Json(VerifyResponse {
        decision,
        hash: hex::encode(hash),
        latency_us: latency.as_micros() as u64,
    }))
}

/// Error wrapper for HTTP responses
#[derive(Debug)]
struct MembranaError(Error);

impl IntoResponse for MembranaError {
    fn into_response(self) -> Response {
        let status = StatusCode::INTERNAL_SERVER_ERROR;
        let body = Json(serde_json::json!({
            "error": self.0.to_string()
        }));
        (status, body).into_response()
    }
}

impl From<Error> for MembranaError {
    fn from(err: Error) -> Self {
        MembranaError(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_membrana_service_creation() {
        let service = MembranaService::new("sqlite::memory:").await;
        assert!(service.is_ok());
    }

    #[tokio::test]
    async fn test_verify_decision() {
        let service = MembranaService::new("sqlite::memory:")
            .await
            .expect("Failed to create service");

        let test_data = b"test payload";
        let bytes = Bytes::from_static(test_data);

        let result = verify_handler(State(service.state.clone()), bytes).await;
        assert!(result.is_ok());

        let response = result.unwrap().0;
        assert_eq!(response.decision, Decision::Allow);
        assert!(!response.hash.is_empty());
        assert!(response.latency_us > 0);
    }

    #[tokio::test]
    async fn test_replay_cache() {
        let service = MembranaService::new("sqlite::memory:")
            .await
            .expect("Failed to create service");

        let test_data = b"replay test";
        let bytes = Bytes::from_static(test_data);

        // First request - should ALLOW
        let result1 = verify_handler(State(service.state.clone()), bytes.clone()).await;
        assert!(result1.is_ok());
        let response1 = result1.unwrap().0;
        assert_eq!(response1.decision, Decision::Allow);

        // Second request with same data - should DENY_DUPLICATE (replay detected)
        let result2 = verify_handler(State(service.state.clone()), bytes).await;
        assert!(result2.is_ok());
        let response2 = result2.unwrap().0;
        assert_eq!(response2.decision, Decision::DenyDuplicate);

        // Same hash should be returned for both
        assert_eq!(response1.hash, response2.hash);
    }

    #[tokio::test]
    async fn test_hash_deterministic() {
        let data1 = b"deterministic test";
        let data2 = b"deterministic test";

        let hash1 = blake3_hash(EventDomain::Decision, data1);
        let hash2 = blake3_hash(EventDomain::Decision, data2);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_decision_serialization() {
        let decision = Decision::Allow;
        let json = serde_json::to_string(&decision).unwrap();
        assert_eq!(json, "\"ALLOW\"");

        let decision = Decision::Deny;
        let json = serde_json::to_string(&decision).unwrap();
        assert_eq!(json, "\"DENY\"");
    }
}
