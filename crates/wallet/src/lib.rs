//! # Wallet
//!
//! Passkey 2-eyes vault for secure Permit issuance and revocation.
//!
//! ## Features
//! - Permit issuance with TTL enforcement (≤ 900s)
//! - POST /permit endpoint
//! - Permit revocation via /permit/:jti
//! - Ed25519 signatures for authenticity
//!
//! ## Example
//!
//! ```no_run
//! use wallet::WalletService;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let service = WalletService::new().await?;
//! let addr = "0.0.0.0:3001".parse()?;
//! service.serve(addr).await?;
//! # Ok(())
//! # }
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use ubl_kernel::{ed25519_sign, ed25519_verify};

/// Maximum TTL for permits in seconds (15 minutes)
pub const MAX_PERMIT_TTL: u64 = 900;

/// Error types for Wallet operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Invalid permit
    #[error("Invalid permit: {0}")]
    InvalidPermit(String),

    /// Permit expired
    #[error("Permit expired")]
    PermitExpired,

    /// Permit not found
    #[error("Permit not found")]
    PermitNotFound,

    /// Permit already revoked
    #[error("Permit already revoked")]
    PermitRevoked,

    /// Invalid TTL
    #[error("TTL must be ≤ {MAX_PERMIT_TTL} seconds")]
    InvalidTtl,
}

/// Result type for Wallet operations
pub type Result<T> = std::result::Result<T, Error>;

/// Permit for authorization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permit {
    /// Unique identifier (JWT ID)
    pub jti: String,
    /// Subject (who the permit is for)
    pub sub: String,
    /// Issuer
    pub iss: String,
    /// Issued at (Unix timestamp)
    pub iat: u64,
    /// Expiration time (Unix timestamp)
    pub exp: u64,
    /// Scope/permissions
    pub scope: Vec<String>,
    /// Signature (Ed25519)
    pub signature: Vec<u8>,
}

/// Request to create a new permit
#[derive(Debug, Deserialize)]
pub struct CreatePermitRequest {
    /// Subject
    pub subject: String,
    /// TTL in seconds (max 900)
    pub ttl: u64,
    /// Scope/permissions
    pub scope: Vec<String>,
}

/// Response after creating a permit
#[derive(Debug, Serialize)]
pub struct CreatePermitResponse {
    /// The created permit
    pub permit: Permit,
    /// Human-readable message
    pub message: String,
}

/// Permit status response
#[derive(Debug, Serialize)]
pub struct PermitStatusResponse {
    /// The permit
    pub permit: Permit,
    /// Whether the permit is revoked
    pub revoked: bool,
    /// Whether the permit is expired
    pub expired: bool,
    /// Whether the permit is valid
    pub valid: bool,
}

/// Shared state for the Wallet service
#[derive(Clone)]
pub(crate) struct AppState {
    signing_key: Arc<SigningKey>,
    verifying_key: Arc<VerifyingKey>,
    revoked_permits: Arc<RwLock<HashMap<String, u64>>>, // jti -> revoked_at timestamp
}

/// Wallet service for Permit issuance and revocation
pub struct WalletService {
    state: AppState,
}

impl WalletService {
    /// Create a new Wallet service
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use wallet::WalletService;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let service = WalletService::new().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new() -> Result<Self> {
        // Generate a new signing key (in production, this would be loaded from secure storage)
        let mut csprng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let state = AppState {
            signing_key: Arc::new(signing_key),
            verifying_key: Arc::new(verifying_key),
            revoked_permits: Arc::new(RwLock::new(HashMap::new())),
        };

        Ok(Self { state })
    }

    /// Create the Axum router with all routes
    fn router(&self) -> Router {
        Router::new()
            .route("/permit", post(create_permit_handler))
            .route("/permit/:jti", get(get_permit_handler))
            .route("/permit/:jti", delete(revoke_permit_handler))
            .route("/health", get(health_handler))
            .with_state(self.state.clone())
    }

    /// Start the Wallet service
    ///
    /// # Arguments
    ///
    /// * `addr` - Socket address to bind to
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use wallet::WalletService;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let service = WalletService::new().await?;
    /// let addr = "0.0.0.0:3001".parse()?;
    /// service.serve(addr).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn serve(self, addr: std::net::SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        axum::serve(listener, self.router()).await?;
        Ok(())
    }

    /// Get the verifying key for this wallet
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.state.verifying_key
    }
}

/// Health check endpoint
async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "service": "wallet"
    }))
}

/// Build permit data structure for signing/verification
fn build_permit_data(permit: &Permit) -> serde_json::Value {
    serde_json::json!({
        "jti": permit.jti,
        "sub": permit.sub,
        "iss": permit.iss,
        "iat": permit.iat,
        "exp": permit.exp,
        "scope": permit.scope,
    })
}

/// Create a new permit
async fn create_permit_handler(
    State(state): State<AppState>,
    Json(request): Json<CreatePermitRequest>,
) -> std::result::Result<Json<CreatePermitResponse>, WalletError> {
    // Validate TTL
    if request.ttl > MAX_PERMIT_TTL {
        return Err(Error::InvalidTtl.into());
    }

    let now = chrono::Utc::now().timestamp() as u64;
    let exp = now + request.ttl;

    // Generate unique JTI
    let jti = uuid::Uuid::new_v4().to_string();

    // Create permit structure (without signature)
    let permit = Permit {
        jti: jti.clone(),
        sub: request.subject,
        iss: "ubl-wallet".to_string(),
        iat: now,
        exp,
        scope: request.scope,
        signature: vec![], // Temporary, will be replaced
    };

    // Build data and sign
    let permit_data = build_permit_data(&permit);
    let payload = serde_json::to_vec(&permit_data).map_err(Error::from)?;
    let signature = ed25519_sign(&state.signing_key, &payload);

    // Update permit with signature
    let permit = Permit {
        signature,
        ..permit
    };

    Ok(Json(CreatePermitResponse {
        permit,
        message: format!("Permit created with TTL of {} seconds", request.ttl),
    }))
}

/// Get permit status
async fn get_permit_handler(
    State(_state): State<AppState>,
    Path(_jti): Path<String>,
) -> std::result::Result<Json<PermitStatusResponse>, WalletError> {
    // In a real implementation, this would query a database
    // For now, we'll return an error since we don't store permits
    Err(Error::PermitNotFound.into())
}

/// Revoke a permit
async fn revoke_permit_handler(
    State(state): State<AppState>,
    Path(jti): Path<String>,
) -> std::result::Result<Json<serde_json::Value>, WalletError> {
    let now = chrono::Utc::now().timestamp() as u64;
    
    let mut revoked = state.revoked_permits.write().await;
    
    if revoked.contains_key(&jti) {
        return Err(Error::PermitRevoked.into());
    }
    
    revoked.insert(jti.clone(), now);

    Ok(Json(serde_json::json!({
        "jti": jti,
        "revoked_at": now,
        "message": "Permit revoked successfully"
    })))
}

/// Verify a permit
#[allow(dead_code)]
pub(crate) async fn verify_permit(
    state: &AppState,
    permit: &Permit,
) -> Result<bool> {
    let now = chrono::Utc::now().timestamp() as u64;

    // Check expiration
    if permit.exp < now {
        return Err(Error::PermitExpired);
    }

    // Check revocation
    let revoked = state.revoked_permits.read().await;
    if revoked.contains_key(&permit.jti) {
        return Err(Error::PermitRevoked);
    }

    // Verify signature using the same data structure
    let permit_data = build_permit_data(permit);
    let payload = serde_json::to_vec(&permit_data).map_err(Error::from)?;
    
    match ed25519_verify(&state.verifying_key, &payload, &permit.signature) {
        Ok(()) => Ok(true),
        Err(_) => Err(Error::InvalidPermit("Invalid signature".to_string())),
    }
}

/// Check if a permit is revoked
#[allow(dead_code)]
pub(crate) async fn is_revoked(state: &AppState, jti: &str) -> bool {
    let revoked = state.revoked_permits.read().await;
    revoked.contains_key(jti)
}

/// Error wrapper for HTTP responses
#[derive(Debug)]
struct WalletError(Error);

impl IntoResponse for WalletError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            Error::PermitNotFound => StatusCode::NOT_FOUND,
            Error::InvalidTtl => StatusCode::BAD_REQUEST,
            Error::PermitExpired => StatusCode::UNAUTHORIZED,
            Error::PermitRevoked => StatusCode::FORBIDDEN,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        
        let body = Json(serde_json::json!({
            "error": self.0.to_string()
        }));
        
        (status, body).into_response()
    }
}

impl From<Error> for WalletError {
    fn from(err: Error) -> Self {
        WalletError(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_wallet_service_creation() {
        let service = WalletService::new().await;
        assert!(service.is_ok());
    }

    #[tokio::test]
    async fn test_create_permit_valid_ttl() {
        let service = WalletService::new().await.unwrap();
        
        let request = CreatePermitRequest {
            subject: "user@example.com".to_string(),
            ttl: 300,
            scope: vec!["read".to_string(), "write".to_string()],
        };

        let result = create_permit_handler(
            State(service.state.clone()),
            Json(request),
        ).await;

        assert!(result.is_ok());
        let response = result.unwrap().0;
        assert_eq!(response.permit.sub, "user@example.com");
        assert_eq!(response.permit.scope.len(), 2);
        assert!(response.permit.exp > response.permit.iat);
    }

    #[tokio::test]
    async fn test_create_permit_invalid_ttl() {
        let service = WalletService::new().await.unwrap();
        
        let request = CreatePermitRequest {
            subject: "user@example.com".to_string(),
            ttl: 1000, // Too high
            scope: vec!["read".to_string()],
        };

        let result = create_permit_handler(
            State(service.state.clone()),
            Json(request),
        ).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_permit_signature_verification() {
        let service = WalletService::new().await.unwrap();
        
        let request = CreatePermitRequest {
            subject: "test@example.com".to_string(),
            ttl: 600,
            scope: vec!["admin".to_string()],
        };

        let result = create_permit_handler(
            State(service.state.clone()),
            Json(request),
        ).await.unwrap();

        let permit = result.0.permit;
        
        // Verify the permit
        let verification = verify_permit(&service.state, &permit).await;
        assert!(verification.is_ok());
        assert!(verification.unwrap());
    }

    #[tokio::test]
    async fn test_permit_revocation() {
        let service = WalletService::new().await.unwrap();
        let jti = "test-permit-123".to_string();

        // Revoke the permit
        let result = revoke_permit_handler(
            State(service.state.clone()),
            Path(jti.clone()),
        ).await;

        assert!(result.is_ok());

        // Check if revoked
        let is_rev = is_revoked(&service.state, &jti).await;
        assert!(is_rev);

        // Try to revoke again
        let result2 = revoke_permit_handler(
            State(service.state.clone()),
            Path(jti.clone()),
        ).await;

        assert!(result2.is_err());
    }

    #[test]
    fn test_max_ttl_constant() {
        assert_eq!(MAX_PERMIT_TTL, 900);
    }
}
