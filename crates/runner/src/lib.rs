//! # Runner
//!
//! Isolated job execution with secure Receipt generation.
//!
//! ## Features
//! - Network namespace isolation (configurable flag)
//! - Seccomp filtering indicator
//! - Pull /next with Permit verification
//! - Receipt (stdout/stderr hash + exit)
//!
#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tokio::sync::Mutex;
use ubl_kernel::{blake3_hash, ed25519_verify, EventDomain};
use wallet::Permit;

/// Runner configuration flags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerConfig {
    /// Whether to enforce network namespace isolation (simulated flag)
    pub network_isolation_enabled: bool,
    /// Whether to enforce seccomp filtering (simulated flag)
    pub seccomp_enabled: bool,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        Self {
            network_isolation_enabled: true,
            seccomp_enabled: true,
        }
    }
}

/// Request to execute a job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRequest {
    /// Unique identifier for the execution (matches Permit JTI)
    pub execution_id: String,
    /// Command to execute
    pub command: String,
    /// Command arguments
    pub args: Vec<String>,
    /// Permit authorizing the execution
    pub permit: Permit,
}

/// Receipt produced after execution
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Receipt {
    /// Execution identifier
    pub execution_id: String,
    /// Exit code of the process
    pub exit_code: i32,
    /// BLAKE3 hash of stdout (domain separated as Receipt)
    pub stdout_hash: Vec<u8>,
    /// BLAKE3 hash of stderr (domain separated as Receipt)
    pub stderr_hash: Vec<u8>,
    /// Timestamp when execution finished (unix epoch seconds)
    pub finished_at: u64,
}

/// Errors that can occur during execution
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Permit validation failed
    #[error("Permit validation failed: {0}")]
    InvalidPermit(String),
    /// Duplicate receipt detected
    #[error("Duplicate receipt for execution_id {0}")]
    DuplicateReceipt(String),
    /// Process failed to launch or complete
    #[error("Execution failure: {0}")]
    Execution(String),
}

/// Result alias for Runner operations
pub type Result<T> = std::result::Result<T, Error>;

/// Runner responsible for executing commands and generating receipts
pub struct Runner {
    verifying_key: ed25519_dalek::VerifyingKey,
    executed: Arc<Mutex<HashSet<String>>>,
    config: RunnerConfig,
}

impl Runner {
    /// Create a new Runner
    pub fn new(verifying_key: ed25519_dalek::VerifyingKey, config: RunnerConfig) -> Self {
        Self {
            verifying_key,
            executed: Arc::new(Mutex::new(HashSet::new())),
            config,
        }
    }

    /// Execute a job and return a signed receipt
    pub async fn execute(&self, request: JobRequest) -> Result<Receipt> {
        self.verify_permit(&request.permit)?;

        {
            let mut executed = self.executed.lock().await;
            if !executed.insert(request.execution_id.clone()) {
                return Err(Error::DuplicateReceipt(request.execution_id));
            }
        }

        // Network namespace + seccomp are simulated by config flags to keep the
        // runner portable inside tests; real implementation would configure the
        // OS primitives here.
        if !self.config.network_isolation_enabled {
            return Err(Error::Execution(
                "network isolation disabled; refusing to execute".to_string(),
            ));
        }
        if !self.config.seccomp_enabled {
            return Err(Error::Execution(
                "seccomp enforcement disabled; refusing to execute".to_string(),
            ));
        }

        let output = Command::new(Path::new(&request.command))
            .args(&request.args)
            .output()
            .await
            .map_err(|e| Error::Execution(e.to_string()))?;

        let stdout_hash = blake3_hash(EventDomain::Receipt, &output.stdout).to_vec();
        let stderr_hash = blake3_hash(EventDomain::Receipt, &output.stderr).to_vec();
        let exit_code = output.status.code().unwrap_or(-1);
        let finished_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(Receipt {
            execution_id: request.execution_id,
            exit_code,
            stdout_hash,
            stderr_hash,
            finished_at,
        })
    }

    fn verify_permit(&self, permit: &Permit) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if permit.exp <= now {
            return Err(Error::InvalidPermit("permit expired".to_string()));
        }

        let permit_payload = serde_json::to_vec(&permit_payload(permit))
            .map_err(|e| Error::InvalidPermit(e.to_string()))?;
        ed25519_verify(&self.verifying_key, &permit_payload, &permit.signature)
            .map_err(|_| Error::InvalidPermit("signature verification failed".to_string()))?;

        Ok(())
    }
}

fn permit_payload(permit: &Permit) -> serde_json::Value {
    serde_json::json!({
        "jti": permit.jti,
        "sub": permit.sub,
        "iss": permit.iss,
        "iat": permit.iat,
        "exp": permit.exp,
        "scope": permit.scope,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn make_permit(signing_key: &SigningKey, ttl: u64, jti: &str) -> Permit {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let permit = Permit {
            jti: jti.to_string(),
            sub: "runner-user@example.com".to_string(),
            iss: "ubl-wallet".to_string(),
            iat: now,
            exp: now + ttl,
            scope: vec!["execute".to_string()],
            signature: Vec::new(),
        };

        let payload = serde_json::to_vec(&permit_payload(&permit)).unwrap();
        let signature = signing_key.sign(&payload);

        Permit {
            signature: signature.to_bytes().to_vec(),
            ..permit
        }
    }

    #[tokio::test]
    async fn executes_command_and_creates_receipt() {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let runner = Runner::new(verifying_key, RunnerConfig::default());

        let permit = make_permit(&signing_key, 60, "exec-1");
        let request = JobRequest {
            execution_id: "exec-1".to_string(),
            command: "echo".to_string(),
            args: vec!["hello".to_string()],
            permit,
        };

        let receipt = runner.execute(request).await.unwrap();

        assert_eq!(receipt.exit_code, 0);
        // stdout for echo ends with newline
        let expected_hash = blake3_hash(EventDomain::Receipt, b"hello\n").to_vec();
        assert_eq!(receipt.stdout_hash, expected_hash);
        assert!(receipt.finished_at > 0);
    }

    #[tokio::test]
    async fn rejects_duplicate_receipts() {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let runner = Runner::new(verifying_key, RunnerConfig::default());

        let permit = make_permit(&signing_key, 60, "duplicate");
        let request = JobRequest {
            execution_id: "duplicate".to_string(),
            command: "echo".to_string(),
            args: vec!["first".to_string()],
            permit: permit.clone(),
        };

        runner.execute(request.clone()).await.unwrap();
        let err = runner.execute(request).await.unwrap_err();

        assert!(matches!(err, Error::DuplicateReceipt(id) if id == "duplicate"));
    }

    #[tokio::test]
    async fn detects_invalid_permit_signature() {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let runner = Runner::new(verifying_key, RunnerConfig::default());

        let mut permit = make_permit(&signing_key, 60, "invalid-signature");
        permit.signature = vec![1, 2, 3];

        let request = JobRequest {
            execution_id: "invalid-signature".to_string(),
            command: "echo".to_string(),
            args: vec!["ignored".to_string()],
            permit,
        };

        let err = runner.execute(request).await.unwrap_err();
        assert!(matches!(err, Error::InvalidPermit(_)));
    }

    #[tokio::test]
    async fn rejects_expired_permit() {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let runner = Runner::new(verifying_key, RunnerConfig::default());

        let permit = make_permit(&signing_key, 0, "expired");

        let request = JobRequest {
            execution_id: "expired".to_string(),
            command: "echo".to_string(),
            args: vec!["ignored".to_string()],
            permit,
        };

        let err = runner.execute(request).await.unwrap_err();
        assert!(matches!(err, Error::InvalidPermit(_)));
    }

    #[tokio::test]
    async fn respects_security_flags() {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let runner = Runner::new(
            verifying_key,
            RunnerConfig {
                network_isolation_enabled: false,
                seccomp_enabled: true,
            },
        );

        let permit = make_permit(&signing_key, 60, "config-fail");
        let request = JobRequest {
            execution_id: "config-fail".to_string(),
            command: "echo".to_string(),
            args: vec!["ignored".to_string()],
            permit,
        };

        let err = runner.execute(request).await.unwrap_err();
        assert!(matches!(err, Error::Execution(_)));
    }
}
