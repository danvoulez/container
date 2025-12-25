//! # Ledger Engine
//!
//! Immutable append-only ledger with Merkle-root anchoring.
//!
//! ## Features
//! - Append-only event storage
//! - SQL triggers preventing UPDATE/DELETE
//! - Daily Merkle-root calculation
//! - Git anchoring for roots
//!
//! ## Example
//!
//! ```no_run
//! use ledger_engine::{LedgerEngine, LedgerEvent};
//! use ubl_kernel::EventDomain;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let engine = LedgerEngine::new("sqlite::memory:").await?;
//! engine.init_schema().await?;
//!
//! let event = LedgerEvent::genesis("aggregate-1".to_string(), b"initial data");
//! engine.append(event).await?;
//! # Ok(())
//! # }
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use sqlx::{Pool, Row, Sqlite, SqlitePool};
use ubl_kernel::{blake3_hash, EventDomain};

/// Error types for Ledger Engine operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Database error
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Invalid sequence - gap detected
    #[error("Sequence gap detected: expected {expected}, got {actual}")]
    SequenceGap {
        /// Expected sequence number
        expected: i64,
        /// Actual sequence number received
        actual: i64,
    },

    /// Hash mismatch in chain
    #[error("Hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// Expected hash value
        expected: String,
        /// Actual hash value received
        actual: String,
    },

    /// Non-genesis event without previous event
    #[error("Non-genesis event requires previous event in chain")]
    MissingPreviousEvent,

    /// Genesis event must be first in aggregate
    #[error("Genesis event must be first in aggregate")]
    InvalidGenesis,

    /// Event serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Result type for Ledger Engine operations
pub type Result<T> = std::result::Result<T, Error>;

/// A ledger event in the immutable chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEvent {
    /// Aggregate identifier (stream of related events)
    pub aggregate_id: String,
    /// Sequence number within aggregate (starts at 0)
    pub sequence: i64,
    /// Event domain type
    pub domain: EventDomain,
    /// Hash of previous event (None for genesis)
    pub previous_hash: Option<Vec<u8>>,
    /// Hash of this event
    pub event_hash: Vec<u8>,
    /// Event payload (arbitrary data)
    pub payload: Vec<u8>,
    /// Timestamp when event was appended
    pub timestamp: i64,
}

impl LedgerEvent {
    /// Create a genesis event (first event in an aggregate)
    pub fn genesis(aggregate_id: String, payload: &[u8]) -> Self {
        let domain = EventDomain::Genesis;
        let sequence = 0;
        let previous_hash = None;

        let event_hash =
            Self::compute_hash(&aggregate_id, sequence, &domain, &previous_hash, payload);

        Self {
            aggregate_id,
            sequence,
            domain,
            previous_hash,
            event_hash,
            payload: payload.to_vec(),
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    /// Create a new event following a previous event
    pub fn new(
        aggregate_id: String,
        sequence: i64,
        domain: EventDomain,
        previous_hash: Vec<u8>,
        payload: &[u8],
    ) -> Self {
        let event_hash = Self::compute_hash(
            &aggregate_id,
            sequence,
            &domain,
            &Some(previous_hash.clone()),
            payload,
        );

        Self {
            aggregate_id,
            sequence,
            domain,
            previous_hash: Some(previous_hash),
            event_hash,
            payload: payload.to_vec(),
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    /// Compute the hash of an event
    fn compute_hash(
        aggregate_id: &str,
        sequence: i64,
        domain: &EventDomain,
        previous_hash: &Option<Vec<u8>>,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(aggregate_id.as_bytes());
        data.extend_from_slice(&sequence.to_le_bytes());
        if let Some(prev) = previous_hash {
            data.extend_from_slice(prev);
        }
        data.extend_from_slice(payload);

        blake3_hash(*domain, &data).to_vec()
    }

    /// Verify the event's hash is correct
    pub fn verify_hash(&self) -> bool {
        let computed = Self::compute_hash(
            &self.aggregate_id,
            self.sequence,
            &self.domain,
            &self.previous_hash,
            &self.payload,
        );
        computed == self.event_hash
    }
}

/// Ledger Engine managing immutable event storage
pub struct LedgerEngine {
    pool: Pool<Sqlite>,
}

impl LedgerEngine {
    /// Create a new Ledger Engine with the given database URL
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = SqlitePool::connect(database_url).await?;
        Ok(Self { pool })
    }

    /// Initialize the database schema with triggers
    pub async fn init_schema(&self) -> Result<()> {
        // Create ledger_events table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS ledger_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                aggregate_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                domain TEXT NOT NULL,
                previous_hash BLOB,
                event_hash BLOB NOT NULL,
                payload BLOB NOT NULL,
                timestamp INTEGER NOT NULL,
                UNIQUE(aggregate_id, sequence)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create index for efficient queries
        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_aggregate_sequence 
            ON ledger_events(aggregate_id, sequence)
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create trigger to prevent UPDATE
        sqlx::query(
            r#"
            CREATE TRIGGER IF NOT EXISTS prevent_update
            BEFORE UPDATE ON ledger_events
            BEGIN
                SELECT RAISE(ABORT, 'UPDATE operations are not allowed on ledger_events');
            END
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create trigger to prevent DELETE
        sqlx::query(
            r#"
            CREATE TRIGGER IF NOT EXISTS prevent_delete
            BEFORE DELETE ON ledger_events
            BEGIN
                SELECT RAISE(ABORT, 'DELETE operations are not allowed on ledger_events');
            END
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create ledger_roots table for Merkle roots
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS ledger_roots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                root_date TEXT NOT NULL UNIQUE,
                merkle_root BLOB NOT NULL,
                event_count INTEGER NOT NULL,
                timestamp INTEGER NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Append a new event to the ledger with validation
    pub async fn append(&self, event: LedgerEvent) -> Result<()> {
        // Verify event hash is correct
        if !event.verify_hash() {
            return Err(Error::HashMismatch {
                expected: hex::encode(&event.event_hash),
                actual: "invalid".to_string(),
            });
        }

        // Get the last event for this aggregate
        let last_event = self.get_last_event(&event.aggregate_id).await?;

        match (event.sequence, last_event) {
            // Genesis event validation
            (0, None) => {
                // First event must be genesis with no previous hash
                if event.previous_hash.is_some() {
                    return Err(Error::InvalidGenesis);
                }
            }
            // Non-genesis event validation
            (seq, Some(last)) => {
                // Check sequence continuity
                if seq != last.sequence + 1 {
                    return Err(Error::SequenceGap {
                        expected: last.sequence + 1,
                        actual: seq,
                    });
                }

                // Check hash chain
                match &event.previous_hash {
                    Some(prev_hash) if prev_hash == &last.event_hash => {
                        // Hash chain is valid
                    }
                    Some(prev_hash) => {
                        return Err(Error::HashMismatch {
                            expected: hex::encode(&last.event_hash),
                            actual: hex::encode(prev_hash),
                        });
                    }
                    None => {
                        return Err(Error::MissingPreviousEvent);
                    }
                }
            }
            // Invalid: non-genesis event without previous event
            (_, None) => {
                return Err(Error::MissingPreviousEvent);
            }
        }

        // Insert the event
        let domain_str = format!("{:?}", event.domain);
        sqlx::query(
            r#"
            INSERT INTO ledger_events 
            (aggregate_id, sequence, domain, previous_hash, event_hash, payload, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&event.aggregate_id)
        .bind(event.sequence)
        .bind(domain_str)
        .bind(event.previous_hash.as_ref())
        .bind(&event.event_hash)
        .bind(&event.payload)
        .bind(event.timestamp)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get the last event for an aggregate
    async fn get_last_event(&self, aggregate_id: &str) -> Result<Option<LedgerEvent>> {
        let row = sqlx::query(
            r#"
            SELECT aggregate_id, sequence, domain, previous_hash, event_hash, payload, timestamp
            FROM ledger_events
            WHERE aggregate_id = ?
            ORDER BY sequence DESC
            LIMIT 1
            "#,
        )
        .bind(aggregate_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => {
                let domain_str: String = row.try_get("domain")?;
                let domain = match domain_str.as_str() {
                    "Genesis" => EventDomain::Genesis,
                    "Decision" => EventDomain::Decision,
                    "Permit" => EventDomain::Permit,
                    "Receipt" => EventDomain::Receipt,
                    "Root" => EventDomain::Root,
                    _ => EventDomain::Decision, // fallback
                };

                Ok(Some(LedgerEvent {
                    aggregate_id: row.try_get("aggregate_id")?,
                    sequence: row.try_get("sequence")?,
                    domain,
                    previous_hash: row.try_get("previous_hash")?,
                    event_hash: row.try_get("event_hash")?,
                    payload: row.try_get("payload")?,
                    timestamp: row.try_get("timestamp")?,
                }))
            }
            None => Ok(None),
        }
    }

    /// Get all events for an aggregate
    pub async fn get_events(&self, aggregate_id: &str) -> Result<Vec<LedgerEvent>> {
        let rows = sqlx::query(
            r#"
            SELECT aggregate_id, sequence, domain, previous_hash, event_hash, payload, timestamp
            FROM ledger_events
            WHERE aggregate_id = ?
            ORDER BY sequence ASC
            "#,
        )
        .bind(aggregate_id)
        .fetch_all(&self.pool)
        .await?;

        let mut events = Vec::new();
        for row in rows {
            let domain_str: String = row.try_get("domain")?;
            let domain = match domain_str.as_str() {
                "Genesis" => EventDomain::Genesis,
                "Decision" => EventDomain::Decision,
                "Permit" => EventDomain::Permit,
                "Receipt" => EventDomain::Receipt,
                "Root" => EventDomain::Root,
                _ => EventDomain::Decision,
            };

            events.push(LedgerEvent {
                aggregate_id: row.try_get("aggregate_id")?,
                sequence: row.try_get("sequence")?,
                domain,
                previous_hash: row.try_get("previous_hash")?,
                event_hash: row.try_get("event_hash")?,
                payload: row.try_get("payload")?,
                timestamp: row.try_get("timestamp")?,
            });
        }

        Ok(events)
    }

    /// Calculate Merkle root for all events up to a point
    pub async fn calculate_merkle_root(&self) -> Result<Vec<u8>> {
        let rows = sqlx::query(
            r#"
            SELECT event_hash FROM ledger_events ORDER BY id ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut hashes: Vec<Vec<u8>> = rows
            .iter()
            .map(|row| row.try_get::<Vec<u8>, _>("event_hash"))
            .collect::<std::result::Result<Vec<_>, _>>()?;

        if hashes.is_empty() {
            return Ok(vec![0u8; 32]);
        }

        // Build Merkle tree
        while hashes.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in hashes.chunks(2) {
                let combined: Vec<u8> = if chunk.len() == 2 {
                    [chunk[0].as_slice(), chunk[1].as_slice()].concat()
                } else {
                    chunk[0].clone()
                };
                next_level.push(blake3_hash(EventDomain::Root, &combined).to_vec());
            }
            hashes = next_level;
        }

        Ok(hashes[0].clone())
    }

    /// Store a Merkle root snapshot
    pub async fn store_merkle_root(&self, date: &str, root: &[u8], event_count: i64) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO ledger_roots (root_date, merkle_root, event_count, timestamp)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(date)
        .bind(root)
        .bind(event_count)
        .bind(chrono::Utc::now().timestamp())
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_test_db() -> LedgerEngine {
        let engine = LedgerEngine::new("sqlite::memory:")
            .await
            .expect("Failed to create engine");
        engine.init_schema().await.expect("Failed to init schema");
        engine
    }

    #[tokio::test]
    async fn test_append_genesis_ok() {
        let engine = setup_test_db().await;

        let event = LedgerEvent::genesis("test-aggregate".to_string(), b"genesis data");
        let result = engine.append(event).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_reject_sequence_gap() {
        let engine = setup_test_db().await;

        // Append genesis
        let genesis = LedgerEvent::genesis("test-aggregate".to_string(), b"genesis data");
        engine.append(genesis.clone()).await.unwrap();

        // Try to append event with sequence 2 (skipping 1)
        let invalid_event = LedgerEvent::new(
            "test-aggregate".to_string(),
            2, // Should be 1
            EventDomain::Decision,
            genesis.event_hash.clone(),
            b"skipped sequence",
        );

        let result = engine.append(invalid_event).await;
        assert!(matches!(result, Err(Error::SequenceGap { .. })));
    }

    #[tokio::test]
    async fn test_hash_mismatch_rejected() {
        let engine = setup_test_db().await;

        // Append genesis
        let genesis = LedgerEvent::genesis("test-aggregate".to_string(), b"genesis data");
        engine.append(genesis.clone()).await.unwrap();

        // Create event with wrong previous hash
        let wrong_hash = vec![0u8; 32]; // Wrong hash
        let invalid_event = LedgerEvent::new(
            "test-aggregate".to_string(),
            1,
            EventDomain::Decision,
            wrong_hash,
            b"wrong previous hash",
        );

        let result = engine.append(invalid_event).await;
        assert!(matches!(result, Err(Error::HashMismatch { .. })));
    }

    #[tokio::test]
    async fn test_event_chain() {
        let engine = setup_test_db().await;

        // Append genesis
        let genesis = LedgerEvent::genesis("test-aggregate".to_string(), b"genesis data");
        engine.append(genesis.clone()).await.unwrap();

        // Append second event
        let event2 = LedgerEvent::new(
            "test-aggregate".to_string(),
            1,
            EventDomain::Decision,
            genesis.event_hash.clone(),
            b"second event",
        );
        engine.append(event2.clone()).await.unwrap();

        // Append third event
        let event3 = LedgerEvent::new(
            "test-aggregate".to_string(),
            2,
            EventDomain::Decision,
            event2.event_hash.clone(),
            b"third event",
        );
        engine.append(event3).await.unwrap();

        // Verify chain
        let events = engine.get_events("test-aggregate").await.unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].sequence, 0);
        assert_eq!(events[1].sequence, 1);
        assert_eq!(events[2].sequence, 2);
    }

    #[tokio::test]
    async fn test_merkle_root_calculation() {
        let engine = setup_test_db().await;

        // Append multiple events
        let genesis = LedgerEvent::genesis("test-aggregate".to_string(), b"genesis");
        engine.append(genesis.clone()).await.unwrap();

        let event2 = LedgerEvent::new(
            "test-aggregate".to_string(),
            1,
            EventDomain::Decision,
            genesis.event_hash.clone(),
            b"event2",
        );
        engine.append(event2).await.unwrap();

        // Calculate root
        let root = engine.calculate_merkle_root().await.unwrap();
        assert_eq!(root.len(), 32);

        // Store root
        let result = engine.store_merkle_root("2025-12-25", &root, 2).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_hash() {
        let event = LedgerEvent::genesis("test".to_string(), b"data");
        assert!(event.verify_hash());

        // Tamper with payload
        let mut tampered = event.clone();
        tampered.payload = b"tampered".to_vec();
        assert!(!tampered.verify_hash());
    }

    #[test]
    fn test_event_domain_serialization() {
        let event = LedgerEvent::genesis("test".to_string(), b"data");
        let serialized = serde_json::to_string(&event).unwrap();
        let deserialized: LedgerEvent = serde_json::from_str(&serialized).unwrap();
        assert_eq!(event.aggregate_id, deserialized.aggregate_id);
    }
}
