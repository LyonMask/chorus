//! Resource Declaration Module — Walkie Talkie Phase 2
//!
//! Implements the Resource Contribution Protocol (D1 spec):
//! - ResourceAdvertisement: node resource capability declarations
//! - ResourceTable: local cache of all known node resources
//! - ResourceSession: lifecycle of a resource allocation
//! - ContributionRecord: contribution measurement
//! - EconomyParams: frozen v1.1 economic parameters (20 constants)
//!
//! Key design decisions (per 驚羽 review):
//! - ResourceSpec sub-struct for hardware specs (驚羽意見1)
//! - Backoff on rejection (驚羽意見3)
//! - Heartbeat payload extension (zero-breakage upgrade)
//! - No new MessageProtocol variants — use DataExchange + Heartbeat

mod types;
mod table;
mod session;
mod proof;
mod backoff;
mod engine;
pub mod match_engine;
pub mod economy_params;

pub use types::*;
pub use table::ResourceTable;
pub use session::ResourceSessionManager;
pub use proof::{BandwidthReceipt, PoRVerifier, StorageChallenge, StorageProof, WorkReceipt};
pub use backoff::RequestBackoff;
pub use engine::{ContributionEngine, MaintenanceReport};
pub use match_engine::{MatchEngine, MatchResult, ScoreComponents, LatencyTracker, ReliabilityTracker, RESERVATION_TTL_MS};
