//! Trust Layer — Walkie Talkie v0.4
//!
//! Multi-layer trust system built on top of Phase 2B+3's E2EE and
//! resource management.  Implements identity attestation, endorsement,
//! reputation scoring, guarantor机制, and slash惩罚.
//!
//! # Module Map
//!
//! - [`types`]       — shared types (TrustLevel, TrustError, TrustScore)
//! - [`peer_binding`] — PeerId↔DID cryptographic binding (IdentityAttestation)
//! - [`endorsement`] — contribution cross-validation (Phase 4.0)
//! - [`reputation`]  — composite trust score engine (Phase 4.1)
//! - [`guarantor`]  — guarantor mechanism (Phase 4.1)
//! - [`slash`]      — punishment matrix (Phase 4.1)

pub mod types;
pub mod peer_binding;
pub mod endorsement;
