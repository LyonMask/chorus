//! Economy module — Walkie Talkie Phase 4.
//!
//! Contains WC (WalkieCoin) ledger and CRP accumulator.

pub mod crp_accumulator;
pub mod wc_ledger;

pub use crp_accumulator::{CrpAccumulator, ContributionSample, CrpEntry};
pub use wc_ledger::{WcLedger, LedgerError, CrpRecord};
