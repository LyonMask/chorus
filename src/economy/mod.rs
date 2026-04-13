//! Economy module — Walkie Talkie Phase 4.
//!
//! Contains WC (WalkieCoin) ledger and CRP accumulator.

pub mod wc_ledger;

pub use wc_ledger::{WcLedger, LedgerError, CrpRecord};
