//! Economy module — Walkie Talkie Phase 4.
//!
//! Contains WC (WalkieCoin) ledger, CRP accumulator, and payment flow.

pub mod crp_accumulator;
pub mod payment;
pub mod wc_ledger;

pub use crp_accumulator::{CrpAccumulator, ContributionSample, CrpEntry};
pub use payment::{
    ResourcePayment, PaymentRequest, PaymentResponse, PaymentError,
    UsageDetails, execute_payment, handle_payment_request, handle_payment_response,
    verify_amount_reasonable,
};
pub use wc_ledger::{WcLedger, LedgerError, CrpRecord};
