//! Exponential backoff for resource request rejections (驚羽意見3).

use serde::{Deserialize, Serialize};

/// Maximum backoff level (2^5 = 32 seconds).
const DEFAULT_MAX_LEVEL: u8 = 5;

/// Exponential backoff for resource request rejections.
///
/// When a request is rejected (provider full or conflicted), the consumer
/// should not immediately retry. Instead, wait with exponential backoff:
/// level 0 = 1s, level 1 = 2s, level 2 = 4s, ..., level 5 = 32s.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RequestBackoff {
    /// Current backoff level (0 = immediate retry allowed).
    pub level: u8,
    /// Maximum backoff level (default 5 → 32s max delay).
    pub max_level: u8,
}

impl Default for RequestBackoff {
    fn default() -> Self {
        Self::new()
    }
}

impl RequestBackoff {
    pub fn new() -> Self {
        Self {
            level: 0,
            max_level: DEFAULT_MAX_LEVEL,
        }
    }

    /// Create with a custom max level.
    pub fn with_max_level(max_level: u8) -> Self {
        Self {
            level: 0,
            max_level,
        }
    }

    /// Get the current delay in milliseconds.
    /// Level 0 → 1000ms, level 1 → 2000ms, ..., level N → 2^N * 1000ms.
    pub fn delay_ms(&self) -> u64 {
        2u64.pow(self.level as u32) * 1000
    }

    /// Called when a request is rejected: increase backoff level.
    pub fn on_reject(&mut self) {
        self.level = (self.level + 1).min(self.max_level);
    }

    /// Called when a request is accepted: reset backoff to 0.
    pub fn on_accept(&mut self) {
        self.level = 0;
    }

    /// Check if we're currently in a backoff period.
    /// Returns true if the last rejection was within the delay window.
    pub fn is_backing_off(&self, last_reject_ms: u64, now_ms: u64) -> bool {
        if self.level == 0 {
            return false;
        }
        now_ms < last_reject_ms + self.delay_ms()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let bo = RequestBackoff::new();
        assert_eq!(bo.level, 0);
        assert_eq!(bo.delay_ms(), 1000);
    }

    #[test]
    fn test_on_reject_increments() {
        let mut bo = RequestBackoff::new();
        bo.on_reject();
        assert_eq!(bo.level, 1);
        assert_eq!(bo.delay_ms(), 2000);

        bo.on_reject();
        assert_eq!(bo.level, 2);
        assert_eq!(bo.delay_ms(), 4000);
    }

    #[test]
    fn test_on_accept_resets() {
        let mut bo = RequestBackoff::new();
        bo.on_reject();
        bo.on_reject();
        bo.on_reject();
        assert_eq!(bo.level, 3);

        bo.on_accept();
        assert_eq!(bo.level, 0);
        assert_eq!(bo.delay_ms(), 1000);
    }

    #[test]
    fn test_max_level_cap() {
        let mut bo = RequestBackoff::new();
        for _ in 0..20 {
            bo.on_reject();
        }
        assert_eq!(bo.level, DEFAULT_MAX_LEVEL);
        assert_eq!(bo.delay_ms(), 32_000);
    }

    #[test]
    fn test_custom_max_level() {
        let mut bo = RequestBackoff::with_max_level(3);
        for _ in 0..10 {
            bo.on_reject();
        }
        assert_eq!(bo.level, 3);
        assert_eq!(bo.delay_ms(), 8000);
    }

    #[test]
    fn test_is_backing_off() {
        let mut bo = RequestBackoff::new();
        bo.on_reject(); // level 1 → 2000ms

        let reject_time = 100_000;
        // Within backoff window.
        assert!(bo.is_backing_off(reject_time, 100_500));
        // After backoff window.
        assert!(!bo.is_backing_off(reject_time, 103_000));
        // Level 0 never backs off.
        bo.on_accept();
        assert!(!bo.is_backing_off(reject_time, 100_500));
    }
}
