//! Free Tier Rate Limiting — Phase 4.1
//!
//! Unverified nodes are rate-limited to `FREE_TIER_MSG_PER_HOUR` messages
//! per hour to prevent spam.  Verified nodes (Cryptographic+) have no limit.
//!
//! Rate limits are derived from [`crate::resource::economy_params::FREE_TIER_MSG_PER_HOUR`].

use std::collections::HashMap;
use libp2p::PeerId;

use crate::resource::economy_params;
use super::types::TrustLevel;

/// Number of milliseconds in one hour.
const HOUR_MS: u64 = 3_600_000;

/// Per-peer message rate limiter.
///
/// Tracks timestamps of recent messages and enforces the rate limit
/// based on the peer's [`TrustLevel`].
#[derive(Debug, Clone)]
pub struct RateLimiter {
    /// peer_id → list of message timestamps (ms).
    counts: HashMap<PeerId, Vec<u64>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            counts: HashMap::new(),
        }
    }

    /// Check whether a message from `peer_id` at `now_ms` should be allowed.
    ///
    /// Returns `true` if the message is within rate limits, `false` if it
    /// should be dropped.
    pub fn check(&mut self, peer_id: &PeerId, trust_level: TrustLevel, now_ms: u64) -> bool {
        // Verified nodes have no rate limit
        match trust_level {
            TrustLevel::Cryptographic
            | TrustLevel::Guaranteed
            | TrustLevel::CommunityVerified => return true,
            TrustLevel::Unverified => {} // continue to check
        }

        let limit = economy_params::FREE_TIER_MSG_PER_HOUR as usize;
        let timestamps = self.counts.entry(*peer_id).or_default();

        // Count messages within the last hour
        let cutoff = now_ms.saturating_sub(HOUR_MS);
        let recent_count = timestamps.iter().filter(|&&ts| ts >= cutoff).count();

        if recent_count >= limit {
            return false; // rate limited
        }

        timestamps.push(now_ms);
        true
    }

    /// Get the current message count for a peer in the last hour.
    pub fn current_count(&self, peer_id: &PeerId, now_ms: u64) -> usize {
        let cutoff = now_ms.saturating_sub(HOUR_MS);
        self.counts
            .get(peer_id)
            .map(|ts| ts.iter().filter(|&&t| t >= cutoff).count())
            .unwrap_or(0)
    }

    /// Get the rate limit for a given trust level.
    pub fn limit_for_level(trust_level: TrustLevel) -> Option<usize> {
        match trust_level {
            TrustLevel::Unverified => Some(economy_params::FREE_TIER_MSG_PER_HOUR as usize),
            TrustLevel::Cryptographic
            | TrustLevel::Guaranteed
            | TrustLevel::CommunityVerified => None, // no limit
        }
    }

    /// Remove all tracking for a peer (e.g., on disconnect).
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.counts.remove(peer_id);
    }

    /// Prune all entries older than 1 hour.  Called periodically to
    /// prevent unbounded memory growth.
    pub fn prune_all(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(HOUR_MS);
        for timestamps in self.counts.values_mut() {
            timestamps.retain(|&ts| ts >= cutoff);
        }
        // Remove peers with empty lists
        self.counts.retain(|_, ts| !ts.is_empty());
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_peer() -> PeerId {
        libp2p::identity::Keypair::generate_ed25519().public().to_peer_id()
    }

    fn test_peer_2() -> PeerId {
        libp2p::identity::Keypair::generate_ed25519().public().to_peer_id()
    }

    #[test]
    fn test_unverified_within_limit() {
        let mut limiter = RateLimiter::new();
        let peer = test_peer();
        let limit = economy_params::FREE_TIER_MSG_PER_HOUR as usize;

        // Should allow up to FREE_TIER_MSG_PER_HOUR messages
        for i in 0u64..limit as u64 {
            assert!(
                limiter.check(&peer, TrustLevel::Unverified, 1_000_000 + i),
                "Message {} should be allowed",
                i + 1,
            );
        }
    }

    #[test]
    fn test_unverified_over_limit_rejected() {
        let mut limiter = RateLimiter::new();
        let peer = test_peer();
        let limit = economy_params::FREE_TIER_MSG_PER_HOUR as usize;

        // Fill up
        for i in 0u64..limit as u64 {
            limiter.check(&peer, TrustLevel::Unverified, 1_000_000 + i);
        }

        // Next message should be rejected
        assert!(!limiter.check(&peer, TrustLevel::Unverified, 1_000_000 + limit as u64));
    }

    #[test]
    fn test_verified_no_limit() {
        let mut limiter = RateLimiter::new();
        let peer = test_peer();

        // Cryptographic nodes bypass limit
        for i in 0..100u64 {
            assert!(
                limiter.check(&peer, TrustLevel::Cryptographic, 1_000_000 + i),
                "Message {} should be allowed for Cryptographic peer",
                i + 1,
            );
        }
    }

    #[test]
    fn test_guaranteed_no_limit() {
        let mut limiter = RateLimiter::new();
        let peer = test_peer();

        for i in 0..100u64 {
            assert!(
                limiter.check(&peer, TrustLevel::Guaranteed, 1_000_000 + i),
            );
        }
    }

    #[test]
    fn test_community_verified_no_limit() {
        let mut limiter = RateLimiter::new();
        let peer = test_peer();

        for i in 0..100u64 {
            assert!(
                limiter.check(&peer, TrustLevel::CommunityVerified, 1_000_000 + i),
            );
        }
    }

    #[test]
    fn test_upgrade_removes_limit() {
        let mut limiter = RateLimiter::new();
        let peer = test_peer();
        let limit = economy_params::FREE_TIER_MSG_PER_HOUR as usize;

        // Fill up as Unverified
        for i in 0u64..limit as u64 {
            limiter.check(&peer, TrustLevel::Unverified, 1_000_000 + i);
        }
        // Next Unverified message is blocked
        assert!(!limiter.check(&peer, TrustLevel::Unverified, 1_000_000 + limit as u64));

        // Upgrade to Cryptographic — should allow
        assert!(limiter.check(&peer, TrustLevel::Cryptographic, 1_000_000 + limit as u64 + 1));
    }

    #[test]
    fn test_prune_old_entries() {
        let mut limiter = RateLimiter::new();
        let peer = test_peer();

        // Send messages well before HOUR_MS
        for i in 0u64..5 {
            limiter.check(&peer, TrustLevel::Unverified, i);
        }
        assert_eq!(limiter.current_count(&peer, 5), 5);

        // Prune at HOUR_MS+100 — cutoff = 100, all messages at 0..4 are pruned
        limiter.prune_all(HOUR_MS + 100);
        assert_eq!(limiter.current_count(&peer, HOUR_MS + 100), 0);
        assert!(!limiter.counts.contains_key(&peer));
    }

    #[test]
    fn test_prune_keeps_recent() {
        let mut limiter = RateLimiter::new();
        let peer = test_peer();

        // First message at time=100 (old), second at HOUR_MS+100 (recent)
        limiter.check(&peer, TrustLevel::Unverified, 100);
        limiter.check(&peer, TrustLevel::Unverified, HOUR_MS + 100);

        // Prune at HOUR_MS+200 — cutoff = 200
        // First msg (100) is NOT > 200: pruned
        // Second msg (HOUR_MS+100) > 200: kept
        limiter.prune_all(HOUR_MS + 200);
        assert_eq!(limiter.current_count(&peer, HOUR_MS + 200), 1);
    }

    #[test]
    fn test_remove_peer() {
        let mut limiter = RateLimiter::new();
        let peer = test_peer();
        limiter.check(&peer, TrustLevel::Unverified, 1000);
        limiter.check(&peer, TrustLevel::Unverified, 1001);

        limiter.remove_peer(&peer);
        assert_eq!(limiter.current_count(&peer, 2000), 0);
    }

    #[test]
    fn test_limit_for_level() {
        assert!(RateLimiter::limit_for_level(TrustLevel::Unverified).is_some());
        assert_eq!(
            RateLimiter::limit_for_level(TrustLevel::Unverified),
            Some(economy_params::FREE_TIER_MSG_PER_HOUR as usize),
        );
        assert!(RateLimiter::limit_for_level(TrustLevel::Cryptographic).is_none());
        assert!(RateLimiter::limit_for_level(TrustLevel::Guaranteed).is_none());
        assert!(RateLimiter::limit_for_level(TrustLevel::CommunityVerified).is_none());
    }

    #[test]
    fn test_multiple_peers_independent() {
        let mut limiter = RateLimiter::new();
        let peer1 = test_peer();
        let peer2 = test_peer_2();
        let limit = economy_params::FREE_TIER_MSG_PER_HOUR as usize;

        // Fill up peer1
        for i in 0u64..limit as u64 {
            limiter.check(&peer1, TrustLevel::Unverified, 1_000_000 + i);
        }
        // peer1 is blocked
        assert!(!limiter.check(&peer1, TrustLevel::Unverified, 2_000_000));

        // peer2 should still be fine
        assert!(limiter.check(&peer2, TrustLevel::Unverified, 2_000_000));
    }
}
