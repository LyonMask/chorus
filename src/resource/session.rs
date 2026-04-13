//! Resource session lifecycle management.

use crate::resource::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// How long an offer remains valid before automatic expiry (ms).
const OFFER_TTL_MS: u64 = 30_000; // 30 seconds
/// Maximum concurrent active+pending sessions per node.
const MAX_CONCURRENT_SESSIONS: usize = 8;

/// Manages active resource sessions on the provider side.
#[derive(Debug, Clone)]
pub struct ResourceSessionManager {
    /// Active and pending sessions keyed by session_id.
    sessions: HashMap<String, ResourceSession>,

    /// Track allocated resources per provider: agent_id → (cpu, memory_mb, bw, storage).
    allocations: HashMap<String, (f32, u64, u64, u64)>,
}

/// A resource allocation session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResourceSession {
    pub session_id: String,
    pub consumer: String,
    pub provider: String,
    pub resource_type: ResourceType,
    pub amount: f64,
    pub cpu_amount: f32,
    pub memory_amount_mb: u64,
    pub started_at: u64,
    pub ends_at: u64,
    pub actual_end: Option<u64>,
    pub status: SessionStatus,
}

impl Default for ResourceSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceSessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            allocations: HashMap::new(),
        }
    }

    /// Create a pending session from an accepted offer.
    /// Returns the session ID.
    pub fn create_session(
        &mut self,
        consumer: String,
        provider: String,
        cpu: f32,
        memory_mb: u64,
        duration_ms: u64,
    ) -> String {
        let session_id = Self::generate_session_id(&consumer, &provider);
        let now = now_ms();

        let session = ResourceSession {
            session_id: session_id.clone(),
            consumer,
            provider: provider.clone(),
            resource_type: ResourceType::Cpu, // primary type
            amount: cpu as f64,
            cpu_amount: cpu,
            memory_amount_mb: memory_mb,
            started_at: now,
            ends_at: now + duration_ms,
            actual_end: None,
            status: SessionStatus::Pending,
        };

        // Track allocation.
        let entry = self.allocations.entry(provider).or_insert((0.0, 0, 0, 0));
        entry.0 += cpu;
        entry.1 += memory_mb;

        self.sessions.insert(session_id.clone(), session);
        session_id
    }

    /// Activate a pending session (consumer confirmed acceptance).
    pub fn activate(&mut self, session_id: &str) -> bool {
        if let Some(session) = self.sessions.get_mut(session_id) {
            if session.status == SessionStatus::Pending {
                session.status = SessionStatus::Active;
                return true;
            }
        }
        false
    }

    /// Release a session (consumer finished using the resource).
    /// Returns the completed session if found.
    pub fn release(&mut self, session_id: &str) -> Option<ResourceSession> {
        if let Some(session) = self.sessions.get_mut(session_id) {
            if session.status == SessionStatus::Active || session.status == SessionStatus::Pending {
                let now = now_ms();
                session.status = SessionStatus::Released;
                session.actual_end = Some(now);

                // Subtract from allocations.
                if let Some(alloc) = self.allocations.get_mut(&session.provider) {
                    alloc.0 = (alloc.0 - session.cpu_amount).max(0.0);
                    alloc.1 = alloc.1.saturating_sub(session.memory_amount_mb);
                }

                return Some(session.clone());
            }
        }
        None
    }

    /// Revoke a session (provider-initiated).
    pub fn revoke(&mut self, session_id: &str) -> bool {
        if let Some(session) = self.sessions.get_mut(session_id) {
            if session.status == SessionStatus::Active || session.status == SessionStatus::Pending {
                session.status = SessionStatus::Revoked;
                session.actual_end = Some(now_ms());

                if let Some(alloc) = self.allocations.get_mut(&session.provider) {
                    alloc.0 = (alloc.0 - session.cpu_amount).max(0.0);
                    alloc.1 = alloc.1.saturating_sub(session.memory_amount_mb);
                }
                return true;
            }
        }
        false
    }

    /// Expire sessions whose `ends_at` has passed.
    /// Returns the number of expired sessions.
    pub fn expire_timed_out(&mut self) -> usize {
        let now = now_ms();
        let mut count = 0;

        for session in self.sessions.values_mut() {
            if session.status == SessionStatus::Active && now > session.ends_at {
                session.status = SessionStatus::Expired;
                session.actual_end = Some(now);
                count += 1;
            }
        }

        count
    }

    /// Expire pending offers older than OFFER_TTL_MS.
    pub fn expire_stale_offers(&mut self) -> usize {
        let now = now_ms();
        let mut count = 0;

        for session in self.sessions.values_mut() {
            if session.status == SessionStatus::Pending
                && now > session.started_at + OFFER_TTL_MS
            {
                session.status = SessionStatus::Expired;
                session.actual_end = Some(now);
                count += 1;
            }
        }

        count
    }

    /// Check if a provider can accept a new allocation given their declared limits.
    pub fn can_allocate(
        &self,
        provider: &str,
        ad: &ResourceAdvertisement,
        cpu: f32,
        memory_mb: u64,
    ) -> bool {
        // Enforce maximum concurrent sessions to prevent resource exhaustion.
        let active_count = self
            .sessions
            .values()
            .filter(|s| s.status == SessionStatus::Active || s.status == SessionStatus::Pending)
            .count();
        if active_count >= MAX_CONCURRENT_SESSIONS {
            return false;
        }

        let (used_cpu, used_mem, _, _) = self
            .allocations
            .get(provider)
            .copied()
            .unwrap_or((0.0, 0, 0, 0));

        let cpu_ok = used_cpu + cpu <= ad.cpu_offer;
        let mem_ok = used_mem + memory_mb <= ad.memory_offer_mb;
        cpu_ok && mem_ok
    }

    /// Get a session by ID.
    pub fn get(&self, session_id: &str) -> Option<&ResourceSession> {
        self.sessions.get(session_id)
    }

    /// List all sessions with a given status.
    pub fn list_by_status(&self, status: SessionStatus) -> Vec<&ResourceSession> {
        self.sessions
            .values()
            .filter(|s| s.status == status)
            .collect()
    }

    /// Current allocation for a provider.
    pub fn current_allocation(&self, provider: &str) -> (f32, u64) {
        self.allocations
            .get(provider)
            .map(|(cpu, mem, _, _)| (*cpu, *mem))
            .unwrap_or((0.0, 0))
    }

    fn generate_session_id(consumer: &str, provider: &str) -> String {
        let now = now_ms();
        let mut bytes = [0u8; 4];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
        let rand_hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        format!("{consumer}_{provider}_{now}_{rand_hex}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ad(cpu: f32, mem: u64) -> ResourceAdvertisement {
        ResourceAdvertisement {
            agent_id: "provider".to_string(),
            sequence: 1,
            timestamp: now_ms(),
            spec: ResourceSpec {
                cpu_cores: 4,
                total_memory_mb: 8192,
                max_bandwidth_up_mbps: 100,
                total_storage_bytes: 0,
            },
            cpu_offer: cpu,
            memory_offer_mb: mem,
            bandwidth_offer: 0,
            storage_offer: 0,
            features: vec![],
            signing_pubkey: Vec::new(),
            signature: Vec::new(),
        }
    }

    #[test]
    fn test_create_and_activate_session() {
        let mut mgr = ResourceSessionManager::new();
        let sid = mgr.create_session(
            "consumer".to_string(),
            "provider".to_string(),
            0.2,
            1024,
            60_000,
        );

        assert_eq!(mgr.get(&sid).unwrap().status, SessionStatus::Pending);
        assert!(mgr.activate(&sid));
        assert_eq!(mgr.get(&sid).unwrap().status, SessionStatus::Active);
    }

    #[test]
    fn test_release_session() {
        let mut mgr = ResourceSessionManager::new();
        let sid = mgr.create_session(
            "consumer".to_string(),
            "provider".to_string(),
            0.2,
            1024,
            60_000,
        );
        mgr.activate(&sid);

        let released = mgr.release(&sid).unwrap();
        assert_eq!(released.status, SessionStatus::Released);
        assert!(released.actual_end.is_some());

        // Allocation should be freed.
        let (cpu, mem) = mgr.current_allocation("provider");
        assert!((cpu - 0.0).abs() < f32::EPSILON);
        assert_eq!(mem, 0);
    }

    #[test]
    fn test_revoke_session() {
        let mut mgr = ResourceSessionManager::new();
        let sid = mgr.create_session(
            "consumer".to_string(),
            "provider".to_string(),
            0.2,
            1024,
            60_000,
        );
        mgr.activate(&sid);

        assert!(mgr.revoke(&sid));
        assert_eq!(mgr.get(&sid).unwrap().status, SessionStatus::Revoked);
    }

    #[test]
    fn test_cannot_release_twice() {
        let mut mgr = ResourceSessionManager::new();
        let sid = mgr.create_session(
            "consumer".to_string(),
            "provider".to_string(),
            0.2,
            1024,
            60_000,
        );
        mgr.release(&sid);
        assert!(mgr.release(&sid).is_none());
    }

    #[test]
    fn test_can_allocate_within_limits() {
        let mut mgr = ResourceSessionManager::new();
        let ad = make_ad(0.5, 4096);

        assert!(mgr.can_allocate("provider", &ad, 0.3, 2048));

        mgr.create_session("c1".into(), "provider".into(), 0.4, 3000, 60_000);

        // Remaining: cpu=0.1, mem=1096 — cannot fit another 0.2 CPU
        assert!(!mgr.can_allocate("provider", &ad, 0.2, 1024));
    }

    #[test]
    fn test_expire_timed_out() {
        let mut mgr = ResourceSessionManager::new();
        let sid = mgr.create_session(
            "consumer".to_string(),
            "provider".to_string(),
            0.2,
            1024,
            1, // 1ms duration — will expire immediately
        );
        mgr.activate(&sid);

        // Wait a tiny bit for time to pass.
        std::thread::sleep(std::time::Duration::from_millis(2));

        let expired = mgr.expire_timed_out();
        assert_eq!(expired, 1);
        assert_eq!(mgr.get(&sid).unwrap().status, SessionStatus::Expired);
    }

    #[test]
    fn test_expire_stale_offers() {
        let mut mgr = ResourceSessionManager::new();
        let sid = mgr.create_session(
            "consumer".to_string(),
            "provider".to_string(),
            0.2,
            1024,
            60_000,
        );
        // Leave it as Pending, don't activate.

        // Manually backdate the started_at.
        if let Some(s) = mgr.sessions.get_mut(&sid) {
            s.started_at = now_ms().saturating_sub(OFFER_TTL_MS + 1000);
        }

        let expired = mgr.expire_stale_offers();
        assert_eq!(expired, 1);
        assert_eq!(mgr.get(&sid).unwrap().status, SessionStatus::Expired);
    }

    #[test]
    fn test_list_by_status() {
        let mut mgr = ResourceSessionManager::new();
        let s1 = mgr.create_session("c1".into(), "p1".into(), 0.1, 512, 60_000);
        let s2 = mgr.create_session("c2".into(), "p1".into(), 0.1, 512, 60_000);
        mgr.activate(&s1);

        let active = mgr.list_by_status(SessionStatus::Active);
        let pending = mgr.list_by_status(SessionStatus::Pending);
        assert_eq!(active.len(), 1);
        assert_eq!(pending.len(), 1);
        assert_eq!(active[0].session_id, s1);
        assert_eq!(pending[0].session_id, s2);
    }

    #[test]
    fn test_allocation_tracking() {
        let mut mgr = ResourceSessionManager::new();
        mgr.create_session("c1".into(), "provider".into(), 0.2, 1024, 60_000);
        mgr.create_session("c2".into(), "provider".into(), 0.1, 2048, 60_000);

        let (cpu, mem) = mgr.current_allocation("provider");
        assert!((cpu - 0.3).abs() < f32::EPSILON);
        assert_eq!(mem, 3072);
    }

    #[test]
    fn test_max_concurrent_sessions() {
        let mut mgr = ResourceSessionManager::new();
        let ad = make_ad(8.0, 65536); // plenty of resources

        // Create 7 sessions (below limit of 8)
        for i in 0..7 {
            let _sid = mgr.create_session(
                format!("consumer-{i}"), "provider".into(), 0.1, 512, 60_000,
            );
        }
        assert!(
            mgr.can_allocate("provider", &ad, 0.1, 512),
            "7 sessions should still allow one more"
        );

        // 8th session hits the limit
        mgr.create_session("consumer-7".into(), "provider".into(), 0.1, 512, 60_000);
        assert!(
            !mgr.can_allocate("provider", &ad, 0.1, 512),
            "8 sessions should reject 9th (at max limit)"
        );

        // Release one, should allow again
        let first_sid = {
            let pending = mgr.list_by_status(SessionStatus::Pending);
            assert_eq!(pending.len(), 8);
            pending[0].session_id.clone()
        };
        mgr.release(&first_sid);
        assert!(
            mgr.can_allocate("provider", &ad, 0.1, 512),
            "should allow after releasing one"
        );
    }
}
