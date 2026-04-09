//! Tenant — Walkie Talkie v4 Platform Layer
//!
//! A Tenant represents an organization or project that owns a set of agents.

use crate::identity::AgentIdentity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// ─── Tenant Config ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct TenantConfig {
    #[serde(default)]
    pub max_agents: usize,
    #[serde(default)]
    pub allowed_capabilities: Vec<String>,
    #[serde(default)]
    pub rate_limit: u32,
    #[serde(default)]
    pub require_approval: bool,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}


// ─── Tenant ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub tenant_id: String,
    pub name: String,
    #[serde(default)]
    pub agents: Vec<AgentIdentity>,
    #[serde(default)]
    pub config: TenantConfig,
    #[serde(default = "now_ms")]
    pub created_at: u64,
    #[serde(default = "default_true")]
    pub active: bool,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

fn default_true() -> bool { true }

impl Tenant {
    pub fn new(tenant_id: &str, name: &str) -> Self {
        Self {
            tenant_id: tenant_id.to_string(),
            name: name.to_string(),
            agents: Vec::new(),
            config: TenantConfig::default(),
            created_at: now_ms(),
            active: true,
        }
    }

    pub fn with_config(mut self, config: TenantConfig) -> Self {
        self.config = config;
        self
    }

    pub fn agent_count(&self) -> usize { self.agents.len() }

    pub fn has_agent(&self, agent_id: &str) -> bool {
        self.agents.iter().any(|a| a.agent_id == agent_id)
    }

    pub fn find_agent(&self, agent_id: &str) -> Option<&AgentIdentity> {
        self.agents.iter().find(|a| a.agent_id == agent_id)
    }

    pub fn register_agent(&mut self, agent: AgentIdentity) -> Result<(), TenantError> {
        if !self.active {
            return Err(TenantError::TenantInactive { tenant_id: self.tenant_id.clone() });
        }
        if self.config.max_agents > 0 && self.agents.len() >= self.config.max_agents {
            return Err(TenantError::MaxAgentsReached {
                tenant_id: self.tenant_id.clone(),
                max: self.config.max_agents,
            });
        }
        if !self.config.allowed_capabilities.is_empty() {
            for cap in &agent.capabilities {
                if !self.config.allowed_capabilities.iter().any(|ac| ac.eq_ignore_ascii_case(cap)) {
                    return Err(TenantError::CapabilityNotAllowed {
                        capability: cap.clone(),
                        allowed: self.config.allowed_capabilities.clone(),
                    });
                }
            }
        }
        if self.has_agent(&agent.agent_id) {
            return Err(TenantError::AgentAlreadyRegistered {
                agent_id: agent.agent_id.clone(),
            });
        }
        self.agents.push(agent);
        Ok(())
    }

    pub fn deregister_agent(&mut self, agent_id: &str) -> Option<AgentIdentity> {
        if let Some(idx) = self.agents.iter().position(|a| a.agent_id == agent_id) {
            Some(self.agents.remove(idx))
        } else {
            None
        }
    }

    pub fn list_agent_ids(&self) -> Vec<String> {
        self.agents.iter().map(|a| a.agent_id.clone()).collect()
    }

    pub fn summary(&self) -> TenantSummary {
        TenantSummary {
            tenant_id: self.tenant_id.clone(),
            name: self.name.clone(),
            agent_count: self.agent_count(),
            active: self.active,
            created_at: self.created_at,
        }
    }
}

// ─── Error & Types ──────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum TenantError {
    #[error("Tenant '{tenant_id}' is inactive")]
    TenantInactive { tenant_id: String },
    #[error("Tenant '{tenant_id}' has reached max agents ({max})")]
    MaxAgentsReached { tenant_id: String, max: usize },
    #[error("Agent '{agent_id}' already registered")]
    AgentAlreadyRegistered { agent_id: String },
    #[error("Capability '{capability}' not allowed (allowed: {allowed:?})")]
    CapabilityNotAllowed { capability: String, allowed: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantSummary {
    pub tenant_id: String,
    pub name: String,
    pub agent_count: usize,
    pub active: bool,
    pub created_at: u64,
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityBuilder;

    fn make_agent(name: &str, caps: &[&str]) -> AgentIdentity {
        let seed = { let mut b = name.as_bytes().to_vec(); b.resize(32, 0); b };
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed.try_into().unwrap());
        IdentityBuilder::new(name).capabilities(caps).build_with_key(&sk).unwrap()
    }

    #[test]
    fn test_new_tenant() {
        let t = Tenant::new("org-1", "Acme Corp");
        assert_eq!(t.tenant_id, "org-1");
        assert!(t.active);
        assert_eq!(t.agent_count(), 0);
    }

    #[test]
    fn test_register_agent() {
        let agent = make_agent("Alice", &["crypto"]);
        let mut t = Tenant::new("org-1", "Test");
        t.register_agent(agent).unwrap();
        assert_eq!(t.agent_count(), 1);
    }

    #[test]
    fn test_duplicate_agent() {
        let agent = make_agent("Alice", &["crypto"]);
        let mut t = Tenant::new("org-1", "Test");
        t.register_agent(agent.clone()).unwrap();
        let err = t.register_agent(agent).unwrap_err();
        assert!(matches!(err, TenantError::AgentAlreadyRegistered { .. }));
    }

    #[test]
    fn test_deregister_agent() {
        let agent = make_agent("Alice", &["crypto"]);
        let aid = agent.agent_id.clone();
        let mut t = Tenant::new("org-1", "Test");
        t.register_agent(agent).unwrap();
        let removed = t.deregister_agent(&aid).unwrap();
        assert_eq!(removed.agent_id, aid);
        assert_eq!(t.agent_count(), 0);
        assert!(t.deregister_agent(&aid).is_none());
    }

    #[test]
    fn test_max_agents_limit() {
        let config = TenantConfig { max_agents: 1, ..Default::default() };
        let mut t = Tenant::new("org-1", "Strict").with_config(config);
        t.register_agent(make_agent("A", &[])).unwrap();
        let err = t.register_agent(make_agent("B", &[])).unwrap_err();
        assert!(matches!(err, TenantError::MaxAgentsReached { max: 1, .. }));
    }

    #[test]
    fn test_capability_restriction() {
        let config = TenantConfig {
            allowed_capabilities: vec!["read-only".into()],
            ..Default::default()
        };
        let mut t = Tenant::new("org-1", "Strict").with_config(config);
        t.register_agent(make_agent("Good", &["read-only"])).unwrap();
        let err = t.register_agent(make_agent("Bad", &["admin"])).unwrap_err();
        assert!(matches!(err, TenantError::CapabilityNotAllowed { .. }));
    }

    #[test]
    fn test_inactive_tenant() {
        let mut t = Tenant::new("org-1", "Test");
        t.active = false;
        let err = t.register_agent(make_agent("A", &[])).unwrap_err();
        assert!(matches!(err, TenantError::TenantInactive { .. }));
    }

    #[test]
    fn test_list_agent_ids() {
        let mut t = Tenant::new("org-1", "Test");
        t.register_agent(make_agent("Alice", &["crypto"])).unwrap();
        t.register_agent(make_agent("Bob", &["translate"])).unwrap();
        assert_eq!(t.list_agent_ids().len(), 2);
    }

    #[test]
    fn test_summary() {
        let mut t = Tenant::new("org-1", "Test");
        t.register_agent(make_agent("A", &[])).unwrap();
        let s = t.summary();
        assert_eq!(s.agent_count, 1);
        assert!(s.active);
    }
}
