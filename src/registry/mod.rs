//! Agent Registry — Walkie Talkie v4 Platform Layer
//!
//! Thread-safe tenant/agent registry.

use crate::identity::AgentIdentity;
use crate::tenant::{Tenant, TenantConfig, TenantError};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// ─── Registry ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AgentRegistry {
    inner: Arc<RwLock<HashMap<String, Tenant>>>,
}

impl AgentRegistry {
    pub fn new() -> Self {
        Self { inner: Arc::new(RwLock::new(HashMap::new())) }
    }

    // ── Tenant ──

    pub fn create_tenant(&self, tenant_id: &str, name: &str) -> Result<Tenant, RegistryError> {
        let mut map = self.inner.write().unwrap();
        if map.contains_key(tenant_id) {
            return Err(RegistryError::TenantExists { tenant_id: tenant_id.to_string() });
        }
        let tenant = Tenant::new(tenant_id, name);
        map.insert(tenant_id.to_string(), tenant.clone());
        Ok(tenant)
    }

    pub fn create_tenant_with_config(
        &self, tenant_id: &str, name: &str, config: TenantConfig,
    ) -> Result<Tenant, RegistryError> {
        let mut map = self.inner.write().unwrap();
        if map.contains_key(tenant_id) {
            return Err(RegistryError::TenantExists { tenant_id: tenant_id.to_string() });
        }
        let tenant = Tenant::new(tenant_id, name).with_config(config);
        map.insert(tenant_id.to_string(), tenant.clone());
        Ok(tenant)
    }

    pub fn get_tenant(&self, tenant_id: &str) -> Option<Tenant> {
        self.inner.read().unwrap().get(tenant_id).cloned()
    }

    pub fn list_tenants(&self) -> Vec<TenantSummary> {
        self.inner.read().unwrap().values().map(|t| t.summary()).collect()
    }

    pub fn remove_tenant(&self, tenant_id: &str) -> bool {
        self.inner.write().unwrap().remove(tenant_id).is_some()
    }

    pub fn update_tenant(
        &self, tenant_id: &str,
        name: Option<&str>, active: Option<bool>, config: Option<TenantConfig>,
    ) -> Option<Tenant> {
        let mut map = self.inner.write().unwrap();
        let tenant = map.get_mut(tenant_id)?;
        if let Some(n) = name { tenant.name = n.to_string(); }
        if let Some(a) = active { tenant.active = a; }
        if let Some(cfg) = config { tenant.config = cfg; }
        Some(tenant.clone())
    }

    pub fn has_tenant(&self, tenant_id: &str) -> bool {
        self.inner.read().unwrap().contains_key(tenant_id)
    }

    // ── Agent ──

    pub fn register_agent(&self, tenant_id: &str, agent: AgentIdentity) -> Result<AgentIdentity, RegistryError> {
        let mut map = self.inner.write().unwrap();
        let tenant = map.get_mut(tenant_id)
            .ok_or_else(|| RegistryError::TenantNotFound { tenant_id: tenant_id.to_string() })?;
        tenant.register_agent(agent.clone()).map_err(RegistryError::Tenant)?;
        Ok(agent)
    }

    pub fn deregister_agent(&self, tenant_id: &str, agent_id: &str) -> Result<AgentIdentity, RegistryError> {
        let mut map = self.inner.write().unwrap();
        let tenant = map.get_mut(tenant_id)
            .ok_or_else(|| RegistryError::TenantNotFound { tenant_id: tenant_id.to_string() })?;
        tenant.deregister_agent(agent_id)
            .ok_or_else(|| RegistryError::AgentNotFound { agent_id: agent_id.to_string() })
    }

    pub fn list_agents(&self, tenant_id: &str) -> Result<Vec<AgentIdentity>, RegistryError> {
        let map = self.inner.read().unwrap();
        let tenant = map.get(tenant_id)
            .ok_or_else(|| RegistryError::TenantNotFound { tenant_id: tenant_id.to_string() })?;
        Ok(tenant.agents.clone())
    }

    pub fn find_agent(&self, tenant_id: &str, agent_id: &str) -> Result<AgentIdentity, RegistryError> {
        let map = self.inner.read().unwrap();
        let tenant = map.get(tenant_id)
            .ok_or_else(|| RegistryError::TenantNotFound { tenant_id: tenant_id.to_string() })?;
        tenant.find_agent(agent_id).cloned()
            .ok_or_else(|| RegistryError::AgentNotFound { agent_id: agent_id.to_string() })
    }

    pub fn tenant_has_agent(&self, tenant_id: &str, agent_id: &str) -> bool {
        self.inner.read().unwrap().get(tenant_id)
            .map(|t| t.has_agent(agent_id)).unwrap_or(false)
    }
}

// ─── Error & Types ──────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("Tenant '{tenant_id}' not found")]
    TenantNotFound { tenant_id: String },
    #[error("Agent '{agent_id}' not found")]
    AgentNotFound { agent_id: String },
    #[error("Tenant '{tenant_id}' already exists")]
    TenantExists { tenant_id: String },
    #[error("Tenant error: {0}")]
    Tenant(#[from] TenantError),
}

pub use crate::tenant::TenantSummary;

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
    fn test_create_tenant() {
        let reg = AgentRegistry::new();
        let t = reg.create_tenant("org-1", "Acme").unwrap();
        assert_eq!(t.tenant_id, "org-1");
        assert!(reg.has_tenant("org-1"));
    }

    #[test]
    fn test_duplicate_tenant() {
        let reg = AgentRegistry::new();
        reg.create_tenant("org-1", "A").unwrap();
        let err = reg.create_tenant("org-1", "B").unwrap_err();
        assert!(matches!(err, RegistryError::TenantExists { .. }));
    }

    #[test]
    fn test_remove_tenant() {
        let reg = AgentRegistry::new();
        reg.create_tenant("org-1", "A").unwrap();
        assert!(reg.remove_tenant("org-1"));
        assert!(!reg.has_tenant("org-1"));
        assert!(!reg.remove_tenant("org-1"));
    }

    #[test]
    fn test_list_tenants() {
        let reg = AgentRegistry::new();
        reg.create_tenant("org-1", "A").unwrap();
        reg.create_tenant("org-2", "B").unwrap();
        assert_eq!(reg.list_tenants().len(), 2);
    }

    #[test]
    fn test_register_agent() {
        let reg = AgentRegistry::new();
        reg.create_tenant("org-1", "Test").unwrap();
        reg.register_agent("org-1", make_agent("Alice", &["crypto"])).unwrap();
        assert_eq!(reg.list_agents("org-1").unwrap().len(), 1);
    }

    #[test]
    fn test_register_nonexistent_tenant() {
        let reg = AgentRegistry::new();
        let err = reg.register_agent("nope", make_agent("A", &[])).unwrap_err();
        assert!(matches!(err, RegistryError::TenantNotFound { .. }));
    }

    #[test]
    fn test_deregister_agent() {
        let reg = AgentRegistry::new();
        reg.create_tenant("org-1", "Test").unwrap();
        let agent = make_agent("Alice", &["crypto"]);
        let aid = agent.agent_id.clone();
        reg.register_agent("org-1", agent).unwrap();
        let removed = reg.deregister_agent("org-1", &aid).unwrap();
        assert_eq!(removed.display_name, "Alice");
        assert_eq!(reg.list_agents("org-1").unwrap().len(), 0);
    }

    #[test]
    fn test_deregister_nonexistent() {
        let reg = AgentRegistry::new();
        reg.create_tenant("org-1", "Test").unwrap();
        let err = reg.deregister_agent("org-1", "fake-id").unwrap_err();
        assert!(matches!(err, RegistryError::AgentNotFound { .. }));
    }

    #[test]
    fn test_find_agent() {
        let reg = AgentRegistry::new();
        reg.create_tenant("org-1", "Test").unwrap();
        let agent = make_agent("Alice", &["crypto"]);
        let aid = agent.agent_id.clone();
        reg.register_agent("org-1", agent).unwrap();
        assert_eq!(reg.find_agent("org-1", &aid).unwrap().display_name, "Alice");
    }

    #[test]
    fn test_find_agent_wrong_tenant() {
        let reg = AgentRegistry::new();
        reg.create_tenant("org-1", "A").unwrap();
        reg.create_tenant("org-2", "B").unwrap();
        let agent = make_agent("Alice", &[]);
        let aid = agent.agent_id.clone();
        reg.register_agent("org-1", agent).unwrap();
        let err = reg.find_agent("org-2", &aid).unwrap_err();
        assert!(matches!(err, RegistryError::AgentNotFound { .. }));
    }

    #[test]
    fn test_tenant_has_agent() {
        let reg = AgentRegistry::new();
        reg.create_tenant("org-1", "Test").unwrap();
        let agent = make_agent("Alice", &[]);
        let aid = agent.agent_id.clone();
        reg.register_agent("org-1", agent).unwrap();
        assert!(reg.tenant_has_agent("org-1", &aid));
        assert!(!reg.tenant_has_agent("org-2", &aid));
    }

    #[test]
    fn test_create_tenant_with_config() {
        let reg = AgentRegistry::new();
        let config = TenantConfig { max_agents: 2, ..Default::default() };
        reg.create_tenant_with_config("org-1", "Strict", config).unwrap();
        assert_eq!(reg.get_tenant("org-1").unwrap().config.max_agents, 2);
    }

    #[test]
    fn test_update_tenant_name() {
        let reg = AgentRegistry::new();
        reg.create_tenant("org-1", "Old Name").unwrap();
        let t = reg.update_tenant("org-1", Some("New Name"), None, None).unwrap();
        assert_eq!(t.name, "New Name");
        assert_eq!(reg.get_tenant("org-1").unwrap().name, "New Name");
    }

    #[test]
    fn test_update_tenant_deactivate() {
        let reg = AgentRegistry::new();
        reg.create_tenant("org-1", "Test").unwrap();
        let t = reg.update_tenant("org-1", None, Some(false), None).unwrap();
        assert!(!t.active);
        // Should not be able to register agents
        let err = reg.register_agent("org-1", make_agent("A", &[])).unwrap_err();
        assert!(matches!(err, RegistryError::Tenant(_)));
    }

    #[test]
    fn test_update_tenant_config() {
        let reg = AgentRegistry::new();
        reg.create_tenant("org-1", "Test").unwrap();
        let config = TenantConfig { max_agents: 1, ..Default::default() };
        let t = reg.update_tenant("org-1", None, None, Some(config)).unwrap();
        assert_eq!(t.config.max_agents, 1);
    }

    #[test]
    fn test_update_tenant_not_found() {
        let reg = AgentRegistry::new();
        assert!(reg.update_tenant("nope", None, None, None).is_none());
    }

    #[test]
    fn test_update_tenant_preserves_agents() {
        let reg = AgentRegistry::new();
        reg.create_tenant("org-1", "Test").unwrap();
        reg.register_agent("org-1", make_agent("Alice", &["chat"])).unwrap();
        reg.update_tenant("org-1", Some("Updated"), None, None).unwrap();
        assert_eq!(reg.list_agents("org-1").unwrap().len(), 1);
    }
}
