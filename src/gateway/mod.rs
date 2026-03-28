//! API Gateway — Walkie Talkie v4 Platform Layer
//!
//! HTTP API for tenant/agent management and message routing.

use crate::identity::AgentIdentity;
use crate::ratelimit::RateLimiter;
use crate::registry::{AgentRegistry, RegistryError};
use crate::tenant::TenantConfig;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub type ApiResult = (StatusCode, Json<serde_json::Value>);

// ─── App State ──────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<AgentRegistry>,
    pub rate_limiter: Arc<RateLimiter>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            registry: Arc::new(AgentRegistry::new()),
            rate_limiter: Arc::new(RateLimiter::new(5, 10)),
        }
    }
}

// ─── Request / Response Types ───────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTenantRequest {
    pub tenant_id: String,
    pub name: String,
    #[serde(default)]
    pub config: Option<TenantConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateTenantRequest {
    pub name: Option<String>,
    pub active: Option<bool>,
    pub config: Option<TenantConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMessageRequest {
    pub from_agent: String,
    pub to_agent: String,
    pub tenant_id: String,
    pub protocol: String,
    #[serde(default)]
    pub payload: serde_json::Value,
}

// ─── Response helpers ───────────────────────────────────────────

fn ok_json(data: serde_json::Value) -> ApiResult {
    (StatusCode::OK, Json(serde_json::json!({ "ok": true, "data": data })))
}

fn created_json(data: serde_json::Value) -> ApiResult {
    (StatusCode::CREATED, Json(serde_json::json!({ "ok": true, "data": data })))
}

fn err_json(status: StatusCode, msg: &str) -> ApiResult {
    (status, Json(serde_json::json!({ "ok": false, "error": msg })))
}

fn registry_error(e: RegistryError) -> ApiResult {
    match &e {
        RegistryError::TenantNotFound { .. } | RegistryError::AgentNotFound { .. } =>
            err_json(StatusCode::NOT_FOUND, &e.to_string()),
        RegistryError::TenantExists { .. } =>
            err_json(StatusCode::CONFLICT, &e.to_string()),
        RegistryError::Tenant(_) =>
            err_json(StatusCode::BAD_REQUEST, &e.to_string()),
    }
}

// ─── Handlers ───────────────────────────────────────────────────

pub async fn health() -> ApiResult {
    ok_json(serde_json::json!({ "status": "healthy", "version": "0.2.0" }))
}

// ── Tenant CRUD ──

pub async fn create_tenant(
    State(state): State<AppState>,
    Json(req): Json<CreateTenantRequest>,
) -> ApiResult {
    let result = if let Some(config) = req.config {
        state.registry.create_tenant_with_config(&req.tenant_id, &req.name, config)
    } else {
        state.registry.create_tenant(&req.tenant_id, &req.name)
    };
    match result {
        Ok(t) => created_json(serde_json::json!({
            "tenant_id": t.tenant_id, "name": t.name,
            "agent_count": 0, "active": t.active, "created_at": t.created_at,
        })),
        Err(e) => registry_error(e),
    }
}

pub async fn list_tenants(State(state): State<AppState>) -> ApiResult {
    let tenants = state.registry.list_tenants();
    let data: Vec<serde_json::Value> = tenants.iter().map(|t| {
        serde_json::json!({
            "tenant_id": &t.tenant_id, "name": &t.name,
            "agent_count": t.agent_count, "active": t.active, "created_at": t.created_at,
        })
    }).collect();
    ok_json(serde_json::json!(data))
}

pub async fn get_tenant(State(state): State<AppState>, Path(tenant_id): Path<String>) -> ApiResult {
    match state.registry.get_tenant(&tenant_id) {
        Some(t) => ok_json(serde_json::json!({
            "tenant_id": t.tenant_id, "name": t.name,
            "agent_count": t.agent_count(), "active": t.active, "created_at": t.created_at,
        })),
        None => err_json(StatusCode::NOT_FOUND, "Tenant not found"),
    }
}

pub async fn update_tenant(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    Json(req): Json<UpdateTenantRequest>,
) -> ApiResult {
    let name = req.name.as_deref();
    let active = req.active;
    let config = req.config;

    match state.registry.update_tenant(&tenant_id, name, active, config) {
        Some(t) => ok_json(serde_json::json!({
            "tenant_id": &t.tenant_id, "name": &t.name, "active": t.active,
        })),
        None => err_json(StatusCode::NOT_FOUND, "Tenant not found"),
    }
}

pub async fn delete_tenant(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
) -> ApiResult {
    if state.registry.remove_tenant(&tenant_id) {
        ok_json(serde_json::json!({ "deleted": true, "tenant_id": tenant_id }))
    } else {
        err_json(StatusCode::NOT_FOUND, "Tenant not found")
    }
}

// ── Agent Management ──

pub async fn register_agent(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    Json(agent): Json<AgentIdentity>,
) -> ApiResult {
    match state.registry.register_agent(&tenant_id, agent) {
        Ok(a) => created_json(serde_json::json!({
            "agent_id": a.agent_id, "display_name": a.display_name,
            "capabilities": a.capabilities,
        })),
        Err(e) => registry_error(e),
    }
}

pub async fn list_agents(State(state): State<AppState>, Path(tenant_id): Path<String>) -> ApiResult {
    match state.registry.list_agents(&tenant_id) {
        Ok(agents) => {
            let data: Vec<serde_json::Value> = agents.iter().map(|a| {
                serde_json::json!({
                    "agent_id": &a.agent_id, "display_name": &a.display_name,
                    "capabilities": &a.capabilities,
                })
            }).collect();
            ok_json(serde_json::json!(data))
        },
        Err(e) => registry_error(e),
    }
}

pub async fn deregister_agent(
    State(state): State<AppState>,
    Path((tenant_id, agent_id)): Path<(String, String)>,
) -> ApiResult {
    match state.registry.deregister_agent(&tenant_id, &agent_id) {
        Ok(a) => ok_json(serde_json::json!({ "agent_id": a.agent_id, "display_name": a.display_name })),
        Err(e) => registry_error(e),
    }
}

// ── Message Routing ──

pub async fn send_message(State(state): State<AppState>, Json(req): Json<SendMessageRequest>) -> ApiResult {
    // Validate sender
    if let Err(e) = state.registry.find_agent(&req.tenant_id, &req.from_agent) {
        return registry_error(e);
    }
    // Rate limit
    if !state.rate_limiter.try_acquire(&req.tenant_id, &req.from_agent, 1) {
        return err_json(StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded");
    }
    // Validate protocol
    let valid_protocols = ["task_assignment", "status_report", "data_exchange",
                           "intent_negotiation", "human_handoff", "heartbeat", "text"];
    if !valid_protocols.contains(&req.protocol.as_str()) {
        return err_json(StatusCode::BAD_REQUEST, &format!("Invalid protocol: {}", req.protocol));
    }
    // In production: route to P2P network via the from_agent's connection
    ok_json(serde_json::json!({
        "status": "delivered",
        "from": req.from_agent,
        "to": req.to_agent,
        "protocol": req.protocol,
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_millis(),
    }))
}

pub async fn query_messages(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
) -> ApiResult {
    if !state.registry.has_tenant(&tenant_id) {
        return err_json(StatusCode::NOT_FOUND, "Tenant not found");
    }
    // In production: query persistent message store
    ok_json(serde_json::json!({
        "messages": [],
        "total": 0,
        "tenant_id": tenant_id,
    }))
}

// ─── Router ─────────────────────────────────────────────────────

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/tenants", post(create_tenant).get(list_tenants))
        .route("/tenants/{tenant_id}", get(get_tenant).put(update_tenant).delete(delete_tenant))
        .route("/tenants/{tenant_id}/agents", post(register_agent).get(list_agents))
        .route("/tenants/{tenant_id}/agents/{agent_id}", delete(deregister_agent))
        .route("/messages", post(send_message))
        .route("/messages/{tenant_id}", get(query_messages))
        .with_state(state)
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
#[allow(unused)]
mod tests {
    use super::*;
    use crate::identity::IdentityBuilder;

    fn make_agent(name: &str, caps: &[&str]) -> AgentIdentity {
        let seed = { let mut b = name.as_bytes().to_vec(); b.resize(32, 0); b };
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed.try_into().unwrap());
        IdentityBuilder::new(name).capabilities(caps).build_with_key(&sk).unwrap()
    }

    fn state() -> AppState { AppState::new() }
    fn s(r: &ApiResult) -> StatusCode { r.0 }

    #[tokio::test]
    async fn test_health() {
        assert_eq!(s(&health().await), StatusCode::OK);
    }

    // ── Tenant CRUD ──

    #[tokio::test]
    async fn test_create_and_get_tenant() {
        let st = state();
        create_tenant(State(st.clone()), Json(CreateTenantRequest {
            tenant_id: "org-1".into(), name: "Test Corp".into(), config: None,
        })).await;
        let r = get_tenant(State(st), Path("org-1".into())).await;
        assert_eq!(s(&r), StatusCode::OK);
        assert_eq!(r.1 .0["data"]["name"], "Test Corp");
    }

    #[tokio::test]
    async fn test_create_tenant_with_config() {
        let st = state();
        let r = create_tenant(State(st), Json(CreateTenantRequest {
            tenant_id: "strict".into(), name: "S".into(),
            config: Some(TenantConfig { max_agents: 5, require_approval: true, ..Default::default() }),
        })).await;
        assert_eq!(s(&r), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_duplicate_tenant() {
        let st = state();
        let req = CreateTenantRequest { tenant_id: "dup".into(), name: "D".into(), config: None };
        assert_eq!(s(&create_tenant(State(st.clone()), Json(req.clone())).await), StatusCode::CREATED);
        assert_eq!(s(&create_tenant(State(st), Json(req)).await), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_list_tenants() {
        let st = state();
        for id in &["org-1", "org-2"] {
            create_tenant(State(st.clone()), Json(CreateTenantRequest {
                tenant_id: id.to_string(), name: "T".into(), config: None,
            })).await;
        }
        let r = list_tenants(State(st)).await;
        assert_eq!(s(&r), StatusCode::OK);
        assert_eq!(r.1 .0["data"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_get_tenant_not_found() {
        let r = get_tenant(State(state()), Path("nope".into())).await;
        assert_eq!(s(&r), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_update_tenant_name() {
        let st = state();
        create_tenant(State(st.clone()), Json(CreateTenantRequest {
            tenant_id: "org-1".into(), name: "Old".into(), config: None,
        })).await;
        let r = update_tenant(State(st.clone()), Path("org-1".into()), Json(UpdateTenantRequest {
            name: Some("New Name".into()), active: None, config: None,
        })).await;
        assert_eq!(s(&r), StatusCode::OK);
        assert_eq!(r.1 .0["data"]["name"], "New Name");
    }

    #[tokio::test]
    async fn test_update_tenant_not_found() {
        let r = update_tenant(State(state()), Path("nope".into()), Json(UpdateTenantRequest {
            name: Some("X".into()), active: None, config: None,
        })).await;
        assert_eq!(s(&r), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_tenant() {
        let st = state();
        create_tenant(State(st.clone()), Json(CreateTenantRequest {
            tenant_id: "org-1".into(), name: "T".into(), config: None,
        })).await;
        let r = delete_tenant(State(st.clone()), Path("org-1".into())).await;
        assert_eq!(s(&r), StatusCode::OK);
        assert_eq!(r.1 .0["data"]["deleted"], true);
        // Verify gone
        let r2 = get_tenant(State(st), Path("org-1".into())).await;
        assert_eq!(s(&r2), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_tenant_not_found() {
        let r = delete_tenant(State(state()), Path("nope".into())).await;
        assert_eq!(s(&r), StatusCode::NOT_FOUND);
    }

    // ── Agent Management ──

    #[tokio::test]
    async fn test_register_agent() {
        let st = state();
        create_tenant(State(st.clone()), Json(CreateTenantRequest {
            tenant_id: "org-1".into(), name: "T".into(), config: None,
        })).await;
        let r = register_agent(State(st), Path("org-1".into()), Json(make_agent("Alice", &["crypto"]))).await;
        assert_eq!(s(&r), StatusCode::CREATED);
        assert_eq!(r.1 .0["data"]["display_name"], "Alice");
    }

    #[tokio::test]
    async fn test_register_agent_nonexistent_tenant() {
        let r = register_agent(State(state()), Path("nope".into()), Json(make_agent("A", &[]))).await;
        assert_eq!(s(&r), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_register_agent_max_limit() {
        let st = state();
        create_tenant(State(st.clone()), Json(CreateTenantRequest {
            tenant_id: "strict".into(), name: "S".into(),
            config: Some(TenantConfig { max_agents: 1, ..Default::default() }),
        })).await;
        let r1 = register_agent(State(st.clone()), Path("strict".into()), Json(make_agent("A", &[]))).await;
        assert_eq!(s(&r1), StatusCode::CREATED);
        let r2 = register_agent(State(st), Path("strict".into()), Json(make_agent("B", &[]))).await;
        assert_eq!(s(&r2), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_list_agents() {
        let st = state();
        create_tenant(State(st.clone()), Json(CreateTenantRequest {
            tenant_id: "org-1".into(), name: "T".into(), config: None,
        })).await;
        register_agent(State(st.clone()), Path("org-1".into()), Json(make_agent("Alice", &["crypto"]))).await;
        let r = list_agents(State(st), Path("org-1".into())).await;
        assert_eq!(s(&r), StatusCode::OK);
        assert_eq!(r.1 .0["data"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_deregister_agent() {
        let st = state();
        create_tenant(State(st.clone()), Json(CreateTenantRequest {
            tenant_id: "org-1".into(), name: "T".into(), config: None,
        })).await;
        let agent = make_agent("Alice", &[]);
        let aid = agent.agent_id.clone();
        register_agent(State(st.clone()), Path("org-1".into()), Json(agent)).await;
        let r = deregister_agent(State(st), Path(("org-1".into(), aid))).await;
        assert_eq!(s(&r), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_deregister_agent_not_found() {
        let st = state();
        create_tenant(State(st.clone()), Json(CreateTenantRequest {
            tenant_id: "org-1".into(), name: "T".into(), config: None,
        })).await;
        let r = deregister_agent(State(st), Path(("org-1".into(), "did:walkie:nope".into()))).await;
        assert_eq!(s(&r), StatusCode::NOT_FOUND);
    }

    // ── Messaging ──

    #[tokio::test]
    async fn test_send_message() {
        let st = state();
        create_tenant(State(st.clone()), Json(CreateTenantRequest {
            tenant_id: "org-1".into(), name: "T".into(), config: None,
        })).await;
        let agent = make_agent("Sender", &["chat"]);
        let aid = agent.agent_id.clone();
        register_agent(State(st.clone()), Path("org-1".into()), Json(agent)).await;
        let r = send_message(State(st), Json(SendMessageRequest {
            from_agent: aid, to_agent: String::new(),
            tenant_id: "org-1".into(), protocol: "data_exchange".into(),
            payload: serde_json::json!({"text": "hello"}),
        })).await;
        assert_eq!(s(&r), StatusCode::OK);
        assert_eq!(r.1 .0["data"]["status"], "delivered");
    }

    #[tokio::test]
    async fn test_send_message_invalid_protocol() {
        let st = state();
        create_tenant(State(st.clone()), Json(CreateTenantRequest {
            tenant_id: "org-1".into(), name: "T".into(), config: None,
        })).await;
        let agent = make_agent("Sender", &[]);
        let aid = agent.agent_id.clone();
        register_agent(State(st.clone()), Path("org-1".into()), Json(agent)).await;
        let r = send_message(State(st), Json(SendMessageRequest {
            from_agent: aid, to_agent: String::new(),
            tenant_id: "org-1".into(), protocol: "evil_protocol".into(),
            payload: serde_json::json!({}),
        })).await;
        assert_eq!(s(&r), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_send_message_nonexistent_agent() {
        let r = send_message(State(state()), Json(SendMessageRequest {
            from_agent: "did:walkie:nope".into(), to_agent: String::new(),
            tenant_id: "nope".into(), protocol: "text".into(), payload: serde_json::json!({}),
        })).await;
        assert_eq!(s(&r), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let st = state();
        create_tenant(State(st.clone()), Json(CreateTenantRequest {
            tenant_id: "org-1".into(), name: "T".into(), config: None,
        })).await;
        let agent = make_agent("Sender", &[]);
        let aid = agent.agent_id.clone();
        register_agent(State(st.clone()), Path("org-1".into()), Json(agent)).await;
        for _ in 0..10 {
            let r = send_message(State(st.clone()), Json(SendMessageRequest {
                from_agent: aid.clone(), to_agent: String::new(),
                tenant_id: "org-1".into(), protocol: "text".into(), payload: serde_json::json!({}),
            })).await;
            assert_eq!(s(&r), StatusCode::OK);
        }
        let r = send_message(State(st), Json(SendMessageRequest {
            from_agent: aid, to_agent: String::new(),
            tenant_id: "org-1".into(), protocol: "text".into(), payload: serde_json::json!({}),
        })).await;
        assert_eq!(s(&r), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn test_query_messages() {
        let st = state();
        create_tenant(State(st.clone()), Json(CreateTenantRequest {
            tenant_id: "org-1".into(), name: "T".into(), config: None,
        })).await;
        let r = query_messages(State(st), Path("org-1".into())).await;
        assert_eq!(s(&r), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_query_messages_not_found() {
        let r = query_messages(State(state()), Path("nope".into())).await;
        assert_eq!(s(&r), StatusCode::NOT_FOUND);
    }

    // ── Edge Cases & Integration ──

    #[tokio::test]
    async fn test_list_tenants_empty() {
        let r = list_tenants(State(state())).await;
        assert_eq!(s(&r), StatusCode::OK);
        assert_eq!(r.1 .0["data"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_update_tenant_config() {
        let st = state();
        create_tenant(State(st.clone()), Json(CreateTenantRequest {
            tenant_id: "org-1".into(), name: "Acme".into(), config: None,
        })).await;
        let r = update_tenant(State(st.clone()), Path("org-1".into()), Json(UpdateTenantRequest {
            name: None, active: None,
            config: Some(TenantConfig {
                max_agents: 3,
                require_approval: true,
                allowed_capabilities: vec!["chat".into()],
                ..Default::default()
            }),
        })).await;
        assert_eq!(s(&r), StatusCode::OK);
        // Verify config applied: should now reject > 3 agents
        create_tenant(State(st.clone()), Json(CreateTenantRequest {
            tenant_id: "org-1b".into(), name: "dummy".into(), config: None,
        })).await;
        for name in &["A", "B", "C"] {
            let rr = register_agent(State(st.clone()), Path("org-1".into()), Json(make_agent(name, &["chat"]))).await;
            assert_eq!(s(&rr), StatusCode::CREATED, "Agent {} should register", name);
        }
        let r_fail = register_agent(State(st), Path("org-1".into()), Json(make_agent("D", &["chat"]))).await;
        assert_eq!(s(&r_fail), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_update_tenant_deactivate() {
        let st = state();
        create_tenant(State(st.clone()), Json(CreateTenantRequest {
            tenant_id: "org-1".into(), name: "Acme".into(), config: None,
        })).await;
        register_agent(State(st.clone()), Path("org-1".into()), Json(make_agent("A", &[]))).await;
        // Deactivate
        let r = update_tenant(State(st.clone()), Path("org-1".into()), Json(UpdateTenantRequest {
            name: None, active: Some(false), config: None,
        })).await;
        assert_eq!(s(&r), StatusCode::OK);
        assert_eq!(r.1 .0["data"]["active"], false);
        // Should not be able to register new agents
        let r2 = register_agent(State(st.clone()), Path("org-1".into()), Json(make_agent("B", &[]))).await;
        assert_eq!(s(&r2), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_send_message_multiple_protocols() {
        let st = state();
        create_tenant(State(st.clone()), Json(CreateTenantRequest {
            tenant_id: "org-1".into(), name: "T".into(), config: None,
        })).await;
        let agent = make_agent("Sender", &[]);
        let aid = agent.agent_id.clone();
        register_agent(State(st.clone()), Path("org-1".into()), Json(agent)).await;
        for proto in &["text", "task_assignment", "status_report", "data_exchange", "intent_negotiation", "human_handoff", "heartbeat"] {
            let r = send_message(State(st.clone()), Json(SendMessageRequest {
                from_agent: aid.clone(), to_agent: String::new(),
                tenant_id: "org-1".into(), protocol: proto.to_string(),
                payload: serde_json::json!({"test": true}),
            })).await;
            assert_eq!(s(&r), StatusCode::OK, "Protocol {} should succeed", proto);
        }
    }

    #[tokio::test]
    async fn test_send_message_missing_from_agent() {
        let st = state();
        create_tenant(State(st.clone()), Json(CreateTenantRequest {
            tenant_id: "org-1".into(), name: "T".into(), config: None,
        })).await;
        let r = send_message(State(st), Json(SendMessageRequest {
            from_agent: "did:walkie:notregistered".into(), to_agent: String::new(),
            tenant_id: "org-1".into(), protocol: "text".into(),
            payload: serde_json::json!({}),
        })).await;
        assert_eq!(s(&r), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_full_workflow() {
        let st = state();

        // 1. Create tenant
        let r = create_tenant(State(st.clone()), Json(CreateTenantRequest {
            tenant_id: "workflow-org".into(), name: "Workflow Test".into(),
            config: Some(TenantConfig { max_agents: 3, ..Default::default() }),
        })).await;
        assert_eq!(s(&r), StatusCode::CREATED);

        // 2. Get tenant
        let r2 = get_tenant(State(st.clone()), Path("workflow-org".into())).await;
        assert_eq!(s(&r2), StatusCode::OK);
        assert_eq!(r2.1 .0["data"]["name"], "Workflow Test");

        // 3. Register two agents
        let alice = make_agent("Alice", &["chat", "crypto"]);
        let bob = make_agent("Bob", &["chat"]);
        let alice_id = alice.agent_id.clone();
        let bob_id = bob.agent_id.clone();
        assert_eq!(s(&register_agent(State(st.clone()), Path("workflow-org".into()), Json(alice)).await), StatusCode::CREATED);
        assert_eq!(s(&register_agent(State(st.clone()), Path("workflow-org".into()), Json(bob)).await), StatusCode::CREATED);

        // 4. List agents
        let r3 = list_agents(State(st.clone()), Path("workflow-org".into())).await;
        assert_eq!(r3.1 .0["data"].as_array().unwrap().len(), 2);

        // 5. Alice sends task to Bob
        let r4 = send_message(State(st.clone()), Json(SendMessageRequest {
            from_agent: alice_id.clone(), to_agent: bob_id.clone(),
            tenant_id: "workflow-org".into(), protocol: "task_assignment".into(),
            payload: serde_json::json!({"title": "Analyze data", "priority": "high"}),
        })).await;
        assert_eq!(s(&r4), StatusCode::OK);
        assert_eq!(r4.1 .0["data"]["from"], alice_id);

        // 6. Bob reports status
        let r5 = send_message(State(st.clone()), Json(SendMessageRequest {
            from_agent: bob_id.clone(), to_agent: alice_id,
            tenant_id: "workflow-org".into(), protocol: "status_report".into(),
            payload: serde_json::json!({"status": "completed", "progress": 1.0}),
        })).await;
        assert_eq!(s(&r5), StatusCode::OK);

        // 7. Query messages
        let r6 = query_messages(State(st.clone()), Path("workflow-org".into())).await;
        assert_eq!(s(&r6), StatusCode::OK);

        // 8. Update tenant name
        let r7 = update_tenant(State(st.clone()), Path("workflow-org".into()), Json(UpdateTenantRequest {
            name: Some("Updated Workflow".into()), active: None, config: None,
        })).await;
        assert_eq!(s(&r7), StatusCode::OK);

        // 9. Deregister Bob
        let r8 = deregister_agent(State(st.clone()), Path(("workflow-org".into(), bob_id))).await;
        assert_eq!(s(&r8), StatusCode::OK);

        // 10. Delete tenant
        let r9 = delete_tenant(State(st), Path("workflow-org".into())).await;
        assert_eq!(s(&r9), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_tenant_minimal() {
        let r = create_tenant(State(state()), Json(CreateTenantRequest {
            tenant_id: "minimal".into(), name: "M".into(), config: None,
        })).await;
        assert_eq!(s(&r), StatusCode::CREATED);
        // Verify defaults
        assert_eq!(r.1 .0["data"]["active"], true);
        assert_eq!(r.1 .0["data"]["agent_count"], 0);
    }

    #[tokio::test]
    async fn test_register_agent_duplicate_different_tenant() {
        let st = state();
        create_tenant(State(st.clone()), Json(CreateTenantRequest {
            tenant_id: "org-1".into(), name: "T1".into(), config: None,
        })).await;
        create_tenant(State(st.clone()), Json(CreateTenantRequest {
            tenant_id: "org-2".into(), name: "T2".into(), config: None,
        })).await;
        let agent = make_agent("Alice", &[]);
        assert_eq!(s(&register_agent(State(st.clone()), Path("org-1".into()), Json(agent.clone())).await), StatusCode::CREATED);
        // Same agent in different tenant should succeed
        let r2 = register_agent(State(st), Path("org-2".into()), Json(agent)).await;
        assert_eq!(s(&r2), StatusCode::CREATED);
    }

}
