//! SDK Integration Example — OpenClaw Agent connecting to Walkie Talkie Platform
//!
//! Demonstrates how an AI agent (e.g., an OpenClaw session) registers with
//! the gateway and sends/receives messages via the HTTP API.
//!
//! Run: cargo run --example sdk_openclaw_agent

use std::time::Duration;

/// Minimal HTTP client for the Walkie Talkie Gateway API.
/// In production, use reqwest or your HTTP client of choice.
struct WalkieSdk {
    base_url: String,
    tenant_id: String,
    agent_id: String,
    // In production: store signing key for message auth
}

impl WalkieSdk {
    fn new(base_url: &str, tenant_id: &str, agent_id: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            tenant_id: tenant_id.to_string(),
            agent_id: agent_id.to_string(),
        }
    }

    /// Build API URL for a given path.
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Check gateway health.
    fn health_url(&self) -> String {
        self.url("/health")
    }

    /// Register this agent with the tenant.
    fn register_url(&self) -> String {
        self.url(&format!("/tenants/{}/agents", self.tenant_id))
    }

    /// Send a message.
    fn send_message_url(&self) -> String {
        self.url("/messages")
    }

    /// Query messages for this tenant.
    fn query_messages_url(&self) -> String {
        self.url(&format!("/messages/{}", self.tenant_id))
    }
}

fn main() {
    println!("=== Walkie Talkie SDK — OpenClaw Agent Integration Demo ===\n");

    // ── 1. Configuration ──
    let gateway_url = "http://localhost:3000"; // Walkie Talkie Gateway
    let tenant_id = "openclaw-team";
    let agent_name = "steve-jobs"; // OpenClaw agent session name

    println!("📡 Connecting to Gateway: {}", gateway_url);
    println!("🏢 Tenant: {}", tenant_id);
    println!("🤖 Agent:  {}\n", agent_name);

    // ── 2. Create SDK instance ──
    let sdk = WalkieSdk::new(gateway_url, tenant_id, agent_name);

    // ── 3. Show API endpoints ──
    println!("── API Endpoints ──");
    println!("  Health:      {}", sdk.health_url());
    println!("  Register:    {}", sdk.register_url());
    println!("  Send:        {}", sdk.send_message_url());
    println!("  Query:       {}", sdk.query_messages_url());
    println!();

    // ── 4. Simulated registration ──
    println!("── Registration Payload ──");
    let register_body = serde_json::json!({
        "agent_id": format!("did:walkie:{}", agent_name),
        "display_name": "Steve Jobs",
        "capabilities": ["strategic_planning", "product_vision", "task_assignment"],
        "status": "online",
    });
    println!("  POST {}", sdk.register_url());
    println!("  Body: {}", serde_json::to_string_pretty(&register_body).unwrap());
    println!();

    // ── 5. Simulated task assignment ──
    println!("── Send Task Assignment ──");
    let task_body = serde_json::json!({
        "from_agent": format!("did:walkie:{}", agent_name),
        "to_agent": "did:walkie:rustacean",
        "tenant_id": tenant_id,
        "protocol": "task_assignment",
        "payload": {
            "task_id": "task-001",
            "title": "Implement NAT traversal",
            "description": "Add STUN/TURN support for P2P connections behind NAT",
            "priority": "high",
            "deadline": "2026-03-29T12:00:00Z",
        }
    });
    println!("  POST {}", sdk.send_message_url());
    println!("  Body: {}", serde_json::to_string_pretty(&task_body).unwrap());
    println!();

    // ── 6. Simulated human handoff ──
    println!("── Send Human Handoff ──");
    let handoff_body = serde_json::json!({
        "from_agent": format!("did:walkie:{}", agent_name),
        "to_agent": "did:walkie:system",
        "tenant_id": tenant_id,
        "protocol": "human_handoff",
        "payload": {
            "reason": "budget_approval_required",
            "summary": "Phase 3 needs $5000 for cloud hosting",
            "context": {"phase": 3, "amount_usd": 5000, "provider": "AWS"},
            "urgency": "medium",
        }
    });
    println!("  POST {}", sdk.send_message_url());
    println!("  Body: {}", serde_json::to_string_pretty(&handoff_body).unwrap());
    println!();

    // ── 7. Integration pattern for OpenClaw ──
    println!("── OpenClaw Integration Pattern ──");
    println!("
In an OpenClaw session, integrate like this:

```rust
// In your OpenClaw agent's startup
let sdk = WalkieSdk::new(
    &std::env::var(\"WALKIE_GATEWAY_URL\").unwrap_or(\"http://localhost:3000\".into()),
    &std::env::var(\"WALKIE_TENANT_ID\").unwrap_or(\"default\".into()),
    &session.agent_id,
);

// On task assignment from TUI/human:
// 1. POST /messages with protocol=task_assignment
// 2. Agent processes task
// 3. POST /messages with protocol=status_report

// On human handoff:
// 1. POST /messages with protocol=human_handoff
// 2. TUI shows alert
// 3. Human approves/rejects via TUI
// 4. Agent receives response via GET /messages/{tenant_id}
```

Environment variables:
  WALKIE_GATEWAY_URL  — Gateway HTTP endpoint
  WALKIE_TENANT_ID    — Tenant to register under
  WALKIE_AGENT_ID     — Agent DID (auto-generated from signing key)
    ");

    println!("=== Demo Complete ===");
}
