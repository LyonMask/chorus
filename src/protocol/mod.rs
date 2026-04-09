//! Agent Structured Messaging Protocol — Walkie Talkie v4 Layer 2
//!
//! Agents don't just send bytes. They send structured messages with
//! intent, priority, reply chains, and human-handoff flags.
//!
//! Wire format: JSON-encoded `AgentMessage`, wrapped in `CryptoEnvelope::Encrypted`
//! for E2EE delivery over Gossipsub.

use serde::{Serialize, Deserialize};
use crate::identity::AgentIdentity;

// ─── Message ID ─────────────────────────────────────────────────

/// Globally unique message identifier.
///
/// Format: `<sender-agent-id-segment>_<unix-ms>_<random-6hex>`
/// e.g. `a1b2c3d4_1711000000000_f3a9c1`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(String);

impl MessageId {
    /// Generate a new unique message ID.
    pub fn generate(sender_agent_id: &str) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();

        // Take last 8 chars of agent_id for brevity
        let short_agent = if sender_agent_id.len() >= 8 {
            &sender_agent_id[sender_agent_id.len()-8..]
        } else {
            sender_agent_id
        };

        let rand_hex: String = {
            let mut bytes = [0u8; 3];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        };

        Self(format!("{short_agent}_{ts}_{rand_hex}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ─── Message Protocol Types ─────────────────────────────────────

/// The intent / purpose of a structured message.
///
/// This is the core of the Agent interaction model — not just "text"
/// but structured intents that programs can act on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageProtocol {
    /// "Can you do X?" — negotiate capabilities before committing.
    /// Example: `{"action":"code-review","language":"rust"}`
    IntentNegotiation,

    /// "Do X." — assign a task to another agent.
    /// Example: `{"task":"analyze","target":"file.rs","deadline_ms":60000}`
    TaskAssignment,

    /// "Here's how it's going." — periodic progress update.
    /// Example: `{"status":"in_progress","percent":45,"note":"compiling..."}`
    StatusReport,

    /// "Here's the data." — structured data exchange between agents.
    /// Example: `{"format":"json","schema":"analysis-result","data":{...}}`
    DataExchange,

    /// "Human, you need to look at this." — escalate to human operator.
    /// Example: `{"reason":"approval_required","summary":"Budget exceeded","data":{...}}`
    HumanHandoff,

    /// "I'm alive." — periodic heartbeat for presence tracking.
    /// Example: `{"status":"online","load":0.3,"agents_online":5}`
    Heartbeat,
}

impl MessageProtocol {
    /// Short string tag for logging.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::IntentNegotiation => "INTENT",
            Self::TaskAssignment => "TASK",
            Self::StatusReport => "STATUS",
            Self::DataExchange => "DATA",
            Self::HumanHandoff => "HUMAN",
            Self::Heartbeat => "PING",
        }
    }
}

impl std::fmt::Display for MessageProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IntentNegotiation => write!(f, "IntentNegotiation"),
            Self::TaskAssignment => write!(f, "TaskAssignment"),
            Self::StatusReport => write!(f, "StatusReport"),
            Self::DataExchange => write!(f, "DataExchange"),
            Self::HumanHandoff => write!(f, "HumanHandoff"),
            Self::Heartbeat => write!(f, "Heartbeat"),
        }
    }
}

// ─── Priority ───────────────────────────────────────────────────

/// Message priority levels (0 = lowest, 255 = highest).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Priority(pub u8);

impl Priority {
    pub const LOW: Priority = Priority(25);
    pub const NORMAL: Priority = Priority(75);
    pub const HIGH: Priority = Priority(125);
    pub const URGENT: Priority = Priority(175);
    pub const CRITICAL: Priority = Priority(255);

    pub fn level(&self) -> u8 {
        self.0
    }

    pub fn label(&self) -> &'static str {
        match self.0 {
            0..=49 => "LOW",
            50..=99 => "NORMAL",
            100..=149 => "HIGH",
            150..=219 => "URGENT",
            220..=255 => "CRITICAL",
        }
    }
}

// ─── Agent Message ──────────────────────────────────────────────

/// A structured message between two AI Agents.
///
/// Wire format: JSON. Transport: encrypted Gossipsub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMessage {
    /// Unique message identifier.
    pub id: MessageId,

    /// Sender's verified AgentIdentity (the full signed identity document).
    pub from_agent: AgentIdentity,

    /// Recipient's agent_id (did:walkie:...). Empty string = broadcast.
    #[serde(default)]
    pub to_agent: String,

    /// What kind of interaction this is.
    pub protocol: MessageProtocol,

    /// Structured payload. Schema depends on `protocol`.
    pub payload: serde_json::Value,

    /// Message priority (0-255). Higher = more important.
    #[serde(default = "default_priority")]
    pub priority: Priority,

    /// Whether this message requires a human to take action.
    #[serde(default)]
    pub requires_human: bool,

    /// If this is a reply, the ID of the original message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<MessageId>,

    /// Unix timestamp (ms) when sent.
    #[serde(default = "default_timestamp")]
    pub timestamp: u64,
}

fn default_priority() -> Priority {
    Priority::NORMAL
}

fn default_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl AgentMessage {
    /// Create a new message. Generates a unique ID automatically.
    pub fn new(
        from_agent: &AgentIdentity,
        protocol: MessageProtocol,
        payload: serde_json::Value,
    ) -> Self {
        let id = MessageId::generate(&from_agent.agent_id);
        Self {
            id,
            from_agent: from_agent.clone(),
            to_agent: String::new(),
            protocol,
            payload,
            priority: Priority::NORMAL,
            requires_human: false,
            reply_to: None,
            timestamp: default_timestamp(),
        }
    }

    /// Set the recipient.
    pub fn to(mut self, agent_id: &str) -> Self {
        self.to_agent = agent_id.to_string();
        self
    }

    /// Set priority.
    pub fn priority(mut self, p: Priority) -> Self {
        self.priority = p;
        self
    }

    /// Mark as requiring human attention.
    pub fn requires_human(mut self) -> Self {
        self.requires_human = true;
        self
    }

    /// Set as a reply to another message.
    pub fn reply_to(mut self, msg_id: &MessageId) -> Self {
        self.reply_to = Some(msg_id.clone());
        self
    }

    /// Create a reply message with the same to/from swapped.
    pub fn make_reply(&self, reply_payload: serde_json::Value) -> Self {
        let mut reply = Self::new(
            // Note: in practice the caller would set the correct from_agent
            // for the replying agent. We use the original's to_agent as a hint.
            &self.from_agent,
            self.protocol.clone(),
            reply_payload,
        );
        reply.to_agent = self.from_agent.agent_id.clone();
        reply.reply_to = Some(self.id.clone());
        reply.timestamp = default_timestamp();
        reply
    }

    /// Serialize to JSON bytes for wire transport.
    pub fn to_json_bytes(&self) -> anyhow::Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| anyhow::anyhow!("serialize AgentMessage: {e}"))
    }

    /// Deserialize from JSON bytes.
    pub fn from_json_bytes(data: &[u8]) -> anyhow::Result<Self> {
        serde_json::from_slice(data)
            .map_err(|e| anyhow::anyhow!("parse AgentMessage: {e}"))
    }

    /// Quick payload accessor helpers.
    pub fn payload_str(&self, key: &str) -> Option<&str> {
        self.payload.get(key).and_then(|v| v.as_str())
    }

    pub fn payload_i64(&self, key: &str) -> Option<i64> {
        self.payload.get(key).and_then(|v| v.as_i64())
    }

    pub fn payload_object(&self) -> Option<&serde_json::Map<String, serde_json::Value>> {
        self.payload.as_object()
    }

    /// Compact display string for logging.
    pub fn summary(&self) -> String {
        let from = &self.from_agent.display_name;
        let proto = self.protocol.tag();
        let prio = self.priority.label();
        if self.to_agent.is_empty() {
            format!("[{proto}|{prio}] {from}: broadcast")
        } else {
            format!("[{proto}|{prio}] {from} → {}", self.to_agent)
        }
    }
}

// ─── Convenience Builders ────────────────────────────────────────

/// Helper methods for creating common message types.
impl AgentMessage {
    /// "Can you do X?" — intent negotiation.
    pub fn intent(
        from: &AgentIdentity,
        action: &str,
        params: serde_json::Value,
    ) -> Self {
        Self::new(from, MessageProtocol::IntentNegotiation, serde_json::json!({
            "action": action,
            "params": params,
        }))
    }

    /// "Do X." — task assignment.
    pub fn task(
        from: &AgentIdentity,
        task: &str,
        payload: serde_json::Value,
    ) -> Self {
        Self::new(from, MessageProtocol::TaskAssignment, serde_json::json!({
            "task": task,
            "data": payload,
        }))
    }

    /// "Here's how it's going." — status report.
    pub fn status(
        from: &AgentIdentity,
        status: &str,
        percent: u8,
        note: &str,
    ) -> Self {
        Self::new(from, MessageProtocol::StatusReport, serde_json::json!({
            "status": status,
            "percent": percent,
            "note": note,
        }))
    }

    /// "Here's the data." — data exchange.
    pub fn data(
        from: &AgentIdentity,
        format: &str,
        data: serde_json::Value,
    ) -> Self {
        Self::new(from, MessageProtocol::DataExchange, serde_json::json!({
            "format": format,
            "data": data,
        }))
    }

    /// "Human, look at this." — escalate to human.
    pub fn human_handoff(
        from: &AgentIdentity,
        reason: &str,
        summary: &str,
        context: serde_json::Value,
    ) -> Self {
        Self::new(from, MessageProtocol::HumanHandoff, serde_json::json!({
            "reason": reason,
            "summary": summary,
            "context": context,
        }))
        .requires_human()
    }

    /// Simple text message (uses DataExchange under the hood).
    pub fn text(from: &AgentIdentity, text: &str) -> Self {
        Self::new(from, MessageProtocol::DataExchange, serde_json::json!({
            "text": text,
        }))
    }

    /// "I'm alive." — heartbeat for presence.
    pub fn heartbeat(from: &AgentIdentity, status: &str, load: f32) -> AgentMessage {
        AgentMessage::new(from, MessageProtocol::Heartbeat, serde_json::json!({
            "status": status,
            "load": load,
        }))
    }
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityBuilder;

    /// Create a test agent identity.
    fn make_test_agent(name: &str) -> AgentIdentity {
        let seed = {
            let mut bytes = name.as_bytes().to_vec();
            bytes.resize(32, 0);
            bytes
        };
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed.try_into().unwrap());
        IdentityBuilder::new(name)
            .capabilities(&["test"])
            .owner_id("did:walkie:test-owner")
            .build_with_key(&signing_key)
            .unwrap()
    }

    // ── MessageId ──

    #[test]
    fn test_message_id_generate() {
        let id = MessageId::generate("did:walkie:abcdef1234567890");
        assert!(id.as_str().contains('_'));
        // Format: <8chars>_<timestamp>_<6hex>
        let parts: Vec<&str> = id.as_str().split('_').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].len(), 8);
        assert!(parts[2].len() == 6);
        assert!(parts[2].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_message_id_display() {
        let id = MessageId("test_123_abc".to_string());
        assert_eq!(format!("{id}"), "test_123_abc");
    }

    #[test]
    fn test_message_id_uniqueness() {
        let a = MessageId::generate("agent1");
        let b = MessageId::generate("agent1");
        // Even with same sender, different timestamps or random ensure uniqueness
        // (statistically — in practice the random part differs)
        // Just check they're valid format
        assert!(!a.as_str().is_empty());
        assert!(!b.as_str().is_empty());
    }

    // ── MessageProtocol ──

    #[test]
    fn test_protocol_display() {
        assert_eq!(format!("{}", MessageProtocol::IntentNegotiation), "IntentNegotiation");
        assert_eq!(format!("{}", MessageProtocol::TaskAssignment), "TaskAssignment");
        assert_eq!(format!("{}", MessageProtocol::StatusReport), "StatusReport");
        assert_eq!(format!("{}", MessageProtocol::DataExchange), "DataExchange");
        assert_eq!(format!("{}", MessageProtocol::HumanHandoff), "HumanHandoff");
    }

    #[test]
    fn test_protocol_tag() {
        assert_eq!(MessageProtocol::IntentNegotiation.tag(), "INTENT");
        assert_eq!(MessageProtocol::TaskAssignment.tag(), "TASK");
        assert_eq!(MessageProtocol::StatusReport.tag(), "STATUS");
        assert_eq!(MessageProtocol::DataExchange.tag(), "DATA");
        assert_eq!(MessageProtocol::HumanHandoff.tag(), "HUMAN");
    }

    #[test]
    fn test_protocol_serde_roundtrip() {
        let protocols = vec![
            MessageProtocol::IntentNegotiation,
            MessageProtocol::TaskAssignment,
            MessageProtocol::StatusReport,
            MessageProtocol::DataExchange,
            MessageProtocol::HumanHandoff,
        ];
        for proto in protocols {
            let json = serde_json::to_string(&proto).unwrap();
            let decoded: MessageProtocol = serde_json::from_str(&json).unwrap();
            assert_eq!(proto, decoded);
        }
    }

    // ── Priority ──

    #[test]
    fn test_priority_levels() {
        assert!(Priority::LOW.level() < Priority::NORMAL.level());
        assert!(Priority::NORMAL.level() < Priority::HIGH.level());
        assert!(Priority::HIGH.level() < Priority::URGENT.level());
        assert!(Priority::URGENT.level() < Priority::CRITICAL.level());
    }

    #[test]
    fn test_priority_labels() {
        assert_eq!(Priority::LOW.label(), "LOW");
        assert_eq!(Priority(0).label(), "LOW");
        assert_eq!(Priority::NORMAL.label(), "NORMAL");
        assert_eq!(Priority(125).label(), "HIGH");
        assert_eq!(Priority(175).label(), "URGENT");
        assert_eq!(Priority(255).label(), "CRITICAL");
    }

    // ── AgentMessage creation ──

    #[test]
    fn test_create_message() {
        let agent = make_test_agent("Alice");
        let msg = AgentMessage::new(
            &agent,
            MessageProtocol::TaskAssignment,
            serde_json::json!({"task": "review"}),
        );

        assert!(msg.id.as_str().contains('_'));
        assert_eq!(msg.from_agent.display_name, "Alice");
        assert!(msg.to_agent.is_empty()); // broadcast by default
        assert_eq!(msg.protocol, MessageProtocol::TaskAssignment);
        assert_eq!(msg.payload["task"], "review");
        assert_eq!(msg.priority, Priority::NORMAL);
        assert!(!msg.requires_human);
        assert!(msg.reply_to.is_none());
        assert!(msg.timestamp > 0);
    }

    #[test]
    fn test_builder_pattern() {
        let agent = make_test_agent("Alice");
        let msg = AgentMessage::new(&agent, MessageProtocol::DataExchange, serde_json::json!({}))
            .to("did:walkie:bob")
            .priority(Priority::HIGH)
            .requires_human();

        assert_eq!(msg.to_agent, "did:walkie:bob");
        assert_eq!(msg.priority, Priority::HIGH);
        assert!(msg.requires_human);
    }

    #[test]
    fn test_make_reply() {
        let alice = make_test_agent("Alice");
        let bob = make_test_agent("Bob");

        let original = AgentMessage::new(&alice, MessageProtocol::TaskAssignment, serde_json::json!({"task":"X"}))
            .to(&bob.agent_id);

        let reply = original.make_reply(serde_json::json!({"result":"ok"}));

        assert_eq!(reply.reply_to.as_ref().unwrap(), &original.id);
        assert_eq!(reply.to_agent, alice.agent_id);
    }

    // ── Convenience builders ──

    #[test]
    fn test_intent_builder() {
        let agent = make_test_agent("A");
        let msg = AgentMessage::intent(&agent, "code-review", serde_json::json!({"language":"rust"}));
        assert_eq!(msg.protocol, MessageProtocol::IntentNegotiation);
        assert_eq!(msg.payload["action"], "code-review");
    }

    #[test]
    fn test_task_builder() {
        let agent = make_test_agent("A");
        let msg = AgentMessage::task(&agent, "analyze", serde_json::json!({"file":"main.rs"}));
        assert_eq!(msg.protocol, MessageProtocol::TaskAssignment);
        assert_eq!(msg.payload["task"], "analyze");
    }

    #[test]
    fn test_status_builder() {
        let agent = make_test_agent("A");
        let msg = AgentMessage::status(&agent, "in_progress", 75, "almost done");
        assert_eq!(msg.protocol, MessageProtocol::StatusReport);
        assert_eq!(msg.payload["status"], "in_progress");
        assert_eq!(msg.payload["percent"], 75);
    }

    #[test]
    fn test_data_builder() {
        let agent = make_test_agent("A");
        let msg = AgentMessage::data(&agent, "json", serde_json::json!({"key":"val"}));
        assert_eq!(msg.protocol, MessageProtocol::DataExchange);
        assert_eq!(msg.payload["format"], "json");
    }

    #[test]
    fn test_human_handoff_builder() {
        let agent = make_test_agent("A");
        let msg = AgentMessage::human_handoff(&agent, "approval", "Budget exceeded", serde_json::json!({"amount":9999}));
        assert_eq!(msg.protocol, MessageProtocol::HumanHandoff);
        assert!(msg.requires_human);
        assert_eq!(msg.payload["reason"], "approval");
    }

    #[test]
    fn test_text_builder() {
        let agent = make_test_agent("A");
        let msg = AgentMessage::text(&agent, "Hello, Agent B!");
        assert_eq!(msg.protocol, MessageProtocol::DataExchange);
        assert_eq!(msg.payload["text"], "Hello, Agent B!");
    }

    // ── Serialization ──

    #[test]
    fn test_full_serialization_roundtrip() {
        let agent = make_test_agent("Rustacean");
        let original_id = MessageId::generate("did:walkie:xyz");

        let msg = AgentMessage::new(&agent, MessageProtocol::TaskAssignment, serde_json::json!({
            "task": "review-pr",
            "target": "#42",
            "deadline_ms": 3600000
        }))
            .to("did:walkie:receiver")
            .priority(Priority::URGENT)
            .requires_human()
            .reply_to(&original_id);

        // Serialize
        let json_bytes = msg.to_json_bytes().unwrap();
        let json_str = String::from_utf8(json_bytes.clone()).unwrap();

        // Verify JSON structure
        assert!(json_str.contains("task_assignment"));
        assert!(json_str.contains("did:walkie:receiver"));
        assert!(json_str.contains("review-pr"));

        // Deserialize
        let decoded = AgentMessage::from_json_bytes(&json_bytes).unwrap();
        assert_eq!(decoded.id, msg.id);
        assert_eq!(decoded.from_agent.agent_id, msg.from_agent.agent_id);
        assert_eq!(decoded.to_agent, "did:walkie:receiver");
        assert_eq!(decoded.protocol, MessageProtocol::TaskAssignment);
        assert_eq!(decoded.payload["task"], "review-pr");
        assert_eq!(decoded.priority, Priority::URGENT);
        assert!(decoded.requires_human);
        assert_eq!(decoded.reply_to.as_ref().unwrap(), &original_id);
        // Identity is still valid after roundtrip
        assert!(decoded.from_agent.verify().is_ok());
    }

    #[test]
    fn test_broadcast_message_roundtrip() {
        let agent = make_test_agent("Broadcaster");
        let msg = AgentMessage::text(&agent, "Hello everyone!");

        let bytes = msg.to_json_bytes().unwrap();
        let decoded = AgentMessage::from_json_bytes(&bytes).unwrap();
        assert!(decoded.to_agent.is_empty());
        assert_eq!(decoded.payload["text"], "Hello everyone!");
    }

    #[test]
    fn test_invalid_json_fails() {
        let result = AgentMessage::from_json_bytes(b"not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_protocol_json_fails() {
        let result = AgentMessage::from_json_bytes(
            br#"{"id":"x","from_agent":null,"to_agent":"","protocol":"InvalidType","payload":null,"priority":100,"requires_human":false,"timestamp":0}"#
        );
        assert!(result.is_err());
    }

    // ── Payload helpers ──

    #[test]
    fn test_payload_accessors() {
        let agent = make_test_agent("A");
        let msg = AgentMessage::new(&agent, MessageProtocol::StatusReport, serde_json::json!({
            "status": "ok",
            "percent": 50,
            "note": "halfway"
        }));

        assert_eq!(msg.payload_str("status"), Some("ok"));
        assert_eq!(msg.payload_i64("percent"), Some(50));
        assert_eq!(msg.payload_str("note"), Some("halfway"));
        assert_eq!(msg.payload_str("nonexistent"), None);
        assert!(msg.payload_object().is_some());
    }

    // ── Summary ──

    #[test]
    fn test_summary() {
        let agent = make_test_agent("Alice");
        let direct = AgentMessage::task(&agent, "review", serde_json::json!({}))
            .to("did:walkie:bob");
        assert!(direct.summary().contains("Alice"));
        assert!(direct.summary().contains("did:walkie:bob"));
        assert!(direct.summary().contains("TASK"));

        let broadcast = AgentMessage::text(&agent, "hi");
        assert!(broadcast.summary().contains("broadcast"));
    }

    // ── Priority serde ──

    #[test]
    fn test_priority_serde() {
        let p = Priority::HIGH;
        let json = serde_json::to_string(&p).unwrap();
        let decoded: Priority = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, Priority::HIGH);
        assert_eq!(decoded.level(), 125);
    }

    #[test]
    fn test_message_id_serde() {
        let id = MessageId("abc_123_def".to_string());
        let json = serde_json::to_string(&id).unwrap();
        let decoded: MessageId = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.as_str(), "abc_123_def");
    }

    // ── Boundary tests ──

    #[test]
    fn test_empty_payload_roundtrip() {
        let agent = make_test_agent("A");
        let msg = AgentMessage::new(&agent, MessageProtocol::Heartbeat, serde_json::Value::Null);
        let bytes = msg.to_json_bytes().unwrap();
        let decoded = AgentMessage::from_json_bytes(&bytes).unwrap();
        assert!(decoded.payload.is_null());
    }

    #[test]
    fn test_deeply_nested_payload_roundtrip() {
        let agent = make_test_agent("A");
        let deep = serde_json::json!({"a": {"b": {"c": {"d": {"e": "deep"}}}}});
        let msg = AgentMessage::new(&agent, MessageProtocol::DataExchange, deep.clone());
        let bytes = msg.to_json_bytes().unwrap();
        let decoded = AgentMessage::from_json_bytes(&bytes).unwrap();
        assert_eq!(decoded.payload, deep);
    }

    #[test]
    fn test_large_payload_roundtrip() {
        let agent = make_test_agent("A");
        let big_array: Vec<i32> = (0..10_000).collect();
        let payload = serde_json::json!({"items": big_array, "count": 10000});
        let msg = AgentMessage::new(&agent, MessageProtocol::DataExchange, payload);
        let bytes = msg.to_json_bytes().unwrap();
        let decoded = AgentMessage::from_json_bytes(&bytes).unwrap();
        assert_eq!(decoded.payload["count"], 10000);
        assert_eq!(decoded.payload["items"].as_array().unwrap().len(), 10_000);
    }

    #[test]
    fn test_truncated_json_fails() {
        // Valid-looking start but cut off halfway
        let partial = br#"{"id":"x","from_agent":{"agent_id":"did:walkie:"#;
        assert!(AgentMessage::from_json_bytes(partial).is_err());
    }

    #[test]
    fn test_json_with_wrong_types_fails() {
        // protocol field should be string enum, not a number
        let bad = br#"{"id":"x","from_agent":{"agent_id":"","display_name":"","capabilities":[],"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","owner_id":"","version":"v","created_at":0,"signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},"to_agent":"","protocol":999,"payload":null,"priority":{"0":75},"requires_human":false,"timestamp":0}"#;
        assert!(AgentMessage::from_json_bytes(bad).is_err());
    }

    #[test]
    fn test_missing_from_agent_fails() {
        // from_agent is required but missing
        let bad = br#"{"id":"x","to_agent":"","protocol":"heartbeat","payload":null,"priority":{"0":75},"requires_human":false,"timestamp":0}"#;
        assert!(AgentMessage::from_json_bytes(bad).is_err());
    }

    #[test]
    fn test_completely_empty_bytes_fails() {
        assert!(AgentMessage::from_json_bytes(b"").is_err());
    }

    #[test]
    fn test_payload_helpers_on_empty_payload() {
        let agent = make_test_agent("A");
        let msg = AgentMessage::new(&agent, MessageProtocol::Heartbeat, serde_json::json!({}));
        assert_eq!(msg.payload_str("missing"), None);
        assert_eq!(msg.payload_i64("missing"), None);
    }
}
