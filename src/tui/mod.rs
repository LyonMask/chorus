//! TUI Module — Layer 3 Human Interface core logic
//!
//! This module contains the testable state machine and event processing
//! for the terminal UI. Rendering is in `examples/tui_demo.rs`.
//!
//! Separated from rendering so `cargo test --lib` works without TTY.

use serde::{Serialize, Deserialize};
use std::collections::HashMap;

use crate::identity::AgentIdentity;
use crate::protocol::{AgentMessage, MessageProtocol};

// ─── Activity Action Types ─────────────────────────────────────

/// Maps MessageProtocol to a human-readable action category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActivityAction {
    AgentOnline,
    AgentOffline,
    CapabilityQuery,
    TaskAssigned,
    TaskAccepted,
    TaskProgress,
    TaskCompleted,
    TaskFailed,
    TaskBlocked,
    DataExchanged,
    HumanEscalation,
    TextMessage,
    E2EESession,
    IdentityVerified,
    Connected,
    RawMessage,
    SystemInfo,
    Approved,
    Rejected,
    Dismissed,
}

impl ActivityAction {
    /// Map a MessageProtocol + payload to an ActivityAction.
    pub fn from_message(msg: &AgentMessage) -> (Self, String) {
        let actor = msg.from_agent.display_name.clone();
        match msg.protocol {
            MessageProtocol::Heartbeat => {
                let status = msg.payload_str("status").unwrap_or("unknown");
                if status == "offline" {
                    (Self::AgentOffline, format!("{} went offline", actor))
                } else {
                    (Self::AgentOnline, format!("{} is {}", actor, status))
                }
            }
            MessageProtocol::IntentNegotiation => {
                let action = msg.payload_str("action").unwrap_or("?");
                (Self::CapabilityQuery,
                    format!("{} asked: can you {}?", actor, action))
            }
            MessageProtocol::TaskAssignment => {
                let task = msg.payload_str("task").unwrap_or("a task");
                let target = if msg.to_agent.is_empty() { "ALL".into() } else { msg.to_agent.clone() };
                (Self::TaskAssigned, format!("{} assigned \"{}\" to {}", actor, task, target))
            }
            MessageProtocol::StatusReport => {
                let status = msg.payload_str("status").unwrap_or("?");
                let pct = msg.payload_i64("percent").unwrap_or(0);
                let note = msg.payload_str("note").unwrap_or("");
                let note_part = if note.is_empty() { String::new() } else { format!(" — {}", note) };
                let action = match status {
                    "pending" => Self::TaskAccepted,
                    "in_progress" => Self::TaskProgress,
                    "completed" => Self::TaskCompleted,
                    "failed" => Self::TaskFailed,
                    "blocked" => Self::TaskBlocked,
                    _ => Self::TaskProgress,
                };
                (action, format!("{} [{}]: {}%{}", actor, status, pct, note_part))
            }
            MessageProtocol::DataExchange => {
                if msg.payload_str("text").is_some() {
                    let text = msg.payload_str("text").unwrap_or("");
                    (Self::TextMessage, format!("{}: \"{}\"", actor, text))
                } else {
                    let schema = msg.payload_str("schema").unwrap_or("data");
                    (Self::DataExchanged, format!("{} sent {} to {}", actor, schema,
                        if msg.to_agent.is_empty() { "ALL".into() } else { msg.to_agent.clone() }))
                }
            }
            MessageProtocol::HumanHandoff => {
                let summary = msg.payload_str("summary").unwrap_or("needs human");
                (Self::HumanEscalation,
                    format!("🚨 {} needs human: {}", actor, summary))
            }
        }
    }

    /// Emoji icon for rendering.
    pub fn icon(&self) -> &'static str {
        match self {
            Self::HumanEscalation => "🚨",
            Self::TaskAssigned => "📋",
            Self::TaskProgress | Self::TaskAccepted => "📊",
            Self::TaskCompleted => "✅",
            Self::TaskFailed => "❌",
            Self::TaskBlocked => "⚠️",
            Self::TextMessage => "💬",
            Self::DataExchanged => "📦",
            Self::AgentOnline => "💚",
            Self::AgentOffline => "⚫",
            Self::CapabilityQuery => "🤝",
            Self::Approved => "✅",
            Self::Rejected => "❌",
            Self::Dismissed => "⬜",
            Self::E2EESession => "🔒",
            Self::IdentityVerified => "🪪",
            Self::Connected => "🔗",
            Self::RawMessage => "📨",
            Self::SystemInfo => "ℹ️",
        }
    }

    /// Short tag for log output.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::HumanEscalation => "ESCALATE",
            Self::TaskAssigned => "TASK",
            Self::TaskProgress => "PROGRESS",
            Self::TaskAccepted => "ACCEPTED",
            Self::TaskCompleted => "COMPLETED",
            Self::TaskFailed => "FAILED",
            Self::TaskBlocked => "BLOCKED",
            Self::TextMessage => "TEXT",
            Self::DataExchanged => "DATA",
            Self::AgentOnline => "ONLINE",
            Self::AgentOffline => "OFFLINE",
            Self::CapabilityQuery => "INTENT",
            Self::Approved => "APPROVED",
            Self::Rejected => "REJECTED",
            Self::Dismissed => "DISMISSED",
            Self::E2EESession => "E2EE",
            Self::IdentityVerified => "IDENTITY",
            Self::Connected => "CONNECT",
            Self::RawMessage => "MSG",
            Self::SystemInfo => "INFO",
        }
    }
}

// ─── Activity Item ─────────────────────────────────────────────

/// A single entry in the human-readable activity feed.
#[derive(Debug, Clone)]
pub struct ActivityItem {
    pub timestamp_ms: u64,
    pub actor: String,
    pub action: ActivityAction,
    pub detail: String,
    pub requires_human: bool,
}

impl ActivityItem {
    pub fn new(actor: &str, action: ActivityAction, detail: &str) -> Self {
        Self {
            timestamp_ms: now_millis(),
            actor: actor.to_string(),
            action,
            detail: detail.to_string(),
            requires_human: action == ActivityAction::HumanEscalation,
        }
    }

    pub fn human_summary(&self) -> String {
        format!("{} {} {}", self.action.icon(), self.actor, self.detail)
    }
}

// ─── Alert ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertStatus {
    Pending,
    Approved,
    Rejected,
    Dismissed,
}

/// A HumanHandoff alert requiring human intervention.
#[derive(Debug, Clone)]
pub struct Alert {
    pub id: usize,
    pub from_agent: String,
    pub reason: String,
    pub summary: String,
    pub context: String,
    pub status: AlertStatus,
}

impl Alert {
    pub fn new(id: usize, from: &str, reason: &str, summary: &str, context: &str) -> Self {
        Self {
            id,
            from_agent: from.to_string(),
            reason: reason.to_string(),
            summary: summary.to_string(),
            context: context.to_string(),
            status: AlertStatus::Pending,
        }
    }

    pub fn is_pending(&self) -> bool {
        self.status == AlertStatus::Pending
    }
}

// ─── Agent Info ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AgentInfo {
    pub peer_key: String,
    pub display_name: String,
    pub did: String,
    pub online: bool,
    pub load: f32,
    pub capabilities: Vec<String>,
}

impl AgentInfo {
    pub fn new(peer_key: &str, name: &str, did: &str) -> Self {
        Self {
            peer_key: peer_key.to_string(),
            display_name: name.to_string(),
            did: did.to_string(),
            online: true,
            load: 0.0,
            capabilities: Vec::new(),
        }
    }

    pub fn short_did(&self) -> String {
        if self.did.len() > 24 {
            self.did[..24].to_string()
        } else {
            self.did.clone()
        }
    }
}

// ─── App Mode ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppMode {
    Dashboard,
    AlertDetail,
}

// ─── App State (fully testable) ────────────────────────────────

/// Core TUI application state. All mutation methods are testable without TTY.
pub struct TuiApp {
    pub agents: HashMap<String, AgentInfo>,
    pub activities: Vec<ActivityItem>,
    pub alerts: Vec<Alert>,
    pub selected_alert: usize,
    pub mode: AppMode,
    pub should_quit: bool,
    pub pending_approvals: usize,
    pub tasks_assigned: u32,
    pub tasks_completed: u32,
    pub event_count: u64,
}

impl Default for TuiApp {
    fn default() -> Self {
        Self::new()
    }
}

impl TuiApp {
    pub fn new() -> Self {
        Self {
            agents: HashMap::new(),
            activities: Vec::new(),
            alerts: Vec::new(),
            selected_alert: 0,
            mode: AppMode::Dashboard,
            should_quit: false,
            pending_approvals: 0,
            tasks_assigned: 0,
            tasks_completed: 0,
            event_count: 0,
        }
    }

    // ── Agent Management ──

    pub fn add_agent(&mut self, peer_key: &str, name: &str, did: &str) {
        self.agents.entry(peer_key.to_string())
            .or_insert_with(|| AgentInfo::new(peer_key, name, did));
    }

    pub fn set_agent_offline(&mut self, peer_key: &str) {
        let name = self.agents.get(peer_key).map(|a| a.display_name.clone());
        if let Some(agent) = self.agents.get_mut(peer_key) {
            agent.online = false;
        }
        if let Some(name) = name {
            self.push_activity(ActivityItem::new(
                &name, ActivityAction::AgentOffline,
                &format!("{} went offline", name),
            ));
        }
    }

    pub fn update_agent_from_identity(&mut self, peer_key: &str, identity: &AgentIdentity) {
        let agent = self.agents.entry(peer_key.to_string())
            .or_insert_with(|| AgentInfo::new(peer_key, &identity.display_name, &identity.agent_id));
        agent.display_name = identity.display_name.clone();
        agent.did = identity.agent_id.clone();
        agent.capabilities = identity.capabilities.clone();
        agent.online = true;

        self.push_activity(ActivityItem::new(
            &identity.display_name, ActivityAction::IdentityVerified,
            &format!("✅ {} identity verified", identity.display_name),
        ));
    }

    pub fn online_agent_count(&self) -> usize {
        self.agents.values().filter(|a| a.online).count()
    }

    // ── Activity Feed ──

    pub fn push_activity(&mut self, item: ActivityItem) {
        self.event_count += 1;
        self.activities.push(item);
        if self.activities.len() > 500 {
            self.activities.remove(0);
        }
    }

    pub fn process_agent_message(&mut self, msg: &AgentMessage) {
        let (action, detail) = ActivityAction::from_message(msg);

        if action == ActivityAction::TaskAssigned {
            self.tasks_assigned += 1;
        }
        if action == ActivityAction::TaskCompleted {
            self.tasks_completed += 1;
        }

        // Update agent load from heartbeat
        if action == ActivityAction::AgentOnline {
            let did = &msg.from_agent.agent_id;
            if let Some(agent) = self.agents.get_mut(did) {
                agent.online = true;
                if let Some(load_val) = msg.payload.get("load").and_then(|v| v.as_f64()) {
                    agent.load = load_val as f32;
                }
            }
        }

        let requires_human = msg.requires_human || action == ActivityAction::HumanEscalation;

        let item = ActivityItem {
            timestamp_ms: now_millis(),
            actor: msg.from_agent.display_name.clone(),
            action,
            detail,
            requires_human,
        };
        self.push_activity(item);

        // Auto-create alert for HumanHandoff
        if msg.protocol == MessageProtocol::HumanHandoff {
            let _id = self.alerts.len();
            let reason = msg.payload_str("reason").unwrap_or("unknown").to_string();
            let summary = msg.payload_str("summary").unwrap_or("").to_string();
            let context = msg.payload_object()
                .and_then(|o| o.get("context").cloned())
                .map(|v| v.to_string())
                .unwrap_or_default();
            self.add_alert(
                &msg.from_agent.display_name,
                &reason, &summary, &context,
            );
        }
    }

    // ── Alert Management ──

    pub fn add_alert(&mut self, from: &str, reason: &str, summary: &str, context: &str) {
        let _id = self.alerts.len();
        self.alerts.push(Alert::new(_id, from, reason, summary, context));
        self.pending_approvals += 1;
        // Auto-switch to alert view
        if self.mode == AppMode::Dashboard {
            self.mode = AppMode::AlertDetail;
            self.selected_alert = _id;
        }
    }

    pub fn approve_selected_alert(&mut self) -> bool {
        let idx = self.selected_alert;
        if let Some(alert) = self.alerts.get_mut(idx) {
            if alert.is_pending() {
                let from = alert.from_agent.clone();
                alert.status = AlertStatus::Approved;
                self.pending_approvals = self.pending_approvals.saturating_sub(1);
                self.push_activity(ActivityItem::new(
                    "Human", ActivityAction::Approved,
                    &format!("✅ Approved alert from {}", from),
                ));
                self.advance_to_next_pending();
                return true;
            }
        }
        false
    }

    pub fn reject_selected_alert(&mut self) -> bool {
        let idx = self.selected_alert;
        if let Some(alert) = self.alerts.get_mut(idx) {
            if alert.is_pending() {
                let from = alert.from_agent.clone();
                alert.status = AlertStatus::Rejected;
                self.pending_approvals = self.pending_approvals.saturating_sub(1);
                self.push_activity(ActivityItem::new(
                    "Human", ActivityAction::Rejected,
                    &format!("❌ Rejected alert from {}", from),
                ));
                self.advance_to_next_pending();
                return true;
            }
        }
        false
    }

    pub fn dismiss_selected_alert(&mut self) -> bool {
        let idx = self.selected_alert;
        if let Some(alert) = self.alerts.get_mut(idx) {
            if alert.is_pending() {
                alert.status = AlertStatus::Dismissed;
                self.pending_approvals = self.pending_approvals.saturating_sub(1);
                self.advance_to_next_pending();
                return true;
            }
        }
        false
    }

    pub fn next_alert(&mut self) {
        for i in (self.selected_alert + 1)..self.alerts.len() {
            if self.alerts[i].is_pending() {
                self.selected_alert = i;
                return;
            }
        }
    }

    pub fn prev_alert(&mut self) {
        if self.selected_alert > 0 {
            for i in (0..self.selected_alert).rev() {
                if self.alerts[i].is_pending() {
                    self.selected_alert = i;
                    return;
                }
            }
        }
    }

    fn advance_to_next_pending(&mut self) {
        for i in (self.selected_alert + 1)..self.alerts.len() {
            if self.alerts[i].is_pending() {
                self.selected_alert = i;
                return;
            }
        }
        if self.pending_approvals == 0 {
            self.mode = AppMode::Dashboard;
        }
    }

    // ── Key Handling ──

    pub fn handle_key(&mut self, code: Key) {
        match code {
            Key::Quit => self.should_quit = true,
            Key::GoToAlerts => {
                if self.pending_approvals > 0 {
                    self.mode = AppMode::AlertDetail;
                }
            }
            Key::GoToDashboard => self.mode = AppMode::Dashboard,
            Key::Approve if self.mode == AppMode::AlertDetail => { self.approve_selected_alert(); }
            Key::Reject if self.mode == AppMode::AlertDetail => { self.reject_selected_alert(); }
            Key::Dismiss if self.mode == AppMode::AlertDetail => { self.dismiss_selected_alert(); }
            Key::Next if self.mode == AppMode::AlertDetail => self.next_alert(),
            Key::Prev if self.mode == AppMode::AlertDetail => self.prev_alert(),
            _ => {}
        }
    }

    // ── Status Line ──

    pub fn status_line(&self) -> String {
        format!(
            "Agents: {} online | Tasks: {}/{} | Events: {} | Alerts: {} pending",
            self.online_agent_count(),
            self.tasks_completed, self.tasks_assigned,
            self.event_count,
            self.pending_approvals,
        )
    }

    // ── Demo Data ──

    pub fn load_demo_data(&mut self) {
        self.add_agent("alice", "Alice", "did:walkie:maMVNJDswURGw");
        if let Some(a) = self.agents.get_mut("alice") {
            a.capabilities = vec!["coordinate".into(), "strategy".into()];
        }
        self.add_agent("rustacean", "Rustacean", "did:walkie:fLYf2Xc0I3qyO");
        if let Some(a) = self.agents.get_mut("rustacean") {
            a.capabilities = vec!["code-review".into(), "crypto".into(), "p2p".into()];
        }
        self.add_agent("bridge", "Bridge", "did:walkie:fmYIb9jntMvbj");
        if let Some(a) = self.agents.get_mut("bridge") {
            a.capabilities = vec!["product".into(), "review".into(), "human-handoff".into()];
        }

        // Simulate task flow
        self.push_activity(ActivityItem::new(
            "Alice", ActivityAction::TaskAssigned,
            "Alice assigned \"code-review\" to Rustacean",
        ));
        self.tasks_assigned += 1;

        self.push_activity(ActivityItem::new(
            "Rustacean", ActivityAction::TaskProgress,
            "Rustacean [in_progress]: 50% — Checking encryption layer...",
        ));

        self.push_activity(ActivityItem::new(
            "Rustacean", ActivityAction::TaskCompleted,
            "Rustacean [completed]: 100% — Code review done, 2 findings",
        ));
        self.tasks_completed += 1;

        // Create alert
        self.add_alert(
            "Bridge", "review_complete",
            "Code review passed. 2 findings need human review.",
            "Reviewer: Rustacean\nVerdict: PASS\nFindings: 2 (1 info, 1 warning)",
        );

        self.push_activity(ActivityItem::new(
            "Alice", ActivityAction::TaskAssigned,
            "Alice assigned \"human-review\" to Bridge",
        ));
        self.tasks_assigned += 1;
    }
}

// ─── Key abstraction (decouples from crossterm for testing) ─────

/// Abstract key events — crossterm::KeyCode mapped here so TuiApp is testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Key {
    Quit,          // 'q'
    GoToDashboard, // 'd' / Esc
    GoToAlerts,    // 'a'
    Approve,       // 'y'
    Reject,        // 'n'
    Dismiss,       // 'x'
    Next,          // Down
    Prev,          // Up
    Unknown,
}

// ─── Utilities ──────────────────────────────────────────────────

pub fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityBuilder;
    
    use serde_json::json;

    fn make_test_identity(name: &str) -> AgentIdentity {
        IdentityBuilder::new(name)
            .capabilities(&["test"])
            .build()
            .unwrap()
            .0
    }

    // ── ActivityAction tests ──

    #[test]
    fn test_activity_action_from_task() {
        let id = make_test_identity("Alice");
        let msg = AgentMessage::task(&id, "code-review", json!({"target": "main.rs"}));
        let (action, detail) = ActivityAction::from_message(&msg);
        assert_eq!(action, ActivityAction::TaskAssigned);
        assert!(detail.contains("Alice"));
        assert!(detail.contains("code-review"));
    }

    #[test]
    fn test_activity_action_from_status() {
        let id = make_test_identity("Bob");
        let msg = AgentMessage::status(&id, "in_progress", 50, "compiling");
        let (action, detail) = ActivityAction::from_message(&msg);
        assert_eq!(action, ActivityAction::TaskProgress);
        assert!(detail.contains("50%"));
        assert!(detail.contains("compiling"));
    }

    #[test]
    fn test_activity_action_from_completed() {
        let id = make_test_identity("Carol");
        let msg = AgentMessage::status(&id, "completed", 100, "done");
        let (action, _) = ActivityAction::from_message(&msg);
        assert_eq!(action, ActivityAction::TaskCompleted);
    }

    #[test]
    fn test_activity_action_from_failed() {
        let id = make_test_identity("Dave");
        let msg = AgentMessage::status(&id, "failed", 30, "OOM");
        let (action, _) = ActivityAction::from_message(&msg);
        assert_eq!(action, ActivityAction::TaskFailed);
    }

    #[test]
    fn test_activity_action_from_blocked() {
        let id = make_test_identity("Eve");
        let msg = AgentMessage::status(&id, "blocked", 10, "waiting for approval");
        let (action, _) = ActivityAction::from_message(&msg);
        assert_eq!(action, ActivityAction::TaskBlocked);
    }

    #[test]
    fn test_activity_action_from_heartbeat() {
        let id = make_test_identity("Frank");
        let msg = AgentMessage::heartbeat(&id, "online", 0.3);
        let (action, detail) = ActivityAction::from_message(&msg);
        assert_eq!(action, ActivityAction::AgentOnline);
        assert!(detail.contains("online"));
    }

    #[test]
    fn test_activity_action_from_heartbeat_offline() {
        let id = make_test_identity("Grace");
        let msg = AgentMessage::heartbeat(&id, "offline", 0.0);
        let (action, _) = ActivityAction::from_message(&msg);
        assert_eq!(action, ActivityAction::AgentOffline);
    }

    #[test]
    fn test_activity_action_from_text() {
        let id = make_test_identity("Alice");
        let msg = AgentMessage::text(&id, "hello world");
        let (action, detail) = ActivityAction::from_message(&msg);
        assert_eq!(action, ActivityAction::TextMessage);
        assert!(detail.contains("hello world"));
    }

    #[test]
    fn test_activity_action_from_intent() {
        let id = make_test_identity("Alice");
        let msg = AgentMessage::intent(&id, "code-review", json!({"language": "rust"}));
        let (action, detail) = ActivityAction::from_message(&msg);
        assert_eq!(action, ActivityAction::CapabilityQuery);
        assert!(detail.contains("code-review"));
    }

    #[test]
    fn test_activity_action_from_human_handoff() {
        let id = make_test_identity("Bridge");
        let msg = AgentMessage::human_handoff(&id, "approval", "Over budget", json!({"amount": 500}));
        let (action, detail) = ActivityAction::from_message(&msg);
        assert_eq!(action, ActivityAction::HumanEscalation);
        assert!(detail.contains("Over budget"));
    }

    #[test]
    fn test_activity_action_icons() {
        assert_eq!(ActivityAction::HumanEscalation.icon(), "🚨");
        assert_eq!(ActivityAction::TaskAssigned.icon(), "📋");
        assert_eq!(ActivityAction::TaskCompleted.icon(), "✅");
        assert_eq!(ActivityAction::TextMessage.icon(), "💬");
        assert_eq!(ActivityAction::AgentOnline.icon(), "💚");
    }

    #[test]
    fn test_activity_action_tags() {
        assert_eq!(ActivityAction::HumanEscalation.tag(), "ESCALATE");
        assert_eq!(ActivityAction::TaskAssigned.tag(), "TASK");
        assert_eq!(ActivityAction::TaskCompleted.tag(), "COMPLETED");
    }

    // ── ActivityItem tests ──

    #[test]
    fn test_activity_item_creation() {
        let item = ActivityItem::new("Alice", ActivityAction::TaskAssigned, "assigned task");
        assert_eq!(item.actor, "Alice");
        assert_eq!(item.action, ActivityAction::TaskAssigned);
        assert!(!item.requires_human);
    }

    #[test]
    fn test_activity_item_human_escalation_requires_human() {
        let item = ActivityItem::new("Bridge", ActivityAction::HumanEscalation, "needs help");
        assert!(item.requires_human);
    }

    #[test]
    fn test_activity_item_summary() {
        let item = ActivityItem::new("Alice", ActivityAction::TaskAssigned, "assigned code-review");
        let summary = item.human_summary();
        assert!(summary.contains("📋"));
        assert!(summary.contains("Alice"));
    }

    // ── Alert tests ──

    #[test]
    fn test_alert_creation() {
        let alert = Alert::new(0, "Bridge", "review", "Code review passed", "Verdict: PASS");
        assert_eq!(alert.status, AlertStatus::Pending);
        assert!(alert.is_pending());
    }

    #[test]
    fn test_alert_not_pending_after_approve() {
        let mut alert = Alert::new(0, "Bridge", "review", "passed", "");
        alert.status = AlertStatus::Approved;
        assert!(!alert.is_pending());
    }

    // ── TuiApp tests ──

    #[test]
    fn test_app_initial_state() {
        let app = TuiApp::new();
        assert_eq!(app.online_agent_count(), 0);
        assert_eq!(app.pending_approvals, 0);
        assert_eq!(app.activities.len(), 0);
        assert_eq!(app.alerts.len(), 0);
        assert_eq!(app.mode, AppMode::Dashboard);
        assert!(!app.should_quit);
    }

    #[test]
    fn test_app_add_agent() {
        let mut app = TuiApp::new();
        app.add_agent("p1", "Alice", "did:walkie:abc123");
        assert_eq!(app.online_agent_count(), 1);
        assert_eq!(app.agents["p1"].display_name, "Alice");
        assert!(app.agents["p1"].online);
    }

    #[test]
    fn test_app_set_agent_offline() {
        let mut app = TuiApp::new();
        app.add_agent("p1", "Alice", "did:walkie:abc123");
        app.set_agent_offline("p1");
        assert_eq!(app.online_agent_count(), 0);
        assert!(!app.agents["p1"].online);
        // Should create an activity
        assert!(app.activities.iter().any(|a| a.action == ActivityAction::AgentOffline));
    }

    #[test]
    fn test_app_process_task_message() {
        let mut app = TuiApp::new();
        let id = make_test_identity("Alice");
        let msg = AgentMessage::task(&id, "review", json!({}));
        app.process_agent_message(&msg);
        assert_eq!(app.tasks_assigned, 1);
        assert_eq!(app.event_count, 1);
        assert!(app.activities[0].detail.contains("review"));
    }

    #[test]
    fn test_app_process_completed_status() {
        let mut app = TuiApp::new();
        let id = make_test_identity("Bob");
        let msg = AgentMessage::status(&id, "completed", 100, "done");
        app.process_agent_message(&msg);
        assert_eq!(app.tasks_completed, 1);
    }

    #[test]
    fn test_app_process_human_handoff_creates_alert() {
        let mut app = TuiApp::new();
        let id = make_test_identity("Bridge");
        let msg = AgentMessage::human_handoff(&id, "approval", "Need money", json!({}));
        app.process_agent_message(&msg);

        assert_eq!(app.pending_approvals, 1);
        assert_eq!(app.alerts.len(), 1);
        assert_eq!(app.alerts[0].from_agent, "Bridge");
        assert_eq!(app.alerts[0].reason, "approval");
        // Auto-switched to alert mode
        assert_eq!(app.mode, AppMode::AlertDetail);
    }

    #[test]
    fn test_app_approve_alert() {
        let mut app = TuiApp::new();
        app.add_alert("Bridge", "review", "passed", "");
        assert_eq!(app.pending_approvals, 1);

        let result = app.approve_selected_alert();
        assert!(result);
        assert_eq!(app.pending_approvals, 0);
        assert_eq!(app.alerts[0].status, AlertStatus::Approved);
        assert_eq!(app.mode, AppMode::Dashboard);
        // Should have an activity
        assert!(app.activities.iter().any(|a| a.action == ActivityAction::Approved));
    }

    #[test]
    fn test_app_reject_alert() {
        let mut app = TuiApp::new();
        app.add_alert("Bridge", "review", "passed", "");

        let result = app.reject_selected_alert();
        assert!(result);
        assert_eq!(app.pending_approvals, 0);
        assert_eq!(app.alerts[0].status, AlertStatus::Rejected);
    }

    #[test]
    fn test_app_dismiss_alert() {
        let mut app = TuiApp::new();
        app.add_alert("Bridge", "review", "passed", "");

        let result = app.dismiss_selected_alert();
        assert!(result);
        assert_eq!(app.pending_approvals, 0);
        assert_eq!(app.alerts[0].status, AlertStatus::Dismissed);
    }

    #[test]
    fn test_app_approve_non_pending_returns_false() {
        let mut app = TuiApp::new();
        app.add_alert("Bridge", "review", "passed", "");
        app.approve_selected_alert(); // approve first
        let result = app.approve_selected_alert(); // try again
        assert!(!result);
    }

    #[test]
    fn test_app_multiple_alerts_navigation() {
        let mut app = TuiApp::new();
        app.add_alert("A", "r1", "s1", "");
        app.add_alert("B", "r2", "s2", "");
        app.add_alert("C", "r3", "s3", "");

        assert_eq!(app.pending_approvals, 3);
        assert_eq!(app.selected_alert, 0);

        app.next_alert();
        assert_eq!(app.selected_alert, 1);

        app.next_alert();
        assert_eq!(app.selected_alert, 2);

        app.prev_alert();
        assert_eq!(app.selected_alert, 1);

        app.prev_alert();
        assert_eq!(app.selected_alert, 0);
    }

    #[test]
    fn test_app_advance_after_approve() {
        let mut app = TuiApp::new();
        app.add_alert("A", "r1", "s1", "");
        app.add_alert("B", "r2", "s2", "");
        app.add_alert("C", "r3", "s3", "");

        // Approve current (index 0), should auto-advance to next pending (index 1)
        app.approve_selected_alert();
        assert_eq!(app.selected_alert, 1);
        assert_eq!(app.pending_approvals, 2);
        assert_eq!(app.mode, AppMode::AlertDetail);
    }

    #[test]
    fn test_app_back_to_dashboard_when_no_pending() {
        let mut app = TuiApp::new();
        app.add_alert("A", "r1", "s1", "");
        assert_eq!(app.mode, AppMode::AlertDetail);

        app.approve_selected_alert();
        assert_eq!(app.mode, AppMode::Dashboard);
    }

    #[test]
    fn test_app_key_quit() {
        let mut app = TuiApp::new();
        app.handle_key(Key::Quit);
        assert!(app.should_quit);
    }

    #[test]
    fn test_app_key_goto_dashboard() {
        let mut app = TuiApp::new();
        app.mode = AppMode::AlertDetail;
        app.handle_key(Key::GoToDashboard);
        assert_eq!(app.mode, AppMode::Dashboard);
    }

    #[test]
    fn test_app_key_goto_alerts_no_pending() {
        let mut app = TuiApp::new();
        app.handle_key(Key::GoToAlerts);
        assert_eq!(app.mode, AppMode::Dashboard);
    }

    #[test]
    fn test_app_key_approve() {
        let mut app = TuiApp::new();
        app.add_alert("Bridge", "r", "s", "");
        app.handle_key(Key::Approve);
        assert_eq!(app.pending_approvals, 0);
    }

    #[test]
    fn test_app_key_reject() {
        let mut app = TuiApp::new();
        app.add_alert("Bridge", "r", "s", "");
        app.handle_key(Key::Reject);
        assert_eq!(app.alerts[0].status, AlertStatus::Rejected);
    }

    #[test]
    fn test_app_key_dismiss() {
        let mut app = TuiApp::new();
        app.add_alert("Bridge", "r", "s", "");
        app.handle_key(Key::Dismiss);
        assert_eq!(app.alerts[0].status, AlertStatus::Dismissed);
    }

    #[test]
    fn test_app_status_line() {
        let mut app = TuiApp::new();
        app.add_agent("p1", "Alice", "did:walkie:abc");
        let line = app.status_line();
        assert!(line.contains("Agents: 1 online"));
        assert!(line.contains("Tasks: 0/0"));
    }

    #[test]
    fn test_activity_feed_max_500() {
        let mut app = TuiApp::new();
        for i in 0..600 {
            app.push_activity(ActivityItem::new("Bot", ActivityAction::SystemInfo, &format!("event {}", i)));
        }
        assert_eq!(app.activities.len(), 500);
        // Oldest items are removed
        assert!(app.activities[0].detail.contains("100")); // first kept is event 100
    }

    #[test]
    fn test_demo_data() {
        let mut app = TuiApp::new();
        app.load_demo_data();

        assert_eq!(app.agents.len(), 3);
        assert_eq!(app.online_agent_count(), 3);
        assert!(app.activities.len() > 3);
        assert_eq!(app.pending_approvals, 1);
        assert_eq!(app.alerts.len(), 1);
        assert_eq!(app.tasks_assigned, 2);
        assert_eq!(app.tasks_completed, 1);
    }

    #[test]
    fn test_agent_info_short_did() {
        let info = AgentInfo::new("p1", "Alice", "did:walkie:abcdefghijklmnopqrstuvwx");
        assert_eq!(info.short_did(), "did:walkie:abcdefghijklm");
    }

    #[test]
    fn test_agent_info_short_did_short_input() {
        let info = AgentInfo::new("p1", "Alice", "short");
        assert_eq!(info.short_did(), "short");
    }

    // ═══════════════════════════════════════════════════════════════
    // NEW TESTS — C1 Coverage Expansion
    // ═══════════════════════════════════════════════════════════════

    // ── ActivityAction::from_message — additional paths ──

    #[test]
    fn test_activity_action_from_pending_status() {
        let id = make_test_identity("Hank");
        let msg = AgentMessage::status(&id, "pending", 0, "queued");
        let (action, detail) = ActivityAction::from_message(&msg);
        assert_eq!(action, ActivityAction::TaskAccepted);
        assert!(detail.contains("pending"));
    }

    #[test]
    fn test_activity_action_from_unknown_status() {
        let id = make_test_identity("Ivy");
        let msg = AgentMessage::status(&id, "weird_state", 42, "something");
        let (action, _) = ActivityAction::from_message(&msg);
        // Unknown status falls through to TaskProgress (default arm)
        assert_eq!(action, ActivityAction::TaskProgress);
    }

    #[test]
    fn test_activity_action_from_status_empty_note() {
        let id = make_test_identity("Jack");
        let msg = AgentMessage::status(&id, "in_progress", 75, "");
        let (_, detail) = ActivityAction::from_message(&msg);
        // Empty note should not produce " — " suffix
        assert!(!detail.contains(" — "));
        assert!(detail.contains("75%"));
    }

    #[test]
    fn test_activity_action_from_data_exchange_schema() {
        let id = make_test_identity("Kate");
        let msg = AgentMessage::data(&id, "json", json!({"records": 42}));
        let (action, detail) = ActivityAction::from_message(&msg);
        // No "text" key → goes to schema path, falls back to "data" for schema name
        assert_eq!(action, ActivityAction::DataExchanged);
        assert!(detail.contains("Kate"));
        assert!(detail.contains("ALL"));
    }

    #[test]
    fn test_activity_action_from_task_with_empty_to_agent() {
        let id = make_test_identity("Leo");
        let msg = AgentMessage::task(&id, "deploy", json!({}));
        let (action, detail) = ActivityAction::from_message(&msg);
        assert_eq!(action, ActivityAction::TaskAssigned);
        // to_agent is empty → shows "ALL"
        assert!(detail.contains("ALL"));
    }

    #[test]
    fn test_activity_action_from_task_with_target() {
        let id = make_test_identity("Leo");
        let msg = AgentMessage::task(&id, "deploy", json!({})).to("agent-bob");
        let (action, detail) = ActivityAction::from_message(&msg);
        assert_eq!(action, ActivityAction::TaskAssigned);
        assert!(detail.contains("agent-bob"));
        assert!(!detail.contains("ALL"));
    }

    // ── Comprehensive icon coverage ──

    #[test]
    fn test_all_activity_action_icons() {
        assert_eq!(ActivityAction::AgentOffline.icon(), "⚫");
        assert_eq!(ActivityAction::TaskAccepted.icon(), "📊");
        assert_eq!(ActivityAction::TaskProgress.icon(), "📊");
        assert_eq!(ActivityAction::TaskFailed.icon(), "❌");
        assert_eq!(ActivityAction::TaskBlocked.icon(), "⚠️");
        assert_eq!(ActivityAction::DataExchanged.icon(), "📦");
        assert_eq!(ActivityAction::CapabilityQuery.icon(), "🤝");
        assert_eq!(ActivityAction::Approved.icon(), "✅");
        assert_eq!(ActivityAction::Rejected.icon(), "❌");
        assert_eq!(ActivityAction::Dismissed.icon(), "⬜");
        assert_eq!(ActivityAction::E2EESession.icon(), "🔒");
        assert_eq!(ActivityAction::IdentityVerified.icon(), "🪪");
        assert_eq!(ActivityAction::Connected.icon(), "🔗");
        assert_eq!(ActivityAction::RawMessage.icon(), "📨");
        assert_eq!(ActivityAction::SystemInfo.icon(), "ℹ️");
    }

    // ── Comprehensive tag coverage ──

    #[test]
    fn test_all_activity_action_tags() {
        assert_eq!(ActivityAction::AgentOffline.tag(), "OFFLINE");
        assert_eq!(ActivityAction::TaskAccepted.tag(), "ACCEPTED");
        assert_eq!(ActivityAction::TaskProgress.tag(), "PROGRESS");
        assert_eq!(ActivityAction::TaskFailed.tag(), "FAILED");
        assert_eq!(ActivityAction::TaskBlocked.tag(), "BLOCKED");
        assert_eq!(ActivityAction::DataExchanged.tag(), "DATA");
        assert_eq!(ActivityAction::TextMessage.tag(), "TEXT");
        assert_eq!(ActivityAction::CapabilityQuery.tag(), "INTENT");
        assert_eq!(ActivityAction::AgentOnline.tag(), "ONLINE");
        assert_eq!(ActivityAction::Approved.tag(), "APPROVED");
        assert_eq!(ActivityAction::Rejected.tag(), "REJECTED");
        assert_eq!(ActivityAction::Dismissed.tag(), "DISMISSED");
        assert_eq!(ActivityAction::E2EESession.tag(), "E2EE");
        assert_eq!(ActivityAction::IdentityVerified.tag(), "IDENTITY");
        assert_eq!(ActivityAction::Connected.tag(), "CONNECT");
        assert_eq!(ActivityAction::RawMessage.tag(), "MSG");
        assert_eq!(ActivityAction::SystemInfo.tag(), "INFO");
    }

    // ── AlertStatus equality ──

    #[test]
    fn test_alert_status_variants() {
        assert_eq!(AlertStatus::Pending, AlertStatus::Pending);
        assert_ne!(AlertStatus::Pending, AlertStatus::Approved);
        assert_ne!(AlertStatus::Approved, AlertStatus::Rejected);
        assert_ne!(AlertStatus::Rejected, AlertStatus::Dismissed);
    }

    // ── AgentInfo::new defaults ──

    #[test]
    fn test_agent_info_new_defaults() {
        let info = AgentInfo::new("pk1", "Alice", "did:test:123");
        assert_eq!(info.peer_key, "pk1");
        assert_eq!(info.display_name, "Alice");
        assert_eq!(info.did, "did:test:123");
        assert!(info.online);
        assert!((info.load - 0.0).abs() < f32::EPSILON);
        assert!(info.capabilities.is_empty());
    }

    // ── add_agent idempotent ──

    #[test]
    fn test_add_agent_idempotent() {
        let mut app = TuiApp::new();
        app.add_agent("p1", "Alice", "did:a");
        app.add_agent("p1", "Bob", "did:b"); // same key, should NOT overwrite
        assert_eq!(app.agents.len(), 1);
        assert_eq!(app.agents["p1"].display_name, "Alice"); // kept original
    }

    // ── set_agent_offline non-existent ──

    #[test]
    fn test_set_agent_offline_nonexistent() {
        let mut app = TuiApp::new();
        app.set_agent_offline("ghost");
        assert!(app.activities.is_empty()); // no crash, no activity
    }

    // ── update_agent_from_identity ──

    #[test]
    fn test_update_agent_from_identity_new() {
        let mut app = TuiApp::new();
        let id = make_test_identity("Alice");
        app.update_agent_from_identity("p1", &id);
        assert_eq!(app.agents.len(), 1);
        assert_eq!(app.agents["p1"].display_name, "Alice");
        assert!(app.agents["p1"].online);
        assert_eq!(app.agents["p1"].capabilities, vec!["test"]);
        // Should create an IdentityVerified activity
        assert!(app.activities.iter().any(|a| a.action == ActivityAction::IdentityVerified));
    }

    #[test]
    fn test_update_agent_from_identity_updates_existing() {
        let mut app = TuiApp::new();
        app.add_agent("p1", "OldName", "did:old");

        let id = make_test_identity("NewName");
        app.update_agent_from_identity("p1", &id);

        assert_eq!(app.agents["p1"].display_name, "NewName");
        assert_eq!(app.agents["p1"].did, id.agent_id);
        assert_eq!(app.agents["p1"].capabilities, vec!["test"]);
        assert!(app.agents["p1"].online);
    }

    #[test]
    fn test_update_agent_from_identity_sets_online() {
        let mut app = TuiApp::new();
        app.add_agent("p1", "Alice", "did:a");
        app.set_agent_offline("p1");
        assert!(!app.agents["p1"].online);

        let id = make_test_identity("Alice");
        app.update_agent_from_identity("p1", &id);
        assert!(app.agents["p1"].online);
    }

    // ── process_agent_message — heartbeat load update ──

    #[test]
    fn test_process_heartbeat_updates_load() {
        let mut app = TuiApp::new();
        let id = make_test_identity("Worker");
        // Register agent keyed by agent_id so the load update can find it
        app.agents.entry(id.agent_id.clone())
            .or_insert_with(|| AgentInfo::new(&id.agent_id, &id.display_name, &id.agent_id));

        let msg = AgentMessage::heartbeat(&id, "online", 0.75);
        app.process_agent_message(&msg);

        let agent = &app.agents[&id.agent_id];
        assert!(agent.online);
        assert!((agent.load - 0.75).abs() < 0.01);
    }

    // ── process_agent_message — DataExchange text via process path ──

    #[test]
    fn test_process_data_exchange_text() {
        let mut app = TuiApp::new();
        let id = make_test_identity("Chatter");
        let msg = AgentMessage::text(&id, "hello from process path");
        app.process_agent_message(&msg);

        assert_eq!(app.event_count, 1);
        assert_eq!(app.activities[0].action, ActivityAction::TextMessage);
        assert!(app.activities[0].detail.contains("hello from process path"));
        assert!(!app.activities[0].requires_human);
    }

    // ── process_agent_message — DataExchange schema via process path ──

    #[test]
    fn test_process_data_exchange_schema() {
        let mut app = TuiApp::new();
        let id = make_test_identity("DataBot");
        let msg = AgentMessage::data(&id, "json", json!({"rows": 100}));
        app.process_agent_message(&msg);

        assert_eq!(app.event_count, 1);
        assert_eq!(app.activities[0].action, ActivityAction::DataExchanged);
    }

    // ── process_agent_message — requires_human flag propagation ──

    #[test]
    fn test_process_message_requires_human_flag() {
        let mut app = TuiApp::new();
        let id = make_test_identity("Agent");
        // Create a regular text message then mark requires_human
        let msg = AgentMessage::text(&id, "urgent").requires_human();
        app.process_agent_message(&msg);

        assert!(app.activities[0].requires_human);
    }

    // ── process_agent_message — StatusReport (pending) ──

    #[test]
    fn test_process_pending_status() {
        let mut app = TuiApp::new();
        let id = make_test_identity("Worker");
        let msg = AgentMessage::status(&id, "pending", 0, "waiting to start");
        app.process_agent_message(&msg);

        assert_eq!(app.activities[0].action, ActivityAction::TaskAccepted);
    }

    // ── Key handling — GoToAlerts with pending alerts ──

    #[test]
    fn test_app_key_goto_alerts_with_pending() {
        let mut app = TuiApp::new();
        app.add_alert("A", "r", "s", "");
        // approve it first to go back to dashboard
        app.approve_selected_alert();
        assert_eq!(app.mode, AppMode::Dashboard);

        // Add another alert — stays in AlertDetail since already there
        // but let's go to dashboard first then trigger GoToAlerts
        app.mode = AppMode::Dashboard;
        app.add_alert("B", "r2", "s2", "");
        // add_alert auto-switches to AlertDetail, so test GoToAlerts from dashboard
        app.mode = AppMode::Dashboard;
        app.add_alert("C", "r3", "s3", ""); // auto-switches again

        // Now go to dashboard manually and test GoToAlerts
        app.mode = AppMode::Dashboard;
        app.handle_key(Key::GoToAlerts);
        assert_eq!(app.mode, AppMode::AlertDetail);
    }

    // ── Key handling — Approve/Reject/Dismiss in Dashboard mode (no-op) ──

    #[test]
    fn test_app_key_approve_in_dashboard_noop() {
        let mut app = TuiApp::new();
        app.add_alert("A", "r", "s", "");
        // Manually switch to dashboard (add_alert auto-switches to AlertDetail)
        app.mode = AppMode::Dashboard;
        app.handle_key(Key::Approve);
        // Should still be pending since we were in Dashboard mode
        assert_eq!(app.alerts[0].status, AlertStatus::Pending);
        assert_eq!(app.pending_approvals, 1);
    }

    #[test]
    fn test_app_key_reject_in_dashboard_noop() {
        let mut app = TuiApp::new();
        app.add_alert("A", "r", "s", "");
        app.mode = AppMode::Dashboard;
        app.handle_key(Key::Reject);
        assert_eq!(app.alerts[0].status, AlertStatus::Pending);
    }

    #[test]
    fn test_app_key_dismiss_in_dashboard_noop() {
        let mut app = TuiApp::new();
        app.add_alert("A", "r", "s", "");
        app.mode = AppMode::Dashboard;
        app.handle_key(Key::Dismiss);
        assert_eq!(app.alerts[0].status, AlertStatus::Pending);
    }

    // ── Key handling — Next/Prev in Dashboard mode (no-op) ──

    #[test]
    fn test_app_key_next_in_dashboard_noop() {
        let mut app = TuiApp::new();
        app.add_alert("A", "r", "s", "");
        app.add_alert("B", "r2", "s2", "");
        app.mode = AppMode::Dashboard;
        let before = app.selected_alert;
        app.handle_key(Key::Next);
        assert_eq!(app.selected_alert, before);
    }

    #[test]
    fn test_app_key_prev_in_dashboard_noop() {
        let mut app = TuiApp::new();
        app.add_alert("A", "r", "s", "");
        app.mode = AppMode::Dashboard;
        let before = app.selected_alert;
        app.handle_key(Key::Prev);
        assert_eq!(app.selected_alert, before);
    }

    // ── Key handling — Unknown key ──

    #[test]
    fn test_app_key_unknown_noop() {
        let mut app = TuiApp::new();
        app.handle_key(Key::Unknown);
        assert!(!app.should_quit);
        assert_eq!(app.mode, AppMode::Dashboard);
    }

    // ── next_alert / prev_alert boundary conditions ──

    #[test]
    fn test_next_alert_no_more_pending() {
        let mut app = TuiApp::new();
        app.add_alert("A", "r", "s", "");
        // Only one alert, already selected at 0
        let initial = app.selected_alert;
        app.next_alert();
        // No next pending, selected stays the same
        assert_eq!(app.selected_alert, initial);
    }

    #[test]
    fn test_prev_alert_at_zero() {
        let mut app = TuiApp::new();
        app.add_alert("A", "r", "s", "");
        assert_eq!(app.selected_alert, 0);
        app.prev_alert();
        assert_eq!(app.selected_alert, 0); // stays at 0
    }

    // ── status_line with tasks ──

    #[test]
    fn test_status_line_with_tasks() {
        let mut app = TuiApp::new();
        app.tasks_assigned = 5;
        app.tasks_completed = 3;
        let line = app.status_line();
        assert!(line.contains("Tasks: 3/5"));
        assert!(line.contains("Events: 0"));
        assert!(line.contains("Alerts: 0 pending"));
    }

    // ── ActivityItem timestamp is set ──

    #[test]
    fn test_activity_item_timestamp_set() {
        let before = now_millis();
        let item = ActivityItem::new("Bot", ActivityAction::SystemInfo, "test");
        let after = now_millis();
        assert!(item.timestamp_ms >= before);
        assert!(item.timestamp_ms <= after);
    }

    // ── TuiApp Default trait ──

    #[test]
    fn test_tuiapp_default() {
        let app = TuiApp::default();
        assert_eq!(app.online_agent_count(), 0);
        assert_eq!(app.mode, AppMode::Dashboard);
    }

    // ── Alert fields are stored correctly ──

    #[test]
    fn test_alert_fields() {
        let alert = Alert::new(7, "Bridge", "review", "Need approval", "Context details here");
        assert_eq!(alert.id, 7);
        assert_eq!(alert.from_agent, "Bridge");
        assert_eq!(alert.reason, "review");
        assert_eq!(alert.summary, "Need approval");
        assert_eq!(alert.context, "Context details here");
    }

    // ── advance_to_next_pending: skip non-pending alerts ──

    #[test]
    fn test_advance_skips_non_pending() {
        let mut app = TuiApp::new();
        app.add_alert("A", "r1", "s1", ""); // index 0
        app.add_alert("B", "r2", "s2", ""); // index 1
        app.add_alert("C", "r3", "s3", ""); // index 2

        // Dismiss first, should advance to index 1
        app.dismiss_selected_alert();
        assert_eq!(app.selected_alert, 1);
        assert_eq!(app.alerts[0].status, AlertStatus::Dismissed);
    }

    // ── Multiple alerts: approve last one returns to dashboard ──

    #[test]
    fn test_approve_last_alert_returns_to_dashboard() {
        let mut app = TuiApp::new();
        app.add_alert("A", "r1", "s1", "");
        // Approve the only alert
        app.approve_selected_alert();
        assert_eq!(app.mode, AppMode::Dashboard);
        assert_eq!(app.pending_approvals, 0);
    }

    // ── process_agent_message increments event_count ──

    #[test]
    fn test_process_message_increments_event_count() {
        let mut app = TuiApp::new();
        let id = make_test_identity("Bot");

        let msg1 = AgentMessage::text(&id, "msg1");
        let msg2 = AgentMessage::text(&id, "msg2");
        let msg3 = AgentMessage::heartbeat(&id, "online", 0.1);

        app.process_agent_message(&msg1);
        app.process_agent_message(&msg2);
        app.process_agent_message(&msg3);

        assert_eq!(app.event_count, 3);
        assert_eq!(app.activities.len(), 3);
    }

    // ── AppMode equality ──

    #[test]
    fn test_app_mode_equality() {
        assert_eq!(AppMode::Dashboard, AppMode::Dashboard);
        assert_eq!(AppMode::AlertDetail, AppMode::AlertDetail);
        assert_ne!(AppMode::Dashboard, AppMode::AlertDetail);
    }

    // ── Key equality ──

    #[test]
    fn test_key_equality() {
        assert_eq!(Key::Quit, Key::Quit);
        assert_eq!(Key::Approve, Key::Approve);
        assert_ne!(Key::Approve, Key::Reject);
        assert_eq!(Key::Unknown, Key::Unknown);
    }
}
