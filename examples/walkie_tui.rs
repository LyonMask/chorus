#![allow(dead_code)]
//! 🖥️ walkie_tui.rs — Layer 3 Human Interface (Terminal UI)
//!
//! Minimal viable TUI for observing and controlling AI Agent collaboration.
//!
//! Panels:
//!   Left:  Agent status (online/offline, load, capabilities)
//!   Right: Activity feed (real-time message stream)
//!   Bottom: Alert panel (HumanHandoff with Approve/Reject)
//!
//! Usage:
//!   cargo run --example walkie_tui --features tui

use std::collections::HashMap;
use std::io;
use std::time::{Duration, Instant};

use crossterm::{
    event::{self, Event, KeyCode, KeyEvent},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    execute,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, List, ListItem, ListState, Paragraph, Wrap,
    },
    Frame, Terminal,
};

use chorus_core::identity::IdentityBuilder;
use chorus_core::p2p::{P2PConfig, P2PEvent, P2PNetwork};
use chorus_core::protocol::{AgentMessage, MessageProtocol};

// ─── Data Types ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct AgentInfo {
    display_name: String,
    did: String,
    online: bool,
    load: f32,
    #[allow(dead_code)]
    capabilities: Vec<String>,
    last_seen: Instant,
    #[allow(dead_code)] tasks_active: u32,
}

#[derive(Debug, Clone)]
struct ActivityItem {
    timestamp: String,
    actor: String,
    action: String,
    detail: String,
    is_urgent: bool,
    requires_human: bool,
    raw_json: String,
}

#[derive(Debug, Clone)]
struct Alert {
    id: usize,
    from_agent: String,
    reason: String,
    summary: String,
    context: String,
    timestamp: String,
    status: AlertStatus,
    original_message: String,
}

#[derive(Debug, Clone, PartialEq)]
enum AlertStatus {
    Pending,
    Approved,
    Rejected,
    Dismissed,
}

#[derive(Debug, Clone, PartialEq)]
enum AppMode {
    Dashboard,
    AlertDetail,
}

// ─── App State ──────────────────────────────────────────────────

struct App {
    agents: HashMap<String, AgentInfo>,
    activities: Vec<ActivityItem>,
    alerts: Vec<Alert>,
    alert_list_state: ListState,
    mode: AppMode,
    activity_scroll: u16,
    should_quit: bool,
    my_name: String,
    pending_approvals: usize,
    tasks_assigned: u32,
    tasks_completed: u32,
    event_count: u64,
    // Demo mode: auto-generate activity if no P2P peers
    demo_mode: bool,
    demo_tick: u64,
}

impl App {
    fn new(name: &str) -> Self {
        let mut alert_list_state = ListState::default();
        alert_list_state.select(Some(0));

        Self {
            agents: HashMap::new(),
            activities: Vec::new(),
            alerts: Vec::new(),
            alert_list_state,
            mode: AppMode::Dashboard,
            activity_scroll: 0,
            should_quit: false,
            my_name: name.to_string(),
            pending_approvals: 0,
            tasks_assigned: 0,
            tasks_completed: 0,
            event_count: 0,
            demo_mode: true,
            demo_tick: 0,
        }
    }

    fn add_agent(&mut self, peer_id: &str, name: &str, did: &str, caps: Vec<String>) {
        self.agents.entry(peer_id.to_string()).or_insert(AgentInfo {
            display_name: name.to_string(),
            did: did.to_string(),
            online: true,
            load: 0.0,
            capabilities: caps,
            last_seen: Instant::now(),
            tasks_active: 0,
        });
    }

    fn set_agent_offline(&mut self, peer_id: &str) {
        let name = self.agents.get(peer_id).map(|a| a.display_name.clone());
        if let Some(agent) = self.agents.get_mut(peer_id) {
            agent.online = false;
        }
        if let Some(name) = name {
            self.add_activity(ActivityItem {
                timestamp: now_str(),
                actor: name.clone(),
                action: "OFFLINE".to_string(),
                detail: format!("{} went offline", name),
                is_urgent: false,
                requires_human: false,
                raw_json: String::new(),
            });
        }
    }

    fn add_activity(&mut self, item: ActivityItem) {
        self.event_count += 1;
        self.activities.push(item);
        // Keep last 200 activities
        if self.activities.len() > 200 {
            self.activities.remove(0);
        }
        // Auto-scroll to bottom
        self.activity_scroll = self.activities.len().saturating_sub(1) as u16;
    }

    fn add_alert(&mut self, from: &str, reason: &str, summary: &str, context: &str, raw: &str) {
        let id = self.alerts.len();
        self.alerts.push(Alert {
            id,
            from_agent: from.to_string(),
            reason: reason.to_string(),
            summary: summary.to_string(),
            context: context.to_string(),
            timestamp: now_str(),
            status: AlertStatus::Pending,
            original_message: raw.to_string(),
        });
        self.pending_approvals += 1;
        // Auto-switch to alert detail
        if self.mode == AppMode::Dashboard {
            self.mode = AppMode::AlertDetail;
        }
    }

    fn handle_p2p_event(&mut self, event: P2PEvent) {
        match event {
            P2PEvent::PeerConnected { peer_id } => {
                self.add_agent(
                    &peer_id.to_string(),
                    &format!("Agent-{}", &peer_id.to_string()[..8]),
                    &format!("did:walkie:{}", &peer_id.to_string()[..12]),
                    vec![],
                );
                self.add_activity(ActivityItem {
                    timestamp: now_str(),
                    actor: format!("Agent-{}", &peer_id.to_string()[..8]),
                    action: "CONNECTED".to_string(),
                    detail: format!("Peer {} connected", &peer_id.to_string()[..16]),
                    is_urgent: false,
                    requires_human: false,
                    raw_json: String::new(),
                });
            }
            P2PEvent::PeerDisconnected { peer_id } => {
                self.set_agent_offline(&peer_id.to_string());
            }
            P2PEvent::StructuredMessage { from: _, message } => {
                self.process_agent_message(&message);
            }
            P2PEvent::EncryptedMessage { from, plaintext } => {
                if let Ok(msg) = AgentMessage::from_json_bytes(&plaintext) {
                    self.process_agent_message(&msg);
                } else {
                    // Raw encrypted message, log it
                    self.add_activity(ActivityItem {
                        timestamp: now_str(),
                        actor: format!("Peer-{}", &from.to_string()[..8]),
                        action: "ENCRYPTED_MSG".to_string(),
                        detail: format!("Encrypted message from {}", &from.to_string()[..16]),
                        is_urgent: false,
                        requires_human: false,
                        raw_json: String::new(),
                    });
                }
            }
            P2PEvent::RawMessage { from, data } => {
                if let Ok(msg) = AgentMessage::from_json_bytes(&data) {
                    self.process_agent_message(&msg);
                } else {
                    self.add_activity(ActivityItem {
                        timestamp: now_str(),
                        actor: format!("Peer-{}", &from.to_string()[..8]),
                        action: "RAW_MSG".to_string(),
                        detail: format!("Raw message from {}", &from.to_string()[..16]),
                        is_urgent: false,
                        requires_human: false,
                        raw_json: String::new(),
                    });
                }
            }
            P2PEvent::AgentIdentified { peer_id, identity } => {
                // Update agent info with verified identity
                let key = peer_id.to_string();
                if let Some(agent) = self.agents.get_mut(&key) {
                    agent.display_name = identity.display_name.clone();
                    agent.did = identity.agent_id.clone();
                    agent.capabilities = identity.capabilities.clone();
                } else {
                    self.add_agent(
                        &key,
                        &identity.display_name,
                        &identity.agent_id,
                        identity.capabilities,
                    );
                }
                self.add_activity(ActivityItem {
                    timestamp: now_str(),
                    actor: identity.display_name.clone(),
                    action: "IDENTITY_VERIFIED".to_string(),
                    detail: format!("✅ {} identity verified", identity.display_name),
                    is_urgent: false,
                    requires_human: false,
                    raw_json: String::new(),
                });
            }
            P2PEvent::SessionEstablished { peer_id } => {
                self.add_activity(ActivityItem {
                    timestamp: now_str(),
                    actor: format!("Peer-{}", &peer_id.to_string()[..8]),
                    action: "E2EE_SESSION".to_string(),
                    detail: format!("🔒 Encrypted session with {}", &peer_id.to_string()[..16]),
                    is_urgent: false,
                    requires_human: false,
                    raw_json: String::new(),
                });
            }
            P2PEvent::Listening { address } => {
                self.add_activity(ActivityItem {
                    timestamp: now_str(),
                    actor: self.my_name.clone(),
                    action: "LISTENING".to_string(),
                    detail: format!("📡 Listening on {}", address),
                    is_urgent: false,
                    requires_human: false,
                    raw_json: String::new(),
                });
            }
            _ => {
                // Ignore other events for TUI (ping, identify, etc.)
            }
        }
    }

    fn process_agent_message(&mut self, msg: &AgentMessage) {
        let actor = msg.from_agent.display_name.clone();
        let protocol = msg.protocol.clone();
        let is_urgent = msg.requires_human || protocol == MessageProtocol::HumanHandoff;

        let (action, detail) = match protocol {
            MessageProtocol::Heartbeat => {
                let status = msg.payload_str("status").unwrap_or("?");
                let load = msg.payload_str("load").unwrap_or("?");
                // Update agent load
                let did = &msg.from_agent.agent_id;
                if let Some(agent) = self.agents.get_mut(did) {
                    agent.load = load.parse().unwrap_or(0.0);
                    agent.last_seen = Instant::now();
                    agent.online = true;
                }
                ("HEARTBEAT".to_string(), format!("{} is {}", actor, status))
            }
            MessageProtocol::TaskAssignment => {
                self.tasks_assigned += 1;
                let task = msg.payload_str("task").unwrap_or("unknown task");
                let target = if msg.to_agent.is_empty() {
                    "ALL".to_string()
                } else {
                    msg.to_agent.clone()
                };
                ("TASK_ASSIGNED".to_string(),
                    format!("{} assigned \"{}\" to {}", actor, task, target))
            }
            MessageProtocol::StatusReport => {
                let status = msg.payload_str("status").unwrap_or("?");
                let pct = msg.payload_i64("percent").unwrap_or(0);
                let note = msg.payload_str("note").unwrap_or("");
                if status == "completed" {
                    self.tasks_completed += 1;
                }
                let note_part = if note.is_empty() { String::new() } else { format!(" — {}", note) };
                ("STATUS".to_string(),
                    format!("{} [{}]: {}%{}", actor, status, pct, note_part))
            }
            MessageProtocol::DataExchange => {
                let text = msg.payload_str("text");
                if let Some(t) = text {
                    ("TEXT".to_string(), format!("{}: \"{}\"", actor, t))
                } else {
                    let schema = msg.payload_str("schema").unwrap_or("data");
                    ("DATA".to_string(), format!("{} sent {} to {}", actor, schema,
                        if msg.to_agent.is_empty() { "ALL".to_string() } else { msg.to_agent.clone() }))
                }
            }
            MessageProtocol::IntentNegotiation => {
                let action_name = msg.payload_str("action").unwrap_or("?");
                ("INTENT".to_string(), format!("{} asked: can you {}?", actor, action_name))
            }
            MessageProtocol::HumanHandoff => {
                let reason = msg.payload_str("reason").unwrap_or("?");
                let summary = msg.payload_str("summary").unwrap_or("");
                let context = msg.payload_object()
                    .and_then(|o| o.get("context").cloned())
                    .map(|v| v.to_string())
                    .unwrap_or_default();
                // Create alert
                self.add_alert(
                    &actor,
                    reason,
                    summary,
                    context.as_str(),
                    &msg.summary(),
                );
                ("HUMAN_ESCALATION".to_string(),
                    format!("🚨 {} needs human: {}", actor, summary))
            }
        };

        self.add_activity(ActivityItem {
            timestamp: now_str(),
            actor,
            action,
            detail,
            is_urgent,
            requires_human: msg.requires_human,
            raw_json: msg.summary(),
        });
    }

    fn approve_alert(&mut self) {
        if let Some(idx) = self.alert_list_state.selected() {
            let from = self.alerts.get(idx).map(|a| a.from_agent.clone());
            if let Some(alert) = self.alerts.get_mut(idx) {
                if alert.status == AlertStatus::Pending {
                    alert.status = AlertStatus::Approved;
                    self.pending_approvals = self.pending_approvals.saturating_sub(1);
                    if let Some(from) = from {
                        self.add_activity(ActivityItem {
                            timestamp: now_str(),
                            actor: self.my_name.clone(),
                            action: "APPROVED".to_string(),
                            detail: format!("✅ Approved alert from {}", from),
                            is_urgent: false,
                            requires_human: false,
                            raw_json: String::new(),
                        });
                    }
                    // Move to next pending alert
                    self.next_alert();
                }
            }
        }
    }

    fn reject_alert(&mut self) {
        if let Some(idx) = self.alert_list_state.selected() {
            let from = self.alerts.get(idx).map(|a| a.from_agent.clone());
            if let Some(alert) = self.alerts.get_mut(idx) {
                if alert.status == AlertStatus::Pending {
                    alert.status = AlertStatus::Rejected;
                    self.pending_approvals = self.pending_approvals.saturating_sub(1);
                    if let Some(from) = from {
                        self.add_activity(ActivityItem {
                            timestamp: now_str(),
                            actor: self.my_name.clone(),
                            action: "REJECTED".to_string(),
                            detail: format!("❌ Rejected alert from {}", from),
                            is_urgent: false,
                            requires_human: false,
                            raw_json: String::new(),
                        });
                    }
                    self.next_alert();
                }
            }
        }
    }

    fn dismiss_alert(&mut self) {
        if let Some(idx) = self.alert_list_state.selected() {
            if let Some(alert) = self.alerts.get_mut(idx) {
                if alert.status == AlertStatus::Pending {
                    alert.status = AlertStatus::Dismissed;
                    self.pending_approvals = self.pending_approvals.saturating_sub(1);
                    self.next_alert();
                }
            }
        }
    }

    fn next_alert(&mut self) {
        let current = self.alert_list_state.selected().unwrap_or(0);
        for i in (current + 1)..self.alerts.len() {
            if self.alerts[i].status == AlertStatus::Pending {
                self.alert_list_state.select(Some(i));
                return;
            }
        }
        // No more pending, back to dashboard
        if self.pending_approvals == 0 {
            self.mode = AppMode::Dashboard;
        }
    }

    fn prev_alert(&mut self) {
        let current = self.alert_list_state.selected().unwrap_or(0);
        if current > 0 {
            for i in (0..current).rev() {
                if self.alerts[i].status == AlertStatus::Pending {
                    self.alert_list_state.select(Some(i));
                    return;
                }
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => {
                self.should_quit = true;
            }
            KeyCode::Char('a') => {
                if self.pending_approvals > 0 {
                    self.mode = AppMode::AlertDetail;
                }
            }
            KeyCode::Char('d') | KeyCode::Esc => {
                self.mode = AppMode::Dashboard;
            }
            KeyCode::Char('y') if self.mode == AppMode::AlertDetail => {
                self.approve_alert();
            }
            KeyCode::Char('n') if self.mode == AppMode::AlertDetail => {
                self.reject_alert();
            }
            KeyCode::Char('x') if self.mode == AppMode::AlertDetail => {
                self.dismiss_alert();
            }
            KeyCode::Down if self.mode == AppMode::AlertDetail => {
                self.next_alert();
            }
            KeyCode::Up if self.mode == AppMode::AlertDetail => {
                self.prev_alert();
            }
            _ => {}
        }
    }

    // ─── Demo Data Generation ───────────────────────────────────

    fn generate_demo_tick(&mut self) {
        self.demo_tick += 1;

        // Simulate 3 agents connecting
        if self.demo_tick == 1 {
            self.demo_mode = true;
            self.add_agent("alice", "Alice", "did:walkie:maMVNJDswURGw",
                vec!["coordinate".into(), "strategy".into()]);
            self.add_agent("rustacean", "Rustacean", "did:walkie:fLYf2Xc0I3qyO",
                vec!["code-review".into(), "crypto".into(), "p2p".into()]);
            self.add_agent("bridge", "Bridge", "did:walkie:fmYIb9jntMvbj",
                vec!["product".into(), "review".into(), "human-handoff".into()]);
            self.add_activity(ActivityItem {
                timestamp: now_str(), actor: "System".into(),
                action: "INFO".into(),
                detail: "🤖 Demo mode: 3 agents loaded. Press 'a' to view alerts.".into(),
                is_urgent: false, requires_human: false, raw_json: String::new(),
            });
        }

        // Alice assigns task at tick 2
        if self.demo_tick == 2 {
            self.add_activity(ActivityItem {
                timestamp: now_str(), actor: "Alice".into(),
                action: "TASK_ASSIGNED".into(),
                detail: "Alice assigned \"code-review\" to Rustacean".into(),
                is_urgent: false, requires_human: false, raw_json: String::new(),
            });
            self.tasks_assigned += 1;
        }

        // Rustacean progress at tick 3
        if self.demo_tick == 3 {
            if let Some(a) = self.agents.get_mut("rustacean") { a.load = 0.5; }
            self.add_activity(ActivityItem {
                timestamp: now_str(), actor: "Rustacean".into(),
                action: "STATUS".into(),
                detail: "Rustacean [in_progress]: 50% — Checking encryption layer...".into(),
                is_urgent: false, requires_human: false, raw_json: String::new(),
            });
        }

        // Rustacean completes at tick 4
        if self.demo_tick == 4 {
            self.tasks_completed += 1;
            if let Some(a) = self.agents.get_mut("rustacean") { a.load = 0.0; }
            self.add_activity(ActivityItem {
                timestamp: now_str(), actor: "Rustacean".into(),
                action: "STATUS".into(),
                detail: "Rustacean [completed]: 100% — Code review done, 2 findings".into(),
                is_urgent: false, requires_human: false, raw_json: String::new(),
            });
        }

        // Bridge escalates at tick 5
        if self.demo_tick == 5 {
            self.add_alert(
                "Bridge",
                "review_complete",
                "Code review passed. 2 findings need human review.",
                "Reviewer: Rustacean\nVerdict: PASS\nFindings: 2 (1 info, 1 warning)",
                "",
            );
        }

        // Alice forwards at tick 6
        if self.demo_tick == 6 {
            self.tasks_assigned += 1;
            self.add_activity(ActivityItem {
                timestamp: now_str(), actor: "Alice".into(),
                action: "TASK_ASSIGNED".into(),
                detail: "Alice assigned \"human-review\" to Bridge".into(),
                is_urgent: false, requires_human: false, raw_json: String::new(),
            });
        }
    }
}

// ─── UI Rendering ──────────────────────────────────────────────

fn draw(f: &mut Frame, app: &App) {
    let size = f.area();

    // Outer layout: status bar (top) + main content (bottom)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Status bar
            Constraint::Min(5),    // Main content
            Constraint::Length(1), // Help bar
        ])
        .split(size);

    draw_status_bar(f, app, chunks[0]);

    match app.mode {
        AppMode::Dashboard => draw_dashboard(f, app, chunks[1]),
        AppMode::AlertDetail => draw_alert_detail(f, app, chunks[1]),
    }

    draw_help_bar(f, app, chunks[2]);
}

fn draw_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let title = format!(" 🏠 Walkie Talkie — {} ", app.my_name);
    let alerts = if app.pending_approvals > 0 {
        format!(" 🔔 {} pending ", app.pending_approvals)
    } else {
        " 🔔 0 ".to_string()
    };
    let agents_online = app.agents.values().filter(|a| a.online).count();
    let stats = format!(
        " Agents: {} online | Tasks: {}/{} | Events: {} ",
        agents_online, app.tasks_completed, app.tasks_assigned, app.event_count
    );

    let line = Line::from(vec![
        Span::styled(title, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(stats, Style::default().fg(Color::DarkGray)),
        Span::styled(alerts, if app.pending_approvals > 0 {
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        }),
    ]);

    let bar = Paragraph::new(line)
        .style(Style::default().bg(Color::DarkGray).fg(Color::White))
        .alignment(Alignment::Left);

    f.render_widget(bar, area);
}

fn draw_dashboard(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(28), // Agent panel
            Constraint::Min(20),   // Activity feed
        ])
        .split(area);

    draw_agent_panel(f, app, chunks[0]);
    draw_activity_feed(f, app, chunks[1]);
}

fn draw_agent_panel(f: &mut Frame, app: &App, area: Rect) {
    let title = format!(" Agents ({}) ", app.agents.len());

    let mut items: Vec<ListItem> = app.agents.values().map(|agent| {
        let status_icon = if agent.online { "🟢" } else { "⚫" };
        let load_bar = format!("{:.0}%", agent.load * 100.0);

        let line = Line::from(vec![
            Span::styled(format!(" {} ", status_icon),
                Style::default().fg(if agent.online { Color::Green } else { Color::DarkGray })),
            Span::styled(&agent.display_name,
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::styled(format!(" {}", load_bar),
                Style::default().fg(Color::Yellow)),
        ]);

        let detail = Line::from(Span::styled(
            format!("    {} · {}", agent.capabilities.join(", "), agent.did),
            Style::default().fg(Color::DarkGray),
        ));

        ListItem::new(vec![line, detail])
    }).collect();

    if items.is_empty() {
        items.push(ListItem::new(Line::from(
            Span::styled("  No agents connected", Style::default().fg(Color::DarkGray)),
        )));
    }

    let list = List::new(items)
        .block(Block::default()
            .title(title)
            .borders(Borders::ALL)
            .style(Style::default().bg(Color::Black)));

    f.render_widget(list, area);
}

fn draw_activity_feed(f: &mut Frame, app: &App, area: Rect) {
    let title = format!(" Activity Feed ({}) ", app.activities.len());

    let items: Vec<ListItem> = app.activities.iter().rev().map(|item| {
        let (icon_color, icon) = match item.action.as_str() {
            "HUMAN_ESCALATION" => (Color::Red, "🚨"),
            "TASK_ASSIGNED" => (Color::Yellow, "📋"),
            "STATUS" => (Color::Blue, "📊"),
            "TEXT" => (Color::White, "💬"),
            "DATA" => (Color::Green, "📦"),
            "HEARTBEAT" => (Color::DarkGray, "💚"),
            "APPROVED" => (Color::Green, "✅"),
            "REJECTED" => (Color::Red, "❌"),
            "IDENTITY_VERIFIED" => (Color::Cyan, "🪪"),
            "E2EE_SESSION" => (Color::Magenta, "🔒"),
            "CONNECTED" => (Color::Green, "🔗"),
            "OFFLINE" => (Color::DarkGray, "❌"),
            "INTENT" => (Color::Blue, "🤝"),
            _ => (Color::White, "  "),
        };

        let lines = vec![
            Line::from(vec![
                Span::styled(format!(" {} ", icon), Style::default().fg(icon_color)),
                Span::styled(&item.timestamp, Style::default().fg(Color::DarkGray)),
                Span::styled(format!(" {} ", &item.actor),
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(Span::styled(
                format!("   {}", &item.detail),
                if item.requires_human {
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                } else if item.is_urgent {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::Gray)
                },
            )),
        ];

        ListItem::new(lines)
    }).collect();

    if items.is_empty() {
        let placeholder = ListItem::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  Waiting for agent activity...",
                Style::default().fg(Color::DarkGray),
            )),
        ]);
        f.render_widget(
            List::new(vec![placeholder])
                .block(Block::default().title(title.clone()).borders(Borders::ALL)),
            area,
        );
        return;
    }

    let list = List::new(items)
        .block(Block::default()
            .title(title)
            .borders(Borders::ALL)
            .style(Style::default().bg(Color::Black)));

    f.render_widget(list, area);
}

fn draw_alert_detail(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(28), // Alert list
            Constraint::Min(30),   // Alert detail
        ])
        .split(area);

    draw_alert_list(f, app, chunks[0]);
    draw_alert_view(f, app, chunks[1]);
}

fn draw_alert_list(f: &mut Frame, app: &App, area: Rect) {
    let pending = app.alerts.iter().filter(|a| a.status == AlertStatus::Pending).count();
    let title = format!(" Alerts ({} pending) ", pending);

    let items: Vec<ListItem> = app.alerts.iter().map(|alert| {
        let (icon, style) = match alert.status {
            AlertStatus::Pending => ("🚨", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            AlertStatus::Approved => ("✅", Style::default().fg(Color::Green)),
            AlertStatus::Rejected => ("❌", Style::default().fg(Color::Red)),
            AlertStatus::Dismissed => ("⬜", Style::default().fg(Color::DarkGray)),
        };

        let lines = vec![
            Line::from(vec![
                Span::styled(format!(" {} ", icon), style),
                Span::styled(&alert.from_agent,
                    Style::default().fg(Color::Cyan)),
            ]),
            Line::from(Span::styled(
                format!("   {}", &alert.summary),
                Style::default().fg(Color::Gray),
            )),
        ];

        ListItem::new(lines)
    }).collect();

    let list = List::new(items)
        .block(Block::default().title(title).borders(Borders::ALL))
        .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD));

    f.render_stateful_widget(list, area, &mut app.alert_list_state.clone());
}

fn draw_alert_view(f: &mut Frame, app: &App, area: Rect) {
    let selected = app.alert_list_state.selected().unwrap_or(0);

    if selected >= app.alerts.len() {
        let placeholder = Paragraph::new("  No alert selected")
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().title(" Alert Detail ").borders(Borders::ALL));
        f.render_widget(placeholder, area);
        return;
    }

    let alert = &app.alerts[selected];
    let is_pending = alert.status == AlertStatus::Pending;

    let status_str = match alert.status {
        AlertStatus::Pending => "⏳ PENDING",
        AlertStatus::Approved => "✅ APPROVED",
        AlertStatus::Rejected => "❌ REJECTED",
        AlertStatus::Dismissed => "⬜ DISMISSED",
    };

    let status_color = match alert.status {
        AlertStatus::Pending => Color::Yellow,
        AlertStatus::Approved => Color::Green,
        AlertStatus::Rejected => Color::Red,
        AlertStatus::Dismissed => Color::DarkGray,
    };

    // Split area: detail (top) + actions (bottom)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(area);

    // Detail panel
    let detail_text = vec![
        Line::from(vec![
            Span::styled("  From: ", Style::default().fg(Color::DarkGray)),
            Span::styled(&alert.from_agent,
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled(format!("  │  {}", status_str),
                Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  Reason: ", Style::default().fg(Color::DarkGray)),
            Span::styled(&alert.reason, Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::styled("  Summary: ", Style::default().fg(Color::DarkGray)),
            Span::styled(&alert.summary, Style::default().fg(Color::White)),
        ]),
        Line::from(""),
        Line::from(Span::styled("  Context:", Style::default().fg(Color::DarkGray))),
        Line::from(Span::styled(
            format!("  {}", alert.context.replace('\n', "\n  ")),
            Style::default().fg(Color::Gray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Time: ", Style::default().fg(Color::DarkGray)),
            Span::styled(&alert.timestamp, Style::default().fg(Color::DarkGray)),
        ]),
    ];

    let detail = Paragraph::new(detail_text)
        .block(Block::default()
            .title(format!(" Alert #{} ", alert.id))
            .borders(Borders::ALL))
        .wrap(Wrap { trim: true });

    f.render_widget(detail, chunks[0]);

    // Action panel
    let action_style = if is_pending {
        Style::default().fg(Color::White)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let actions = Paragraph::new(Line::from(vec![
        Span::styled("  Actions: ", Style::default().fg(Color::DarkGray)),
        Span::styled(" [Y] Approve ", action_style),
        Span::styled(" [N] Reject ", action_style),
        Span::styled(" [X] Dismiss ", action_style),
        Span::styled(" [↑↓] Navigate ", Style::default().fg(Color::DarkGray)),
    ]))
    .block(Block::default().title(" Human Intervention ").borders(Borders::ALL))
    .style(Style::default().bg(if is_pending { Color::DarkGray } else { Color::Black }));

    f.render_widget(actions, chunks[1]);
}

fn draw_help_bar(f: &mut Frame, app: &App, area: Rect) {
    let help = match app.mode {
        AppMode::Dashboard => " [D] Dashboard  [A] Alerts  [Q] Quit ",
        AppMode::AlertDetail => " [Y] Approve  [N] Reject  [X] Dismiss  [↑↓] Navigate  [D] Back  [Q] Quit ",
    };

    let bar = Paragraph::new(Line::from(Span::styled(
        help,
        Style::default().fg(Color::Gray),
    )))
    .style(Style::default().bg(Color::Black))
    .alignment(Alignment::Left);

    f.render_widget(bar, area);
}

// ─── Utilities ──────────────────────────────────────────────────

fn now_str() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let secs = (now % 86400) as u32;
    format!("{:02}:{:02}:{:02}", secs / 3600, (secs % 3600) / 60, secs % 60)
}

// ─── Main ──────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create our agent identity
    let (my_identity, _signing_key) = IdentityBuilder::new("Human")
        .capabilities(&["observe", "approve", "control"])
        .build()?;

    // Setup P2P network
    let config = P2PConfig {
        agent_identity: Some(my_identity),
        auto_key_exchange: true,
        ..Default::default()
    };

    let (network, mut p2p_rx) = P2PNetwork::new(config)?;
    network.listen("/ip4/0.0.0.0/tcp/0").await?;

    // App state
    let mut app = App::new("Human");

    // Event loop
    let mut demo_interval = tokio::time::interval(Duration::from_secs(2));
    demo_interval.tick().await; // consume first tick

    let result = loop {
        // Render
        terminal.draw(|f| draw(f, &app))?;

        if app.should_quit {
            break Ok(());
        }

        tokio::select! {
            // P2P events
            event = p2p_rx.recv() => {
                if let Some(event) = event {
                    app.handle_p2p_event(event);
                }
            }

            // Demo ticks (simulate agent activity)
            _ = demo_interval.tick() => {
                if app.demo_mode && app.demo_tick < 8 {
                    app.generate_demo_tick();
                }
            }

            // Terminal events (poll with timeout)
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if event::poll(Duration::from_millis(0))? {
                    if let Ok(Event::Key(key)) = event::read() {
                        app.handle_key(key);
                    }
                }
            }
        }
    };

    // Restore terminal
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    // Shutdown P2P
    network.shutdown()?;

    result
}
