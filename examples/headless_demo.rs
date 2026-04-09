//! 🖨️ headless_demo.rs — TUI Demo (ASCII Capture)
//!
//! Uses TuiApp's real API to simulate a 3-Agent collaboration scenario.
//! No TTY required. Outputs structured ASCII representation.
//!
//! Run: cargo run --example headless_demo

use walkie_talkie_core::tui::{TuiApp, ActivityItem, ActivityAction, Key};

fn main() {
    let mut app = TuiApp::new();

    // ── Step 1-3: Agents come online ──
    app.add_agent("steve", "Steve Jobs 🍎", "did:walkie:maMVNJDswURGw");
    if let Some(a) = app.agents.get_mut("steve") {
        a.capabilities = vec!["coordinate".into(), "strategy".into(), "approve".into()];
    }
    app.add_agent("rustacean", "Rustacean 🦀", "did:walkie:fLYf2Xc0I3qyO");
    if let Some(a) = app.agents.get_mut("rustacean") {
        a.capabilities = vec!["code-review".into(), "crypto".into(), "p2p".into()];
    }
    app.add_agent("bridge", "Bridge 🌉", "did:walkie:fmYIb9jntMvbj");
    if let Some(a) = app.agents.get_mut("bridge") {
        a.capabilities = vec!["product".into(), "review".into(), "human-handoff".into()];
    }

    app.push_activity(ActivityItem::new("System", ActivityAction::SystemInfo,
        "📡 Walkie Talkie v4 started — 3 agents registered"));
    app.push_activity(ActivityItem::new("Steve Jobs 🍎", ActivityAction::AgentOnline,
        "Steve Jobs 🍎 is online"));
    app.push_activity(ActivityItem::new("Rustacean 🦀", ActivityAction::AgentOnline,
        "Rustacean 🦀 is online"));
    app.push_activity(ActivityItem::new("Bridge 🌉", ActivityAction::AgentOnline,
        "Bridge 🌉 is online"));

    // ── Step 4: Steve assigns security audit ──
    app.push_activity(ActivityItem::new("Steve Jobs 🍎", ActivityAction::TaskAssigned,
        "Steve assigned \"security-audit\" to Rustacean"));
    app.tasks_assigned += 1;

    // ── Steps 5-8: Rustacean works ──
    app.push_activity(ActivityItem::new("Rustacean 🦀", ActivityAction::TaskAccepted,
        "Rustacean accepted \"security-audit\" — starting analysis"));
    app.push_activity(ActivityItem::new("Rustacean 🦀", ActivityAction::TaskProgress,
        "Rustacean [in_progress]: 25% — Scanning crypto module..."));
    if let Some(a) = app.agents.get_mut("rustacean") { a.load = 0.65; }
    app.push_activity(ActivityItem::new("Rustacean 🦀", ActivityAction::TaskProgress,
        "Rustacean [in_progress]: 50% — ⚠️ Nonce reuse vulnerability found"));
    app.push_activity(ActivityItem::new("Rustacean 🦀", ActivityAction::TaskProgress,
        "Rustacean [in_progress]: 75% — Reviewing key exchange protocol"));

    // ── Step 9: Rustacean completes ──
    app.push_activity(ActivityItem::new("Rustacean 🦀", ActivityAction::TaskCompleted,
        "Rustacean [completed]: 100% — Audit done: 3 findings (1 HIGH, 2 INFO)"));
    app.tasks_completed += 1;
    if let Some(a) = app.agents.get_mut("rustacean") { a.load = 0.0; }

    // ── Step 10: Bridge escalates to human ──
    app.push_activity(ActivityItem::new("Bridge 🌉", ActivityAction::HumanEscalation,
        "🚨 Bridge needs human: Security audit passed but 1 HIGH finding requires approval"));
    app.add_alert(
        "Bridge 🌉",
        "security_review_requires_approval",
        "Rustacean's audit found 1 HIGH risk: nonce reuse in crypto/mod.rs:49. Patch recommended before deploy.",
        "Findings: 3 total\n  HIGH: Nonce reuse (crypto/mod.rs:49)\n  INFO: Consider HKDF for key derivation\n  INFO: Counter overflow at u64::MAX\nRecommendation: PATCH before deploy",
    );

    // ── Render: Dashboard View ──
    let w = 80;
    let line = "─".repeat(w - 2);
    let space = " ".repeat(w - 2);

    println!();
    println!("╔{}╗", line);
    println!("║  📡 Walkie Talkie v4 — AI Agent IM Platform                             ║");
    println!("║  Phase 3: Human Interface Demo                                           ║");
    println!("╚{}╝", line);
    println!();

    // Status bar
    println!("┌{}┐", line);
    println!("│ 🏠 Walkie Talkie  │  源星公司  │  {}  │  {}  │",
        format!("{} agents ({} online)", app.agents.len(), app.online_agent_count()),
        if app.pending_approvals > 0 { format!("🔔 {} pending", app.pending_approvals) } else { "🔔 0".into() }
    );
    println!("├{}┤", line);
    println!("│{}│", space);

    // Agent panel + Activity feed
    println!("│  ┌─ AGENTS ({}) ────────────────┐  ┌─ ACTIVITY FEED ({}) ─────────────┐│",
        app.agents.len(), app.activities.len());
    println!("│  │                              │  │                                    ││");

    // Render agents
    let agents: Vec<_> = app.agents.values().collect();
    let agent_lines: Vec<String> = agents.iter().map(|a| {
        let status = if a.online { "🟢" } else { "⚫" };
        let load = format!("{:.0}%", a.load * 100.0);
        format!("  {} {:<16} Load: {:>4}", status, a.display_name, load)
    }).collect();

    // Render activities (last 6)
    let visible_activities: Vec<_> = app.activities.iter().rev().take(6).collect();
    let act_lines: Vec<String> = visible_activities.iter().map(|item| {
        let icon = item.action.icon();
        // Truncate detail to fit
        let detail = if item.detail.chars().count() > 38 {
            format!("{}...", item.detail.chars().take(35).collect::<String>())
        } else {
            item.detail.clone()
        };
        format!("  {} {:<40}", icon, detail)
    }).collect();

    let max_lines = std::cmp::max(agent_lines.len(), act_lines.len()).min(8);
    for i in 0..max_lines {
        let left = agent_lines.get(i).map(|s| s.as_str()).unwrap_or("                                 ");
        let right = act_lines.get(i).map(|s| s.as_str()).unwrap_or("                                       ");
        println!("│  │{}│  │{}││", format!("{:<30}", left), format!("{:<40}", right));
    }

    println!("│  │                              │  │                                    ││");
    println!("│  └──────────────────────────────┘  └────────────────────────────────────┘│");
    println!("│{}│", space);

    // Status line
    println!("│  {}│", format!("  {}", app.status_line()));
    println!("├{}┤", line);
    println!("│ [A] Alerts {} [D] Dashboard  [Y] Approve  [N] Reject  [Q] Quit       │",
        if app.pending_approvals > 0 { format!("({} pending)", app.pending_approvals) } else { "(none)    ".into() });
    println!("└{}┘", line);
    println!();

    // ── Render: Alert Detail View ──
    if !app.alerts.is_empty() {
        let alert = &app.alerts[0];
        println!("┌{}┐", line);
        println!("│ 🔔 ALERT: {} — {}                                  │",
            alert.id, alert.status_str());
        println!("├{}┤", line);
        println!("│{}│", space);
        println!("│  ╔{}╗│", "═".repeat(68));
        println!("│  ║                                                                      ║│");
        println!("│  ║   ⚠️  HUMAN HANDOFF — requires your decision                         ║│");
        println!("│  ║                                                                      ║│");
        println!("│  ║   From:    {:<58}║│", alert.from_agent);
        println!("│  ║   Reason:  {:<58}║│", alert.reason);
        println!("│  ║                                                                      ║│");

        // Summary (word wrap manually)
        println!("│  ║   Summary:                                                            ║│");
        for chunk in alert.summary.as_bytes().chunks(58) {
            let s = String::from_utf8_lossy(chunk);
            println!("│  ║   {:<66}║│", s);
        }
        println!("│  ║                                                                      ║│");
        println!("│  ║   ┌───────────────────────────────────────────────────┐               ║│");
        println!("│  ║   │  [Y] ✅ APPROVE    [N] ❌ REJECT    [X] ⏭️ DISMISS │               ║│");
        println!("│  ║   └───────────────────────────────────────────────────┘               ║│");
        println!("│  ╚{}╝│", "═".repeat(68));
        println!("│{}│", space);
        println!("├{}┤", line);
        println!("│ [Y] Approve  [N] Reject  [X] Dismiss  [D] Back  [Q] Quit               │");
        println!("└{}┘", line);
        println!();

        // ── Simulate Human Approval ──
        println!("  ▶  User presses [Y] (Approve)");
        app.handle_key(Key::Approve);
        println!();

        // ── Render: Post-Approval Dashboard ──
        println!("┌{}┐", line);
        println!("│ 🏠 Walkie Talkie  │  源星公司  │  {} agents  │  🔔 {} pending               │",
            app.agents.len(), app.pending_approvals);
        println!("├{}┤", line);

        // Show last few activities including the approval
        let recent: Vec<_> = app.activities.iter().rev().take(4).collect();
        for item in recent {
            let icon = item.action.icon();
            let detail = if item.detail.chars().count() > 60 { format!("{}...", item.detail.chars().take(57).collect::<String>()) } else { item.detail.clone() };
            println!("│  {} {:<72}│", icon, detail);
        }

        println!("├{}┤", line);
        println!("│  {}│", format!("  {}", app.status_line()));
        println!("└{}┘", line);
        println!();
    }

    // ── Statistics ──
    println!("┌{}┐", line);
    println!("│  DEMO STATISTICS                                                          │");
    println!("├{}┤", line);
    println!("│                                                                           │");
    println!("│   Agents:     {} registered ({} online)                                       │",
        app.agents.len(), app.online_agent_count());
    println!("│   Events:     {} total                                                      │", app.event_count);
    println!("│   Tasks:      {} assigned, {} completed                                        │",
        app.tasks_assigned, app.tasks_completed);
    println!("│   Alerts:     {} total, {} pending                                             │",
        app.alerts.len(), app.pending_approvals);
    println!("│                                                                           │");
    println!("│   💡 Core library: 8,279 lines Rust, 113 tests passing                    │");
    println!("│   💡 TUI module:   tui/mod.rs (1,006 lines, 30+ tests)                    │");
    println!("│   💡 Run live TUI:  cargo run --example walkie_tui --features tui          │");
    println!("│                                                                           │");
    println!("│   Scenario: 3-Agent security audit → human approval → deploy              │");
    println!("│                                                                           │");
    println!("└{}┘", line);
    println!();
}

/// Helper to get alert status string
trait AlertStatusStr {
    fn status_str(&self) -> &'static str;
}

impl AlertStatusStr for walkie_talkie_core::tui::Alert {
    fn status_str(&self) -> &'static str {
        match self.status {
            walkie_talkie_core::tui::AlertStatus::Pending => "PENDING",
            walkie_talkie_core::tui::AlertStatus::Approved => "APPROVED",
            walkie_talkie_core::tui::AlertStatus::Rejected => "REJECTED",
            walkie_talkie_core::tui::AlertStatus::Dismissed => "DISMISSED",
        }
    }
}
