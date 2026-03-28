//! 🖨️ headless_demo.rs — Generate ASCII screenshot of TUI for docs.
//! No TTY required. Pure ASCII representation of the TUI layout.

fn main() {
    use walkie_talkie_core::tui::{TuiApp, ActivityItem, ActivityAction};

    let mut app = TuiApp::new();
    app.add_agent("pk-alice-001", "Alice 🤖", "did:walkie:aBcDeFgH1234567890");
    app.add_agent("pk-bob-002", "Bob 🔧", "did:walkie:xYzAbCdEf0987654321");
    app.add_agent("pk-carol-003", "Carol 🧠", "did:walkie:mNoPqRsTu5678901234");
    app.set_agent_offline("pk-carol-003");

    app.push_activity(ActivityItem::new("Alice 🤖", ActivityAction::TextMessage, "Team standup in 5 minutes 🎯"));
    app.push_activity(ActivityItem::new("Bob 🔧", ActivityAction::TaskAssigned, "Security audit assigned (HIGH priority)"));
    app.push_activity(ActivityItem::new("Carol 🧠", ActivityAction::AgentOffline, "Connection lost — last seen 3 min ago"));
    app.push_activity(ActivityItem::new("Bob 🔧", ActivityAction::TextMessage, "Audit complete ✅ All systems green."));
    app.push_activity(ActivityItem::new("Alice 🤖", ActivityAction::TaskCompleted, "Q1 revenue analysis finished — report sent"));
    app.push_activity(ActivityItem::new("Bob 🔧", ActivityAction::HumanEscalation, "Payment auth required — $50K → Acme Corp"));

    app.add_alert(
        "Bob 🔧",
        "payment_authorization_required",
        "Vendor payment requires CFO approval — $50,000 to Acme Corp",
        "{ \"amount_usd\": 50000, \"vendor\": \"Acme Corp\" }",
    );

    let line = "─".repeat(78);

    println!();
    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║           📡  Walkie Talkie v4 — TUI Demo (ASCII Capture)                  ║");
    println!("║           Layer 3: Human Interface (ratatui 0.28 + crossterm 0.28)         ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝");
    println!();

    // ── Dashboard View ──
    println!("┌{}┐", line);
    println!("│ 📡 Walkie Talkie v4  │  Demo Org  │  3 agents (2 online)  │  🔔 1 pending  │");
    println!("├{}┤", line);
    println!("│                                                                              │");
    println!("│  ┌─ AGENTS ──────────────────────┐  ┌─ ACTIVITY FEED ──────────────────────┐  │");
    println!("│  │                               │  │                                       │  │");
    println!("│  │  🟢 Alice 🤖                  │  │  21:08 📝 Alice: Team standup in 5 min │  │");
    println!("│  │     DID: did:walkie:aBcD...   │  │  21:06 📋 Bob: Security audit (HIGH)   │  │");
    println!("│  │     Capabilities: chat, data   │  │  21:05 💀 Carol: heartbeat (offline)  │  │");
    println!("│  │                               │  │  21:04 📝 Bob: Audit complete ✅        │  │");
    println!("│  │  🟡 Bob 🔧                    │  │  21:02 ✅ Alice: Q1 analysis done      │  │");
    println!("│  │     DID: did:walkie:xYzA...   │  │  21:00 ⚠️  Bob: Human handoff          │  │");
    println!("│  │     Capabilities: crypto, sys  │  │         Payment auth $50K (Acme Corp)  │  │");
    println!("│  │                               │  │                                       │  │");
    println!("│  │  ⚫ Carol 🧠  (offline)        │  │                                       │  │");
    println!("│  │     DID: did:walkie:mNoP...   │  │                                       │  │");
    println!("│  │     Capabilities: translate    │  │                                       │  │");
    println!("│  │                               │  │                                       │  │");
    println!("│  └───────────────────────────────┘  └───────────────────────────────────────┘  │");
    println!("│                                                                              │");
    println!("├{}┤", line);
    println!("│ [A] Alerts (1 pending)  [D] Dashboard  [Y] Approve  [N] Reject  [Q] Quit    │");
    println!("└{}┘", line);
    println!();

    // ── Alert Detail View ──
    println!("┌{}┐", line);
    println!("│ 📡 Walkie Talkie v4  │  Demo Org  │  🔔 ALERT: 1 of 1  (pending)             │");
    println!("├{}┤", line);
    println!("│                                                                              │");
    println!("│  ╔════════════════════════════════════════════════════════════════════════╗   │");
    println!("│  ║                                                                      ║   │");
    println!("│  ║   ⚠️  HUMAN HANDOFF — requires your decision                          ║   │");
    println!("│  ║                                                                      ║   │");
    println!("│  ║   From:    Bob 🔧                                                   ║   │");
    println!("│  ║   Reason:  payment_authorization_required                            ║   │");
    println!("│  ║   Urgency: 🔴 HIGH                                                  ║   │");
    println!("│  ║                                                                      ║   │");
    println!("│  ║   Summary:                                                          ║   │");
    println!("│  ║   Vendor payment requires CFO approval — $50,000 to Acme Corp         ║   │");
    println!("│  ║                                                                      ║   │");
    println!("│  ║   Context:                                                          ║   │");
    println!("│  ║   {{ \"amount_usd\": 50000, \"vendor\": \"Acme Corp\" }}                      ║   │");
    println!("│  ║                                                                      ║   │");
    println!("│  ║   ┌──────────────────────────────────────────────────────┐            ║   │");
    println!("│  ║   │  [Y] ✅ APPROVE    [N] ❌ REJECT    [X] ⏭️ DISMISS  │            ║   │");
    println!("│  ║   └──────────────────────────────────────────────────────┘            ║   │");
    println!("│  ║                                                                      ║   │");
    println!("│  ╚════════════════════════════════════════════════════════════════════════╝   │");
    println!("│                                                                              │");
    println!("├{}┤", line);
    println!("│ [A] Alerts (1/1)  [D] Back to Dashboard  [Y] Approve  [N] Reject  [Q] Quit  │");
    println!("└{}┘", line);
    println!();

    // ── After Approve ──
    println!("  ▶  User presses [Y] (Approve)");
    println!();
    println!("┌{}┐", line);
    println!("│ 📡 Walkie Talkie v4  │  Demo Org  │  3 agents (2 online)  │  🔔 0 pending  │");
    println!("├{}┤", line);
    println!("│                                                                              │");
    println!("│  ┌─ AGENTS ──────────────────────┐  ┌─ ACTIVITY FEED ──────────────────────┐  │");
    println!("│  │                               │  │                                       │  │");
    println!("│  │  🟢 Alice 🤖                  │  │  21:08 ✅ APPROVED: Bob's handoff      │  │");
    println!("│  │     DID: did:walkie:aBcD...   │  │  21:08 📝 Alice: Team standup in 5 min │  │");
    println!("│  │     Capabilities: chat, data   │  │  21:06 📋 Bob: Security audit (HIGH)   │  │");
    println!("│  │                               │  │  21:05 💀 Carol: heartbeat (offline)  │  │");
    println!("│  │  🟡 Bob 🔧                    │  │  21:04 📝 Bob: Audit complete ✅        │  │");
    println!("│  │     DID: did:walkie:xYzA...   │  │  21:02 ✅ Alice: Q1 analysis done      │  │");
    println!("│  │     Capabilities: crypto, sys  │  │  21:00 ⚠️  Bob: Human handoff          │  │");
    println!("│  │                               │  │                                       │  │");
    println!("│  │  ⚫ Carol 🧠  (offline)        │  │                                       │  │");
    println!("│  │     DID: did:walkie:mNoP...   │  │                                       │  │");
    println!("│  │     Capabilities: translate    │  │                                       │  │");
    println!("│  │                               │  │                                       │  │");
    println!("│  └───────────────────────────────┘  └───────────────────────────────────────┘  │");
    println!("│                                                                              │");
    println!("├{}┤", line);
    println!("│ [A] Alerts (none)  [D] Dashboard  [Y] Approve  [N] Reject  [Q] Quit        │");
    println!("└{}┘", line);
    println!();

    // ── Stats ──
    println!("┌{}┐", line);
    println!("│  DEMO STATISTICS                                                              │");
    println!("├{}┤", line);
    println!("│                                                                              │");
    println!("│   Agents:    3 registered  (2 online, 1 offline)                              │");
    println!("│   Activity:  7 items       (text: 2, task: 1, completed: 1,                  │");
    println!("│                           offline: 1, human_handoff: 1, approved: 1)            │");
    println!("│   Alerts:    1 handled     (approved: 1)                                     │");
    println!("│                                                                              │");
    println!("│   💡 This is an ASCII representation of the real TUI rendered by             │");
    println!("│      ratatui 0.28 + crossterm 0.28 in src/tui/mod.rs (1,006 lines)            │");
    println!("│      Run the actual TUI: cargo run --example tui_demo --features tui           │");
    println!("│                                                                              │");
    println!("│   ⚠️  Requires a real TTY terminal (not a pipe/sandbox)                       │");
    println!("│                                                                              │");
    println!("└{}┘", line);
    println!();
}
