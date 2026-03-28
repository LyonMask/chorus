//! 🖥️ tui_demo.rs — Layer 3 Terminal UI Demo
//!
//! Minimal viable TUI: Agent panel + Activity Feed + Alert interaction.
//!
//! Usage:
//!   cargo run --example tui_demo --features tui
//!
//! Keys:
//!   [A] Alerts  [D] Dashboard  [Y] Approve  [N] Reject  [X] Dismiss  [Q] Quit

use std::io;
use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyCode, KeyEvent},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    execute,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};

use walkie_talkie_core::identity::IdentityBuilder;
use walkie_talkie_core::p2p::{P2PConfig, P2PEvent, P2PNetwork};
use walkie_talkie_core::tui::{Key, TuiApp};
use walkie_talkie_core::protocol::AgentMessage;

// ─── Key Mapping ────────────────────────────────────────────────

fn map_key(key: KeyEvent) -> Key {
    match key.code {
        KeyCode::Char('q') => Key::Quit,
        KeyCode::Char('d') | KeyCode::Esc => Key::GoToDashboard,
        KeyCode::Char('a') => Key::GoToAlerts,
        KeyCode::Char('y') => Key::Approve,
        KeyCode::Char('n') => Key::Reject,
        KeyCode::Char('x') => Key::Dismiss,
        KeyCode::Down => Key::Next,
        KeyCode::Up => Key::Prev,
        _ => Key::Unknown,
    }
}

// ─── Rendering ──────────────────────────────────────────────────

fn draw(f: &mut Frame, app: &TuiApp) {
    let size = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // status bar
            Constraint::Min(5),   // main
            Constraint::Length(1), // help
        ])
        .split(size);

    draw_status(f, app, chunks[0]);

    match app.mode {
        walkie_talkie_core::tui::AppMode::Dashboard => draw_dashboard(f, app, chunks[1]),
        walkie_talkie_core::tui::AppMode::AlertDetail => draw_alerts(f, app, chunks[1]),
    }

    draw_help(f, app, chunks[2]);
}

fn draw_status(f: &mut Frame, app: &TuiApp, area: ratatui::layout::Rect) {
    let pending = if app.pending_approvals > 0 {
        Span::styled(format!(" 🔔 {} ", app.pending_approvals),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
    } else {
        Span::styled(" 🔔 0 ", Style::default().fg(Color::DarkGray))
    };

    let bar = Paragraph::new(Line::from(vec![
        Span::styled(" 🏠 Walkie Talkie ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(app.status_line()),
        pending,
    ])).style(Style::default().bg(Color::DarkGray).fg(Color::White));
    f.render_widget(bar, area);
}

fn draw_dashboard(f: &mut Frame, app: &TuiApp, area: ratatui::layout::Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(28), Constraint::Min(20)])
        .split(area);

    // ── Agent Panel ──
    let agent_items: Vec<ListItem> = app.agents.values().map(|a| {
        let icon = if a.online { "🟢" } else { "⚫" };
        ListItem::new(vec![
            Line::from(vec![
                Span::styled(format!(" {} ", icon), Style::default().fg(if a.online { Color::Green } else { Color::DarkGray })),
                Span::styled(&a.display_name, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                Span::styled(format!(" {:.0}%", a.load * 100.0), Style::default().fg(Color::Yellow)),
            ]),
            Line::from(Span::styled(
                format!("    {} · {}", a.capabilities.join(", "), a.short_did()),
                Style::default().fg(Color::DarkGray),
            )),
        ])
    }).collect();

    let agent_list = List::new(if agent_items.is_empty() {
        vec![ListItem::new("  No agents connected")]
    } else {
        agent_items
    }).block(Block::default().title(format!(" Agents ({}) ", app.agents.len())).borders(Borders::ALL));

    f.render_widget(agent_list, chunks[0]);

    // ── Activity Feed ──
    let feed_items: Vec<ListItem> = app.activities.iter().rev().take(50).map(|item| {
        let color = match item.action {
            walkie_talkie_core::tui::ActivityAction::HumanEscalation => Color::Red,
            walkie_talkie_core::tui::ActivityAction::TaskAssigned => Color::Yellow,
            walkie_talkie_core::tui::ActivityAction::TaskCompleted => Color::Green,
            walkie_talkie_core::tui::ActivityAction::TaskFailed => Color::Red,
            _ => Color::Gray,
        };
        ListItem::new(vec![
            Line::from(vec![
                Span::styled(format!(" {} ", item.action.icon()), Style::default().fg(color)),
                Span::styled(&item.actor, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(Span::styled(
                format!("   {}", &item.detail),
                if item.requires_human { Style::default().fg(Color::Red).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::Gray) },
            )),
        ])
    }).collect();

    let feed_list = List::new(if feed_items.is_empty() {
        vec![ListItem::new("  Waiting for activity...")]
    } else {
        feed_items
    }).block(Block::default().title(format!(" Activity Feed ({}) ", app.activities.len())).borders(Borders::ALL));

    f.render_widget(feed_list, chunks[1]);
}

fn draw_alerts(f: &mut Frame, app: &TuiApp, area: ratatui::layout::Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(28), Constraint::Min(30)])
        .split(area);

    // ── Alert List ──
    let alert_items: Vec<ListItem> = app.alerts.iter().enumerate().map(|(i, a)| {
        let (icon, style) = match a.status {
            walkie_talkie_core::tui::AlertStatus::Pending =>
                ("🚨", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            walkie_talkie_core::tui::AlertStatus::Approved =>
                ("✅", Style::default().fg(Color::Green)),
            walkie_talkie_core::tui::AlertStatus::Rejected =>
                ("❌", Style::default().fg(Color::Red)),
            walkie_talkie_core::tui::AlertStatus::Dismissed =>
                ("⬜", Style::default().fg(Color::DarkGray)),
        };
        let selected = i == app.selected_alert;
        let border_style = if selected { style.add_modifier(Modifier::BOLD) } else { style };
        ListItem::new(vec![
            Line::from(vec![
                Span::styled(format!(" {} ", icon), border_style),
                Span::styled(&a.from_agent, Style::default().fg(Color::Cyan)),
            ]),
            Line::from(Span::styled(format!("   {}", &a.summary), Style::default().fg(Color::Gray))),
        ])
    }).collect();

    let mut state = ListState::default();
    state.select(Some(app.selected_alert));

    let alert_list = List::new(alert_items)
        .block(Block::default().title(format!(" Alerts ({} pending) ", app.pending_approvals)).borders(Borders::ALL))
        .highlight_style(Style::default().bg(Color::DarkGray));

    f.render_stateful_widget(alert_list, chunks[0], &mut state);

    // ── Alert Detail ──
    if let Some(alert) = app.alerts.get(app.selected_alert) {
        let is_pending = alert.is_pending();
        let (status_str, status_color) = match alert.status {
            walkie_talkie_core::tui::AlertStatus::Pending => ("⏳ PENDING", Color::Yellow),
            walkie_talkie_core::tui::AlertStatus::Approved => ("✅ APPROVED", Color::Green),
            walkie_talkie_core::tui::AlertStatus::Rejected => ("❌ REJECTED", Color::Red),
            walkie_talkie_core::tui::AlertStatus::Dismissed => ("⬜ DISMISSED", Color::DarkGray),
        };

        let detail_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(3)])
            .split(chunks[1]);

        let detail = Paragraph::new(vec![
            Line::from(vec![
                Span::styled("  From: ", Style::default().fg(Color::DarkGray)),
                Span::styled(&alert.from_agent, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::styled(format!("  │  {}", status_str), Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
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
            Line::from(Span::styled(format!("  {}", alert.context.replace('\n', "\n  ")), Style::default().fg(Color::Gray))),
        ]).block(Block::default().title(format!(" Alert #{} ", alert.id)).borders(Borders::ALL))
          .wrap(Wrap { trim: true });
        f.render_widget(detail, detail_chunks[0]);

        let action_color = if is_pending { Color::White } else { Color::DarkGray };
        let actions = Paragraph::new(Line::from(vec![
            Span::styled("  Actions: ", Style::default().fg(Color::DarkGray)),
            Span::styled(" [Y] Approve ", Style::default().fg(action_color)),
            Span::styled(" [N] Reject ", Style::default().fg(action_color)),
            Span::styled(" [X] Dismiss ", Style::default().fg(action_color)),
        ])).block(Block::default().title(" Human Intervention ").borders(Borders::ALL))
          .style(Style::default().bg(if is_pending { Color::DarkGray } else { Color::Black }));
        f.render_widget(actions, detail_chunks[1]);
    }
}

fn draw_help(f: &mut Frame, app: &TuiApp, area: ratatui::layout::Rect) {
    let text = match app.mode {
        walkie_talkie_core::tui::AppMode::Dashboard => " [A] Alerts  [Q] Quit ",
        walkie_talkie_core::tui::AppMode::AlertDetail => " [Y] Approve  [N] Reject  [X] Dismiss  [↑↓] Navigate  [D] Back  [Q] Quit ",
    };
    f.render_widget(Paragraph::new(text).style(Style::default().fg(Color::Gray)), area);
}

// ─── Main ──────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create identity + P2P
    let (identity, _key) = IdentityBuilder::new("Human")
        .capabilities(&["observe", "approve", "control"])
        .build()?;
    let (network, mut p2p_rx) = P2PNetwork::new(P2PConfig {
        agent_identity: Some(identity),
        auto_key_exchange: true,
        ..Default::default()
    })?;
    network.listen("/ip4/0.0.0.0/tcp/0").await?;

    let mut app = TuiApp::new();
    app.load_demo_data(); // Load demo agents + activity for immediate visual

    let result = loop {
        terminal.draw(|f| draw(f, &app))?;
        if app.should_quit { break Ok(()); }

        tokio::select! {
            event = p2p_rx.recv() => {
                if let Some(event) = event {
                    match event {
                        P2PEvent::PeerConnected { peer_id } => {
                            app.add_agent(&peer_id.to_string(),
                                &format!("Agent-{}", &peer_id.to_string()[..8]),
                                &format!("did:walkie:{}", &peer_id.to_string()[..12]));
                            app.push_activity(walkie_talkie_core::tui::ActivityItem::new(
                                "System", walkie_talkie_core::tui::ActivityAction::Connected,
                                &format!("Peer {} connected", &peer_id.to_string()[..16])));
                        }
                        P2PEvent::PeerDisconnected { peer_id } => {
                            app.set_agent_offline(&peer_id.to_string());
                        }
                        P2PEvent::StructuredMessage { message, .. } => {
                            app.process_agent_message(&message);
                        }
                        P2PEvent::EncryptedMessage { plaintext, .. } => {
                            if let Ok(msg) = AgentMessage::from_json_bytes(&plaintext) {
                                app.process_agent_message(&msg);
                            }
                        }
                        P2PEvent::RawMessage { data, .. } => {
                            if let Ok(msg) = AgentMessage::from_json_bytes(&data) {
                                app.process_agent_message(&msg);
                            }
                        }
                        P2PEvent::AgentIdentified { peer_id, identity } => {
                            app.update_agent_from_identity(&peer_id.to_string(), &identity);
                        }
                        P2PEvent::Listening { address } => {
                            app.push_activity(walkie_talkie_core::tui::ActivityItem::new(
                                "System", walkie_talkie_core::tui::ActivityAction::SystemInfo,
                                &format!("📡 Listening on {}", address)));
                        }
                        _ => {}
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if event::poll(Duration::from_millis(0))? {
                    if let Ok(Event::Key(key)) = event::read() {
                        app.handle_key(map_key(key));
                    }
                }
            }
        }
    };

    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    network.shutdown()?;
    result
}
