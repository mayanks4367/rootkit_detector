//! rootkit-radar-tui — Ratatui terminal dashboard.
//!
//! Layout (three panes):
//!
//!  ┌────────────────────────────────────────────────────┐
//!  │ TOP PANE  — System health, kernel version, status  │
//!  ├──────────────────────┬─────────────────────────────┤
//!  │ LEFT PANE            │ RIGHT PANE                  │
//!  │ Syscall Table Monitor│ Process Integrity Monitor   │
//!  │ (hijacked = red)     │ (DKOM discrepancies)        │
//!  └──────────────────────┴─────────────────────────────┘
//!
//! Connects to the daemon's UDS at /run/rootkit_radar.sock and streams events.
//! Falls back to a demo mode with synthetic events when the daemon is absent.

use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use chrono::{DateTime, Utc};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen,
               LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph,
              Wrap},
    Frame, Terminal,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

/* ─── Data model (mirrors daemon's RrEvent) ──────────────────────────────── */

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RrEvent {
    pub event_type:  u32,
    pub pid:         u32,
    pub timestamp:   DateTime<Utc>,
    pub description: String,
    pub type_name:   String,
    pub severity:    Severity,
    pub certainty:   u32,
}

/* ─── Application state ─────────────────────────────────────────────────── */

#[derive(Debug, Clone, PartialEq)]
enum DaemonStatus {
    Connected,
    Disconnected,
    DemoMode,
}

struct AppState {
    // All events received, newest first
    events:         Vec<RrEvent>,
    // Scrolling state for left pane (syscall hooks)
    syscall_scroll: ListState,
    // Scrolling state for right pane (process/module events)
    process_scroll: ListState,
    daemon_status:  DaemonStatus,
    kernel_version: String,
    alert_count:    usize,
    start_time:     Instant,
}

impl AppState {
    fn new(kernel_version: String, demo: bool) -> Self {
        let mut syscall_scroll = ListState::default();
        syscall_scroll.select(Some(0));
        let mut process_scroll = ListState::default();
        process_scroll.select(Some(0));

        AppState {
            events:         Vec::new(),
            syscall_scroll,
            process_scroll,
            daemon_status: if demo {
                DaemonStatus::DemoMode
            } else {
                DaemonStatus::Disconnected
            },
            kernel_version,
            alert_count: 0,
            start_time: Instant::now(),
        }
    }

    fn push_event(&mut self, evt: RrEvent) {
        self.alert_count += 1;
        self.events.insert(0, evt);
        if self.events.len() > 1_000 {
            self.events.pop();
        }
    }

    fn syscall_events(&self) -> Vec<&RrEvent> {
        self.events.iter().filter(|e| e.event_type == 1).collect()
    }

    fn process_module_events(&self) -> Vec<&RrEvent> {
        self.events.iter().filter(|e| e.event_type == 2 || e.event_type == 3).collect()
    }
}

/* ─── UDS reader ─────────────────────────────────────────────────────────── */

const UDS_PATH: &str = "/run/rootkit_radar.sock";

async fn connect_to_daemon(
    state: Arc<Mutex<AppState>>,
) -> bool {
    if !Path::new(UDS_PATH).exists() {
        return false;
    }

    let stream = match UnixStream::connect(UDS_PATH).await {
        Ok(s)  => s,
        Err(_) => return false,
    };

    {
        let mut s = state.lock().await;
        s.daemon_status = DaemonStatus::Connected;
    }

    // The first message from daemon is a JSON array (snapshot)
    // Subsequent messages are single-line JSON objects.
    let reader     = BufReader::new(stream);
    let mut lines  = reader.lines();
    let state2     = state.clone();

    tokio::spawn(async move {
        let mut first = true;
        while let Ok(Some(line)) = lines.next_line().await {
            if line.is_empty() {
                continue;
            }
            if first {
                first = false;
                // Try parsing as array (snapshot)
                if let Ok(evts) = serde_json::from_str::<Vec<RrEvent>>(&line) {
                    let mut s = state2.lock().await;
                    for evt in evts.into_iter().rev() {
                        s.push_event(evt);
                    }
                    continue;
                }
            }
            // Single event
            if let Ok(evt) = serde_json::from_str::<RrEvent>(&line) {
                let mut s = state2.lock().await;
                s.push_event(evt);
            }
        }

        // Connection dropped
        let mut s = state2.lock().await;
        s.daemon_status = DaemonStatus::Disconnected;
    });

    true
}

/* ─── Demo mode synthetic events ─────────────────────────────────────────── */

fn make_demo_event(seq: u32) -> RrEvent {
    let (event_type, type_name, severity, desc) = match seq % 3 {
        0 => (1u32, "SYSCALL_HOOK", Severity::Critical,
              format!("sys_call_table[{}] pointer changed: 0xffffffff81234567 → 0xffffffffc0ab1234",
                      [0, 1, 59, 217][seq as usize % 4])),
        1 => (2, "HIDDEN_PROCESS", Severity::High,
              format!("PID {} in kernel task_struct but absent from /proc — DKOM suspected",
                      1000 + seq * 13)),
        _ => (3, "HIDDEN_MODULE", Severity::Critical,
              format!("Module 'evil_mod_{}' present in kset but absent from modules list",
                      seq)),
    };
    RrEvent {
        event_type,
        pid: if event_type == 2 { 1000 + seq * 13 } else { 0 },
        timestamp: Utc::now(),
        description: desc,
        type_name: type_name.to_owned(),
        severity,
        certainty: if severity == Severity::Critical { 2 } else { 1 },
    }
}

/* ─── UI rendering ───────────────────────────────────────────────────────── */

fn render(frame: &mut Frame, state: &mut AppState) {
    let size = frame.size();

    // ── Outer layout: top bar + main body ──
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),  // top pane
            Constraint::Min(0),     // main body
        ])
        .split(size);

    // ── Main body: left + right ──
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .split(outer[1]);

    render_top_pane(frame, state, outer[0]);
    render_left_pane(frame, state, body[0]);
    render_right_pane(frame, state, body[1]);
}

/* ── Top pane ── */
fn render_top_pane(frame: &mut Frame, state: &AppState, area: Rect) {
    let uptime_secs = state.start_time.elapsed().as_secs();
    let uptime_str  = format!("{}h {}m {}s",
        uptime_secs / 3600, (uptime_secs % 3600) / 60, uptime_secs % 60);

    let (status_text, status_color) = match &state.daemon_status {
        DaemonStatus::Connected    => ("CONNECTED",    Color::Green),
        DaemonStatus::Disconnected => ("DISCONNECTED", Color::Red),
        DaemonStatus::DemoMode     => ("DEMO MODE",    Color::Yellow),
    };

    let alert_color = if state.alert_count > 0 { Color::Red } else { Color::Green };
    let is_isolated = state.events.iter().any(|e| e.severity == Severity::Critical);
    
    let alert_label = if state.alert_count > 0 {
        format!("  *** {} ALERTS DETECTED ***  ", state.alert_count)
    } else {
        "  SYSTEM CLEAN  ".to_owned()
    };

    let isolation_status = if is_isolated {
        Span::styled("   Network: [HOST ISOLATED]", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
    } else {
        Span::styled("   Network: [ACTIVE]", Style::default().fg(Color::Green))
    };

    let content = vec![
        Line::from(vec![
            Span::styled(" Kernel: ", Style::default().fg(Color::Cyan)),
            Span::raw(&state.kernel_version),
            Span::styled("   Uptime: ", Style::default().fg(Color::Cyan)),
            Span::raw(&uptime_str),
            Span::styled("   Daemon: ", Style::default().fg(Color::Cyan)),
            Span::styled(status_text, Style::default().fg(status_color)
                .add_modifier(Modifier::BOLD)),
            isolation_status,
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(&alert_label,
                Style::default()
                    .fg(Color::Black)
                    .bg(alert_color)
                    .add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" [q] Quit  [Tab] Switch pane  [↑/↓] Scroll  ",
                Style::default().fg(Color::DarkGray)),
        ]),
    ];

    let block = Block::default()
        .title(Span::styled(
            " rootkit-radar  Security Dashboard ",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let para = Paragraph::new(content)
        .block(block)
        .wrap(Wrap { trim: true });

    frame.render_widget(para, area);
}

/* ── Left pane: Syscall Table Monitor ── */
fn render_left_pane(frame: &mut Frame, state: &mut AppState, area: Rect) {
    let events = state.syscall_events();

    let items: Vec<ListItem> = if events.is_empty() {
        vec![ListItem::new(Line::from(vec![
            Span::styled(" No syscall hook events", Style::default().fg(Color::Green)),
        ]))]
    } else {
        events.iter().map(|evt| {
            let ts = evt.timestamp.format("%H:%M:%S").to_string();
            let sev_color = match evt.severity {
                Severity::Critical => Color::Red,
                Severity::High => Color::LightRed,
                _ => Color::Yellow,
            };
            let line = Line::from(vec![
                Span::styled(format!(" {ts} "), Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("[{:?}] ", evt.severity),
                    Style::default().fg(sev_color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("[{}] ", evt.type_name),
                    Style::default().fg(Color::Red),
                ),
                Span::styled(
                    evt.description.chars().take(60).collect::<String>(),
                    Style::default().fg(Color::Red),
                ),
            ]);
            ListItem::new(line)
        }).collect()
    };

    let title = format!(" Syscall Table Monitor ({} alerts) ", events.len());
    let block = Block::default()
        .title(Span::styled(&title,
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));

    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    frame.render_stateful_widget(list, area, &mut state.syscall_scroll);
}

/* ── Right pane: Process Integrity Monitor ── */
fn render_right_pane(frame: &mut Frame, state: &mut AppState, area: Rect) {
    let events = state.process_module_events();

    let items: Vec<ListItem> = if events.is_empty() {
        vec![ListItem::new(Line::from(vec![
            Span::styled(" No process/module anomalies", Style::default().fg(Color::Green)),
        ]))]
    } else {
        events.iter().map(|evt| {
            let ts    = evt.timestamp.format("%H:%M:%S").to_string();
            let color = if evt.event_type == 2 { Color::Magenta } else { Color::LightRed };
            let sev_color = match evt.severity {
                Severity::Critical => Color::Red,
                Severity::High => Color::Yellow,
                _ => Color::Gray,
            };
            let pid_str = if evt.pid > 0 {
                format!("PID:{} ", evt.pid)
            } else {
                String::new()
            };

            let line = Line::from(vec![
                Span::styled(format!(" {ts} "), Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("[{:?}] ", evt.severity),
                    Style::default().fg(sev_color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("[{}] {}", evt.type_name, pid_str),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    evt.description.chars().take(55).collect::<String>(),
                    Style::default().fg(color),
                ),
            ]);
            ListItem::new(line)
        }).collect()
    };

    let title = format!(" Process Integrity Monitor ({} anomalies) ", events.len());
    let block = Block::default()
        .title(Span::styled(&title,
            Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));

    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    frame.render_stateful_widget(list, area, &mut state.process_scroll);
}

/* ─── Input handling ─────────────────────────────────────────────────────── */

#[derive(Debug, PartialEq)]
enum ActivePane { Left, Right }

/* ─── Main ───────────────────────────────────────────────────────────────── */

#[tokio::main]
async fn main() -> Result<()> {
    // Read kernel version
    let kernel_version = std::fs::read_to_string("/proc/version")
        .unwrap_or_default()
        .split_whitespace()
        .nth(2)
        .unwrap_or("unknown")
        .to_owned();

    // Try to connect to daemon; fall back to demo mode
    let demo = !Path::new(UDS_PATH).exists();
    let state = Arc::new(Mutex::new(AppState::new(kernel_version, demo)));

    if !demo {
        connect_to_daemon(state.clone()).await;
    }

    // Terminal setup
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend  = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;

    let mut active_pane = ActivePane::Left;
    let mut demo_seq    = 0u32;
    let mut last_demo   = Instant::now();

    loop {
        {
            let mut s = state.lock().await;
            // In demo mode, inject a synthetic event every 2 seconds
            if s.daemon_status == DaemonStatus::DemoMode
                && last_demo.elapsed() > Duration::from_secs(2)
            {
                s.push_event(make_demo_event(demo_seq));
                demo_seq    = demo_seq.wrapping_add(1);
                last_demo   = Instant::now();
            }
            term.draw(|f| render(f, &mut *s))?;
        }

        // Poll for input with a 200ms timeout so the UI stays responsive
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                let mut s = state.lock().await;
                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => break,

                    KeyCode::Tab => {
                        active_pane = if active_pane == ActivePane::Left {
                            ActivePane::Right
                        } else {
                            ActivePane::Left
                        };
                    }

                    KeyCode::Down | KeyCode::Char('j') => {
                        if active_pane == ActivePane::Left {
                            let len = s.syscall_events().len();
                            let i   = s.syscall_scroll.selected().unwrap_or(0);
                            s.syscall_scroll.select(Some((i + 1).min(len.saturating_sub(1))));
                        } else {
                            let len = s.process_module_events().len();
                            let i   = s.process_scroll.selected().unwrap_or(0);
                            s.process_scroll.select(Some((i + 1).min(len.saturating_sub(1))));
                        }
                    }

                    KeyCode::Up | KeyCode::Char('k') => {
                        if active_pane == ActivePane::Left {
                            let i = s.syscall_scroll.selected().unwrap_or(0);
                            s.syscall_scroll.select(Some(i.saturating_sub(1)));
                        } else {
                            let i = s.process_scroll.selected().unwrap_or(0);
                            s.process_scroll.select(Some(i.saturating_sub(1)));
                        }
                    }

                    _ => {}
                }
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    term.show_cursor()?;

    Ok(())
}
