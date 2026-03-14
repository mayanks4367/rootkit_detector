//! rootkit-radar-daemon — Userspace aggregation daemon.
//!
//! Responsibilities:
//!   1. Open a Netlink socket (protocol 31, group 1) and receive events
//!      streamed by the `rootkit_radar` LKM.
//!   2. Log every anomaly to:
//!        • /var/log/syslog  (via `tracing` → journald-compatible stderr)
//!        • /var/log/rootkit_radar.log  (structured JSON, one event per line)
//!   3. Maintain an in-memory ring of the last 1 000 events and expose them
//!      over a Unix Domain Socket at /run/rootkit_radar.sock so the TUI can
//!      query real-time state without root Netlink access.
//!
//! The daemon must run as root (required for Netlink protocol 31).

use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, RwLock};
use tracing::{error, info, warn};

/* ─── Constants ──────────────────────────────────────────────────────────── */

const NETLINK_ROOTKIT_RADAR: i32 = 31;
const NL_GROUP: u32              = 1;
const UDS_PATH: &str             = "/run/rootkit_radar.sock";
const JSON_LOG_PATH: &str        = "/var/log/rootkit_radar.log";
const EVENT_RING_SIZE: usize     = 1_000;
const BROADCAST_CAPACITY: usize  = 256;

/* Wire-format event — must match the C struct rr_event exactly.
 * Layout: u32 + u32 + i64 + [u8; 256]  = 272 bytes, no padding. */
const EVENT_WIRE_SIZE: usize = 4 + 4 + 8 + 256; // 272

/* ─── Event model ────────────────────────────────────────────────────────── */

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RrEvent {
    pub event_type:  u32,
    pub pid:         u32,
    pub timestamp:   DateTime<Utc>,
    pub description: String,
    /// Human-readable type name derived from event_type
    pub type_name:   String,
}

fn type_name(t: u32) -> &'static str {
    match t {
        1 => "SYSCALL_HOOK",
        2 => "HIDDEN_PROCESS",
        3 => "HIDDEN_MODULE",
        _ => "UNKNOWN",
    }
}

/// Parse a 272-byte raw Netlink payload into an RrEvent.
fn parse_wire(buf: &[u8]) -> Option<RrEvent> {
    if buf.len() < EVENT_WIRE_SIZE {
        return None;
    }

    let event_type  = u32::from_ne_bytes(buf[0..4].try_into().ok()?);
    let pid         = u32::from_ne_bytes(buf[4..8].try_into().ok()?);
    let ts_ns: i64  = i64::from_ne_bytes(buf[8..16].try_into().ok()?);

    // Description is a null-terminated C string in buf[16..272]
    let desc_bytes  = &buf[16..16 + 256];
    let null_pos    = desc_bytes.iter().position(|&b| b == 0).unwrap_or(256);
    let description = String::from_utf8_lossy(&desc_bytes[..null_pos]).into_owned();

    // Convert nanoseconds since epoch to DateTime<Utc>
    let secs  = ts_ns / 1_000_000_000;
    let nanos = (ts_ns % 1_000_000_000) as u32;
    let timestamp = DateTime::from_timestamp(secs, nanos)
        .unwrap_or_else(Utc::now);

    Some(RrEvent {
        type_name: type_name(event_type).to_owned(),
        event_type,
        pid,
        timestamp,
        description,
    })
}

/* ─── Shared state ───────────────────────────────────────────────────────── */

type EventRing = Arc<RwLock<Vec<RrEvent>>>;

/// Push to the ring, evicting the oldest entry when full.
async fn ring_push(ring: &EventRing, evt: RrEvent) {
    let mut guard = ring.write().await;
    if guard.len() >= EVENT_RING_SIZE {
        guard.remove(0);
    }
    guard.push(evt);
}

/* ─── Netlink listener ───────────────────────────────────────────────────── */

/// Open a raw Netlink socket bound to protocol 31, joined to group 1.
fn open_netlink_socket() -> Result<std::net::UdpSocket> {
    use std::os::unix::io::FromRawFd;

    // SAFETY: syscall with validated constants
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_ROOTKIT_RADAR,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error())
            .context("creating netlink socket (is rootkit_radar.ko loaded?)");
    }

    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_pid    = 0;           // kernel assigns pid
    addr.nl_groups = NL_GROUP;
    
    let ret = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error())
            .context("binding netlink socket to group");
    }

    // Wrap as UdpSocket purely to get a safe Drop — we use raw recv below.
    // SAFETY: fd is a valid socket fd.
    let socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    Ok(socket)
}

/// Blocking receive loop — runs in a dedicated OS thread via `spawn_blocking`.
async fn netlink_receive_loop(
    ring:   EventRing,
    tx:     broadcast::Sender<RrEvent>,
    log:    Arc<std::sync::Mutex<std::fs::File>>,
) {
    let socket = match open_netlink_socket() {
        Ok(s)  => s,
        Err(e) => {
            error!("Failed to open Netlink socket: {e:#}");
            error!("Is rootkit_radar.ko loaded? Try: sudo insmod kernel_module/rootkit_radar.ko");
            return;
        }
    };

    info!("Netlink socket open — listening for LKM events");

    // Move blocking recv into a dedicated thread
    let ring2 = ring.clone();
    let log2  = log.clone();

    tokio::task::spawn_blocking(move || {
        use std::os::unix::io::AsRawFd;

        let fd = socket.as_raw_fd();
        let mut buf = vec![0u8; 4096];

        loop {
            // recv() on a raw Netlink socket returns a full Netlink message
            let n = unsafe {
                libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void,
                           buf.len(), 0)
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted { continue; }
                eprintln!("rootkit-radar: netlink recv error: {err}");
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }

            let raw = &buf[..n as usize];

            // Skip the nlmsghdr (16 bytes) to get to the payload
            if raw.len() < 16 + EVENT_WIRE_SIZE {
                continue;
            }
            let payload = &raw[16..];

            if let Some(evt) = parse_wire(payload) {
                // JSON structured log
                {
                    let line = serde_json::to_string(&evt)
                        .unwrap_or_default();
                    let mut f = log2.lock().unwrap();
                    let _ = writeln!(f, "{line}");
                    let _ = f.flush();
                }

                // In-memory ring  (block_on is fine inside spawn_blocking)
                let ring3 = ring2.clone();
                let evt2  = evt.clone();
                tokio::runtime::Handle::current().block_on(async move {
                    ring_push(&ring3, evt2).await;
                });

                // Broadcast to UDS clients (ignore send errors — no subscribers)
                let _ = tx.send(evt);
            }
        }
    });
}

/* ─── Unix Domain Socket server ─────────────────────────────────────────── */

/// Handle a single TUI client connection.
///
/// Protocol (newline-delimited JSON):
///   Client sends: `{"cmd":"snapshot"}` → daemon replies with JSON array of
///                                         the last N events, then stays open
///                                         streaming new events as they arrive.
///   Client sends: `{"cmd":"ping"}`     → daemon replies `{"pong":true}`.
async fn handle_uds_client(
    mut stream: UnixStream,
    ring:       EventRing,
    mut rx:     broadcast::Receiver<RrEvent>,
) {
    // Send the current snapshot immediately on connect
    {
        let guard    = ring.read().await;
        let snapshot = guard.clone();
        drop(guard);

        let json = serde_json::to_string(&snapshot).unwrap_or_default();
        if stream.write_all(json.as_bytes()).await.is_err() { return; }
        if stream.write_all(b"\n").await.is_err() { return; }
    }

    // Then stream live events as they arrive
    loop {
        match rx.recv().await {
            Ok(evt) => {
                let json = serde_json::to_string(&evt).unwrap_or_default();
                if stream.write_all(json.as_bytes()).await.is_err() { break; }
                if stream.write_all(b"\n").await.is_err() { break; }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!("UDS client lagged, skipped {n} events");
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

async fn run_uds_server(
    ring: EventRing,
    tx:   broadcast::Sender<RrEvent>,
) -> Result<()> {
    // Remove stale socket file if present
    if Path::new(UDS_PATH).exists() {
        std::fs::remove_file(UDS_PATH)
            .context("removing stale UDS socket")?;
    }

    let listener = UnixListener::bind(UDS_PATH)
        .context("binding UDS socket")?;

    // Make it group-readable so the TUI can connect without full root
    std::fs::set_permissions(UDS_PATH,
        std::fs::Permissions::from_mode(0o660))
        .context("setting UDS socket permissions")?;

    info!("UDS server listening at {UDS_PATH}");

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let ring2 = ring.clone();
                let rx    = tx.subscribe();
                tokio::spawn(handle_uds_client(stream, ring2, rx));
            }
            Err(e) => {
                error!("UDS accept error: {e}");
            }
        }
    }
}

/* ─── Entry point ────────────────────────────────────────────────────────── */

#[tokio::main]
async fn main() -> Result<()> {
    // ── Logging setup ──
    // Structured JSON to stderr (captured by journald / syslog)
    tracing_subscriber::fmt()
        .json()
        .with_current_span(false)
        .init();

    // Dedicated JSON log file
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(JSON_LOG_PATH)
        .context(format!("opening JSON log {JSON_LOG_PATH}"))?;
    let log = Arc::new(std::sync::Mutex::new(log_file));

    info!("rootkit-radar daemon starting");

    // ── Shared event ring ──
    let ring: EventRing = Arc::new(RwLock::new(Vec::with_capacity(EVENT_RING_SIZE)));

    // ── Broadcast channel (Netlink → UDS clients) ──
    let (tx, _rx) = broadcast::channel::<RrEvent>(BROADCAST_CAPACITY);

    // ── Start Netlink listener ──
    netlink_receive_loop(ring.clone(), tx.clone(), log.clone()).await;

    // ── Start UDS server (blocks until shutdown) ──
    run_uds_server(ring.clone(), tx).await?;

    Ok(())
}

// libc is used for raw socket calls — declare extern crate for clarity
extern crate libc;
