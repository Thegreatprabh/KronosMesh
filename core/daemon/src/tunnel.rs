//! The mesh data plane: an async UDP multiplexer speaking WireGuard-style
//! frames (1-byte type + indices + AEAD-sealed payloads) with Noise_IK
//! handshakes from `crypto.rs`.
//!
//! Frame layouts (all integers little-endian):
//!   INIT (1): [type][reserved 3][sender_index u32][noise message 1]
//!   RESP (2): [type][reserved 3][sender_index u32][receiver_index u32][noise message 2]
//!   DATA (4): [type][reserved 3][receiver_index u32][counter u64][ciphertext]
//!
//! Inner packet (the plaintext inside DATA):
//!   [kind u8][dst_vip 4][body]
//!   kind 0x01 = ping, 0x02 = pong, 0x03 = application data.
//! A node that receives a packet whose dst_vip is not its own forwards
//! it toward the next hop from its routing table — a true userspace
//! mesh relay. This is the fallback data plane when eBPF/XDP is
//! unavailable, and the control path in every mode.

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use x25519_dalek::PublicKey;

use crate::config::Identity;
use crate::crypto::{hex_decode, HandshakeInitiator, HandshakeResponder, Session};
use crate::ebpf_loader::{EventRing, TelemetryCounters};
use crate::wire::{AclRule, PeerNode};

pub const MSG_INIT: u8 = 1;
pub const MSG_RESP: u8 = 2;
pub const MSG_COOKIE: u8 = 3;
pub const MSG_DATA: u8 = 4;

/// Total byte length of an INIT frame (8-byte header + the fixed
/// 104-byte Noise_IK message 1 with its 8-byte timestamp
/// payload). An INIT carrying a cookie proof (mac2) is exactly
/// MAC2_LEN bytes longer.
const INIT_FRAME_LEN: usize = 112;
const MAC2_LEN: usize = 16;
/// How long an issued cookie stays valid for retries.
const COOKIE_TTL: Duration = Duration::from_secs(120);

pub const KIND_PING: u8 = 0x01;
pub const KIND_PONG: u8 = 0x02;
pub const KIND_DATA: u8 = 0x03;
/// Service-stream frames (see gateway.rs): a stream carries one TCP
/// service connection between two nodes' gateways. Policy for streams
/// is decided by the gateways using `acl_decision`; the tunnel only
/// transports authenticated stream frames and relays them like data.
pub const KIND_STREAM_OPEN: u8 = 0x04;
pub const KIND_STREAM_DATA: u8 = 0x05;
pub const KIND_STREAM_CLOSE: u8 = 0x06;
pub const KIND_STREAM_ACK: u8 = 0x07;
pub const KIND_STREAM_RESET: u8 = 0x08;

/// Reliable-stream parameters. Service streams carry TCP connections,
/// so the stream layer implements the reliability TCP assumes:
/// per-direction sequence numbers, cumulative acknowledgements, a
/// bounded sender window (backpressure), and retransmission on a
/// fixed RTO until acknowledged. See `OutStream` / `InStream`.
/// Maximum unacknowledged DATA frames per stream direction.
pub const STREAM_WINDOW: usize = 32;
/// Maximum payload bytes per stream DATA frame.
pub const STREAM_FRAME_PAYLOAD: usize = 4096;
/// Retransmission timeout for unacknowledged stream frames.
const STREAM_RTO: Duration = Duration::from_millis(200);
/// Housekeeping cadence for stream retransmission and state purges.
const STREAM_TICK: Duration = Duration::from_millis(50);
/// Ordered frames buffered for the gateway consumer per stream. When
/// it fills, the receiver stops advancing its ACK — that is what
/// propagates a slow consumer's backpressure to the sender.
pub const STREAM_DELIVERY_CAP: usize = 32;
/// How long finished stream state lingers to answer retransmissions.
const STREAM_LINGER: Duration = Duration::from_secs(15);
/// A peer that has sent us nothing for this long is treated as
/// gone. Sessions exchange keepalives every 20 s, so three
/// minutes of total silence is not a pause — it is a departure,
/// and the peer's streams are reaped (see stream_housekeeping).
const PEER_SILENCE_DEAD: Duration = Duration::from_secs(180);
/// Soft cap on concurrent inbound streams per peer. One stream's
/// receive state is bounded (window + delivery cap), but the
/// stream COUNT was not: an authorized peer with a bug — or a
/// compromised key — could grow daemon memory by opening streams
/// it never closes. Beyond the cap, new stream ids are refused
/// with a RESET. (Checked only when a frame would create new
/// state, so it is a safety valve, not a precise quota.)
const MAX_IN_STREAMS_PER_PEER: usize = 1024;

const HANDSHAKE_WAIT: Duration = Duration::from_millis(3000);
/// Hop limit stamped on inner packets; relays decrement it and drop at
/// zero, so a routing loop dies instead of circulating forever.
const DEFAULT_TTL: u8 = 8;
/// Initiator-side session rotation interval (WireGuard-style rekeying).
const REKEY_AFTER_SECS: u64 = 120;
/// Maximum accepted age of a handshake INIT timestamp. Bounds the replay
/// window even across responder restarts (floors are also persisted).
const INIT_MAX_AGE_MS: u64 = 120_000;
/// Per-source INIT processing budget per second. Reading an INIT costs
/// two X25519 DH operations before the sender is authenticated, so
/// unauthenticated floods are capped cheaply, before any DH happens.
const INIT_RATE_LIMIT: u32 = 30;
/// Aggregate proof-less INIT budget per second across ALL
/// sources. The per-source limit alone lets a rotating-source
/// flood buy unbounded X25519 work (30/s per fresh address);
/// past this aggregate, every source needs a cookie proof —
/// WireGuard's "cookie mode under load".
const INIT_GLOBAL_LIMIT: u32 = 300;
/// Aggregate budget for proof-carrying INITs: far higher (the
/// sender proved address ownership), still bounded so a cookie
/// holder cannot monopolize handshake CPU either.
const INIT_GLOBAL_PROOF_LIMIT: u32 = 1500;
/// The per-source INIT rate table is pruned once it grows past this
/// many sources, so the guard itself cannot be memory-flooded.
const INIT_RATE_TABLE_MAX: usize = 4096;
/// Cap on frames being handled concurrently. The receive loop drops
/// (and counts) datagrams beyond this instead of spawning unbounded
/// tasks — a UDP flood must not exhaust memory or the scheduler.
const MAX_IN_FLIGHT_FRAMES: usize = 256;
const KEEPALIVE_EVERY: Duration = Duration::from_secs(20);
const PING_EVERY: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Transport abstraction: the data plane runs over UDP in production.
// Tests (and sandboxes where UDP is unavailable) substitute an in-memory
// switch that delivers datagrams between registered addresses with the
// same fire-and-forget semantics.
// ---------------------------------------------------------------------------

pub trait Transport: Send + Sync + 'static {
    fn local_addr(&self) -> SocketAddr;
    // RPITIT form (not async fn) on purpose: callers spawn these futures
    // onto tokio tasks, so the + Send bound is part of the contract.
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        addr: SocketAddr,
    ) -> impl std::future::Future<Output = std::io::Result<usize>> + Send + 'a;
    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> impl std::future::Future<Output = std::io::Result<(usize, SocketAddr)>> + Send + 'a;
}

pub struct UdpTransport {
    socket: UdpSocket,
}

impl Transport for UdpTransport {
    fn local_addr(&self) -> SocketAddr {
        let addr = self.socket.local_addr().unwrap();
        if addr.ip().is_unspecified() {
            SocketAddr::from(([127, 0, 0, 1], addr.port()))
        } else {
            addr
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        addr: SocketAddr,
    ) -> impl std::future::Future<Output = std::io::Result<usize>> + Send + 'a {
        self.socket.send_to(buf, addr)
    }

    #[allow(clippy::manual_async_fn)]
    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> impl std::future::Future<Output = std::io::Result<(usize, SocketAddr)>> + Send + 'a {
        self.socket.recv_from(buf)
    }
}

/// A shared in-memory switchboard for tests: transports register an
/// address and receive datagrams addressed to them.
/// Datagram queue endpoints keyed by listen address (MemoryHub state).
type HubNodes = HashMap<SocketAddr, mpsc::Sender<(Vec<u8>, SocketAddr)>>;

/// Application payloads delivered by a tunnel: (source virtual IP, bytes).
pub type AppRx = mpsc::Receiver<(String, Vec<u8>)>;

pub struct MemoryHub {
    nodes: std::sync::Mutex<HubNodes>,
}

impl MemoryHub {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            nodes: std::sync::Mutex::new(HashMap::new()),
        })
    }

    pub fn register(self: &Arc<Self>, addr: SocketAddr) -> MemoryTransport {
        let (tx, rx) = mpsc::channel(4096);
        self.nodes.lock().unwrap().insert(addr, tx);
        MemoryTransport {
            hub: self.clone(),
            addr,
            inbox: tokio::sync::Mutex::new(rx),
        }
    }
}

pub struct MemoryTransport {
    hub: Arc<MemoryHub>,
    addr: SocketAddr,
    inbox: tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
}

impl Transport for MemoryTransport {
    fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    #[allow(clippy::manual_async_fn)]
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        addr: SocketAddr,
    ) -> impl std::future::Future<Output = std::io::Result<usize>> + Send + 'a {
        async move {
            let dest = self.hub.nodes.lock().unwrap().get(&addr).cloned();
            if let Some(tx) = dest {
                // Fire-and-forget, exactly like UDP: a full or closed
                // queue drops the datagram without erroring the sender.
                let _ = tx.try_send((buf.to_vec(), self.addr));
            }
            Ok(buf.len())
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> impl std::future::Future<Output = std::io::Result<(usize, SocketAddr)>> + Send + 'a {
        async move {
            let mut inbox = self.inbox.lock().await;
            match inbox.recv().await {
                Some((data, from)) => {
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    Ok((n, from))
                }
                None => Err(std::io::Error::other("hub closed")),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Chaos transport (tests only): wraps a MemoryTransport and subjects
// datagrams to seeded, deterministic loss, duplication and
// reordering — the failure modes of a real UDP path — so stream
// reliability is proven against them instead of against a perfect
// switchboard. A background flusher releases held (reordered)
// datagrams in random order on a short cadence.
// ---------------------------------------------------------------------------

#[cfg(test)]
pub struct ChaosTransport {
    inner: Arc<MemoryTransport>,
    state: Arc<std::sync::Mutex<ChaosState>>,
}

#[cfg(test)]
struct ChaosState {
    rng: u64,
    drop_pct: u32,
    dup_pct: u32,
    hold_pct: u32,
    held: Vec<(Vec<u8>, SocketAddr)>,
    /// Deterministic loss for regression tests: while > 0, the
    /// next sends are dropped regardless of the random rolls.
    drop_next: u32,
}

#[cfg(test)]
fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

#[cfg(test)]
impl ChaosTransport {
    pub fn wrap(inner: MemoryTransport, seed: u64, drop_pct: u32, dup_pct: u32) -> Self {
        let inner = Arc::new(inner);
        let state = Arc::new(std::sync::Mutex::new(ChaosState {
            rng: if seed == 0 { 0x9E3779B97F4A7C15 } else { seed },
            drop_pct,
            dup_pct,
            hold_pct: 20,
            held: Vec::new(),
            drop_next: 0,
        }));
        let flush_inner = inner.clone();
        let flush_state = state.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(2)).await;
                let batch: Vec<(Vec<u8>, SocketAddr)> = {
                    let mut st = flush_state.lock().unwrap();
                    let mut out = Vec::new();
                    while !st.held.is_empty() {
                        let idx = (xorshift(&mut st.rng) as usize) % st.held.len();
                        out.push(st.held.swap_remove(idx));
                    }
                    out
                };
                for (frame, addr) in batch {
                    let _ = flush_inner.send_to(&frame, addr).await;
                }
            }
        });
        Self { inner, state }
    }
}

#[cfg(test)]
impl Clone for ChaosTransport {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            state: self.state.clone(),
        }
    }
}

#[cfg(test)]
impl ChaosTransport {
    /// Arms deterministic loss: the next `n` datagrams this
    /// transport sends are dropped, whatever the random rolls
    /// say. Used to kill one specific protocol frame (e.g. a
    /// stream OPEN) on demand.
    pub fn drop_next_sends(&self, n: u32) {
        self.state.lock().unwrap().drop_next = n;
    }
}

#[cfg(test)]
impl Transport for ChaosTransport {
    fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr()
    }

    #[allow(clippy::manual_async_fn)]
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        addr: SocketAddr,
    ) -> impl std::future::Future<Output = std::io::Result<usize>> + Send + 'a {
        async move {
            enum Act {
                Drop,
                Send,
                Dup,
                Hold,
            }
            let act = {
                let mut st = self.state.lock().unwrap();
                if st.drop_next > 0 {
                    st.drop_next -= 1;
                    Act::Drop
                } else {
                    let roll = xorshift(&mut st.rng) % 100;
                    if roll < st.drop_pct as u64 {
                        Act::Drop
                    } else if roll < (st.drop_pct + st.dup_pct) as u64 {
                        Act::Dup
                    } else if roll < (st.drop_pct + st.dup_pct + st.hold_pct) as u64 {
                        st.held.push((buf.to_vec(), addr));
                        Act::Hold
                    } else {
                        Act::Send
                    }
                }
            };
            match act {
                Act::Drop => Ok(buf.len()),
                Act::Send => self.inner.send_to(buf, addr).await,
                Act::Dup => {
                    let _ = self.inner.send_to(buf, addr).await;
                    self.state.lock().unwrap().held.push((buf.to_vec(), addr));
                    Ok(buf.len())
                }
                Act::Hold => Ok(buf.len()),
            }
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> impl std::future::Future<Output = std::io::Result<(usize, SocketAddr)>> + Send + 'a {
        self.inner.recv_from(buf)
    }
}

enum PeerState {
    Idle,
    AwaitingResponse {
        initiator: Option<HandshakeInitiator>,
        local_index: u32,
        since: Instant,
    },
    Established {
        session: Session,
        local_index: u32,
        remote_index: u32,
        since: Instant,
    },
}

/// Rotating secret behind issued cookies (see cookie_value).
struct CookieJar {
    current: [u8; 32],
    prev: Option<[u8; 32]>,
    rotated: Instant,
}

impl CookieJar {
    fn new() -> Self {
        use rand_core::RngCore;
        let mut current = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut current);
        Self {
            current,
            prev: None,
            rotated: Instant::now(),
        }
    }
}

struct Peer {
    public: PublicKey,
    public_hex: String,
    role: Mutex<String>,
    vip: [u8; 4],
    endpoint: Mutex<Option<SocketAddr>>,
    state: Mutex<PeerState>,
    /// Highest handshake-init timestamp accepted from this peer so far
    /// (millis). Enforces strictly increasing INIT freshness.
    last_init_ms: Mutex<u64>,
    latency_ms: Mutex<f64>,
    /// Last AUTHENTICATED INBOUND frame from this peer. Never
    /// updated on send — silence-based liveness reads this.
    last_activity: Mutex<Instant>,
}

/// Coalescing state for the freshness writer: at most one
/// writer thread exists; persists that arrive while it writes
/// replace `pending`, and the writer loops until no newer
/// snapshot is waiting (see Tunnel::persist_freshness).
struct FreshnessWriter {
    pending: Option<(std::path::PathBuf, String)>,
    active: bool,
}

/// On-disk INIT freshness state (see Tunnel::set_freshness_dir).
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct FreshnessFile {
    self_last_init_ms: u64,
    peers: HashMap<String, u64>,
}

/// Why mesh-data traffic was denied: an explicit DENY rule, or the
/// default posture when no ALLOW rule matches the source role.
#[derive(Debug, Clone)]
pub enum AclDeny {
    Rule(AclRule),
    DefaultDeny,
}

/// The verdict of the single ACL decision every enforcement point
/// shares: the tunnel's data gate (service "mesh-data", port 0) and
/// the service gateway (a named service on a concrete port).
#[derive(Debug, Clone, PartialEq)]
pub enum AclDecision {
    Allow,
    /// A matching DENY rule decides (deny-override at any priority).
    DenyRule(AclRule),
    /// No ALLOW rule matched: the default posture is deny.
    DefaultDeny,
}

/// Evaluates `rules` for one (source role, service, port) question.
///
/// A rule matches when its role is "*" or the source role, its
/// service is "*" or the queried service, and its port is 0 (any) or
/// the queried port. DENY overrides ALLOW regardless of priority;
/// with no matching ALLOW the default is deny. Since the Round-3
/// review this is the only place these semantics live: before, the
/// data path evaluated a wildcard-only subset and service-specific
/// rules were decided nowhere.
pub fn acl_decision(rules: &[AclRule], source_role: &str, service: &str, port: u16) -> AclDecision {
    let mut best_deny: Option<&AclRule> = None;
    let mut allowed = false;
    for rule in rules {
        let matches = (rule.source_role == "*" || rule.source_role == source_role)
            && (rule.dest_service == "*" || rule.dest_service == service)
            && (rule.port == 0 || rule.port == port);
        if !matches {
            continue;
        }
        if rule.action == "DENY" {
            if best_deny.is_none_or(|b| rule.priority < b.priority) {
                best_deny = Some(rule);
            }
        } else if rule.action == "ALLOW" {
            allowed = true;
        }
    }
    if let Some(rule) = best_deny {
        return AclDecision::DenyRule(rule.clone());
    }
    if allowed {
        AclDecision::Allow
    } else {
        AclDecision::DefaultDeny
    }
}

/// A service-stream event delivered to the gateway. Only OPEN is an
/// event: stream DATA is pulled in order through
/// [`Tunnel::next_stream_data`] (which is what makes ordered,
/// loss-free delivery natural to consume), and end-of-stream is that
/// call returning `None`. The sender's vip and role are resolved from
/// the authenticated session and the peer table exactly like the data
/// path — a relaying peer cannot launder the origin's identity.
#[derive(Debug, Clone)]
pub enum StreamEvent {
    Open {
        src_vip: String,
        src_role: String,
        stream_id: u32,
        service: String,
        port: u16,
    },
}

/// Sender-side state for one stream direction (us -> peer).
struct OutStream {
    state: Mutex<OutStreamState>,
    /// Signalled when an ACK advances the window or the stream dies.
    notify: tokio::sync::Notify,
}

struct OutStreamState {
    /// Next sequence number to assign.
    next_seq: u32,
    /// Frames sent but not yet cumulatively acknowledged, kept for
    /// retransmission: seq -> (last sent, full frame body).
    unacked: std::collections::BTreeMap<u32, (Instant, Vec<u8>)>,
    open_body: Vec<u8>,
    open_last_sent: Instant,
    open_acked: bool,
    /// Set when close was requested: the final sequence number (one
    /// past the last DATA frame) the peer must reach.
    close_final: Option<u32>,
    close_last_sent: Option<Instant>,
    close_acked: bool,
    /// A RESET arrived (or the stream was abandoned locally): sends
    /// fail and retransmission stops.
    dead: bool,
    last_activity: Instant,
}

impl OutStream {
    fn new() -> Self {
        Self {
            state: Mutex::new(OutStreamState {
                next_seq: 0,
                unacked: std::collections::BTreeMap::new(),
                open_body: Vec::new(),
                open_last_sent: Instant::now(),
                open_acked: false,
                close_final: None,
                close_last_sent: None,
                close_acked: false,
                dead: false,
                last_activity: Instant::now(),
            }),
            notify: tokio::sync::Notify::new(),
        }
    }
}

/// Receiver-side state for one stream direction (peer -> us).
struct InStream {
    state: Mutex<InStreamState>,
    /// Signalled when ordered data or end-of-stream becomes
    /// available for `next_stream_data`.
    notify: tokio::sync::Notify,
}

struct InStreamState {
    /// Next sequence number to release to the consumer; also the
    /// cumulative acknowledgement we advertise.
    next_expected: u32,
    /// Out-of-order frames waiting for their predecessors.
    buffered: std::collections::BTreeMap<u32, Vec<u8>>,
    /// In-order payloads ready for the consumer (bounded: see
    /// STREAM_DELIVERY_CAP).
    delivery: std::collections::VecDeque<Vec<u8>>,
    /// The sender's final sequence number, once its CLOSE arrives.
    close_at: Option<u32>,
    open_seen: bool,
    open_emitted: bool,
    /// End-of-stream was reached and reported.
    finished: bool,
    /// A RESET arrived: the consumer sees end-of-stream and buffered
    /// data is discarded (the stream was refused or aborted).
    dead: bool,
    last_activity: Instant,
}

impl InStream {
    fn new() -> Self {
        Self {
            state: Mutex::new(InStreamState {
                next_expected: 0,
                buffered: std::collections::BTreeMap::new(),
                delivery: std::collections::VecDeque::new(),
                close_at: None,
                open_seen: false,
                open_emitted: false,
                finished: false,
                dead: false,
                last_activity: Instant::now(),
            }),
            notify: tokio::sync::Notify::new(),
        }
    }

    /// True when the CLOSE is fully satisfied: every frame up to the
    /// final sequence number has been released to the delivery
    /// queue. This is the flag ACKs advertise as "close complete".
    fn close_complete(st: &InStreamState) -> bool {
        match st.close_at {
            Some(final_seq) => st.next_expected >= final_seq && st.buffered.is_empty(),
            None => false,
        }
    }

    /// Moves consecutive buffered frames into the delivery queue,
    /// stopping at the delivery cap (backpressure) or a gap.
    fn drain(st: &mut InStreamState) {
        while st.delivery.len() < STREAM_DELIVERY_CAP {
            match st.buffered.remove(&st.next_expected) {
                Some(payload) => {
                    st.delivery.push_back(payload);
                    st.next_expected += 1;
                }
                None => break,
            }
        }
    }
}

pub struct Tunnel<T: Transport> {
    transport: Arc<T>,
    identity: Arc<Identity>,
    local_vip: [u8; 4],
    peers: Mutex<HashMap<String, Arc<Peer>>>,
    by_index: Mutex<HashMap<u32, String>>,
    routes: Mutex<HashMap<[u8; 4], String>>,
    telemetry: Arc<TelemetryCounters>,
    ring: Arc<EventRing>,
    acl_rules: Mutex<Vec<AclRule>>,
    local_role: String,
    last_init_ms: Mutex<u64>,
    rekey_after_secs: std::sync::atomic::AtomicU64,
    /// Persisted per-peer INIT freshness floors (survive restarts).
    init_floors: Mutex<HashMap<String, u64>>,
    /// Boot-time replay floor applied to EVERY peer. Zero in the
    /// normal case; seeded to the boot time when the persisted
    /// freshness state could not be read back (corrupt or
    /// unreadable), so a damaged state file fails CLOSED — old
    /// INITs stay rejected — instead of silently reopening the
    /// replay window.
    init_floor_default: Mutex<u64>,
    /// Serializes the background freshness writer threads.
    freshness_writer: std::sync::Arc<Mutex<FreshnessWriter>>,
    freshness_file: Mutex<Option<std::path::PathBuf>>,
    /// Per-source INIT rate-limit windows (pre-auth DoS guard).
    init_rate: Mutex<HashMap<SocketAddr, (Instant, u32)>>,
    /// Aggregate initiation budget: (window start, proof-less
    /// count, proof count) over a 1 s window, across all sources.
    init_global: Mutex<(Instant, u32, u32)>,
    /// WireGuard-style cookie state. `cookie_jar` holds our
    /// rotating responder secret (current + previous); a peer
    /// that exceeds the INIT rate limit is sent a cookie bound
    /// to its source address and must retry with a MAC over the
    /// INIT frame (mac2) — proving it can RECEIVE at the address
    /// it claims — before we spend any X25519 work on it.
    /// `cookies_out` caches cookies peers issued to us, keyed by
    /// their endpoint.
    cookie_jar: Mutex<CookieJar>,
    cookies_out: Mutex<HashMap<SocketAddr, ([u8; 16], Instant)>>,
    cookie_sent: Mutex<HashMap<SocketAddr, Instant>>,
    /// Bounds concurrent frame handlers (UDP flood guard); acquired in
    /// the receive loop before a handler task is spawned.
    frame_permits: Arc<tokio::sync::Semaphore>,
    app_tx: mpsc::Sender<(String, Vec<u8>)>,
    stream_tx: mpsc::Sender<StreamEvent>,
    stream_rx: Mutex<Option<mpsc::Receiver<StreamEvent>>>,
    /// Reliable-stream state, keyed by (peer vip, stream id); the
    /// two maps are the two independent directions of a stream.
    out_streams: Mutex<HashMap<(String, u32), Arc<OutStream>>>,
    in_streams: Mutex<HashMap<(String, u32), Arc<InStream>>>,
    /// Recently reset (peer, stream id) pairs. A RESET can race
    /// ahead of the gateway registering its interest in the stream;
    /// the tombstone makes a stream state created just after the
    /// reset still come up dead instead of hanging forever. Entries
    /// expire (see housekeeping), after which the id may be reused.
    stream_tombstones: Mutex<HashMap<(String, u32), Instant>>,
    started: Instant,
}

pub fn vip_to_octets(vip: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = vip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        out[i] = p.parse().ok()?;
    }
    Some(out)
}

pub fn octets_to_vip(octets: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

impl Tunnel<UdpTransport> {
    pub async fn bind(
        listen_port: u16,
        identity: Identity,
        local_vip: &str,
        local_role: &str,
        telemetry: Arc<TelemetryCounters>,
        ring: Arc<EventRing>,
    ) -> Result<(Arc<Tunnel<UdpTransport>>, mpsc::Receiver<(String, Vec<u8>)>)> {
        let socket = UdpSocket::bind(("0.0.0.0", listen_port)).await?;
        Self::bind_with_transport(
            UdpTransport { socket },
            identity,
            local_vip,
            local_role,
            telemetry,
            ring,
        )
    }
}

impl<T: Transport> Tunnel<T> {
    pub fn bind_with_transport(
        transport: T,
        identity: Identity,
        local_vip: &str,
        local_role: &str,
        telemetry: Arc<TelemetryCounters>,
        ring: Arc<EventRing>,
    ) -> Result<(Arc<Self>, AppRx)> {
        let octets =
            vip_to_octets(local_vip).ok_or_else(|| anyhow!("invalid virtual ip {local_vip}"))?;
        let (app_tx, app_rx) = mpsc::channel(1024);
        let (stream_tx, stream_rx) = mpsc::channel(256);
        let tunnel = Arc::new(Self {
            transport: Arc::new(transport),
            identity: Arc::new(identity),
            local_vip: octets,
            peers: Mutex::new(HashMap::new()),
            by_index: Mutex::new(HashMap::new()),
            routes: Mutex::new(HashMap::new()),
            telemetry,
            ring,
            acl_rules: Mutex::new(Vec::new()),
            local_role: local_role.to_string(),
            last_init_ms: Mutex::new(0),
            rekey_after_secs: std::sync::atomic::AtomicU64::new(REKEY_AFTER_SECS),
            init_floors: Mutex::new(HashMap::new()),
            init_floor_default: Mutex::new(0),
            freshness_writer: std::sync::Arc::new(Mutex::new(FreshnessWriter {
                pending: None,
                active: false,
            })),
            freshness_file: Mutex::new(None),
            init_rate: Mutex::new(HashMap::new()),
            init_global: Mutex::new((Instant::now(), 0, 0)),
            cookie_jar: Mutex::new(CookieJar::new()),
            cookies_out: Mutex::new(HashMap::new()),
            cookie_sent: Mutex::new(HashMap::new()),
            frame_permits: Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT_FRAMES)),
            app_tx,
            stream_tx,
            stream_rx: Mutex::new(Some(stream_rx)),
            out_streams: Mutex::new(HashMap::new()),
            in_streams: Mutex::new(HashMap::new()),
            stream_tombstones: Mutex::new(HashMap::new()),
            started: Instant::now(),
        });
        Ok((tunnel, app_rx))
    }

    /// The address peers can reach this node at (the transport's
    /// reachable form — never the unspecified bind address).
    pub fn local_addr(&self) -> SocketAddr {
        self.transport.local_addr()
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    fn next_index(&self) -> u32 {
        // Session indices are wire-visible lookup keys; sequential values
        // are predictable, so draw random ones (as WireGuard does) and
        // retry on the (astronomically unlikely) collision.
        use rand_core::RngCore;
        let by_index = self.by_index.lock().unwrap();
        loop {
            let mut b = [0u8; 4];
            rand_core::OsRng.fill_bytes(&mut b);
            let idx = u32::from_le_bytes(b);
            if idx != 0 && !by_index.contains_key(&idx) {
                return idx;
            }
        }
    }

    /// Monotonically increasing handshake timestamp (millis). The wall
    /// clock alone can repeat a millisecond or step backwards; responders
    /// enforce strictly increasing timestamps per peer, so the initiator
    /// guarantees them even across rapid successive handshakes.
    fn next_init_ts(&self) -> u64 {
        let ts = {
            let mut last = self.last_init_ms.lock().unwrap();
            let ts = now_millis().max(*last + 1);
            *last = ts;
            ts
        };
        self.persist_freshness();
        ts
    }

    /// Points the tunnel at a state directory for INIT-freshness
    /// persistence and seeds both monotonic clocks from disk. Without
    /// this, a restart would forget the accepted-timestamp floors: a
    /// captured INIT could be replayed at a fresh responder, and our own
    /// clock could sit behind a responder's floor after a backward step.
    pub fn set_freshness_dir(&self, dir: &std::path::Path) {
        let path = dir.join("freshness.json");
        match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<FreshnessFile>(&text) {
                Ok(f) => {
                    {
                        let mut last = self.last_init_ms.lock().unwrap();
                        *last = (*last).max(f.self_last_init_ms);
                    }
                    *self.init_floors.lock().unwrap() = f.peers;
                }
                Err(e) => self.freshness_fail_closed(&path, &format!("parse error: {e}")),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // First run on this state dir: nothing to restore.
            }
            Err(e) => self.freshness_fail_closed(&path, &format!("read error: {e}")),
        }
        *self.freshness_file.lock().unwrap() = Some(path);
    }

    /// The persisted INIT-freshness state is damaged: seed the
    /// floors at the current time so no INIT older than this
    /// boot can be replayed, and say so loudly. Availability is
    /// preserved (fresh handshakes carry fresh timestamps);
    /// only the replay window stays shut.
    fn freshness_fail_closed(&self, path: &std::path::Path, why: &str) {
        let now = now_millis();
        {
            let mut last = self.last_init_ms.lock().unwrap();
            *last = (*last).max(now);
        }
        *self.init_floor_default.lock().unwrap() = now;
        self.ring.push(format!(
            "freshness state {} unusable ({why}); replay floors seeded at boot time (fail-closed)",
            path.display()
        ));
    }

    fn persist_freshness(&self) {
        let path = match self.freshness_file.lock().unwrap().clone() {
            Some(p) => p,
            None => return,
        };
        // Snapshot synchronously (cheap), then write OFF the
        // caller's path: this runs inside async handshake code,
        // where blocking file IO would stall the runtime.
        let f = FreshnessFile {
            self_last_init_ms: *self.last_init_ms.lock().unwrap(),
            peers: self.init_floors.lock().unwrap().clone(),
        };
        let text = match serde_json::to_string(&f) {
            Ok(t) => t,
            Err(_) => return,
        };
        // Coalesced writer: persists can arrive far faster than
        // fsync completes (every accepted INIT persists). Instead
        // of one thread per call queueing on a lock, a single
        // writer thread drains the LATEST snapshot: calls that
        // arrive while it writes just replace the pending
        // snapshot. Each write is atomic (temp file + fsync +
        // rename + dir fsync), so a crash leaves either the old
        // or the new complete file — never a torn one that
        // would reopen the replay window.
        let spawn_writer = {
            let mut w = self.freshness_writer.lock().unwrap();
            w.pending = Some((path, text));
            if w.active {
                false
            } else {
                w.active = true;
                true
            }
        };
        if !spawn_writer {
            return;
        }
        let writer = self.freshness_writer.clone();
        std::thread::spawn(move || loop {
            let (path, text) = {
                let mut w = writer.lock().unwrap();
                match w.pending.take() {
                    Some(v) => v,
                    None => {
                        w.active = false;
                        return;
                    }
                }
            };
            let tmp = path.with_extension("json.tmp");
            let write = (|| -> std::io::Result<()> {
                use std::io::Write;
                let mut file = std::fs::File::create(&tmp)?;
                file.write_all(text.as_bytes())?;
                file.sync_all()?;
                drop(file);
                std::fs::rename(&tmp, &path)?;
                if let Some(dir) = path.parent() {
                    if let Ok(d) = std::fs::File::open(dir) {
                        let _ = d.sync_all();
                    }
                }
                Ok(())
            })();
            if write.is_err() {
                let _ = std::fs::remove_file(&tmp);
            }
        });
    }

    // -- peer table -----------------------------------------------------------

    pub fn add_peer(&self, public_hex: &str, vip: &str, endpoint: Option<SocketAddr>, role: &str) {
        let key_bytes = match hex_decode(public_hex) {
            Ok(b) if b.len() == 32 => b,
            _ => return,
        };
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key_bytes);
        let octets = match vip_to_octets(vip) {
            Some(o) => o,
            None => return,
        };
        // LOCK DISCIPLINE (whole file): a tunnel-level lock (peers,
        // routes, by_index, ...) is never held while acquiring another
        // one. An earlier version nested peers->routes here and
        // routes->peers in peer_by_vip - a classic ABBA deadlock when a
        // heartbeat peer-sync raced a data packet.
        let is_new = {
            let mut peers = self.peers.lock().unwrap();
            if let Some(existing) = peers.get(public_hex) {
                if let Some(ep) = endpoint {
                    *existing.endpoint.lock().unwrap() = Some(ep);
                }
                *existing.role.lock().unwrap() = role.to_string();
                false
            } else {
                let peer = Arc::new(Peer {
                    public: PublicKey::from(arr),
                    public_hex: public_hex.to_string(),
                    role: Mutex::new(role.to_string()),
                    vip: octets,
                    endpoint: Mutex::new(endpoint),
                    state: Mutex::new(PeerState::Idle),
                    last_init_ms: Mutex::new(0),
                    latency_ms: Mutex::new(0.0),
                    last_activity: Mutex::new(Instant::now()),
                });
                peers.insert(public_hex.to_string(), peer);
                true
            }
        };
        self.routes
            .lock()
            .unwrap()
            .insert(octets, public_hex.to_string());
        if is_new {
            self.ring
                .push(format!("peer added: {} ({})", public_hex, vip));
        }
    }

    /// Syncs the peer table from a control-plane peer list (heartbeat
    /// responses / registration). Our own entry is skipped.
    ///
    /// Departed peers are removed: a peer that is absent from
    /// the list AND has been silent past the dead threshold is
    /// dropped (routes, session indices and stream state
    /// included), so the table reflects current membership
    /// instead of growing for the life of the daemon. Two guards
    /// keep a glitch from doing damage: an empty list removes
    /// nobody, and a peer that is actively talking to us is
    /// never removed by a sync.
    pub fn update_peers(&self, peers: &[PeerNode]) {
        let self_hex = self.identity.public_hex();
        let incoming: std::collections::HashSet<&str> =
            peers.iter().map(|p| p.public_key.as_str()).collect();
        for p in peers {
            if p.public_key == self_hex {
                continue;
            }
            let endpoint = p.endpoint.parse::<SocketAddr>().ok();
            self.add_peer(&p.public_key, &p.virtual_ip, endpoint, &p.role);
        }
        if peers.is_empty() {
            return;
        }
        let current: Vec<(String, [u8; 4], Duration)> = {
            let table = self.peers.lock().unwrap();
            table
                .values()
                .map(|peer| {
                    (
                        peer.public_hex.clone(),
                        peer.vip,
                        peer.last_activity.lock().unwrap().elapsed(),
                    )
                })
                .collect()
        };
        for (pubkey, vip_octets, silence) in current {
            if pubkey == self_hex
                || incoming.contains(pubkey.as_str())
                || silence <= PEER_SILENCE_DEAD
            {
                continue;
            }
            let vip = octets_to_vip(&vip_octets);
            let stream_ids: Vec<u32> = {
                let mut ids: Vec<u32> = self
                    .out_streams
                    .lock()
                    .unwrap()
                    .keys()
                    .filter(|(v, _)| v == &vip)
                    .map(|(_, id)| *id)
                    .collect();
                ids.extend(
                    self.in_streams
                        .lock()
                        .unwrap()
                        .keys()
                        .filter(|(v, _)| v == &vip)
                        .map(|(_, id)| *id),
                );
                ids.sort_unstable();
                ids.dedup();
                ids
            };
            for stream_id in stream_ids {
                self.apply_reset(&vip, stream_id);
            }
            {
                let mut routes = self.routes.lock().unwrap();
                if routes.get(&vip_octets).map(|k| k.as_str()) == Some(pubkey.as_str()) {
                    routes.remove(&vip_octets);
                }
            }
            self.by_index.lock().unwrap().retain(|_, v| v != &pubkey);
            self.peers.lock().unwrap().remove(&pubkey);
            self.ring.push(format!("peer removed: {pubkey} ({vip})"));
        }
    }

    pub fn peer_count(&self) -> usize {
        self.peers.lock().unwrap().len()
    }

    /// The end-to-end key shared with the node that OWNS
    /// `dst_vip` (the final destination, not the next hop),
    /// derived from the pairwise static X25519 secret. `None`
    /// when the destination is not a known peer.
    /// The directional E2E key for traffic involving the peer at
    /// `other_vip`. `from_local` = true derives the key for traffic
    /// WE originate to that peer (sender = us); false derives the
    /// key for traffic that peer originates to us (sender = them).
    /// The two directions use different keys.
    fn e2e_key_for(&self, other_vip: &[u8; 4], from_local: bool) -> Option<[u8; 32]> {
        let peer = {
            let peers = self.peers.lock().unwrap();
            peers.values().find(|p| p.vip == *other_vip).cloned()
        }?;
        let sender = if from_local {
            self.identity.public
        } else {
            peer.public
        };
        crate::crypto::e2e_key(&self.identity.secret(), &peer.public, &sender).ok()
    }

    /// Public keys of peers with established encrypted sessions; the
    /// control plane renders topology links from these reports.
    pub fn established_peer_keys(&self) -> Vec<String> {
        let peers: Vec<Arc<Peer>> = self.peers.lock().unwrap().values().cloned().collect();
        peers
            .iter()
            .filter(|p| matches!(*p.state.lock().unwrap(), PeerState::Established { .. }))
            .map(|p| p.public_hex.clone())
            .collect()
    }

    pub fn connected_peer_count(&self) -> u32 {
        let peers: Vec<Arc<Peer>> = self.peers.lock().unwrap().values().cloned().collect();
        peers
            .iter()
            .filter(|p| matches!(*p.state.lock().unwrap(), PeerState::Established { .. }))
            .count() as u32
    }

    pub fn avg_latency_ms(&self) -> f64 {
        let peers: Vec<Arc<Peer>> = self.peers.lock().unwrap().values().cloned().collect();
        let vals: Vec<f64> = peers
            .iter()
            .map(|p| *p.latency_ms.lock().unwrap())
            .filter(|v| *v > 0.0)
            .collect();
        if vals.is_empty() {
            0.0
        } else {
            vals.iter().sum::<f64>() / vals.len() as f64
        }
    }

    fn peer_by_vip(&self, vip: &[u8; 4]) -> Option<Arc<Peer>> {
        // Two separate, sequential lock acquisitions (see add_peer).
        let key = self.routes.lock().unwrap().get(vip).cloned()?;
        self.peers.lock().unwrap().get(&key).cloned()
    }

    fn peer_by_index(&self, index: u32) -> Option<Arc<Peer>> {
        let key = self.by_index.lock().unwrap().get(&index).cloned()?;
        self.peers.lock().unwrap().get(&key).cloned()
    }

    // -- zero-trust ACL enforcement -------------------------------------
    //
    // Policy is evaluated at the mesh-data service granularity: rules
    // whose destination is "*" or "mesh-data" with port 0 (wildcard)
    // govern data-plane traffic; service-specific rules (e.g.
    // edge -> postgres:5432) are enforced by the service gateways that
    // terminate those services.
    //
    // Semantics are DENY-OVERRIDE with a DEFAULT-DENY posture:
    // * every matching rule is considered — priority never decides the
    //   outcome (it only picks which DENY rule gets reported);
    // * any matching DENY drops the traffic, even when an ALLOW with a
    //   better priority also matches;
    // * traffic with no matching ALLOW is denied by default, so an
    //   empty policy passes nothing.
    // A denial increments telemetry.drops and logs to the ring.

    /// Replaces the enforced policy (called by the ACL sync loop).
    pub fn update_acls(&self, rules: &[AclRule]) {
        *self.acl_rules.lock().unwrap() = rules.to_vec();
        self.ring
            .push(format!("acl: policy updated ({} rules)", rules.len()));
    }

    /// Decides whether mesh data from `source_role` is denied, and why.
    /// Returns `None` only when a matching ALLOW grants the traffic and
    /// no matching DENY overrides it.
    fn acl_denied_for(&self, source_role: &str) -> Option<AclDeny> {
        let rules = self.acl_rules.lock().unwrap();
        match acl_decision(&rules, source_role, "mesh-data", 0) {
            AclDecision::Allow => None,
            AclDecision::DenyRule(rule) => Some(AclDeny::Rule(rule)),
            AclDecision::DefaultDeny => Some(AclDeny::DefaultDeny),
        }
    }

    // -- sending ---------------------------------------------------------------

    async fn send_raw(&self, endpoint: SocketAddr, frame: &[u8]) {
        match self.transport.send_to(frame, endpoint).await {
            Ok(n) => {
                self.telemetry.packets_out.fetch_add(1, Ordering::Relaxed);
                self.telemetry
                    .bytes_out
                    .fetch_add(n as u64, Ordering::Relaxed);
                self.telemetry
                    .userspace_packets
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                self.ring.push(format!("send to {endpoint} failed: {e}"));
            }
        }
    }

    async fn initiate_handshake(&self, peer: &Arc<Peer>) -> Result<()> {
        let local_index = self.next_index();
        let mut initiator = HandshakeInitiator::new(self.identity.secret(), peer.public);
        let init_ts = self.next_init_ts();
        let msg1 = initiator.write_message1(&init_ts.to_le_bytes())?;
        self.by_index
            .lock()
            .unwrap()
            .insert(local_index, peer.public_hex.clone());
        {
            let mut state = peer.state.lock().unwrap();
            *state = PeerState::AwaitingResponse {
                initiator: Some(initiator),
                local_index,
                since: Instant::now(),
            };
        }
        let endpoint = peer
            .endpoint
            .lock()
            .unwrap()
            .ok_or_else(|| anyhow!("peer {} has no known endpoint", peer.public_hex))?;
        let mut frame = Vec::with_capacity(8 + msg1.len());
        frame.push(MSG_INIT);
        frame.extend_from_slice(&[0, 0, 0]);
        frame.extend_from_slice(&local_index.to_le_bytes());
        frame.extend_from_slice(&msg1);
        // If this peer challenged us recently, attach the proof:
        // mac2 over the whole INIT frame, keyed by their cookie.
        let cookie = self
            .cookies_out
            .lock()
            .unwrap()
            .get(&endpoint)
            .and_then(|(c, at)| {
                if at.elapsed() < COOKIE_TTL {
                    Some(*c)
                } else {
                    None
                }
            });
        if let Some(cookie) = cookie {
            let proof = Self::mac2(&cookie, &frame);
            frame.extend_from_slice(&proof);
        }
        self.send_raw(endpoint, &frame).await;
        Ok(())
    }

    async fn ensure_session(&self, peer: &Arc<Peer>) -> Result<()> {
        // One retry around the single-attempt helper: if the first attempt
        // timed out and left a stale AwaitingResponse behind (its INIT or
        // the answering RESP was lost), reset it and initiate again rather
        // than wedging the peer until restart.
        for attempt in 0..2 {
            match self.ensure_session_once(peer).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if attempt == 0 {
                        let stale = {
                            let state = peer.state.lock().unwrap();
                            matches!(
                                &*state,
                                PeerState::AwaitingResponse { since, .. }
                                    if since.elapsed() > HANDSHAKE_WAIT
                            )
                        };
                        if stale {
                            *peer.state.lock().unwrap() = PeerState::Idle;
                            continue;
                        }
                    }
                    return Err(e);
                }
            }
        }
        Err(anyhow!(
            "handshake with {} did not complete",
            peer.public_hex
        ))
    }

    async fn ensure_session_once(&self, peer: &Arc<Peer>) -> Result<()> {
        let needs_init = {
            let mut state = peer.state.lock().unwrap();
            match &mut *state {
                PeerState::Established {
                    session,
                    since,
                    local_index,
                    ..
                } => {
                    if session.initiator
                        && since.elapsed()
                            > Duration::from_secs(self.rekey_after_secs.load(Ordering::Relaxed))
                    {
                        // Rekey: retire the old session index and fall
                        // through to a fresh handshake with new keys.
                        let old = *local_index;
                        *state = PeerState::Idle;
                        drop(state);
                        self.by_index.lock().unwrap().remove(&old);
                        true
                    } else {
                        return Ok(());
                    }
                }
                PeerState::Idle => true,
                PeerState::AwaitingResponse { since, .. } => {
                    if since.elapsed() > HANDSHAKE_WAIT {
                        // The INIT or its RESP was lost; reset instead of
                        // wedging this peer in AwaitingResponse forever.
                        *state = PeerState::Idle;
                        true
                    } else {
                        false
                    }
                }
            }
        };
        if needs_init {
            self.initiate_handshake(peer).await?;
        }
        let deadline = Instant::now() + HANDSHAKE_WAIT;
        loop {
            {
                let state = peer.state.lock().unwrap();
                if matches!(*state, PeerState::Established { .. }) {
                    return Ok(());
                }
            }
            if Instant::now() > deadline {
                return Err(anyhow!(
                    "handshake with {} did not complete in time",
                    peer.public_hex
                ));
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Seals and sends an inner packet toward `dst_vip` (direct peer or
    /// via the routing table's next hop).
    pub async fn send_inner(&self, dst_vip: [u8; 4], kind: u8, body: &[u8]) -> Result<()> {
        self.send_inner_full(dst_vip, kind, body, self.local_vip, DEFAULT_TTL)
            .await
    }

    /// Inner wire format: kind(1) | ttl(1) | src_vip(4) | dst_vip(4) |
    /// body. The source address and TTL travel inside the encrypted
    /// packet, so relays forward with the ORIGINAL source intact (the
    /// receiver evaluates ACLs against the sender, not the relay) and
    /// loops die when the TTL runs out.
    async fn send_inner_full(
        &self,
        dst_vip: [u8; 4],
        kind: u8,
        body: &[u8],
        src_vip: [u8; 4],
        ttl: u8,
    ) -> Result<()> {
        if kind == KIND_DATA && src_vip == self.local_vip {
            if let Some(deny) = self.acl_denied_for(&self.local_role) {
                self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                match &deny {
                    AclDeny::Rule(rule) => self.ring.push(format!(
                        "acl: send blocked by DENY rule {} ({} -> {})",
                        rule.id, rule.source_role, rule.dest_service
                    )),
                    AclDeny::DefaultDeny => self.ring.push(format!(
                        "acl: send blocked - no ALLOW rule matches role {} (default deny)",
                        self.local_role
                    )),
                }
                return Err(anyhow!(
                    "ACL policy denies mesh data for role {}",
                    self.local_role
                ));
            }
        }
        let peer = self
            .peer_by_vip(&dst_vip)
            .ok_or_else(|| anyhow!("no route to {}", octets_to_vip(&dst_vip)))?;
        self.ensure_session(&peer).await?;
        // End-to-end layer: when WE are the origin (src == local),
        // the body of data/stream packets is sealed to the final
        // destination before the hop session wraps it. Relays
        // (src != local) forward the body exactly as received —
        // opaque to them — and the destination's open is what
        // authenticates the claimed source. Hop-local kinds
        // (PING/PONG) are never sealed: they belong to the link.
        let sealed_body;
        let body: &[u8] = if src_vip == self.local_vip
            && matches!(
                kind,
                KIND_DATA
                    | KIND_STREAM_OPEN
                    | KIND_STREAM_DATA
                    | KIND_STREAM_CLOSE
                    | KIND_STREAM_ACK
                    | KIND_STREAM_RESET
            ) {
            let key = self
                .e2e_key_for(&dst_vip, true)
                .ok_or_else(|| anyhow!("no peer key for {}", octets_to_vip(&dst_vip)))?;
            sealed_body = crate::crypto::e2e_seal(&key, kind, &src_vip, &dst_vip, body)?;
            &sealed_body
        } else {
            body
        };
        let mut inner = Vec::with_capacity(10 + body.len());
        inner.push(kind);
        inner.push(ttl);
        inner.extend_from_slice(&src_vip);
        inner.extend_from_slice(&dst_vip);
        inner.extend_from_slice(body);
        let (counter, remote_index, ciphertext) = {
            let mut state = peer.state.lock().unwrap();
            match &mut *state {
                PeerState::Established {
                    session,
                    remote_index,
                    ..
                } => {
                    // The transport AEAD is bound to the frame
                    // header (type | reserved | receiver index |
                    // counter) as associated data.
                    let mut aad = Vec::with_capacity(16);
                    aad.push(MSG_DATA);
                    aad.extend_from_slice(&[0, 0, 0]);
                    aad.extend_from_slice(&remote_index.to_le_bytes());
                    aad.extend_from_slice(&session.next_counter().to_le_bytes());
                    let (c, ct) = session.seal(&aad, &inner)?;
                    (c, *remote_index, ct)
                }
                _ => return Err(anyhow!("session lost during send")),
            }
        };
        let endpoint = peer
            .endpoint
            .lock()
            .unwrap()
            .ok_or_else(|| anyhow!("peer endpoint unknown"))?;
        let mut frame = Vec::with_capacity(16 + ciphertext.len());
        frame.push(MSG_DATA);
        frame.extend_from_slice(&[0, 0, 0]);
        frame.extend_from_slice(&remote_index.to_le_bytes());
        frame.extend_from_slice(&counter.to_le_bytes());
        frame.extend_from_slice(&ciphertext);
        // NOTE: last_activity is deliberately NOT refreshed here.
        // It records the last AUTHENTICATED INBOUND frame only;
        // the dead-peer reaper and keepalive probe read it as
        // silence, and refreshing it on send (e.g. with our own
        // 10 s PINGs) would make a vanished peer look alive.
        self.send_raw(endpoint, &frame).await;
        self.telemetry.packets_out.fetch_add(0, Ordering::Relaxed); // counted in send_raw
        Ok(())
    }

    pub async fn send_data(&self, dst_vip: &str, payload: &[u8]) -> Result<()> {
        let octets =
            vip_to_octets(dst_vip).ok_or_else(|| anyhow!("invalid virtual ip {dst_vip}"))?;
        self.send_inner(octets, KIND_DATA, payload).await
    }

    /// A snapshot of the currently enforced ACL rules. The service
    /// gateway evaluates service questions against the same list.
    pub fn acl_snapshot(&self) -> Vec<AclRule> {
        self.acl_rules.lock().unwrap().clone()
    }

    /// Takes the service-stream OPEN event receiver (once). The
    /// gateway consumes it; stream data itself is pulled in order
    /// through `next_stream_data`.
    pub fn take_stream_receiver(&self) -> Option<mpsc::Receiver<StreamEvent>> {
        self.stream_rx.lock().unwrap().take()
    }

    fn tombstoned(&self, peer_vip: &str, stream_id: u32) -> bool {
        self.stream_tombstones
            .lock()
            .unwrap()
            .get(&(peer_vip.to_string(), stream_id))
            .map(|t| t.elapsed() < STREAM_LINGER * 4)
            .unwrap_or(false)
    }

    fn out_stream(&self, dst_vip: &str, stream_id: u32) -> Arc<OutStream> {
        let dead = self.tombstoned(dst_vip, stream_id);
        self.out_streams
            .lock()
            .unwrap()
            .entry((dst_vip.to_string(), stream_id))
            .or_insert_with(|| {
                let stream = OutStream::new();
                if dead {
                    stream.state.lock().unwrap().dead = true;
                }
                Arc::new(stream)
            })
            .clone()
    }

    fn in_stream(&self, src_vip: &str, stream_id: u32) -> Arc<InStream> {
        let dead = self.tombstoned(src_vip, stream_id);
        self.in_streams
            .lock()
            .unwrap()
            .entry((src_vip.to_string(), stream_id))
            .or_insert_with(|| {
                let stream = InStream::new();
                if dead {
                    stream.state.lock().unwrap().dead = true;
                }
                Arc::new(stream)
            })
            .clone()
    }

    /// Applies a reset (ours or the peer's): tombstone the id so
    /// late state creation still comes up dead, then drop both
    /// directions' state, waking every waiter.
    fn apply_reset(&self, peer_vip: &str, stream_id: u32) {
        self.stream_tombstones
            .lock()
            .unwrap()
            .insert((peer_vip.to_string(), stream_id), Instant::now());
        self.drop_stream_state(peer_vip, stream_id);
    }

    fn find_out_stream(&self, dst_vip: &str, stream_id: u32) -> Option<Arc<OutStream>> {
        self.out_streams
            .lock()
            .unwrap()
            .get(&(dst_vip.to_string(), stream_id))
            .cloned()
    }

    fn find_in_stream(&self, src_vip: &str, stream_id: u32) -> Option<Arc<InStream>> {
        self.in_streams
            .lock()
            .unwrap()
            .get(&(src_vip.to_string(), stream_id))
            .cloned()
    }

    /// Opens a service stream at a peer's gateway. The OPEN is
    /// retransmitted by housekeeping until the peer acknowledges the
    /// stream, so a lost OPEN cannot strand it. Policy is the
    /// gateways' job on both ends; the tunnel only transports.
    pub async fn send_stream_open(
        &self,
        dst_vip: &str,
        stream_id: u32,
        service: &str,
        port: u16,
    ) -> Result<()> {
        let octets =
            vip_to_octets(dst_vip).ok_or_else(|| anyhow!("invalid virtual ip {dst_vip}"))?;
        let mut body = Vec::with_capacity(6 + service.len());
        body.extend_from_slice(&stream_id.to_be_bytes());
        body.extend_from_slice(&port.to_be_bytes());
        body.extend_from_slice(service.as_bytes());
        let stream = self.out_stream(dst_vip, stream_id);
        {
            let mut st = stream.state.lock().unwrap();
            st.open_body = body.clone();
            st.open_last_sent = Instant::now();
            st.last_activity = Instant::now();
        }
        self.send_inner(octets, KIND_STREAM_OPEN, &body).await
    }

    /// Sends data on a stream, reliably and in order. The payload is
    /// chunked into sequenced frames; when STREAM_WINDOW frames are
    /// unacknowledged this call WAITS — that wait is the backpressure
    /// path. A fast local sender is throttled by the peer's actual
    /// consumption, and no byte is ever discarded to make progress:
    /// unacknowledged frames are retransmitted until the peer's
    /// cumulative ACK passes them.
    pub async fn send_stream_data(&self, dst_vip: &str, stream_id: u32, data: &[u8]) -> Result<()> {
        let octets =
            vip_to_octets(dst_vip).ok_or_else(|| anyhow!("invalid virtual ip {dst_vip}"))?;
        let stream = self.out_stream(dst_vip, stream_id);
        for chunk in data.chunks(STREAM_FRAME_PAYLOAD) {
            let body = loop {
                let notified = stream.notify.notified();
                tokio::pin!(notified);
                // Register for wakeup BEFORE checking state, so an
                // ACK landing between the check and the await cannot
                // be missed.
                let _ = notified.as_mut().enable();
                let candidate = {
                    let mut st = stream.state.lock().unwrap();
                    if st.dead {
                        return Err(anyhow!("stream {stream_id} to {dst_vip} was reset"));
                    }
                    if st.close_final.is_some() {
                        return Err(anyhow!("stream {stream_id} is closing"));
                    }
                    if st.unacked.len() < STREAM_WINDOW {
                        let seq = st.next_seq;
                        st.next_seq += 1;
                        let mut body = Vec::with_capacity(8 + chunk.len());
                        body.extend_from_slice(&stream_id.to_be_bytes());
                        body.extend_from_slice(&seq.to_be_bytes());
                        body.extend_from_slice(chunk);
                        st.unacked.insert(seq, (Instant::now(), body.clone()));
                        st.last_activity = Instant::now();
                        Some(body)
                    } else {
                        None
                    }
                };
                match candidate {
                    Some(body) => break body,
                    None => notified.await,
                }
            };
            if let Err(e) = self.send_inner(octets, KIND_STREAM_DATA, &body).await {
                // A hard send error (no route, session lost): pull
                // the frame back out of the retransmission set and
                // fail visibly instead of buffering it forever.
                let seq = u32::from_be_bytes(body[4..8].try_into().unwrap());
                stream.state.lock().unwrap().unacked.remove(&seq);
                return Err(e);
            }
        }
        Ok(())
    }

    /// Closes our sending direction of a stream. The CLOSE carries
    /// the final sequence number and is retransmitted by
    /// housekeeping until the peer acknowledges it complete, so the
    /// peer delivers every queued byte before reporting
    /// end-of-stream. Returns after the first send; completion is
    /// asynchronous (`stream_close_acked` exposes it).
    pub async fn send_stream_close(&self, dst_vip: &str, stream_id: u32) -> Result<()> {
        let octets =
            vip_to_octets(dst_vip).ok_or_else(|| anyhow!("invalid virtual ip {dst_vip}"))?;
        let stream = self.out_stream(dst_vip, stream_id);
        let body = {
            let mut st = stream.state.lock().unwrap();
            let next = st.next_seq;
            let final_seq = *st.close_final.get_or_insert(next);
            st.close_last_sent = Some(Instant::now());
            st.last_activity = Instant::now();
            let mut body = Vec::with_capacity(8);
            body.extend_from_slice(&stream_id.to_be_bytes());
            body.extend_from_slice(&final_seq.to_be_bytes());
            body
        };
        self.send_inner(octets, KIND_STREAM_CLOSE, &body).await
    }

    /// Test/diagnostic snapshot of stream state for (peer, id).
    #[cfg(test)]
    pub fn stream_debug(&self, peer_vip: &str, stream_id: u32) -> String {
        let out = self
            .find_out_stream(peer_vip, stream_id)
            .map(|s| {
                let st = s.state.lock().unwrap();
                format!(
                    "OUT next_seq={} unacked={} open_acked={} close={:?} close_acked={} dead={}",
                    st.next_seq,
                    st.unacked.len(),
                    st.open_acked,
                    st.close_final,
                    st.close_acked,
                    st.dead
                )
            })
            .unwrap_or_else(|| "OUT none".to_string());
        let inp = self
            .find_in_stream(peer_vip, stream_id)
            .map(|s| {
                let st = s.state.lock().unwrap();
                format!(
                    "IN next_exp={} buffered={} delivery={} close_at={:?} open_seen={} open_emitted={} finished={} dead={}",
                    st.next_expected,
                    st.buffered.len(),
                    st.delivery.len(),
                    st.close_at,
                    st.open_seen,
                    st.open_emitted,
                    st.finished,
                    st.dead
                )
            })
            .unwrap_or_else(|| "IN none".to_string());
        format!("{out} | {inp}")
    }

    /// Test diagnostics: one line per live stream (both maps).
    #[cfg(test)]
    pub fn stream_debug_all(&self) -> String {
        let mut keys: Vec<(String, u32)> = Vec::new();
        {
            let map = self.out_streams.lock().unwrap();
            for k in map.keys() {
                keys.push(k.clone());
            }
        }
        {
            let map = self.in_streams.lock().unwrap();
            for k in map.keys() {
                if !keys.contains(k) {
                    keys.push(k.clone());
                }
            }
        }
        if keys.is_empty() {
            return "(no streams)".to_string();
        }
        keys.iter()
            .map(|(vip, id)| format!("{vip}#{id}: {}", self.stream_debug(vip, *id)))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Whether the peer has acknowledged our CLOSE as fully
    /// delivered (diagnostics and tests).
    pub fn stream_close_acked(&self, dst_vip: &str, stream_id: u32) -> bool {
        self.find_out_stream(dst_vip, stream_id)
            .map(|s| s.state.lock().unwrap().close_acked)
            .unwrap_or(false)
    }

    /// Whether the inbound direction of a stream ended by RESET
    /// (refusal/abort) rather than an orderly close. The gateway
    /// uses this to decide whether the sibling pump must be stopped
    /// immediately or allowed to drain (half-close semantics).
    pub fn stream_was_reset(&self, peer_vip: &str, stream_id: u32) -> bool {
        self.find_in_stream(peer_vip, stream_id)
            .map(|s| s.state.lock().unwrap().dead)
            .unwrap_or(false)
    }

    /// Aborts a stream in both directions and tells the peer to do
    /// the same (RESET). Used for refusals and hard teardown:
    /// buffered data for the stream is discarded on both sides.
    pub async fn reset_stream(&self, peer_vip: &str, stream_id: u32) {
        self.apply_reset(peer_vip, stream_id);
        if let Some(octets) = vip_to_octets(peer_vip) {
            let _ = self
                .send_inner(octets, KIND_STREAM_RESET, &stream_id.to_be_bytes())
                .await;
        }
    }

    /// Drops local stream state for (peer, id) in both directions
    /// without notifying the peer; waiters wake and senders fail.
    pub fn drop_stream_state(&self, peer_vip: &str, stream_id: u32) {
        let key = (peer_vip.to_string(), stream_id);
        if let Some(s) = self.out_streams.lock().unwrap().remove(&key) {
            s.state.lock().unwrap().dead = true;
            s.notify.notify_waiters();
        }
        if let Some(s) = self.in_streams.lock().unwrap().remove(&key) {
            s.state.lock().unwrap().dead = true;
            s.notify.notify_waiters();
        }
    }

    /// Drops only the inbound (peer -> us) state for a stream; the
    /// outbound direction is left to its close/retransmission
    /// lifecycle.
    pub fn drop_in_stream(&self, peer_vip: &str, stream_id: u32) {
        let key = (peer_vip.to_string(), stream_id);
        if let Some(s) = self.in_streams.lock().unwrap().remove(&key) {
            s.state.lock().unwrap().dead = true;
            s.notify.notify_waiters();
        }
    }

    /// Pulls the next in-order payload for a stream from `src_vip`.
    /// Returns `None` at end-of-stream: the peer's CLOSE arrived and
    /// every preceding byte was delivered, or the stream was reset.
    /// This is the ONLY way stream data leaves the tunnel, so order
    /// and completeness are structural. Consuming advances the
    /// receive window and triggers a fresh ACK — the consumer's pace
    /// is the sender's pace.
    pub async fn next_stream_data(&self, src_vip: &str, stream_id: u32) -> Option<Vec<u8>> {
        enum Pull {
            Data(Vec<u8>),
            End,
            Wait,
        }
        let stream = self.in_stream(src_vip, stream_id);
        loop {
            let notified = stream.notify.notified();
            tokio::pin!(notified);
            let _ = notified.as_mut().enable();
            let mut ack: Option<(u32, bool, bool)> = None;
            let step = {
                let mut st = stream.state.lock().unwrap();
                if st.dead {
                    Pull::End
                } else if let Some(front) = st.delivery.pop_front() {
                    let before = st.next_expected;
                    InStream::drain(&mut st);
                    if st.next_expected != before {
                        ack = Some((
                            st.next_expected,
                            InStream::close_complete(&st),
                            st.open_emitted,
                        ));
                    }
                    Pull::Data(front)
                } else if InStream::close_complete(&st) {
                    st.finished = true;
                    Pull::End
                } else {
                    Pull::Wait
                }
            };
            if let Some((next_expected, close_complete, open_confirmed)) = ack {
                self.send_stream_ack(
                    src_vip,
                    stream_id,
                    next_expected,
                    close_complete,
                    open_confirmed,
                )
                .await;
            }
            match step {
                Pull::Data(data) => return Some(data),
                Pull::End => return None,
                Pull::Wait => notified.await,
            }
        }
    }

    async fn send_stream_ack(
        &self,
        dst_vip: &str,
        stream_id: u32,
        next_expected: u32,
        close_complete: bool,
        open_confirmed: bool,
    ) {
        if let Some(octets) = vip_to_octets(dst_vip) {
            // Flags byte: bit 0 = close complete, bit 1 = open
            // confirmed. The open bit is what stops the sender
            // retransmitting OPEN: it is set only once this side
            // has actually seen the OPEN and handed it to the
            // gateway. A plain data ACK must never set it — if
            // the OPEN frame was lost but data got through, the
            // sender has to keep retransmitting the OPEN, or the
            // receiver's gateway never learns the stream exists
            // (it cannot dial the service without the OPEN body).
            let flags = (close_complete as u8) | ((open_confirmed as u8) << 1);
            let mut body = Vec::with_capacity(9);
            body.extend_from_slice(&stream_id.to_be_bytes());
            body.extend_from_slice(&next_expected.to_be_bytes());
            body.push(flags);
            let _ = self.send_inner(octets, KIND_STREAM_ACK, &body).await;
        }
    }

    /// Answers a frame that arrived for a stream this node has
    /// already reset: the peer has not heard (our RESET was lost
    /// on the unreliable transport) and is still retransmitting
    /// into the stream. One fresh RESET per stray frame — the
    /// same rule TCP applies to segments for a closed socket —
    /// makes a lost RESET self-healing instead of a permanent
    /// wedge: the peer's retransmissions keep re-offering us the
    /// chance to tell it the stream is gone.
    async fn reply_reset(&self, src_vip: &str, stream_id: u32) {
        if let Some(octets) = vip_to_octets(src_vip) {
            let _ = self
                .send_inner(octets, KIND_STREAM_RESET, &stream_id.to_be_bytes())
                .await;
        }
    }

    /// Handles one decrypted stream frame addressed to this node.
    /// Malformed frames are dropped silently. ACKs are sent from
    /// here (and from `next_stream_data` when consumption advances
    /// the window), never batched behind a timer, so the sender's
    /// window tracks the receiver's true position.
    async fn handle_stream_frame(
        &self,
        kind: u8,
        src_vip: &[u8; 4],
        src_role: String,
        body: &[u8],
    ) {
        let src = octets_to_vip(src_vip);
        match kind {
            KIND_STREAM_OPEN => {
                if body.len() < 6 {
                    return;
                }
                let stream_id = u32::from_be_bytes(body[0..4].try_into().unwrap());
                let port = u16::from_be_bytes(body[4..6].try_into().unwrap());
                let service = String::from_utf8_lossy(&body[6..]).into_owned();
                if service.is_empty() {
                    return;
                }
                if self.find_in_stream(&src, stream_id).is_none()
                    && self.in_stream_count_for(&src) >= MAX_IN_STREAMS_PER_PEER
                {
                    self.reply_reset(&src, stream_id).await;
                    return;
                }
                let stream = self.in_stream(&src, stream_id);
                let stream_dead = { stream.state.lock().unwrap().dead };
                if stream_dead {
                    self.reply_reset(&src, stream_id).await;
                    return;
                }
                let needs_emit = {
                    let mut st = stream.state.lock().unwrap();
                    st.last_activity = Instant::now();
                    st.open_seen = true;
                    !st.open_emitted
                };
                if needs_emit {
                    let event = StreamEvent::Open {
                        src_vip: src.clone(),
                        src_role,
                        stream_id,
                        service,
                        port,
                    };
                    match self.stream_tx.try_send(event) {
                        Ok(()) => {
                            stream.state.lock().unwrap().open_emitted = true;
                            self.send_stream_ack(&src, stream_id, 0, false, true).await;
                        }
                        Err(_) => {
                            // The event queue is full: do NOT ack.
                            // The sender retransmits the OPEN and the
                            // event is retried — an OPEN is never lost
                            // silently.
                            self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                } else {
                    // Duplicate OPEN (our ACK was lost): re-ack with
                    // the current receive position; the open is
                    // confirmed by definition here (it was emitted
                    // before, or it would not be a duplicate).
                    let (next_expected, close_complete) = {
                        let st = stream.state.lock().unwrap();
                        (st.next_expected, InStream::close_complete(&st))
                    };
                    self.send_stream_ack(&src, stream_id, next_expected, close_complete, true)
                        .await;
                }
            }
            KIND_STREAM_DATA => {
                if body.len() < 8 {
                    return;
                }
                if body.len() - 8 > STREAM_FRAME_PAYLOAD {
                    self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                let stream_id = u32::from_be_bytes(body[0..4].try_into().unwrap());
                let seq = u32::from_be_bytes(body[4..8].try_into().unwrap());
                if self.find_in_stream(&src, stream_id).is_none()
                    && self.in_stream_count_for(&src) >= MAX_IN_STREAMS_PER_PEER
                {
                    self.reply_reset(&src, stream_id).await;
                    return;
                }
                let stream = self.in_stream(&src, stream_id);
                let stream_dead = { stream.state.lock().unwrap().dead };
                if stream_dead {
                    self.reply_reset(&src, stream_id).await;
                    return;
                }
                let (next_expected, close_complete, open_confirmed) = {
                    let mut st = stream.state.lock().unwrap();
                    st.last_activity = Instant::now();
                    if !st.dead {
                        // Accept frames inside the receive horizon:
                        // the reorder buffer plus the delivery queue.
                        // Anything beyond it is dropped; the sender's
                        // retransmission re-offers it once the ACK
                        // has advanced.
                        let horizon = st
                            .next_expected
                            .saturating_add((STREAM_WINDOW + STREAM_DELIVERY_CAP) as u32);
                        if seq >= st.next_expected && seq < horizon {
                            st.buffered.entry(seq).or_insert_with(|| body[8..].to_vec());
                            InStream::drain(&mut st);
                        }
                    }
                    (
                        st.next_expected,
                        InStream::close_complete(&st),
                        st.open_emitted,
                    )
                };
                stream.notify.notify_waiters();
                self.send_stream_ack(
                    &src,
                    stream_id,
                    next_expected,
                    close_complete,
                    open_confirmed,
                )
                .await;
            }
            KIND_STREAM_CLOSE => {
                if body.len() < 8 {
                    return;
                }
                let stream_id = u32::from_be_bytes(body[0..4].try_into().unwrap());
                let final_seq = u32::from_be_bytes(body[4..8].try_into().unwrap());
                {
                    // Create the state if it does not exist: a
                    // CLOSE can legitimately overtake its stream's
                    // DATA on an unreliable transport, and dropping
                    // the final sequence number here would wedge
                    // the stream — the data would be delivered but
                    // end-of-stream never signalled. (The old code
                    // also acked "close complete" unconditionally
                    // in this case, telling the sender to stop
                    // retransmitting a CLOSE whose data had not
                    // even arrived.) With the state recorded, the
                    // ack reports the true completion status and
                    // the sender's retransmissions converge.
                    if self.find_in_stream(&src, stream_id).is_none()
                        && self.in_stream_count_for(&src) >= MAX_IN_STREAMS_PER_PEER
                    {
                        self.reply_reset(&src, stream_id).await;
                        return;
                    }
                    let stream = self.in_stream(&src, stream_id);
                    let stream_dead = { stream.state.lock().unwrap().dead };
                    if stream_dead {
                        self.reply_reset(&src, stream_id).await;
                        return;
                    }
                    let (next_expected, close_complete, open_confirmed) = {
                        let mut st = stream.state.lock().unwrap();
                        st.last_activity = Instant::now();
                        let cur = st.close_at.unwrap_or(0);
                        st.close_at = Some(cur.max(final_seq));
                        (
                            st.next_expected,
                            InStream::close_complete(&st),
                            st.open_emitted,
                        )
                    };
                    stream.notify.notify_waiters();
                    self.send_stream_ack(
                        &src,
                        stream_id,
                        next_expected,
                        close_complete,
                        open_confirmed,
                    )
                    .await;
                }
            }
            KIND_STREAM_ACK => {
                if body.len() < 9 {
                    return;
                }
                let stream_id = u32::from_be_bytes(body[0..4].try_into().unwrap());
                let next_expected = u32::from_be_bytes(body[4..8].try_into().unwrap());
                let flags = body[8];
                let close_complete = flags & 0x01 != 0;
                let open_confirmed = flags & 0x02 != 0;
                if let Some(stream) = self.find_out_stream(&src, stream_id) {
                    {
                        let mut st = stream.state.lock().unwrap();
                        st.last_activity = Instant::now();
                        // Only an ACK whose sender has actually seen
                        // and emitted our OPEN may stop its
                        // retransmission (see send_stream_ack).
                        if open_confirmed {
                            st.open_acked = true;
                        }
                        st.unacked.retain(|seq, _| *seq >= next_expected);
                        if close_complete && st.close_final.is_some() {
                            st.close_acked = true;
                        }
                    }
                    stream.notify.notify_waiters();
                }
            }
            KIND_STREAM_RESET => {
                if body.len() < 4 {
                    return;
                }
                let stream_id = u32::from_be_bytes(body[0..4].try_into().unwrap());
                self.apply_reset(&src, stream_id);
            }
            _ => {}
        }
    }

    /// How long ago this peer last sent us any frame, if the
    /// peer is known. Locks are taken one at a time (routes,
    /// then peers, then the peer's own lock) per the file's
    /// lock discipline.
    fn peer_silence(&self, vip: &str) -> Option<Duration> {
        let octets = vip_to_octets(vip)?;
        let pubkey = self.routes.lock().unwrap().get(&octets).cloned()?;
        let peer = self.peers.lock().unwrap().get(&pubkey).cloned()?;
        let silence = peer.last_activity.lock().unwrap().elapsed();
        Some(silence)
    }

    fn peer_is_dead(&self, vip: &str) -> bool {
        self.peer_silence(vip)
            .map(|silence| silence > PEER_SILENCE_DEAD)
            .unwrap_or(false)
    }

    /// Concurrent inbound streams currently held for one peer.
    fn in_stream_count_for(&self, vip: &str) -> usize {
        self.in_streams
            .lock()
            .unwrap()
            .keys()
            .filter(|(v, _)| v == vip)
            .count()
    }

    /// Periodic stream maintenance: retransmit anything
    /// unacknowledged past the RTO (OPEN until acked, DATA frames,
    /// CLOSE until acked complete) and purge finished state.
    async fn stream_housekeeping(&self) {
        let outs: Vec<((String, u32), Arc<OutStream>)> = self
            .out_streams
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for ((dst, stream_id), stream) in outs {
            let (resend_open, frames, resend_close, purge) = {
                let mut st = stream.state.lock().unwrap();
                let now = Instant::now();
                let mut frames = Vec::new();
                if !st.dead {
                    for (sent_at, body) in st.unacked.values_mut() {
                        if now.duration_since(*sent_at) >= STREAM_RTO {
                            *sent_at = now;
                            frames.push(body.clone());
                        }
                    }
                }
                let resend_open = !st.dead
                    && !st.open_acked
                    && !st.open_body.is_empty()
                    && now.duration_since(st.open_last_sent) >= STREAM_RTO;
                if resend_open {
                    st.open_last_sent = now;
                }
                let resend_close = !st.dead
                    && st.close_final.is_some()
                    && !st.close_acked
                    && st
                        .close_last_sent
                        .map(|t| now.duration_since(t) >= STREAM_RTO)
                        .unwrap_or(false);
                if resend_close {
                    st.close_last_sent = Some(now);
                }
                // A stream may only be purged once its OPEN is
                // confirmed (or it never had one): if the OPEN
                // frame was lost but data + CLOSE were acked, the
                // state must survive so housekeeping keeps
                // retransmitting the OPEN — otherwise the peer's
                // gateway never learns the stream exists and the
                // connection wedges with both sides "done".
                let open_settled = st.open_body.is_empty() || st.open_acked;
                let purge = st.dead || (st.close_acked && st.unacked.is_empty() && open_settled);
                let open_body = if resend_open {
                    Some(st.open_body.clone())
                } else {
                    None
                };
                let close_body = if resend_close {
                    let mut b = Vec::with_capacity(8);
                    b.extend_from_slice(&stream_id.to_be_bytes());
                    b.extend_from_slice(&st.close_final.unwrap().to_be_bytes());
                    Some(b)
                } else {
                    None
                };
                (open_body, frames, close_body, purge)
            };
            if !purge && self.peer_is_dead(&dst) {
                // The peer has been silent far beyond the
                // keepalive cadence: no ACK or RESET will ever
                // arrive. Reap the stream locally (tombstone +
                // drop) so retransmission stops and a sender
                // blocked on the window wakes with an error
                // instead of hanging for the life of the daemon.
                self.apply_reset(&dst, stream_id);
                continue;
            }
            if purge {
                self.out_streams
                    .lock()
                    .unwrap()
                    .remove(&(dst.clone(), stream_id));
                continue;
            }
            if let Some(octets) = vip_to_octets(&dst) {
                if let Some(body) = resend_open {
                    let _ = self.send_inner(octets, KIND_STREAM_OPEN, &body).await;
                }
                for body in frames {
                    let _ = self.send_inner(octets, KIND_STREAM_DATA, &body).await;
                }
                if let Some(body) = resend_close {
                    let _ = self.send_inner(octets, KIND_STREAM_CLOSE, &body).await;
                }
            }
        }
        let ins: Vec<((String, u32), Arc<InStream>)> = self
            .in_streams
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for ((src, stream_id), stream) in ins {
            let purge = {
                let st = stream.state.lock().unwrap();
                let idle = Instant::now().duration_since(st.last_activity);
                ((st.finished || st.dead) && idle > STREAM_LINGER)
                    || (!st.open_seen && idle > STREAM_LINGER)
            };
            if purge {
                self.in_streams.lock().unwrap().remove(&(src, stream_id));
            } else if self.peer_is_dead(&src) {
                // Half-open inbound stream of a peer that has
                // gone silent: reap it like the outbound side.
                self.apply_reset(&src, stream_id);
            }
        }
        self.stream_tombstones
            .lock()
            .unwrap()
            .retain(|_, t| t.elapsed() < STREAM_LINGER * 4);
    }

    // -- receiving ---------------------------------------------------------------

    pub fn spawn_loops(self: &Arc<Self>) {
        let recv_self = self.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match recv_self.transport.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        recv_self
                            .telemetry
                            .packets_in
                            .fetch_add(1, Ordering::Relaxed);
                        recv_self
                            .telemetry
                            .bytes_in
                            .fetch_add(n as u64, Ordering::Relaxed);
                        recv_self
                            .telemetry
                            .userspace_packets
                            .fetch_add(1, Ordering::Relaxed);
                        // Ingress gate — every check runs BEFORE the
                        // frame is copied or a task is spawned, so a
                        // packet flood cannot exhaust memory or the
                        // scheduler with unbounded per-datagram work:
                        //  * frames shorter than the smallest header
                        //    and unknown frame types are dropped;
                        //  * INIT frames pass the pre-auth rate limit
                        //    here, not inside the handler;
                        //  * a bounded semaphore caps concurrent frame
                        //    handlers; overload drops the datagram
                        //    (counted) instead of queueing forever.
                        if n < 8 || !matches!(buf[0], MSG_INIT | MSG_RESP | MSG_DATA | MSG_COOKIE) {
                            recv_self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        // NOTE: the INIT rate gate no longer runs
                        // here — it lives at the top of handle_init
                        // together with the cookie challenge, which
                        // needs a handler to reply from. The frame
                        // semaphore above still bounds concurrent
                        // handlers, and the gate runs before any
                        // X25519 work, which is what it protects.
                        let permit = match recv_self.frame_permits.clone().try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                recv_self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                        };
                        // Each frame is handled in its own task: a
                        // handler may need to complete a handshake with
                        // a third node (mesh relay), which requires this
                        // receive loop to keep reading.
                        let handler = recv_self.clone();
                        let frame = buf[..n].to_vec();
                        tokio::spawn(async move {
                            let _permit = permit;
                            handler.handle_frame(&frame, from).await;
                        });
                    }
                    Err(e) => {
                        recv_self.ring.push(format!("recv error: {e}"));
                    }
                }
            }
        });
        let ka_self = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(KEEPALIVE_EVERY).await;
                ka_self.keepalive_tick().await;
            }
        });
        let stream_self = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(STREAM_TICK);
            loop {
                tick.tick().await;
                stream_self.stream_housekeeping().await;
            }
        });
        let ping_self = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(PING_EVERY).await;
                ping_self.ping_tick().await;
            }
        });
    }

    async fn keepalive_tick(&self) {
        let peers: Vec<Arc<Peer>> = self.peers.lock().unwrap().values().cloned().collect();
        for peer in peers {
            let idle = peer.last_activity.lock().unwrap().elapsed();
            let established = matches!(*peer.state.lock().unwrap(), PeerState::Established { .. });
            if established && idle > KEEPALIVE_EVERY {
                let vip = peer.vip;
                let _ = self
                    .send_inner(vip, KIND_PING, &now_millis().to_le_bytes())
                    .await;
            }
        }
    }

    async fn ping_tick(&self) {
        let peers: Vec<Arc<Peer>> = self.peers.lock().unwrap().values().cloned().collect();
        for peer in peers {
            let established = matches!(*peer.state.lock().unwrap(), PeerState::Established { .. });
            if established {
                let vip = peer.vip;
                let _ = self
                    .send_inner(vip, KIND_PING, &now_millis().to_le_bytes())
                    .await;
            } else if peer.endpoint.lock().unwrap().is_some() {
                // Proactively build the mesh: a node in `up` mode
                // establishes sessions with every known peer instead of
                // waiting for application traffic, so the topology's
                // encrypted links reflect reality.
                let _ = self.ensure_session(&peer).await;
            }
        }
    }

    /// Pre-auth INIT rate limit: allows INIT_RATE_LIMIT INITs per
    /// source per second. Enforced in the receive loop BEFORE a
    /// handler task is spawned, so flood traffic costs no task and no
    /// frame copy. The per-source table is pruned lazily — once it
    /// grows past INIT_RATE_TABLE_MAX entries, sources idle for over
    /// two seconds are evicted, so the table itself stays bounded.
    /// The cookie value bound to a source address under a
    /// given responder secret: HMAC-SHA256(secret, ip || port).
    fn cookie_value(secret: &[u8; 32], from: &SocketAddr) -> [u8; 16] {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = <Hmac<Sha256>>::new_from_slice(secret).expect("HMAC key");
        match from.ip() {
            std::net::IpAddr::V4(v4) => mac.update(&v4.octets()),
            std::net::IpAddr::V6(v6) => mac.update(&v6.octets()),
        }
        mac.update(&from.port().to_be_bytes());
        let out = mac.finalize().into_bytes();
        let mut cookie = [0u8; 16];
        cookie.copy_from_slice(&out[..16]);
        cookie
    }

    /// mac2: the proof a challenged initiator attaches to its
    /// retried INIT — HMAC-SHA256(cookie, init frame)[..16].
    /// Constant-time equality for MAC comparison (the rest of
    /// the system compares credentials in constant time; the
    /// cookie proof gets the same treatment).
    fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for i in 0..a.len() {
            diff |= a[i] ^ b[i];
        }
        diff == 0
    }

    fn mac2(cookie: &[u8; 16], init_frame: &[u8]) -> [u8; 16] {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = <Hmac<Sha256>>::new_from_slice(cookie).expect("HMAC key");
        mac.update(init_frame);
        let out = mac.finalize().into_bytes();
        let mut m = [0u8; 16];
        m.copy_from_slice(&out[..16]);
        m
    }

    /// Does this INIT frame carry a valid cookie proof for its
    /// source? Checked BEFORE any handshake work: a flood from
    /// spoofed sources can never produce one (the cookie is
    /// delivered to the claimed address, which the spoofer does
    /// not control), so spoofed floods cost us one HMAC, not
    /// two X25519 multiplications.
    fn cookie_proof_valid(&self, from: &SocketAddr, frame: &[u8]) -> bool {
        if frame.len() != INIT_FRAME_LEN + MAC2_LEN {
            return false;
        }
        let (init, presented) = frame.split_at(INIT_FRAME_LEN);
        let jar = self.cookie_jar.lock().unwrap();
        for secret in std::iter::once(&jar.current).chain(jar.prev.iter()) {
            let cookie = Self::cookie_value(secret, from);
            if Self::ct_eq(&Self::mac2(&cookie, init), presented) {
                return true;
            }
        }
        false
    }

    /// Issues a fresh cookie for `from`, rotating the responder
    /// secret when it ages out (the previous secret stays valid
    /// for verification during the overlap).
    fn issue_cookie(&self, from: &SocketAddr) -> [u8; 16] {
        use rand_core::RngCore;
        let mut jar = self.cookie_jar.lock().unwrap();
        if jar.rotated.elapsed() > COOKIE_TTL {
            jar.prev = Some(jar.current);
            rand_core::OsRng.fill_bytes(&mut jar.current);
            jar.rotated = Instant::now();
        }
        Self::cookie_value(&jar.current, from)
    }

    /// Sends a COOKIE challenge to `from`, at most once per
    /// second per source (a challenge is itself traffic).
    async fn send_cookie_challenge(&self, from: SocketAddr) {
        {
            let mut sent = self.cookie_sent.lock().unwrap();
            let now = Instant::now();
            sent.retain(|_, t| now.duration_since(*t) < Duration::from_secs(60));
            if let Some(t) = sent.get(&from) {
                if now.duration_since(*t) < Duration::from_secs(1) {
                    return;
                }
            }
            sent.insert(from, now);
        }
        let cookie = self.issue_cookie(&from);
        let mut frame = Vec::with_capacity(20);
        frame.push(MSG_COOKIE);
        frame.extend_from_slice(&[0, 0, 0]);
        frame.extend_from_slice(&cookie);
        self.send_raw(from, &frame).await;
    }

    /// A COOKIE frame arrived: cache the cookie for this
    /// endpoint and reset any pending handshake toward it, so
    /// the next initiation retries with the proof attached.
    async fn handle_cookie(&self, frame: &[u8], from: SocketAddr) {
        if frame.len() < 20 {
            self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let mut cookie = [0u8; 16];
        cookie.copy_from_slice(&frame[4..20]);
        let known = {
            let peers = self.peers.lock().unwrap();
            peers
                .values()
                .any(|p| p.endpoint.lock().unwrap().map(|e| e == from).unwrap_or(false))
        };
        if !known {
            self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
            return;
        }
        {
            let mut out = self.cookies_out.lock().unwrap();
            out.retain(|_, (_, at)| at.elapsed() < COOKIE_TTL);
            out.insert(from, (cookie, Instant::now()));
        }
        let peers: Vec<Arc<Peer>> = self.peers.lock().unwrap().values().cloned().collect();
        for peer in peers {
            if peer.endpoint.lock().unwrap().map(|e| e == from).unwrap_or(false) {
                let mut state = peer.state.lock().unwrap();
                if matches!(*state, PeerState::AwaitingResponse { .. }) {
                    *state = PeerState::Idle;
                    self.ring.push(format!(
                        "cookie received from {from}; handshake will retry with proof"
                    ));
                }
            }
        }
    }

    /// Counts one initiation against the aggregate budget and
    /// reports whether it may proceed. Windows are 1 s, aligned
    /// to first use.
    fn init_global_ok(&self, proof: bool) -> bool {
        let mut g = self.init_global.lock().unwrap();
        if Instant::now().duration_since(g.0) > Duration::from_secs(1) {
            *g = (Instant::now(), 0, 0);
        }
        if proof {
            g.2 += 1;
            g.2 <= INIT_GLOBAL_PROOF_LIMIT
        } else {
            g.1 += 1;
            g.1 <= INIT_GLOBAL_LIMIT
        }
    }

    fn init_rate_ok(&self, from: SocketAddr) -> bool {
        let mut rl = self.init_rate.lock().unwrap();
        if rl.len() > INIT_RATE_TABLE_MAX {
            let now = Instant::now();
            rl.retain(|_, (t, _)| now.duration_since(*t) < Duration::from_secs(2));
        }
        // The cap must be a cap: during a rotating-source flood
        // every entry is fresh, so age-based pruning evicts
        // nothing. A NEW source arriving at a full table is
        // treated as over-limit (it gets a cookie challenge
        // instead of handshake CPU) rather than growing the
        // table further.
        if rl.len() >= INIT_RATE_TABLE_MAX && !rl.contains_key(&from) {
            return false;
        }
        let e = rl.entry(from).or_insert((Instant::now(), 0));
        if Instant::now().duration_since(e.0) > Duration::from_secs(1) {
            *e = (Instant::now(), 0);
        }
        e.1 += 1;
        e.1 <= INIT_RATE_LIMIT
    }

    async fn handle_frame(&self, frame: &[u8], from: SocketAddr) {
        if frame.len() < 8 {
            self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
            return;
        }
        match frame[0] {
            MSG_INIT => self.handle_init(frame, from).await,
            MSG_RESP => self.handle_resp(frame, from).await,
            MSG_COOKIE => self.handle_cookie(frame, from).await,
            MSG_DATA => self.handle_data(frame, from).await,
            _ => {
                self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    async fn handle_init(&self, frame: &[u8], from: SocketAddr) {
        if frame.len() < 8 {
            return;
        }
        // Pre-auth flood gate, BEFORE any X25519 work. A valid
        // cookie proof (mac2) means the source proved it can
        // receive at its claimed address: it is counted against
        // the generous aggregate proof budget and proceeds.
        // Without a valid proof the INIT is proof-less — an
        // INVALID proof is treated exactly like none, so a
        // poisoned cookie cache can never block a handshake that
        // would otherwise pass — and must satisfy BOTH the
        // per-source rate limit and the aggregate proof-less
        // budget. Past either, the source is challenged with a
        // COOKIE frame and the INIT is dropped.
        let has_proof = frame.len() == INIT_FRAME_LEN + MAC2_LEN;
        let proof_ok = has_proof && self.cookie_proof_valid(&from, frame);
        if proof_ok {
            if !self.init_global_ok(true) {
                self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                return;
            }
        } else if !self.init_rate_ok(from) || !self.init_global_ok(false) {
            self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
            self.send_cookie_challenge(from).await;
            return;
        }
        let sender_index = u32::from_le_bytes(frame[4..8].try_into().unwrap());
        let msg_end = if has_proof { INIT_FRAME_LEN } else { frame.len() };
        let msg1 = &frame[8..msg_end];
        let mut responder = HandshakeResponder::new(self.identity.secret());
        let (payload, remote_static) = match responder.read_message1(msg1) {
            Ok(v) => v,
            Err(e) => {
                self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                self.ring
                    .push(format!("bad handshake init from {from}: {e}"));
                return;
            }
        };
        let remote_hex = crate::crypto::hex_encode(remote_static.as_bytes());
        let peer = {
            let peers = self.peers.lock().unwrap();
            match peers.get(&remote_hex) {
                Some(p) => p.clone(),
                None => {
                    self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                    self.ring
                        .push(format!("handshake from unknown peer {remote_hex}"));
                    return;
                }
            }
        };
        // Freshness: the INIT payload is a millisecond timestamp that must
        // be strictly greater than the last one accepted from this peer. A
        // captured INIT replayed later is rejected here, so it can no
        // longer replace the live session or hijack the peer's endpoint.
        if payload.len() != 8 {
            self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
            self.ring
                .push("handshake init without timestamp payload".to_string());
            return;
        }
        let init_ts = u64::from_le_bytes(payload[..8].try_into().unwrap());
        if init_ts > now_millis() + 300_000 {
            self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
            self.ring
                .push("handshake init timestamp too far in the future".to_string());
            return;
        }
        if init_ts + INIT_MAX_AGE_MS < now_millis() {
            self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
            self.ring
                .push("handshake init too old (max age exceeded)".to_string());
            return;
        }
        {
            // The effective floor merges the in-memory value with the
            // persisted one, so a restart cannot reopen the replay window.
            let floor = self
                .init_floors
                .lock()
                .unwrap()
                .get(&peer.public_hex)
                .copied()
                .unwrap_or(0)
                .max(*self.init_floor_default.lock().unwrap());
            let mut last = peer.last_init_ms.lock().unwrap();
            let effective = (*last).max(floor);
            if init_ts <= effective {
                self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                self.ring.push(format!(
                    "stale or replayed handshake init from {} (ts {init_ts} <= last {effective})",
                    peer.public_hex
                ));
                return;
            }
            *last = init_ts;
        }
        self.init_floors
            .lock()
            .unwrap()
            .insert(peer.public_hex.clone(), init_ts);
        self.persist_freshness();
        // Simultaneous initiation tie-break: if we also have a handshake
        // in flight to this peer, exactly one initiation may win or the
        // two crossed handshakes yield mismatched sessions. The smaller
        // public key's initiation wins, deterministically on both sides.
        {
            let mut state = peer.state.lock().unwrap();
            if let PeerState::AwaitingResponse { local_index, .. } = &*state {
                if self.identity.public_hex() < peer.public_hex {
                    // Our initiation wins; ignore this INIT entirely.
                    return;
                }
                // Their initiation wins: abandon ours (retiring its index)
                // and continue below as the responder.
                let abandoned = *local_index;
                *state = PeerState::Idle;
                drop(state);
                self.by_index.lock().unwrap().remove(&abandoned);
            }
        }
        let local_index = self.next_index();
        let (msg2, session) = match responder.write_message2(&[]) {
            Ok(v) => v,
            Err(e) => {
                self.ring.push(format!("handshake response failed: {e}"));
                return;
            }
        };
        let replaced_index = {
            let mut state = peer.state.lock().unwrap();
            let old = match &*state {
                PeerState::Established { local_index, .. } => Some(*local_index),
                _ => None,
            };
            *state = PeerState::Established {
                session,
                local_index,
                remote_index: sender_index,
                since: Instant::now(),
            };
            old
        };
        if let Some(old) = replaced_index {
            // Retire the replaced session's index so stale frames can no
            // longer resolve to this peer.
            self.by_index.lock().unwrap().remove(&old);
        }
        self.by_index
            .lock()
            .unwrap()
            .insert(local_index, peer.public_hex.clone());
        // Endpoint learning happens only here: this INIT authenticated
        // (Noise_IK verifies the initiator's static key) and passed the
        // freshness check, so the source address is trustworthy.
        *peer.endpoint.lock().unwrap() = Some(from);
        self.telemetry
            .handshakes_completed
            .fetch_add(1, Ordering::Relaxed);
        *peer.last_activity.lock().unwrap() = Instant::now();
        let mut resp = Vec::with_capacity(12 + msg2.len());
        resp.push(MSG_RESP);
        resp.extend_from_slice(&[0, 0, 0]);
        resp.extend_from_slice(&local_index.to_le_bytes());
        resp.extend_from_slice(&sender_index.to_le_bytes());
        resp.extend_from_slice(&msg2);
        self.send_raw(from, &resp).await;
    }

    async fn handle_resp(&self, frame: &[u8], from: SocketAddr) {
        if frame.len() < 12 {
            return;
        }
        let sender_index = u32::from_le_bytes(frame[4..8].try_into().unwrap());
        let receiver_index = u32::from_le_bytes(frame[8..12].try_into().unwrap());
        let peer = match self.peer_by_index(receiver_index) {
            Some(p) => p,
            None => {
                self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        let msg2 = &frame[12..];
        let mut state = peer.state.lock().unwrap();
        if let PeerState::AwaitingResponse {
            initiator,
            local_index,
            ..
        } = &mut *state
        {
            if *local_index != receiver_index {
                return;
            }
            if let Some(init) = initiator.take() {
                match init.read_message2(msg2) {
                    Ok(session) => {
                        let li = *local_index;
                        *state = PeerState::Established {
                            session,
                            local_index: li,
                            remote_index: sender_index,
                            since: Instant::now(),
                        };
                        self.telemetry
                            .handshakes_completed
                            .fetch_add(1, Ordering::Relaxed);
                        *peer.last_activity.lock().unwrap() = Instant::now();
                        // Message 2 authenticated (its AEAD tag covers the
                        // handshake transcript); only now is the source
                        // address trusted as the peer's endpoint.
                        *peer.endpoint.lock().unwrap() = Some(from);
                    }
                    Err(e) => {
                        self.ring.push(format!("handshake completion failed: {e}"));
                        *state = PeerState::Idle;
                    }
                }
            }
        }
    }

    async fn handle_data(&self, frame: &[u8], from: SocketAddr) {
        if frame.len() < 16 {
            return;
        }
        let receiver_index = u32::from_le_bytes(frame[4..8].try_into().unwrap());
        let counter = u64::from_le_bytes(frame[8..16].try_into().unwrap());
        let peer = match self.peer_by_index(receiver_index) {
            Some(p) => p,
            None => {
                self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        let plain = {
            let mut state = peer.state.lock().unwrap();
            match &mut *state {
                PeerState::Established { session, .. } => match session.open(counter, &frame[..16], &frame[16..])
                {
                    Ok(p) => p,
                    Err(e) => {
                        self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                        self.ring.push(format!("packet open failed: {e}"));
                        return;
                    }
                },
                _ => {
                    self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        };
        // The packet authenticated and passed the replay window inside
        // session.open(); only authenticated traffic may teach us the
        // peer's endpoint (NAT rebinding keeps working, spoofing does not).
        *peer.endpoint.lock().unwrap() = Some(from);
        *peer.last_activity.lock().unwrap() = Instant::now();
        if plain.len() < 10 {
            return;
        }
        let kind = plain[0];
        let ttl = plain[1];
        let src_vip: [u8; 4] = plain[2..6].try_into().unwrap();
        let dst_vip: [u8; 4] = plain[6..10].try_into().unwrap();
        let body = plain[10..].to_vec();
        match kind {
            KIND_PING => {
                // PING/PONG are hop-local keepalives: the claimed
                // source MUST be the session peer itself. Anything
                // else is a spoof/reflection attempt (a PONG aimed
                // at a third party's VIP) — drop it silently.
                if src_vip != peer.vip {
                    self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                let _ = self.send_inner(src_vip, KIND_PONG, &body).await;
            }
            KIND_PONG => {
                if src_vip != peer.vip {
                    self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                if body.len() >= 8 {
                    let sent = u64::from_le_bytes(body[..8].try_into().unwrap());
                    let rtt = now_millis().saturating_sub(sent) as f64;
                    *peer.latency_ms.lock().unwrap() = rtt;
                }
            }
            KIND_DATA => {
                if dst_vip == self.local_vip {
                    // We are the destination: the claimed source
                    // is trusted ONLY after the end-to-end body
                    // opens under the pairwise key with that
                    // source — proof the packet really came from
                    // the node that owns src_vip. A node claiming
                    // another's VIP fails here and is dropped,
                    // whatever role the claimed identity has.
                    let key = match self.e2e_key_for(&src_vip, false) {
                        Some(k) => k,
                        None => {
                            self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                    };
                    let body = match crate::crypto::e2e_open(&key, kind, &src_vip, &dst_vip, &body) {
                        Ok(b) => b,
                        Err(_) => {
                            self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                            self.ring.push(format!(
                                "e2e: data from claimed {} failed origin authentication",
                                octets_to_vip(&src_vip)
                            ));
                            return;
                        }
                    };
                    // Policy is evaluated against the VERIFIED
                    // sender's role, never the relay's.
                    let src_role = self
                        .peer_by_vip(&src_vip)
                        .map(|p| p.role.lock().unwrap().clone())
                        .unwrap_or_else(|| peer.role.lock().unwrap().clone());
                    if let Some(deny) = self.acl_denied_for(&src_role) {
                        self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                        match &deny {
                            AclDeny::Rule(rule) => self.ring.push(format!(
                                "acl: packet from role {src_role} dropped by DENY rule {}",
                                rule.id
                            )),
                            AclDeny::DefaultDeny => self.ring.push(format!(
                                "acl: packet from role {src_role} dropped - no ALLOW rule matches (default deny)"
                            )),
                        }
                        return;
                    }
                    let src = octets_to_vip(&src_vip);
                    let _ = self.app_tx.send((src, body)).await;
                } else {
                    // Mesh relay: forward toward the destination's next
                    // hop, preserving the original source and decrementing
                    // the TTL so loops die.
                    if ttl <= 1 {
                        self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                        self.ring
                            .push("relay: TTL expired, packet dropped".to_string());
                        return;
                    }
                    let tunnel = self;
                    let body_clone = body.clone();
                    if let Some(next_hop) = tunnel.peer_by_vip(&dst_vip) {
                        if next_hop.public_hex != peer.public_hex {
                            let _ = tunnel
                                .send_inner_full(dst_vip, KIND_DATA, &body_clone, src_vip, ttl - 1)
                                .await;
                        }
                    } else {
                        self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            KIND_STREAM_OPEN | KIND_STREAM_DATA | KIND_STREAM_CLOSE | KIND_STREAM_ACK
            | KIND_STREAM_RESET => {
                if dst_vip == self.local_vip {
                    // Same end-to-end origin proof as the data
                    // path, verified BEFORE any stream state is
                    // created or policy is evaluated: a forged
                    // source dies here.
                    let key = match self.e2e_key_for(&src_vip, false) {
                        Some(k) => k,
                        None => {
                            self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                    };
                    let body = match crate::crypto::e2e_open(&key, kind, &src_vip, &dst_vip, &body) {
                        Ok(b) => b,
                        Err(_) => {
                            self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                            self.ring.push(format!(
                                "e2e: stream frame from claimed {} failed origin authentication",
                                octets_to_vip(&src_vip)
                            ));
                            return;
                        }
                    };
                    let src_role = self
                        .peer_by_vip(&src_vip)
                        .map(|p| p.role.lock().unwrap().clone())
                        .unwrap_or_else(|| peer.role.lock().unwrap().clone());
                    self.handle_stream_frame(kind, &src_vip, src_role, &body)
                        .await;
                } else if ttl > 1 {
                    // Relay toward the destination like data traffic;
                    // policy is enforced by the destination's gateway.
                    if let Some(next_hop) = self.peer_by_vip(&dst_vip) {
                        if next_hop.public_hex != peer.public_hex {
                            let _ = self
                                .send_inner_full(dst_vip, kind, &body, src_vip, ttl - 1)
                                .await;
                        }
                    } else {
                        self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                }
            }
            _ => {
                self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Identity;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    async fn make_node(
        hub: &Arc<MemoryHub>,
        port: u16,
        vip: &str,
        role: &str,
    ) -> (
        Arc<Tunnel<MemoryTransport>>,
        mpsc::Receiver<(String, Vec<u8>)>,
        Identity,
        Arc<TelemetryCounters>,
    ) {
        let dir = std::env::temp_dir().join(format!(
            "kronos-tun-{}-{}",
            std::process::id(),
            vip.replace('.', "-")
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let identity = Identity::load_or_create(&dir).unwrap();
        let telemetry = Arc::new(TelemetryCounters::default());
        let ring = Arc::new(EventRing::new(64));
        let (tunnel, rx) = Tunnel::bind_with_transport(
            hub.register(addr(port)),
            Identity::load_or_create(&dir).unwrap(),
            vip,
            role,
            telemetry.clone(),
            ring,
        )
        .unwrap();
        // The default posture is default-deny: model an operator who
        // has published an allow-all policy so data tests can flow.
        // ACL-focused tests override this with update_acls.
        tunnel.update_acls(&[crate::wire::AclRule {
            id: "test-allow-all".to_string(),
            source_role: "*".to_string(),
            dest_service: "*".to_string(),
            port: 0,
            action: "ALLOW".to_string(),
            priority: 1,
        }]);
        (tunnel, rx, identity, telemetry)
    }

    fn svc_rule(
        id: &str,
        role: &str,
        service: &str,
        port: u16,
        action: &str,
        priority: i32,
    ) -> AclRule {
        AclRule {
            id: id.to_string(),
            source_role: role.to_string(),
            dest_service: service.to_string(),
            port,
            action: action.to_string(),
            priority,
        }
    }

    #[test]
    fn acl_decision_matches_service_and_port() {
        let rules = vec![svc_rule("r1", "edge", "postgres", 5432, "ALLOW", 10)];
        assert_eq!(
            acl_decision(&rules, "edge", "postgres", 5432),
            AclDecision::Allow
        );
        // Wrong port, wrong service, wrong role: no match, default deny.
        assert_eq!(
            acl_decision(&rules, "edge", "postgres", 5433),
            AclDecision::DefaultDeny
        );
        assert_eq!(
            acl_decision(&rules, "edge", "ssh", 5432),
            AclDecision::DefaultDeny
        );
        assert_eq!(
            acl_decision(&rules, "iot", "postgres", 5432),
            AclDecision::DefaultDeny
        );
        // A specific service rule never leaks into the mesh-data gate.
        assert_eq!(
            acl_decision(&rules, "edge", "mesh-data", 0),
            AclDecision::DefaultDeny
        );
    }

    #[test]
    fn acl_decision_wildcards_and_deny_override() {
        // Wildcard service with a concrete port.
        let rules = vec![svc_rule("r1", "*", "*", 443, "ALLOW", 10)];
        assert_eq!(
            acl_decision(&rules, "anyone", "https", 443),
            AclDecision::Allow
        );
        assert_eq!(
            acl_decision(&rules, "anyone", "https", 80),
            AclDecision::DefaultDeny
        );
        // Port 0 in a rule matches any port of that service.
        let rules = vec![svc_rule("r1", "edge", "postgres", 0, "ALLOW", 10)];
        assert_eq!(
            acl_decision(&rules, "edge", "postgres", 6543),
            AclDecision::Allow
        );
        // DENY overrides ALLOW even at a much worse priority number.
        let rules = vec![
            svc_rule("allow", "edge", "postgres", 5432, "ALLOW", 1),
            svc_rule("deny", "edge", "postgres", 5432, "DENY", 100),
        ];
        match acl_decision(&rules, "edge", "postgres", 5432) {
            AclDecision::DenyRule(r) => assert_eq!(r.id, "deny"),
            other => panic!("expected DenyRule, got {other:?}"),
        }
        // The mesh-data question still resolves through the same fn.
        let rules = vec![svc_rule("r1", "*", "*", 0, "ALLOW", 1)];
        assert_eq!(
            acl_decision(&rules, "whoever", "mesh-data", 0),
            AclDecision::Allow
        );
    }

    #[tokio::test]
    async fn two_nodes_handshake_and_exchange_data() {
        let hub = MemoryHub::new();
        let (a, _rx_a, id_a, _tel_a) = make_node(&hub, 6101, "100.64.0.1", "edge").await;
        let (b, mut rx_b, id_b, _tel_b) = make_node(&hub, 6102, "100.64.0.2", "node").await;
        a.add_peer(
            &id_b.public_hex(),
            "100.64.0.2",
            Some(b.local_addr()),
            "node",
        );
        b.add_peer(
            &id_a.public_hex(),
            "100.64.0.1",
            Some(a.local_addr()),
            "edge",
        );
        a.spawn_loops();
        b.spawn_loops();
        a.send_data("100.64.0.2", b"mesh says hello").await.unwrap();
        let (src, payload) = tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
            .await
            .expect("timed out waiting for payload")
            .expect("channel closed");
        assert_eq!(src, "100.64.0.1");
        assert_eq!(payload, b"mesh says hello");
        assert_eq!(a.connected_peer_count(), 1);
        assert_eq!(b.connected_peer_count(), 1);
    }

    #[tokio::test]
    async fn three_node_relay_forwards_through_middle() {
        let hub = MemoryHub::new();
        let (a, _rx_a, id_a, _t1) = make_node(&hub, 6111, "100.64.0.11", "node").await;
        let (b, _rx_b, id_b, _t2) = make_node(&hub, 6112, "100.64.0.12", "node").await;
        let (c, mut rx_c, id_c, _t3) = make_node(&hub, 6113, "100.64.0.13", "node").await;
        a.add_peer(
            &id_b.public_hex(),
            "100.64.0.12",
            Some(b.local_addr()),
            "node",
        );
        a.add_peer(&id_c.public_hex(), "100.64.0.13", None, "node");
        // Point A's route to C at B instead (next-hop relay).
        a.routes
            .lock()
            .unwrap()
            .insert([100, 64, 0, 13], id_b.public_hex());
        b.add_peer(
            &id_a.public_hex(),
            "100.64.0.11",
            Some(a.local_addr()),
            "node",
        );
        b.add_peer(
            &id_c.public_hex(),
            "100.64.0.13",
            Some(c.local_addr()),
            "node",
        );
        c.add_peer(
            &id_b.public_hex(),
            "100.64.0.12",
            Some(b.local_addr()),
            "node",
        );
        // C holds A's key (registry model) so it can verify the
        // end-to-end seal on relayed traffic.
        c.add_peer(&id_a.public_hex(), "100.64.0.11", None, "node");
        a.spawn_loops();
        b.spawn_loops();
        c.spawn_loops();
        a.send_data("100.64.0.13", b"relayed payload")
            .await
            .unwrap();
        let (src, payload) = tokio::time::timeout(Duration::from_secs(5), rx_c.recv())
            .await
            .expect("relay timed out")
            .expect("channel closed");
        assert_eq!(payload, b"relayed payload");
        // The receiver sees the ORIGINAL sender, not the relay (B).
        assert_eq!(src, "100.64.0.11");
    }

    #[tokio::test]
    async fn unknown_peer_handshake_is_dropped() {
        let hub = MemoryHub::new();
        let (a, _rx_a, id_a, _t1) = make_node(&hub, 6121, "100.64.0.21", "node").await;
        let (stranger, _rx_s, _id_s, _t2) = make_node(&hub, 6122, "100.64.0.22", "node").await;
        stranger.add_peer(
            &id_a.public_hex(),
            "100.64.0.21",
            Some(a.local_addr()),
            "node",
        );
        a.spawn_loops();
        stranger.spawn_loops();
        let res = stranger.send_data("100.64.0.21", b"intruder").await;
        assert!(res.is_err());
        assert_eq!(a.connected_peer_count(), 0);
    }

    #[tokio::test]
    async fn simultaneous_initiation_converges() {
        let hub = MemoryHub::new();
        let (a, mut rx_a, id_a, _t) = make_node(&hub, 6301, "100.64.0.41", "edge").await;
        let (b, mut rx_b, id_b, _t2) = make_node(&hub, 6302, "100.64.0.42", "db").await;
        a.add_peer(
            &id_b.public_hex(),
            "100.64.0.42",
            Some(b.local_addr()),
            "db",
        );
        b.add_peer(
            &id_a.public_hex(),
            "100.64.0.41",
            Some(a.local_addr()),
            "edge",
        );
        a.spawn_loops();
        b.spawn_loops();
        // Both sides initiate at the same time; the tie-break must leave
        // exactly one working session, with traffic flowing both ways.
        let (ra, rb) = tokio::join!(
            a.send_data("100.64.0.42", b"from a"),
            b.send_data("100.64.0.41", b"from b"),
        );
        ra.unwrap();
        rb.unwrap();
        let (_s, p) = tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(p, b"from a");
        let (_s, p) = tokio::time::timeout(Duration::from_secs(5), rx_a.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(p, b"from b");
    }

    #[tokio::test]
    async fn stale_awaiting_response_is_retried() {
        let hub = MemoryHub::new();
        let (a, _rx_a, id_a, _t) = make_node(&hub, 6311, "100.64.0.51", "edge").await;
        let (b, mut rx_b, id_b, _t2) = make_node(&hub, 6312, "100.64.0.52", "db").await;
        // A does not know B's endpoint yet: the first send must fail...
        a.add_peer(&id_b.public_hex(), "100.64.0.52", None, "db");
        b.add_peer(
            &id_a.public_hex(),
            "100.64.0.51",
            Some(a.local_addr()),
            "edge",
        );
        a.spawn_loops();
        b.spawn_loops();
        assert!(a.send_data("100.64.0.52", b"too early").await.is_err());
        // ...but the peer must not stay wedged: once the endpoint is
        // known, a retry resets the stale attempt and completes.
        a.add_peer(
            &id_b.public_hex(),
            "100.64.0.52",
            Some(b.local_addr()),
            "db",
        );
        a.send_data("100.64.0.52", b"second attempt").await.unwrap();
        let (_s, p) = tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(p, b"second attempt");
    }

    #[tokio::test]
    async fn session_rekeys_when_stale() {
        let hub = MemoryHub::new();
        let (a, _rx_a, id_a, _t) = make_node(&hub, 6321, "100.64.0.61", "edge").await;
        let (b, mut rx_b, id_b, _t2) = make_node(&hub, 6322, "100.64.0.62", "db").await;
        a.add_peer(
            &id_b.public_hex(),
            "100.64.0.62",
            Some(b.local_addr()),
            "db",
        );
        b.add_peer(
            &id_a.public_hex(),
            "100.64.0.61",
            Some(a.local_addr()),
            "edge",
        );
        a.spawn_loops();
        b.spawn_loops();
        a.send_data("100.64.0.62", b"before rekey").await.unwrap();
        let (_s, p) = tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(p, b"before rekey");
        let index_before = {
            let peer = {
                let peers = a.peers.lock().unwrap();
                peers.get(&id_b.public_hex()).unwrap().clone()
            };
            let state = peer.state.lock().unwrap();
            match &*state {
                PeerState::Established { local_index, .. } => *local_index,
                _ => panic!("not established"),
            }
        };
        // Force every session to count as stale, then send again: the
        // initiator must rotate to a fresh session (new index) and the
        // packet must still arrive.
        a.rekey_after_secs.store(0, Ordering::Relaxed);
        a.send_data("100.64.0.62", b"after rekey").await.unwrap();
        let (_s, p) = tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(p, b"after rekey");
        let index_after = {
            let peer = {
                let peers = a.peers.lock().unwrap();
                peers.get(&id_b.public_hex()).unwrap().clone()
            };
            let state = peer.state.lock().unwrap();
            match &*state {
                PeerState::Established { local_index, .. } => *local_index,
                _ => panic!("not established"),
            }
        };
        assert_ne!(
            index_before, index_after,
            "rekey must rotate the session index"
        );
    }

    #[tokio::test]
    async fn relay_ttl_expiry_drops_packet() {
        let hub = MemoryHub::new();
        let (a, _rx_a, id_a, _t) = make_node(&hub, 6331, "100.64.0.11", "node").await;
        let (b, _rx_b, id_b, _t2) = make_node(&hub, 6332, "100.64.0.12", "node").await;
        let (c, mut rx_c, id_c, _t3) = make_node(&hub, 6333, "100.64.0.13", "node").await;
        a.add_peer(
            &id_b.public_hex(),
            "100.64.0.12",
            Some(b.local_addr()),
            "node",
        );
        b.add_peer(
            &id_a.public_hex(),
            "100.64.0.11",
            Some(a.local_addr()),
            "node",
        );
        b.add_peer(
            &id_c.public_hex(),
            "100.64.0.13",
            Some(c.local_addr()),
            "node",
        );
        c.add_peer(
            &id_b.public_hex(),
            "100.64.0.12",
            Some(b.local_addr()),
            "node",
        );
        // Registry model: A and C hold each other's keys (the
        // control plane distributes them); only the TRANSPORT is
        // relayed — that is what makes end-to-end sealing between
        // them possible.
        a.add_peer(&id_c.public_hex(), "100.64.0.13", None, "node");
        c.add_peer(&id_a.public_hex(), "100.64.0.11", None, "node");
        a.spawn_loops();
        b.spawn_loops();
        c.spawn_loops();
        // Establish the A-B session first.
        a.send_data("100.64.0.12", b"warmup").await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Hand-craft inner packets sealed with the A->B session, destined
        // for C, with a chosen TTL.
        let craft_frame = |a: &Arc<Tunnel<MemoryTransport>>, ttl: u8, body: &[u8]| -> Vec<u8> {
            // The body is end-to-end sealed A -> C, exactly as the
            // real send path does; B can only forward it opaquely.
            let key = a.e2e_key_for(&[100, 64, 0, 13], true).unwrap();
            let sealed =
                crate::crypto::e2e_seal(&key, KIND_DATA, &[100, 64, 0, 11], &[100, 64, 0, 13], body).unwrap();
            let mut inner = vec![KIND_DATA, ttl];
            inner.extend_from_slice(&[100, 64, 0, 11]); // src = A
            inner.extend_from_slice(&[100, 64, 0, 13]); // dst = C
            inner.extend_from_slice(&sealed);
            let peer = {
                let peers = a.peers.lock().unwrap();
                peers
                    .values()
                    .find(|p| p.vip == [100, 64, 0, 12])
                    .unwrap()
                    .clone()
            };
            let mut state = peer.state.lock().unwrap();
            let (counter, remote_index, ct) = match &mut *state {
                PeerState::Established {
                    session,
                    remote_index,
                    ..
                } => {
                    let mut aad = vec![MSG_DATA, 0, 0, 0];
                    aad.extend_from_slice(&remote_index.to_le_bytes());
                    aad.extend_from_slice(&session.next_counter().to_le_bytes());
                    let (c, ct) = session.seal(&aad, &inner).unwrap();
                    (c, *remote_index, ct)
                }
                _ => panic!("A-B session not established"),
            };
            let mut frame = vec![MSG_DATA, 0, 0, 0];
            frame.extend_from_slice(&remote_index.to_le_bytes());
            frame.extend_from_slice(&counter.to_le_bytes());
            frame.extend_from_slice(&ct);
            frame
        };

        // TTL 1: B must drop it instead of forwarding.
        let f1 = craft_frame(&a, 1, b"must die at relay");
        b.handle_frame(&f1, a.local_addr()).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(400), rx_c.recv())
                .await
                .is_err(),
            "TTL-expired packet must not be relayed"
        );

        // TTL 2: B forwards (with TTL 1) and C receives it, sourced from A.
        let f2 = craft_frame(&a, 2, b"relayed with ttl to spare");
        b.handle_frame(&f2, a.local_addr()).await;
        let (src, payload) = tokio::time::timeout(Duration::from_secs(5), rx_c.recv())
            .await
            .expect("relay timed out")
            .expect("channel closed");
        assert_eq!(payload, b"relayed with ttl to spare");
        assert_eq!(src, "100.64.0.11");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_sync_and_traffic_do_not_deadlock() {
        // Regression test for the ABBA lock-order inversion: add_peer took
        // peers->routes while peer_by_vip took routes->peers. Hammering
        // peer-sync, session lookups, and sends concurrently must finish.
        let hub = MemoryHub::new();
        let (a, _rx_a, id_a, _t) = make_node(&hub, 6401, "100.64.0.71", "edge").await;
        let (b, _rx_b, id_b, _t2) = make_node(&hub, 6402, "100.64.0.72", "db").await;
        let hex_a = id_a.public_hex();
        let hex_b = id_b.public_hex();
        let addr_a = a.local_addr();
        let addr_b = b.local_addr();
        a.add_peer(&hex_b, "100.64.0.72", Some(addr_b), "db");
        b.add_peer(&hex_a, "100.64.0.71", Some(addr_a), "edge");
        a.spawn_loops();
        b.spawn_loops();
        a.send_data("100.64.0.72", b"warmup").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let work = async {
            let t1 = {
                let b = b.clone();
                let hex_a = hex_a.clone();
                tokio::spawn(async move {
                    for _ in 0..300 {
                        b.add_peer(&hex_a, "100.64.0.71", Some(addr_a), "edge");
                        tokio::task::yield_now().await;
                    }
                })
            };
            let t2 = {
                let a = a.clone();
                let hex_b = hex_b.clone();
                tokio::spawn(async move {
                    for _ in 0..300 {
                        a.add_peer(&hex_b, "100.64.0.72", Some(addr_b), "db");
                        tokio::task::yield_now().await;
                    }
                })
            };
            let t3 = {
                let b = b.clone();
                tokio::spawn(async move {
                    for _ in 0..100 {
                        let _ = b.send_data("100.64.0.71", b"churn").await;
                        tokio::task::yield_now().await;
                    }
                })
            };
            let t4 = {
                let a = a.clone();
                let b = b.clone();
                tokio::spawn(async move {
                    for _ in 0..300 {
                        let _ = b.established_peer_keys();
                        let _ = b.connected_peer_count();
                        let _ = a.established_peer_keys();
                        tokio::task::yield_now().await;
                    }
                })
            };
            let _ = tokio::join!(t1, t2, t3, t4);
        };
        tokio::time::timeout(Duration::from_secs(20), work)
            .await
            .expect("deadlock: concurrent sync/traffic did not finish in 20s");
    }

    #[tokio::test]
    async fn forged_frame_cannot_hijack_endpoint() {
        let hub = MemoryHub::new();
        let (a, _rx_a, id_a, _t) = make_node(&hub, 6201, "100.64.0.21", "edge").await;
        let (b, mut rx_b, id_b, _t2) = make_node(&hub, 6202, "100.64.0.22", "db").await;
        a.add_peer(
            &id_b.public_hex(),
            "100.64.0.22",
            Some(b.local_addr()),
            "db",
        );
        b.add_peer(
            &id_a.public_hex(),
            "100.64.0.21",
            Some(a.local_addr()),
            "edge",
        );
        a.spawn_loops();
        b.spawn_loops();
        a.send_data("100.64.0.22", b"before attack").await.unwrap();
        let (_s, p) = tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(p, b"before attack");

        // B's receiver index for the session with A.
        let receiver_index = {
            let peer = {
                let peers = b.peers.lock().unwrap();
                peers.get(&id_a.public_hex()).unwrap().clone()
            };
            let state = peer.state.lock().unwrap();
            match &*state {
                PeerState::Established { local_index, .. } => *local_index,
                _ => panic!("session not established"),
            }
        };
        // Forged DATA frame: valid index, garbage ciphertext, attacker source.
        let mut forged = vec![MSG_DATA, 0, 0, 0];
        forged.extend_from_slice(&receiver_index.to_le_bytes());
        forged.extend_from_slice(&7u64.to_le_bytes());
        forged.extend_from_slice(&[0xEE; 48]);
        b.handle_frame(&forged, addr(9999)).await;

        // The endpoint must NOT have moved to the attacker.
        {
            let peer = {
                let peers = b.peers.lock().unwrap();
                peers.get(&id_a.public_hex()).unwrap().clone()
            };
            let endpoint = *peer.endpoint.lock().unwrap();
            assert_eq!(endpoint, Some(a.local_addr()));
        }
        // And the legitimate path still works.
        a.send_data("100.64.0.22", b"after attack").await.unwrap();
        let (_s, p) = tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(p, b"after attack");
    }

    #[tokio::test]
    async fn replayed_init_cannot_replace_live_session() {
        let hub = MemoryHub::new();
        let (a, _rx_a, id_a, _t) = make_node(&hub, 6211, "100.64.0.31", "edge").await;
        let (b, mut rx_b, id_b, _t2) = make_node(&hub, 6212, "100.64.0.32", "db").await;
        a.add_peer(
            &id_b.public_hex(),
            "100.64.0.32",
            Some(b.local_addr()),
            "db",
        );
        b.add_peer(
            &id_a.public_hex(),
            "100.64.0.31",
            Some(a.local_addr()),
            "edge",
        );
        a.spawn_loops();
        b.spawn_loops();
        a.send_data("100.64.0.32", b"session one").await.unwrap();
        let (_s, p) = tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(p, b"session one");

        // Attacker replays a captured-style INIT: a genuine message 1 from
        // A's key, but carrying an ancient (already-seen) timestamp.
        let mut initiator =
            HandshakeInitiator::new(a.identity.secret(), PublicKey::from(&id_b.secret()));
        let msg1 = initiator.write_message1(&1u64.to_le_bytes()).unwrap();
        let mut frame = vec![MSG_INIT, 0, 0, 0];
        frame.extend_from_slice(&7777u32.to_le_bytes());
        frame.extend_from_slice(&msg1);
        b.handle_frame(&frame, addr(9998)).await;

        // B must not have moved A's endpoint to the attacker...
        {
            let peer = {
                let peers = b.peers.lock().unwrap();
                peers.get(&id_a.public_hex()).unwrap().clone()
            };
            let endpoint = *peer.endpoint.lock().unwrap();
            assert_eq!(endpoint, Some(a.local_addr()));
        }
        // ...and the live session must still work.
        a.send_data("100.64.0.32", b"session still alive")
            .await
            .unwrap();
        let (_s, p) = tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(p, b"session still alive");
    }

    #[tokio::test]
    async fn acl_deny_rule_drops_packet() {
        use crate::wire::AclRule;
        let hub = MemoryHub::new();
        let (a, _rx_a, id_a, _tel_a) = make_node(&hub, 6131, "100.64.0.31", "edge").await;
        let (b, mut rx_b, id_b, tel_b) = make_node(&hub, 6132, "100.64.0.32", "database").await;
        a.add_peer(
            &id_b.public_hex(),
            "100.64.0.32",
            Some(b.local_addr()),
            "database",
        );
        b.add_peer(
            &id_a.public_hex(),
            "100.64.0.31",
            Some(a.local_addr()),
            "edge",
        );
        a.spawn_loops();
        b.spawn_loops();

        // Baseline: make_node seeds an allow-all policy (priority 1),
        // so the packet is delivered.
        a.send_data("100.64.0.32", b"before policy").await.unwrap();
        let (_src, payload) = tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
            .await
            .expect("baseline delivery timed out")
            .expect("channel closed");
        assert_eq!(payload, b"before policy");

        // Policy lands on B: role "edge" is denied mesh data. The DENY
        // deliberately carries a WORSE priority (100) than the seeded
        // ALLOW (1): under the old first-match semantics the ALLOW
        // would have won and this packet would have been delivered.
        // Deny-override means the DENY wins anyway.
        b.update_acls(&[
            AclRule {
                id: "test-allow-all".to_string(),
                source_role: "*".to_string(),
                dest_service: "*".to_string(),
                port: 0,
                action: "ALLOW".to_string(),
                priority: 1,
            },
            AclRule {
                id: "deny-edge".to_string(),
                source_role: "edge".to_string(),
                dest_service: "*".to_string(),
                port: 0,
                action: "DENY".to_string(),
                priority: 100,
            },
        ]);

        let drops_before = tel_b.snapshot().drops;
        a.send_data("100.64.0.32", b"after policy").await.unwrap();
        let blocked = tokio::time::timeout(Duration::from_millis(600), rx_b.recv()).await;
        assert!(blocked.is_err(), "denied packet must not be delivered");
        assert!(
            tel_b.snapshot().drops > drops_before,
            "drop counter must record the ACL drop"
        );
    }

    #[tokio::test]
    async fn acl_default_deny_without_allow_rule() {
        let hub = MemoryHub::new();
        let (a, _rx_a, id_a, _tel_a) = make_node(&hub, 6141, "100.64.0.41", "edge").await;
        let (b, mut rx_b, id_b, tel_b) = make_node(&hub, 6142, "100.64.0.42", "database").await;
        a.add_peer(
            &id_b.public_hex(),
            "100.64.0.42",
            Some(b.local_addr()),
            "database",
        );
        b.add_peer(
            &id_a.public_hex(),
            "100.64.0.41",
            Some(a.local_addr()),
            "edge",
        );
        a.spawn_loops();
        b.spawn_loops();

        // Empty policy on both nodes: the default posture denies.
        a.update_acls(&[]);
        b.update_acls(&[]);

        // Send side: A refuses to originate traffic with no ALLOW.
        let res = a.send_data("100.64.0.42", b"no policy").await;
        assert!(res.is_err(), "send must fail under default deny");

        // Receive side: give A an ALLOW so it can send; B still has an
        // empty policy and must drop the packet by default.
        a.update_acls(&[AclRule {
            id: "allow-edge".to_string(),
            source_role: "edge".to_string(),
            dest_service: "*".to_string(),
            port: 0,
            action: "ALLOW".to_string(),
            priority: 1,
        }]);
        let drops_before = tel_b.snapshot().drops;
        a.send_data("100.64.0.42", b"still denied at b")
            .await
            .unwrap();
        let blocked = tokio::time::timeout(Duration::from_millis(600), rx_b.recv()).await;
        assert!(
            blocked.is_err(),
            "default-deny packet must not be delivered"
        );
        assert!(
            tel_b.snapshot().drops > drops_before,
            "drop counter must record the default-deny drop"
        );
    }

    #[tokio::test]
    async fn init_rate_limit_burst_window_and_prune() {
        let hub = MemoryHub::new();
        let (a, _rx, _id, _t) = make_node(&hub, 6161, "100.64.0.61", "edge").await;
        let src = addr(7777);
        // A full burst up to the limit passes...
        for _ in 0..INIT_RATE_LIMIT {
            assert!(a.init_rate_ok(src), "burst up to the limit must pass");
        }
        // ...the next INIT inside the same window is refused...
        assert!(!a.init_rate_ok(src), "over-limit INIT must be refused");
        // ...other sources are unaffected...
        assert!(a.init_rate_ok(addr(7778)));
        // ...and once the window expires the budget resets.
        {
            let mut rl = a.init_rate.lock().unwrap();
            rl.get_mut(&src).unwrap().0 = Instant::now() - Duration::from_secs(2);
        }
        assert!(a.init_rate_ok(src), "expired window must reset the budget");

        // Pruning: a table flooded with stale sources is evicted down
        // when it grows past INIT_RATE_TABLE_MAX.
        {
            let mut rl = a.init_rate.lock().unwrap();
            let old = Instant::now() - Duration::from_secs(10);
            for i in 0..(INIT_RATE_TABLE_MAX + 100) {
                rl.insert(addr(10000 + i as u16), (old, 1));
            }
        }
        assert!(a.init_rate_ok(addr(9999)));
        let len = a.init_rate.lock().unwrap().len();
        assert!(len < 200, "stale sources must be pruned, table len {len}");
    }

    #[tokio::test]
    async fn frame_handler_cap_drops_under_flood() {
        let hub = MemoryHub::new();
        let (a, _rx_a, id_a, _tel_a) = make_node(&hub, 6171, "100.64.0.71", "edge").await;
        let (b, mut rx_b, id_b, tel_b) = make_node(&hub, 6172, "100.64.0.72", "node").await;
        a.add_peer(
            &id_b.public_hex(),
            "100.64.0.72",
            Some(b.local_addr()),
            "node",
        );
        b.add_peer(
            &id_a.public_hex(),
            "100.64.0.71",
            Some(a.local_addr()),
            "edge",
        );
        a.spawn_loops();
        b.spawn_loops();

        // Exhaust B's frame-handler permits: B's receive loop must now
        // DROP incoming frames instead of spawning unbounded tasks.
        let mut held = Vec::new();
        for _ in 0..MAX_IN_FLIGHT_FRAMES {
            held.push(b.frame_permits.clone().try_acquire_owned().unwrap());
        }
        let drops_before = tel_b.snapshot().drops;
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            a.send_data("100.64.0.72", b"during flood"),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            tel_b.snapshot().drops > drops_before,
            "overload must be dropped (and counted), not queued"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(200), rx_b.recv())
                .await
                .is_err(),
            "nothing may be delivered while the handler cap is exhausted"
        );

        // Release the pressure: the mesh recovers and traffic flows.
        drop(held);
        a.send_data("100.64.0.72", b"after flood").await.unwrap();
        let (_s, p) = tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(p, b"after flood");
    }

    // -- reliable streams ------------------------------------------------

    async fn make_node_chaos(
        hub: &Arc<MemoryHub>,
        port: u16,
        vip: &str,
        role: &str,
        seed: u64,
    ) -> (Arc<Tunnel<ChaosTransport>>, Identity) {
        let dir = std::env::temp_dir().join(format!(
            "kronos-chaos-{}-{}",
            std::process::id(),
            vip.replace('.', "-")
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let identity = Identity::load_or_create(&dir).unwrap();
        let (tunnel, _rx) = Tunnel::bind_with_transport(
            ChaosTransport::wrap(hub.register(addr(port)), seed, 10, 5),
            Identity::load_or_create(&dir).unwrap(),
            vip,
            role,
            Arc::new(TelemetryCounters::default()),
            Arc::new(EventRing::new(64)),
        )
        .unwrap();
        tunnel.update_acls(&[crate::wire::AclRule {
            id: "test-allow-all".to_string(),
            source_role: "*".to_string(),
            dest_service: "*".to_string(),
            port: 0,
            action: "ALLOW".to_string(),
            priority: 1,
        }]);
        (tunnel, identity)
    }

    fn pattern(n: usize, seed: u8) -> Vec<u8> {
        (0..n)
            .map(|i| ((i * 31 + seed as usize * 17) % 251) as u8)
            .collect()
    }

    async fn chaos_pair(
        base_port: u16,
        vip_a: &'static str,
        vip_b: &'static str,
    ) -> (Arc<Tunnel<ChaosTransport>>, Arc<Tunnel<ChaosTransport>>) {
        let hub = MemoryHub::new();
        let (a, id_a) = make_node_chaos(&hub, base_port, vip_a, "edge", 0xA5A5_1234).await;
        let (b, id_b) = make_node_chaos(&hub, base_port + 1, vip_b, "node", 0x5A5A_9876).await;
        a.add_peer(&id_b.public_hex(), vip_b, Some(b.local_addr()), "node");
        b.add_peer(&id_a.public_hex(), vip_a, Some(a.local_addr()), "edge");
        a.spawn_loops();
        b.spawn_loops();
        (a, b)
    }

    /// Regression test for the liveness bug CI caught in the
    /// disconnect test: if a stream's OPEN frame is lost but its
    /// DATA gets through, the receiver creates stream state and
    /// ACKs the data — and those data ACKs must NOT silence the
    /// sender's OPEN retransmission, because without the OPEN
    /// the receiver's gateway never learns the stream exists (it
    /// cannot dial the service without the OPEN body) and the
    /// connection wedges forever. The OPEN is dropped
    /// deterministically here; the stream must still open,
    /// deliver and close.
    #[tokio::test]
    async fn stream_open_frame_loss_does_not_wedge_the_stream() {
        let hub = MemoryHub::new();
        let mk = |port: u16, vip: &'static str, role: &'static str, seed: u64| {
            let dir = std::env::temp_dir().join(format!(
                "kronos-open-loss-{}-{}",
                std::process::id(),
                vip.replace('.', "-")
            ));
            let _ = std::fs::remove_dir_all(&dir);
            let transport = ChaosTransport::wrap(hub.register(addr(port)), seed, 10, 5);
            let handle = transport.clone();
            let (tunnel, rx) = Tunnel::bind_with_transport(
                transport,
                Identity::load_or_create(&dir).unwrap(),
                vip,
                role,
                Arc::new(TelemetryCounters::default()),
                Arc::new(EventRing::new(64)),
            )
            .unwrap();
            tunnel.update_acls(&[crate::wire::AclRule {
                id: "test-allow-all".to_string(),
                source_role: "*".to_string(),
                dest_service: "*".to_string(),
                port: 0,
                action: "ALLOW".to_string(),
                priority: 1,
            }]);
            let _ = &rx;
            (tunnel, handle, Identity::load_or_create(&dir).unwrap())
        };
        let (a, a_transport, id_a) = mk(6521, "100.64.26.1", "edge", 0xA5A5_1234);
        let (b, _b_transport, id_b) = mk(6522, "100.64.26.2", "node", 0x5A5A_9876);
        let mut rx_b = b
            .take_stream_receiver()
            .expect("stream receiver must be available once");
        let a = Arc::new(a);
        let b = Arc::new(b);
        // Peer wiring needs both identities: rebuild knowledge
        // from the tunnels' own identities via a warm-up is not
        // possible, so fetch fingerprints from the tunnels.
        a.add_peer(
            &id_b.public_hex(),
            "100.64.26.2",
            Some(b.local_addr()),
            "node",
        );
        b.add_peer(
            &id_a.public_hex(),
            "100.64.26.1",
            Some(a.local_addr()),
            "edge",
        );
        a.spawn_loops();
        b.spawn_loops();

        // Warm-up stream: establishes the Noise session, so the
        // next A->B datagram afterwards is the test stream's OPEN.
        a.send_stream_open("100.64.26.2", 1, "warmup", 9000)
            .await
            .unwrap();
        let warm = tokio::time::timeout(Duration::from_secs(10), rx_b.recv())
            .await
            .expect("warm-up open event timed out")
            .expect("stream event channel closed");
        assert!(matches!(warm, StreamEvent::Open { stream_id: 1, .. }));
        a.send_stream_data("100.64.26.2", 1, b"warm").await.unwrap();
        a.send_stream_close("100.64.26.2", 1).await.unwrap();
        let mut warm_got = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), async {
            while let Some(chunk) = b.next_stream_data("100.64.26.1", 1).await {
                warm_got.extend_from_slice(&chunk);
            }
        })
        .await
        .expect("warm-up stream timed out");
        assert_eq!(warm_got, b"warm");
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Kill exactly the next A->B datagram: stream 2's OPEN.
        a_transport.drop_next_sends(1);
        a.send_stream_open("100.64.26.2", 2, "echo", 9001)
            .await
            .unwrap();
        a.send_stream_data("100.64.26.2", 2, b"still alive")
            .await
            .unwrap();
        a.send_stream_close("100.64.26.2", 2).await.unwrap();

        // The gateway on B must still learn of stream 2 — only
        // the retransmitted OPEN can tell it — and the payload
        // must arrive intact and complete.
        let ev = tokio::time::timeout(Duration::from_secs(15), rx_b.recv())
            .await
            .expect(
                "open event for stream 2 was never emitted:                  a data ACK silenced the OPEN retransmission",
            )
            .expect("stream event channel closed");
        match ev {
            StreamEvent::Open {
                stream_id,
                service,
                port,
                ..
            } => {
                assert_eq!(stream_id, 2);
                assert_eq!(service, "echo");
                assert_eq!(port, 9001);
            }
        }
        let mut got = Vec::new();
        let delivered = tokio::time::timeout(Duration::from_secs(15), async {
            while let Some(chunk) = b.next_stream_data("100.64.26.1", 2).await {
                got.extend_from_slice(&chunk);
            }
        })
        .await;
        if delivered.is_err() {
            eprintln!("A streams:\n{}", a.stream_debug_all());
            eprintln!("B streams:\n{}", b.stream_debug_all());
            panic!("stream 2 delivery timed out");
        }
        assert_eq!(got, b"still alive");
    }

    /// The core reliability claim: 100 KB pushed through a stream
    /// over a transport that drops 10%, duplicates 5% and reorders
    /// 20% of datagrams arrives byte-exact and in order, and the
    /// sender learns its CLOSE was fully delivered.
    #[tokio::test]
    async fn stream_transfer_is_byte_exact_over_chaos() {
        let (a, b) = chaos_pair(6411, "100.64.21.1", "100.64.21.2").await;
        let payload = pattern(100_000, 7);
        let send_a = a.clone();
        let expect = payload.clone();
        let sender = tokio::spawn(async move {
            send_a
                .send_stream_open("100.64.21.2", 42, "bulk", 9000)
                .await
                .unwrap();
            send_a
                .send_stream_data("100.64.21.2", 42, &expect)
                .await
                .unwrap();
            send_a.send_stream_close("100.64.21.2", 42).await.unwrap();
        });
        let mut received = Vec::new();
        let read = async {
            while let Some(chunk) = b.next_stream_data("100.64.21.1", 42).await {
                received.extend_from_slice(&chunk);
            }
        };
        tokio::time::timeout(Duration::from_secs(30), read)
            .await
            .expect("stream read timed out over chaos transport");
        sender.await.unwrap();
        assert_eq!(received.len(), payload.len());
        assert_eq!(
            received, payload,
            "stream bytes must arrive exact and in order"
        );
        // The CLOSE must be acknowledged complete at the sender.
        let deadline = Instant::now() + Duration::from_secs(10);
        while !a.stream_close_acked("100.64.21.2", 42) {
            assert!(Instant::now() < deadline, "close was never acked complete");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// A CLOSE sent immediately after the data (so it can overtake
    /// frames on the wire) must not truncate the stream: the reader
    /// still receives every byte before end-of-stream.
    #[tokio::test]
    async fn stream_close_overtaking_data_still_delivers_everything() {
        let (a, b) = chaos_pair(6421, "100.64.22.1", "100.64.22.2").await;
        let payload = pattern(40_000, 3);
        a.send_stream_open("100.64.22.2", 7, "bulk", 9000)
            .await
            .unwrap();
        a.send_stream_data("100.64.22.2", 7, &payload)
            .await
            .unwrap();
        a.send_stream_close("100.64.22.2", 7).await.unwrap();
        let mut received = Vec::new();
        let read = async {
            while let Some(chunk) = b.next_stream_data("100.64.22.1", 7).await {
                received.extend_from_slice(&chunk);
            }
        };
        tokio::time::timeout(Duration::from_secs(30), read)
            .await
            .expect("pipelined close truncated the stream");
        assert_eq!(received, payload);
    }

    /// Backpressure + reset: with nobody consuming at the receiver,
    /// the sender's window fills and its send blocks (it must NOT
    /// drop bytes to proceed). A RESET then wakes the blocked send
    /// with an error.
    #[tokio::test]
    async fn stream_blocked_sender_is_woken_by_reset_not_by_dropping() {
        let (a, b) = chaos_pair(6431, "100.64.23.1", "100.64.23.2").await;
        a.send_stream_open("100.64.23.2", 9, "bulk", 9000)
            .await
            .unwrap();
        // Nobody ever pulls next_stream_data at B: at most WINDOW +
        // DELIVERY frames can be absorbed; 512 KB cannot complete.
        let big = pattern(512_000, 5);
        let send_a = a.clone();
        let sender =
            tokio::spawn(async move { send_a.send_stream_data("100.64.23.2", 9, &big).await });
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(
            !sender.is_finished(),
            "send must block on a full window instead of dropping bytes"
        );
        b.reset_stream("100.64.23.1", 9).await;
        let result = tokio::time::timeout(Duration::from_secs(10), sender)
            .await
            .expect("blocked sender was not woken by the reset")
            .unwrap();
        assert!(result.is_err(), "send on a reset stream must fail");
    }

    /// A RESET is sent exactly once, and on an unreliable
    /// transport it can be lost. The blocked sender must still
    /// be woken: its retransmitted DATA frames draw a fresh
    /// RESET out of the receiver (the stray-segment rule), so
    /// the loss heals within a few retransmission rounds
    /// instead of wedging the stream forever. The drop budget
    /// below deterministically kills the original RESET (and
    /// the first heal attempts), leaving the heal as the only
    /// path that can wake the sender.
    #[tokio::test]
    async fn stream_lost_reset_heals_via_retransmitted_data() {
        let hub = MemoryHub::new();
        let mk = |port: u16, vip: &'static str, role: &'static str, seed: u64| {
            let dir = std::env::temp_dir().join(format!(
                "kronos-reset-loss-{}-{}",
                std::process::id(),
                vip.replace('.', "-")
            ));
            let _ = std::fs::remove_dir_all(&dir);
            let transport = ChaosTransport::wrap(hub.register(addr(port)), seed, 10, 5);
            let handle = transport.clone();
            let (tunnel, rx) = Tunnel::bind_with_transport(
                transport,
                Identity::load_or_create(&dir).unwrap(),
                vip,
                role,
                Arc::new(TelemetryCounters::default()),
                Arc::new(EventRing::new(64)),
            )
            .unwrap();
            tunnel.update_acls(&[crate::wire::AclRule {
                id: "test-allow-all".to_string(),
                source_role: "*".to_string(),
                dest_service: "*".to_string(),
                port: 0,
                action: "ALLOW".to_string(),
                priority: 1,
            }]);
            let _ = &rx;
            (tunnel, handle, Identity::load_or_create(&dir).unwrap())
        };
        let (a, _a_transport, id_a) = mk(6531, "100.64.27.1", "edge", 0xA5A5_1234);
        let (b, b_transport, id_b) = mk(6532, "100.64.27.2", "node", 0x5A5A_9876);
        let mut rx_b = b
            .take_stream_receiver()
            .expect("stream receiver must be available once");
        let a = Arc::new(a);
        let b = Arc::new(b);
        a.add_peer(
            &id_b.public_hex(),
            "100.64.27.2",
            Some(b.local_addr()),
            "node",
        );
        b.add_peer(
            &id_a.public_hex(),
            "100.64.27.1",
            Some(a.local_addr()),
            "edge",
        );
        a.spawn_loops();
        b.spawn_loops();

        a.send_stream_open("100.64.27.2", 9, "bulk", 9000)
            .await
            .unwrap();
        let opened = tokio::time::timeout(Duration::from_secs(10), rx_b.recv())
            .await
            .expect("open event timed out")
            .expect("stream event channel closed");
        assert!(matches!(opened, StreamEvent::Open { stream_id: 9, .. }));

        // Nobody consumes at B: the 512 KB send blocks on the
        // full window, exactly like the plain reset test.
        let big = pattern(512_000, 5);
        let send_a = a.clone();
        let sender =
            tokio::spawn(async move { send_a.send_stream_data("100.64.27.2", 9, &big).await });
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(
            !sender.is_finished(),
            "send must block on a full window instead of dropping bytes"
        );

        // Kill B's next 64 sends: the RESET below is among the
        // first of them, and the budget also eats the first
        // heal attempts — only a heal that outlives the budget
        // can wake the sender.
        b_transport.drop_next_sends(64);
        b.reset_stream("100.64.27.1", 9).await;
        let result = tokio::time::timeout(Duration::from_secs(15), sender)
            .await
            .expect("blocked sender was not woken: the lost reset never healed")
            .unwrap();
        assert!(result.is_err(), "send on a reset stream must fail");
    }

    fn backdate_peer(a: &Tunnel<MemoryTransport>, pubkey: &str) {
        let peers = a.peers.lock().unwrap();
        let peer = peers.get(pubkey).expect("peer must exist");
        let past = Instant::now()
            .checked_sub(PEER_SILENCE_DEAD + Duration::from_secs(1))
            .expect("host uptime exceeds the dead threshold");
        *peer.last_activity.lock().unwrap() = past;
    }

    fn phantom_identity(tag: &str) -> Identity {
        let dir =
            std::env::temp_dir().join(format!("kronos-phantom-{}-{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&dir);
        Identity::load_or_create(&dir).unwrap()
    }

    /// A peer that dies mid-stream (no CLOSE, no RESET — the
    /// host is simply gone) must not leave its streams behind:
    /// housekeeping reaps both directions once the peer has
    /// been silent past the dead threshold, so retransmission
    /// stops and blocked senders wake with an error. A live
    /// peer's streams are untouched.
    #[tokio::test]
    async fn streams_of_a_silent_peer_are_reaped_by_housekeeping() {
        let hub = Arc::new(MemoryHub::new());
        let (a, _rx, _id_a, _tel) = make_node(&hub, 6621, "100.64.30.1", "edge").await;
        let b_id = phantom_identity("30-2");
        let c_id = phantom_identity("30-3");
        a.add_peer(&b_id.public_hex(), "100.64.30.2", None, "node");
        a.add_peer(&c_id.public_hex(), "100.64.30.3", None, "node");
        let out_b = a.out_stream("100.64.30.2", 5);
        let in_b = a.in_stream("100.64.30.2", 6);
        let _out_c = a.out_stream("100.64.30.3", 7);

        backdate_peer(&a, &b_id.public_hex());
        a.stream_housekeeping().await;

        assert!(
            a.find_out_stream("100.64.30.2", 5).is_none(),
            "outbound stream of a silent peer must be reaped"
        );
        assert!(
            a.find_in_stream("100.64.30.2", 6).is_none(),
            "inbound stream of a silent peer must be reaped"
        );
        assert!(
            out_b.state.lock().unwrap().dead,
            "reaped sender state must be dead (waiters wake)"
        );
        assert!(
            in_b.state.lock().unwrap().dead,
            "reaped receiver state must be dead"
        );
        assert!(
            a.tombstoned("100.64.30.2", 5),
            "reaped stream must be tombstoned"
        );
        assert!(
            a.find_out_stream("100.64.30.3", 7).is_some(),
            "a live peer's stream must not be reaped"
        );
    }

    /// Peer-table membership follows the control plane: a peer
    /// that is absent from the sync list AND silent past the
    /// dead threshold is removed (routes included); an absent
    /// but active peer is kept, and an empty sync removes
    /// nobody.
    #[tokio::test]
    async fn update_peers_removes_departed_silent_peers_only() {
        let hub = Arc::new(MemoryHub::new());
        let (a, _rx, _id_a, _tel) = make_node(&hub, 6631, "100.64.31.1", "edge").await;
        let b_id = phantom_identity("31-2");
        let c_id = phantom_identity("31-3");
        let d_id = phantom_identity("31-4");
        a.add_peer(&b_id.public_hex(), "100.64.31.2", None, "node");
        a.add_peer(&c_id.public_hex(), "100.64.31.3", None, "node");
        backdate_peer(&a, &b_id.public_hex());

        let node = |id: &Identity, name: &str, vip: &str| PeerNode {
            node_id: name.to_string(),
            node_name: name.to_string(),
            public_key: id.public_hex(),
            fingerprint: id.fingerprint(),
            virtual_ip: vip.to_string(),
            endpoint: String::new(),
            role: "node".to_string(),
            online: true,
            nat_type: String::new(),
            ebpf_probe_passed: false,
            last_seen: String::new(),
            tx_bytes: 0,
            rx_bytes: 0,
            avg_latency_ms: 0.0,
        };
        a.update_peers(&[node(&d_id, "node-d", "100.64.31.4")]);
        assert_eq!(
            a.peer_count(),
            2,
            "departed+silent removed, active kept, new added"
        );
        assert!(
            a.peer_silence("100.64.31.2").is_none(),
            "removed peer's route must be gone"
        );
        assert!(
            a.peer_silence("100.64.31.3").is_some(),
            "active peer must survive removal"
        );
        a.update_peers(&[]);
        assert_eq!(a.peer_count(), 2, "an empty sync must remove nobody");
    }

    /// The inbound stream cap is a safety valve: at the limit,
    /// a frame that would create state for a NEW stream id is
    /// refused (RESET) instead of growing the map, while frames
    /// for existing streams keep flowing.
    #[tokio::test]
    async fn inbound_stream_cap_refuses_new_streams_beyond_the_limit() {
        let hub = Arc::new(MemoryHub::new());
        let (a, _rx, _id_a, _tel) = make_node(&hub, 6641, "100.64.32.1", "edge").await;
        let b_id = phantom_identity("32-2");
        a.add_peer(&b_id.public_hex(), "100.64.32.2", None, "node");
        for id in 0..MAX_IN_STREAMS_PER_PEER as u32 {
            a.in_stream("100.64.32.2", id);
        }
        assert_eq!(
            a.in_stream_count_for("100.64.32.2"),
            MAX_IN_STREAMS_PER_PEER
        );
        let src = vip_to_octets("100.64.32.2").unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&9999u32.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(b"x");
        a.handle_stream_frame(KIND_STREAM_DATA, &src, "node".to_string(), &body)
            .await;
        assert!(
            a.find_in_stream("100.64.32.2", 9999).is_none(),
            "a new stream beyond the cap must not create state"
        );
        // An existing stream still accepts data at the cap.
        let mut body0 = Vec::new();
        body0.extend_from_slice(&0u32.to_be_bytes());
        body0.extend_from_slice(&0u32.to_be_bytes());
        body0.extend_from_slice(b"y");
        a.handle_stream_frame(KIND_STREAM_DATA, &src, "node".to_string(), &body0)
            .await;
        let got =
            tokio::time::timeout(Duration::from_secs(5), a.next_stream_data("100.64.32.2", 0))
                .await
                .expect("existing stream must keep flowing at the cap");
        assert_eq!(got.as_deref(), Some(&b"y"[..]));
    }

    /// The Round-7 spoofing hole: a packet's claimed src_vip
    /// decided its ACL role, so any member could steal an
    /// ALLOWed identity by writing the victim's VIP into its
    /// own packet. Now the destination trusts the source only
    /// after the end-to-end body opens under the pairwise key
    /// with the CLAIMED source. The attacker (role "node",
    /// default-denied at D) claims the victim's VIP (role
    /// "edge", the only ALLOW) — the packet must die at the
    /// E2E check, while the victim's genuine packet is
    /// delivered.
    #[tokio::test]
    async fn spoofed_source_vip_cannot_steal_an_allowed_role() {
        let hub = MemoryHub::new();
        let (v, _rx_v, id_v, _t1) = make_node(&hub, 6651, "100.64.40.1", "edge").await;
        let (m, _rx_m, id_m, _t2) = make_node(&hub, 6652, "100.64.40.2", "node").await;
        let (d, mut rx_d, id_d, tel_d) = make_node(&hub, 6653, "100.64.40.3", "node").await;
        // Full key knowledge (registry model).
        for (node, others) in [
            (&v, vec![(&id_m, "100.64.40.2", "node"), (&id_d, "100.64.40.3", "node")]),
            (&m, vec![(&id_v, "100.64.40.1", "edge"), (&id_d, "100.64.40.3", "node")]),
            (&d, vec![(&id_v, "100.64.40.1", "edge"), (&id_m, "100.64.40.2", "node")]),
        ] {
            for (id, vip, role) in others {
                node.add_peer(&id.public_hex(), vip, None, role);
            }
        }
        // Endpoints for the two senders -> D (sessions are direct here).
        m.add_peer(&id_d.public_hex(), "100.64.40.3", Some(d.local_addr()), "node");
        v.add_peer(&id_d.public_hex(), "100.64.40.3", Some(d.local_addr()), "node");
        v.spawn_loops();
        m.spawn_loops();
        d.spawn_loops();
        // D's policy: ONLY role "edge" may send mesh data.
        d.update_acls(&[AclRule {
            id: "allow-edge-only".to_string(),
            source_role: "edge".to_string(),
            dest_service: "*".to_string(),
            port: 0,
            action: "ALLOW".to_string(),
            priority: 1,
        }]);
        // Baseline: M's genuine traffic is default-denied, and the
        // attempt establishes M's session with D.
        m.send_data("100.64.40.3", b"m genuine").await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(400), rx_d.recv())
                .await
                .is_err(),
            "attacker's own traffic must be policy-denied"
        );
        // The attack: M hand-crafts a packet over its own session
        // claiming src = V (.1). The best body M can produce is
        // sealed with the M<->D pairwise key — D verifies against
        // the V<->D key, so it must fail and drop.
        let drops_before = tel_d.snapshot().drops;
        let frame = {
            let key = m.e2e_key_for(&[100, 64, 40, 3], true).unwrap();
            let sealed = crate::crypto::e2e_seal(
                &key,
                KIND_DATA,
                &[100, 64, 40, 1],
                &[100, 64, 40, 3],
                b"i am totally v",
            )
            .unwrap();
            let mut inner = vec![KIND_DATA, DEFAULT_TTL];
            inner.extend_from_slice(&[100, 64, 40, 1]); // claimed src = V
            inner.extend_from_slice(&[100, 64, 40, 3]); // dst = D
            inner.extend_from_slice(&sealed);
            let peer = {
                let peers = m.peers.lock().unwrap();
                peers.values().find(|p| p.vip == [100, 64, 40, 3]).unwrap().clone()
            };
            let mut state = peer.state.lock().unwrap();
            let (counter, remote_index, ct) = match &mut *state {
                PeerState::Established { session, remote_index, .. } => {
                    let mut aad = vec![MSG_DATA, 0, 0, 0];
                    aad.extend_from_slice(&remote_index.to_le_bytes());
                    aad.extend_from_slice(&session.next_counter().to_le_bytes());
                    let (c, ct) = session.seal(&aad, &inner).unwrap();
                    (c, *remote_index, ct)
                }
                _ => panic!("M-D session not established"),
            };
            let mut frame = vec![MSG_DATA, 0, 0, 0];
            frame.extend_from_slice(&remote_index.to_le_bytes());
            frame.extend_from_slice(&counter.to_le_bytes());
            frame.extend_from_slice(&ct);
            frame
        };
        d.handle_frame(&frame, m.local_addr()).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(400), rx_d.recv())
                .await
                .is_err(),
            "spoofed packet must not be delivered"
        );
        assert!(
            tel_d.snapshot().drops > drops_before,
            "spoofed packet must be dropped at origin authentication"
        );
        // Positive control: V's genuine packet IS delivered.
        v.send_data("100.64.40.3", b"v genuine").await.unwrap();
        let (src, payload) = tokio::time::timeout(Duration::from_secs(5), rx_d.recv())
            .await
            .expect("genuine delivery timed out")
            .expect("channel closed");
        assert_eq!(payload, b"v genuine");
        assert_eq!(src, "100.64.40.1");
    }

    /// PING is a hop-local keepalive: a PING whose claimed source
    /// is not the session peer must be dropped, not answered —
    /// otherwise it is a reflection primitive (PONG to any VIP).
    #[tokio::test]
    async fn ping_with_spoofed_source_gets_no_pong() {
        let hub = MemoryHub::new();
        let (m, _rx_m, id_m, _t1) = make_node(&hub, 6661, "100.64.41.2", "node").await;
        let (d, _rx_d, id_d, tel_d) = make_node(&hub, 6662, "100.64.41.3", "node").await;
        m.add_peer(&id_d.public_hex(), "100.64.41.3", Some(d.local_addr()), "node");
        d.add_peer(&id_m.public_hex(), "100.64.41.2", Some(m.local_addr()), "node");
        m.spawn_loops();
        d.spawn_loops();
        // Establish the session with a genuine (allowed) exchange.
        m.send_data("100.64.41.3", b"warmup").await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        let drops_before = tel_d.snapshot().drops;
        // Craft a PING over M's session claiming src = a third
        // party (.9, not even a node here).
        let frame = {
            let mut inner = vec![KIND_PING, DEFAULT_TTL];
            inner.extend_from_slice(&[100, 64, 41, 9]); // claimed src
            inner.extend_from_slice(&[100, 64, 41, 3]); // dst = D
            inner.extend_from_slice(&now_millis().to_le_bytes());
            let peer = {
                let peers = m.peers.lock().unwrap();
                peers.values().find(|p| p.vip == [100, 64, 41, 3]).unwrap().clone()
            };
            let mut state = peer.state.lock().unwrap();
            let (counter, remote_index, ct) = match &mut *state {
                PeerState::Established { session, remote_index, .. } => {
                    let mut aad = vec![MSG_DATA, 0, 0, 0];
                    aad.extend_from_slice(&remote_index.to_le_bytes());
                    aad.extend_from_slice(&session.next_counter().to_le_bytes());
                    let (c, ct) = session.seal(&aad, &inner).unwrap();
                    (c, *remote_index, ct)
                }
                _ => panic!("M-D session not established"),
            };
            let mut frame = vec![MSG_DATA, 0, 0, 0];
            frame.extend_from_slice(&remote_index.to_le_bytes());
            frame.extend_from_slice(&counter.to_le_bytes());
            frame.extend_from_slice(&ct);
            frame
        };
        d.handle_frame(&frame, m.local_addr()).await;
        assert!(
            tel_d.snapshot().drops > drops_before,
            "spoofed PING must be dropped, not answered"
        );
    }

    /// A corrupt freshness.json must fail CLOSED: replay
    /// floors are seeded at boot time, so an INIT replayed from
    /// before the corruption is rejected — while a fresh,
    /// legitimate handshake still succeeds.
    #[tokio::test]
    async fn corrupt_freshness_state_fails_closed() {
        let dir = std::env::temp_dir().join(format!(
            "kronos-fresh-{}-corrupt",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("freshness.json"), "{torn write").unwrap();
        let hub = MemoryHub::new();
        let (a, _rx_a, id_a, _t1) = make_node(&hub, 6671, "100.64.42.1", "node").await;
        let (b, _rx_b, id_b, _t2) = make_node(&hub, 6672, "100.64.42.2", "node").await;
        a.add_peer(&id_b.public_hex(), "100.64.42.2", Some(b.local_addr()), "node");
        b.add_peer(&id_a.public_hex(), "100.64.42.1", Some(a.local_addr()), "node");
        b.set_freshness_dir(&dir);
        assert!(
            *b.init_floor_default.lock().unwrap() > 0,
            "corrupt state must seed the boot floor"
        );
        a.spawn_loops();
        b.spawn_loops();
        // A replayed INIT stamped an hour ago must be rejected:
        // B never establishes a session from it.
        let old_ts = now_millis() - 3_600_000;
        let mut initiator =
            crate::crypto::HandshakeInitiator::new(id_a.secret(), id_b.public);
        let msg1 = initiator.write_message1(&old_ts.to_le_bytes()).unwrap();
        let mut frame = vec![MSG_INIT, 0, 0, 0];
        frame.extend_from_slice(&777u32.to_le_bytes());
        frame.extend_from_slice(&msg1);
        b.handle_frame(&frame, a.local_addr()).await;
        let b_peer_a = {
            let peers = b.peers.lock().unwrap();
            peers.values().find(|p| p.vip == [100, 64, 42, 1]).unwrap().clone()
        };
        assert!(
            !matches!(
                *b_peer_a.state.lock().unwrap(),
                PeerState::Established { .. }
            ),
            "stale INIT must not establish a session after fail-closed seeding"
        );
        // A fresh legitimate handshake still works.
        a.send_data("100.64.42.2", b"fresh still works").await.unwrap();
    }

    /// Persisted freshness state is written atomically (temp +
    /// rename): the final file is always complete and parseable,
    /// and no temp file is left behind.
    #[tokio::test]
    async fn freshness_persist_is_atomic_and_parseable() {
        let dir = std::env::temp_dir().join(format!(
            "kronos-fresh-{}-atomic",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let hub = MemoryHub::new();
        let (a, _rx_a, _id_a, _t1) = make_node(&hub, 6681, "100.64.43.1", "node").await;
        a.set_freshness_dir(&dir);
        let _ = a.next_init_ts();
        let path = dir.join("freshness.json");
        let mut text = String::new();
        for _ in 0..40 {
            if let Ok(t) = std::fs::read_to_string(&path) {
                text = t;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let f: FreshnessFile = serde_json::from_str(&text)
            .expect("persisted freshness file must be complete JSON");
        assert!(f.self_last_init_ms > 0);
        assert!(
            !dir.join("freshness.json.tmp").exists(),
            "temp file must be renamed away, not left behind"
        );
    }

    /// Cookie proof math: a mac2 built from the cookie bound
    /// to the source address verifies; tampered proofs, wrong
    /// sources and missing proofs do not.
    #[tokio::test]
    async fn cookie_proof_math_roundtrips() {
        let hub = MemoryHub::new();
        let (x, _rx, _id, _t) = make_node(&hub, 6694, "100.64.45.9", "node").await;
        let from: SocketAddr = "203.0.113.7:9999".parse().unwrap();
        let secret = x.cookie_jar.lock().unwrap().current;
        let cookie = Tunnel::<MemoryTransport>::cookie_value(&secret, &from);
        let mut init = vec![0u8; INIT_FRAME_LEN];
        init[0] = MSG_INIT;
        let proof = Tunnel::<MemoryTransport>::mac2(&cookie, &init);
        let mut frame = init.clone();
        frame.extend_from_slice(&proof);
        assert!(x.cookie_proof_valid(&from, &frame));
        // Tampered proof.
        let mut bad = frame.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert!(!x.cookie_proof_valid(&from, &bad));
        // Same proof, different source port: the cookie is
        // address-bound, so it must not transfer.
        let other: SocketAddr = "203.0.113.7:8888".parse().unwrap();
        assert!(!x.cookie_proof_valid(&other, &frame));
        // No proof attached at all.
        assert!(!x.cookie_proof_valid(&from, &init));
    }

    /// Past the INIT rate limit, the responder answers with a
    /// COOKIE challenge instead of spending handshake work.
    #[tokio::test]
    async fn init_flood_draws_a_cookie_challenge() {
        let hub = MemoryHub::new();
        let (b, _rx_b, _id_b, _t) = make_node(&hub, 6693, "100.64.45.2", "node").await;
        let attacker_addr: SocketAddr = "127.0.0.1:6699".parse().unwrap();
        let attacker = hub.register(attacker_addr);
        let mut garbage = vec![0u8; INIT_FRAME_LEN];
        garbage[0] = MSG_INIT;
        for _ in 0..(INIT_RATE_LIMIT + 5) {
            b.handle_frame(&garbage, attacker_addr).await;
        }
        let mut buf = [0u8; 64];
        let (n, _from) = tokio::time::timeout(
            Duration::from_secs(3),
            attacker.recv_from(&mut buf),
        )
        .await
        .expect("no challenge arrived")
        .expect("attacker inbox closed");
        assert_eq!(buf[0], MSG_COOKIE, "expected a COOKIE challenge frame");
        assert_eq!(n, 20, "challenge carries exactly the 16-byte cookie");
    }

    /// The full WireGuard-style loop under flood: the bucket
    /// for A's address is saturated with garbage, A's proof-less
    /// path is gated, but A — having received the challenge —
    /// retries with mac2 attached and its data gets through.
    #[tokio::test]
    async fn cookie_retry_handshakes_through_an_init_flood() {
        let hub = MemoryHub::new();
        let (a, _rx_a, id_a, _t1) = make_node(&hub, 6691, "100.64.44.1", "node").await;
        let (b, mut rx_b, id_b, _t2) = make_node(&hub, 6692, "100.64.44.2", "node").await;
        a.add_peer(&id_b.public_hex(), "100.64.44.2", Some(b.local_addr()), "node");
        b.add_peer(&id_a.public_hex(), "100.64.44.1", Some(a.local_addr()), "node");
        a.spawn_loops();
        b.spawn_loops();
        let mut garbage = vec![0u8; INIT_FRAME_LEN];
        garbage[0] = MSG_INIT;
        // Saturate B's bucket for A's address with junk INITs.
        for _ in 0..(INIT_RATE_LIMIT + 5) {
            b.handle_frame(&garbage, a.local_addr()).await;
        }
        // B's challenge reaches A through its receive loop and
        // is cached against B's endpoint.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            a.cookies_out.lock().unwrap().contains_key(&b.local_addr()),
            "the challenged initiator must cache the cookie"
        );
        // Re-arm the gate (fresh 1-second window, saturated
        // again) so the next INIT can only pass WITH the proof.
        for _ in 0..(INIT_RATE_LIMIT + 5) {
            b.handle_frame(&garbage, a.local_addr()).await;
        }
        a.send_data("100.64.44.2", b"through the flood").await.unwrap();
        let (src, payload) = tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
            .await
            .expect("cookie retry timed out")
            .expect("channel closed");
        assert_eq!(payload, b"through the flood");
        assert_eq!(src, "100.64.44.1");
    }

    /// Debug/isolation probe: both directions bulk simultaneously.
    #[tokio::test]
    async fn stream_bidirectional_bulk_over_chaos() {
        let (a, b) = chaos_pair(6481, "100.64.24.1", "100.64.24.2").await;
        let pa = pattern(100_000, 21);
        let pb = pattern(100_000, 22);
        let (a2, b2) = (a.clone(), b.clone());
        let (pa2, pb2) = (pa.clone(), pb.clone());
        let t1 = tokio::spawn(async move {
            a2.send_stream_open("100.64.24.2", 5, "bulk", 9000)
                .await
                .unwrap();
            a2.send_stream_data("100.64.24.2", 5, &pa2).await.unwrap();
            a2.send_stream_close("100.64.24.2", 5).await.unwrap();
        });
        let t2 = tokio::spawn(async move {
            b2.send_stream_open("100.64.24.1", 5, "bulk", 9000)
                .await
                .unwrap();
            b2.send_stream_data("100.64.24.1", 5, &pb2).await.unwrap();
            b2.send_stream_close("100.64.24.1", 5).await.unwrap();
        });
        let mut ra = Vec::new();
        let mut rb = Vec::new();
        let read = async {
            // Pull both directions alternately.
            let (mut done_a, mut done_b) = (false, false);
            while !(done_a && done_b) {
                tokio::select! {
                    r = a.next_stream_data("100.64.24.2", 5), if !done_b => {
                        match r { Some(c) => rb.extend_from_slice(&c), None => done_b = true }
                    }
                    r = b.next_stream_data("100.64.24.1", 5), if !done_a => {
                        match r { Some(c) => ra.extend_from_slice(&c), None => done_a = true }
                    }
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(30), read)
            .await
            .expect("bidir read timed out");
        t1.await.unwrap();
        t2.await.unwrap();
        assert_eq!(ra, pa);
        assert_eq!(rb, pb);
    }

    /// Gateway-pattern probe: only A opens; B echoes per chunk
    /// without ever opening its own direction.
    #[tokio::test]
    async fn stream_gateway_pattern_over_chaos() {
        let (a, b) = chaos_pair(6501, "100.64.25.1", "100.64.25.2").await;
        // B: echo pump — pull a chunk, send it straight back.
        let b_echo = b.clone();
        let echo = tokio::spawn(async move {
            while let Some(chunk) = b_echo.next_stream_data("100.64.25.1", 5).await {
                if b_echo
                    .send_stream_data("100.64.25.1", 5, &chunk)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        a.send_stream_open("100.64.25.2", 5, "echo", 9000)
            .await
            .unwrap();
        let payload = pattern(32_000, 11);
        a.send_stream_data("100.64.25.2", 5, &payload[..16_384])
            .await
            .unwrap();
        a.send_stream_data("100.64.25.2", 5, &payload[16_384..])
            .await
            .unwrap();
        let mut received = Vec::new();
        let read = async {
            while received.len() < payload.len() {
                match a.next_stream_data("100.64.25.2", 5).await {
                    Some(c) => received.extend_from_slice(&c),
                    None => break,
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(15), read)
            .await
            .expect("gateway-pattern read timed out");
        echo.abort();
        assert_eq!(received.len(), payload.len());
        assert_eq!(received, payload);
    }
    /// Round 8 regression: outbound traffic must NOT refresh a
    /// peer's silence clock. Before the fix, the send path
    /// stamped last_activity on every frame and the periodic
    /// PINGs kept it permanently fresh, so a vanished peer was
    /// never considered dead and the Round-6 reaper never fired
    /// for established peers.
    #[tokio::test]
    async fn outbound_traffic_does_not_revive_a_silent_peer() {
        let hub = MemoryHub::new();
        let (a, _rx_a, id_a, _t) = make_node(&hub, 6631, "100.64.31.1", "edge").await;
        let (b, _rx_b, id_b, _t2) = make_node(&hub, 6632, "100.64.31.2", "db").await;
        a.add_peer(&id_b.public_hex(), "100.64.31.2", Some(b.local_addr()), "db");
        b.add_peer(&id_a.public_hex(), "100.64.31.1", Some(a.local_addr()), "edge");
        a.spawn_loops();
        b.spawn_loops();
        a.send_data("100.64.31.2", b"warmup").await.unwrap();
        backdate_peer(&a, &id_b.public_hex());
        assert!(a.peer_is_dead("100.64.31.2"));
        // A keeps SENDING; raw data draws no tunnel-level reply,
        // so nothing inbound can legitimately refresh the clock.
        a.send_data("100.64.31.2", b"still there?").await.unwrap();
        assert!(
            a.peer_is_dead("100.64.31.2"),
            "outbound sends must not reset the silence clock"
        );
    }

    /// Round 8 regression: COOKIE frames are unauthenticated, so
    /// an attacker can plant a forged cookie in our cache for a
    /// peer's endpoint. Our next INIT then carries an invalid
    /// proof — the responder must treat it as proof-less (rate
    /// path), never drop it outright.
    #[tokio::test]
    async fn poisoned_cookie_cache_cannot_block_handshakes() {
        let hub = MemoryHub::new();
        let (c, _rx_c, id_c, _t) = make_node(&hub, 6641, "100.64.32.1", "edge").await;
        let (d, mut rx_d, id_d, _t2) = make_node(&hub, 6642, "100.64.32.2", "db").await;
        c.add_peer(&id_d.public_hex(), "100.64.32.2", Some(d.local_addr()), "db");
        d.add_peer(&id_c.public_hex(), "100.64.32.1", Some(c.local_addr()), "edge");
        c.spawn_loops();
        d.spawn_loops();
        c.cookies_out
            .lock()
            .unwrap()
            .insert(d.local_addr(), ([0xEE; 16], Instant::now()));
        c.send_data("100.64.32.2", b"through").await.unwrap();
        let (_s, p) = tokio::time::timeout(Duration::from_secs(5), rx_d.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(p, b"through");
    }

    /// Round 8: the per-source limit alone gives every rotating
    /// source a fresh handshake-CPU budget. Once the AGGREGATE
    /// proof-less budget is spent, even a fresh, well-behaved
    /// source is challenged; its cookie retry then goes through.
    #[tokio::test]
    async fn aggregate_budget_forces_cookie_mode_for_fresh_sources() {
        let hub = MemoryHub::new();
        let (e, _rx_e, id_e, _t) = make_node(&hub, 6651, "100.64.33.1", "edge").await;
        let (f, mut rx_f, id_f, _t2) = make_node(&hub, 6652, "100.64.33.2", "db").await;
        e.add_peer(&id_f.public_hex(), "100.64.33.2", Some(f.local_addr()), "db");
        f.add_peer(&id_e.public_hex(), "100.64.33.1", Some(e.local_addr()), "edge");
        e.spawn_loops();
        f.spawn_loops();
        *f.init_global.lock().unwrap() = (Instant::now(), INIT_GLOBAL_LIMIT, 0);
        let _ = e.send_data("100.64.33.2", b"knock").await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            e.cookies_out.lock().unwrap().contains_key(&f.local_addr()),
            "a fresh source past the aggregate budget must be challenged with a cookie"
        );
        e.send_data("100.64.33.2", b"knock").await.unwrap();
        let (_s, p) = tokio::time::timeout(Duration::from_secs(5), rx_f.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(p, b"knock");
    }

    /// Round 8: inbound stream DATA is bounded by BYTES, not just
    /// frame count — a payload larger than the send-side chunk
    /// size is non-conformant and must be dropped, not buffered.
    #[tokio::test]
    async fn oversized_stream_data_frame_is_dropped_not_buffered() {
        let hub = MemoryHub::new();
        let (a, _rx, _id_a, _t) = make_node(&hub, 6661, "100.64.34.1", "edge").await;
        let _in = a.in_stream("100.64.34.2", 9);
        let mut body = Vec::new();
        body.extend_from_slice(&9u32.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&vec![0xAA; STREAM_FRAME_PAYLOAD + 1]);
        a.handle_stream_frame(KIND_STREAM_DATA, &[100, 64, 34, 2], "node".to_string(), &body)
            .await;
        assert!(
            a.next_stream_data("100.64.34.2", 9).await.is_none(),
            "oversized payload must not be buffered"
        );
        let mut ok = Vec::new();
        ok.extend_from_slice(&9u32.to_be_bytes());
        ok.extend_from_slice(&0u32.to_be_bytes());
        ok.extend_from_slice(&vec![0xBB; STREAM_FRAME_PAYLOAD]);
        a.handle_stream_frame(KIND_STREAM_DATA, &[100, 64, 34, 2], "node".to_string(), &ok)
            .await;
        let got = a
            .next_stream_data("100.64.34.2", 9)
            .await
            .expect("conformant payload must be delivered");
        assert_eq!(got.len(), STREAM_FRAME_PAYLOAD);
    }

}