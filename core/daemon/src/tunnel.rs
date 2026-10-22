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
pub const MSG_DATA: u8 = 4;

pub const KIND_PING: u8 = 0x01;
pub const KIND_PONG: u8 = 0x02;
pub const KIND_DATA: u8 = 0x03;

const HANDSHAKE_WAIT: Duration = Duration::from_millis(3000);
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

    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        addr: SocketAddr,
    ) -> impl std::future::Future<Output = std::io::Result<usize>> + Send + 'a {
        self.socket.send_to(buf, addr)
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> impl std::future::Future<Output = std::io::Result<(usize, SocketAddr)>> + Send + 'a {
        self.socket.recv_from(buf)
    }
}

/// A shared in-memory switchboard for tests: transports register an
/// address and receive datagrams addressed to them.
pub struct MemoryHub {
    nodes: std::sync::Mutex<HashMap<SocketAddr, mpsc::Sender<(Vec<u8>, SocketAddr)>>>,
}

impl MemoryHub {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { nodes: std::sync::Mutex::new(HashMap::new()) })
    }

    pub fn register(self: &Arc<Self>, addr: SocketAddr) -> MemoryTransport {
        let (tx, rx) = mpsc::channel(4096);
        self.nodes.lock().unwrap().insert(addr, tx);
        MemoryTransport { hub: self.clone(), addr, inbox: tokio::sync::Mutex::new(rx) }
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
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "hub closed",
                )),
            }
        }
    }
}

enum PeerState {
    Idle,
    AwaitingResponse { initiator: Option<HandshakeInitiator>, local_index: u32 },
    Established { session: Session, local_index: u32, remote_index: u32 },
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
    last_activity: Mutex<Instant>,
}

pub struct Tunnel<T: Transport> {
    transport: Arc<T>,
    identity: Arc<Identity>,
    local_vip: [u8; 4],
    local_vip_str: String,
    peers: Mutex<HashMap<String, Arc<Peer>>>,
    by_index: Mutex<HashMap<u32, String>>,
    routes: Mutex<HashMap<[u8; 4], String>>,
    telemetry: Arc<TelemetryCounters>,
    ring: Arc<EventRing>,
    acl_rules: Mutex<Vec<AclRule>>,
    local_role: String,
    last_init_ms: Mutex<u64>,
    app_tx: mpsc::Sender<(String, Vec<u8>)>,
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
    ) -> Result<(Arc<Self>, mpsc::Receiver<(String, Vec<u8>)>)> {
        let octets = vip_to_octets(local_vip)
            .ok_or_else(|| anyhow!("invalid virtual ip {local_vip}"))?;
        let (app_tx, app_rx) = mpsc::channel(1024);
        let tunnel = Arc::new(Self {
            transport: Arc::new(transport),
            identity: Arc::new(identity),
            local_vip: octets,
            local_vip_str: local_vip.to_string(),
            peers: Mutex::new(HashMap::new()),
            by_index: Mutex::new(HashMap::new()),
            routes: Mutex::new(HashMap::new()),
            telemetry,
            ring,
            acl_rules: Mutex::new(Vec::new()),
            local_role: local_role.to_string(),
            last_init_ms: Mutex::new(0),
            app_tx,
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
        let mut last = self.last_init_ms.lock().unwrap();
        let ts = now_millis().max(*last + 1);
        *last = ts;
        ts
    }

    // -- peer table -----------------------------------------------------------

    pub fn add_peer(
        &self,
        public_hex: &str,
        vip: &str,
        endpoint: Option<SocketAddr>,
        role: &str,
    ) {
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
        let mut peers = self.peers.lock().unwrap();
        if let Some(existing) = peers.get(public_hex) {
            if let Some(ep) = endpoint {
                *existing.endpoint.lock().unwrap() = Some(ep);
            }
            *existing.role.lock().unwrap() = role.to_string();
            self.routes.lock().unwrap().insert(octets, public_hex.to_string());
            return;
        }
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
        self.routes.lock().unwrap().insert(octets, public_hex.to_string());
        self.ring.push(format!("peer added: {} ({})", public_hex, vip));
    }

    /// Syncs the peer table from a control-plane peer list (heartbeat
    /// responses / registration). Our own entry is skipped.
    pub fn update_peers(&self, peers: &[PeerNode]) {
        let self_hex = self.identity.public_hex();
        for p in peers {
            if p.public_key == self_hex {
                continue;
            }
            let endpoint = p.endpoint.parse::<SocketAddr>().ok();
            self.add_peer(&p.public_key, &p.virtual_ip, endpoint, &p.role);
        }
    }

    pub fn peer_count(&self) -> usize {
        self.peers.lock().unwrap().len()
    }

    pub fn connected_peer_count(&self) -> u32 {
        let peers = self.peers.lock().unwrap();
        peers
            .values()
            .filter(|p| matches!(*p.state.lock().unwrap(), PeerState::Established { .. }))
            .count() as u32
    }

    pub fn avg_latency_ms(&self) -> f64 {
        let peers = self.peers.lock().unwrap();
        let vals: Vec<f64> = peers
            .values()
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
        let routes = self.routes.lock().unwrap();
        let key = routes.get(vip)?;
        self.peers.lock().unwrap().get(key).cloned()
    }

    fn peer_by_index(&self, index: u32) -> Option<Arc<Peer>> {
        let by_index = self.by_index.lock().unwrap();
        let key = by_index.get(&index)?;
        self.peers.lock().unwrap().get(key).cloned()
    }

    // -- zero-trust ACL enforcement -------------------------------------
    //
    // Policy is evaluated at the mesh-data service granularity: rules
    // whose destination is "*" or "mesh-data" with port 0 (wildcard)
    // govern data-plane traffic; service-specific rules (e.g.
    // edge -> postgres:5432) are enforced by the service gateways that
    // terminate those services. Rules are evaluated in ascending
    // priority; the first matching rule decides. A matching DENY drops
    // the packet, increments telemetry.drops, and logs to the ring.

    /// Replaces the enforced policy (called by the ACL sync loop).
    pub fn update_acls(&self, rules: &[AclRule]) {
        *self.acl_rules.lock().unwrap() = rules.to_vec();
        self.ring
            .push(format!("acl: policy updated ({} rules)", rules.len()));
    }

    /// Returns the DENY rule blocking `source_role`'s mesh data, if any.
    fn acl_denied_for(&self, source_role: &str) -> Option<AclRule> {
        let rules = self.acl_rules.lock().unwrap();
        let mut sorted: Vec<&AclRule> = rules.iter().collect();
        sorted.sort_by_key(|r| r.priority);
        for rule in sorted {
            let role_matches = rule.source_role == source_role || rule.source_role == "*";
            let service_matches =
                rule.dest_service == "*" || rule.dest_service == "mesh-data";
            let port_matches = rule.port == 0;
            if role_matches && service_matches && port_matches {
                if rule.action == "DENY" {
                    return Some(rule.clone());
                }
                return None; // first match decides; it was an ALLOW
            }
        }
        None
    }

    // -- sending ---------------------------------------------------------------

    async fn send_raw(&self, endpoint: SocketAddr, frame: &[u8]) {
        match self.transport.send_to(frame, endpoint).await {
            Ok(n) => {
                self.telemetry.packets_out.fetch_add(1, Ordering::Relaxed);
                self.telemetry.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
                self.telemetry.userspace_packets.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                self.ring.push(format!("send to {endpoint} failed: {e}"));
            }
        }
    }

    async fn initiate_handshake(&self, peer: &Arc<Peer>) -> Result<()> {
        let local_index = self.next_index();
        let mut initiator =
            HandshakeInitiator::new(self.identity.secret(), peer.public);
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
        self.send_raw(endpoint, &frame).await;
        Ok(())
    }

    async fn ensure_session(&self, peer: &Arc<Peer>) -> Result<()> {
        let needs_init = {
            let state = peer.state.lock().unwrap();
            if matches!(*state, PeerState::Established { .. }) {
                return Ok(());
            }
            matches!(*state, PeerState::Idle)
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
        if kind == KIND_DATA {
            if let Some(rule) = self.acl_denied_for(&self.local_role) {
                self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                self.ring.push(format!(
                    "acl: send blocked by DENY rule {} ({} -> {})",
                    rule.id, rule.source_role, rule.dest_service
                ));
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
        let mut inner = Vec::with_capacity(5 + body.len());
        inner.push(kind);
        inner.extend_from_slice(&dst_vip);
        inner.extend_from_slice(body);
        let (counter, remote_index, ciphertext) = {
            let mut state = peer.state.lock().unwrap();
            match &mut *state {
                PeerState::Established { session, remote_index, .. } => {
                    let (c, ct) = session.seal(&inner)?;
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
        *peer.last_activity.lock().unwrap() = Instant::now();
        self.send_raw(endpoint, &frame).await;
        self.telemetry.packets_out.fetch_add(0, Ordering::Relaxed); // counted in send_raw
        Ok(())
    }

    pub async fn send_data(&self, dst_vip: &str, payload: &[u8]) -> Result<()> {
        let octets = vip_to_octets(dst_vip)
            .ok_or_else(|| anyhow!("invalid virtual ip {dst_vip}"))?;
        self.send_inner(octets, KIND_DATA, payload).await
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
                        // Each frame is handled in its own task: a
                        // handler may need to complete a handshake with
                        // a third node (mesh relay), which requires this
                        // receive loop to keep reading.
                        let handler = recv_self.clone();
                        let frame = buf[..n].to_vec();
                        tokio::spawn(async move {
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
            let established =
                matches!(*peer.state.lock().unwrap(), PeerState::Established { .. });
            if established && idle > KEEPALIVE_EVERY {
                let vip = peer.vip;
                let _ = self.send_inner(vip, KIND_PING, &now_millis().to_le_bytes()).await;
            }
        }
    }

    async fn ping_tick(&self) {
        let peers: Vec<Arc<Peer>> = self.peers.lock().unwrap().values().cloned().collect();
        for peer in peers {
            let established =
                matches!(*peer.state.lock().unwrap(), PeerState::Established { .. });
            if established {
                let vip = peer.vip;
                let _ = self.send_inner(vip, KIND_PING, &now_millis().to_le_bytes()).await;
            }
        }
    }

    async fn handle_frame(&self, frame: &[u8], from: SocketAddr) {
        if frame.len() < 8 {
            self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
            return;
        }
        match frame[0] {
            MSG_INIT => self.handle_init(frame, from).await,
            MSG_RESP => self.handle_resp(frame, from).await,
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
        let sender_index = u32::from_le_bytes(frame[4..8].try_into().unwrap());
        let msg1 = &frame[8..];
        let mut responder = HandshakeResponder::new(self.identity.secret());
        let (payload, remote_static) = match responder.read_message1(msg1) {
            Ok(v) => v,
            Err(e) => {
                self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                self.ring.push(format!("bad handshake init from {from}: {e}"));
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
            self.ring.push("handshake init without timestamp payload".to_string());
            return;
        }
        let init_ts = u64::from_le_bytes(payload[..8].try_into().unwrap());
        if init_ts > now_millis() + 300_000 {
            self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
            self.ring
                .push("handshake init timestamp too far in the future".to_string());
            return;
        }
        {
            let mut last = peer.last_init_ms.lock().unwrap();
            if init_ts <= *last {
                self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                self.ring.push(format!(
                    "stale or replayed handshake init from {} (ts {init_ts} <= last {})",
                    peer.public_hex, *last
                ));
                return;
            }
            *last = init_ts;
        }
        let local_index = self.next_index();
        let (msg2, session) = match responder.write_message2(&[]) {
            Ok(v) => v,
            Err(e) => {
                self.ring.push(format!("handshake response failed: {e}"));
                return;
            }
        };
        {
            let mut state = peer.state.lock().unwrap();
            if let PeerState::Established { local_index: old, .. } = &*state {
                // Retire the replaced session's index so stale frames can
                // no longer resolve to this peer.
                self.by_index.lock().unwrap().remove(old);
            }
            *state = PeerState::Established {
                session,
                local_index,
                remote_index: sender_index,
            };
        }
        self.by_index
            .lock()
            .unwrap()
            .insert(local_index, peer.public_hex.clone());
        // Endpoint learning happens only here: this INIT authenticated
        // (Noise_IK verifies the initiator's static key) and passed the
        // freshness check, so the source address is trustworthy.
        *peer.endpoint.lock().unwrap() = Some(from);
        self.telemetry.handshakes_completed.fetch_add(1, Ordering::Relaxed);
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
        if let PeerState::AwaitingResponse { initiator, local_index } = &mut *state {
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
                PeerState::Established { session, .. } => match session.open(counter, &frame[16..]) {
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
        if plain.len() < 5 {
            return;
        }
        let kind = plain[0];
        let dst_vip: [u8; 4] = plain[1..5].try_into().unwrap();
        let body = plain[5..].to_vec();
        match kind {
            KIND_PING => {
                let src_vip = peer.vip;
                let _ = self.send_inner(src_vip, KIND_PONG, &body).await;
            }
            KIND_PONG => {
                if body.len() >= 8 {
                    let sent = u64::from_le_bytes(body[..8].try_into().unwrap());
                    let rtt = now_millis().saturating_sub(sent) as f64;
                    *peer.latency_ms.lock().unwrap() = rtt;
                }
            }
            KIND_DATA => {
                let src_role = peer.role.lock().unwrap().clone();
                if let Some(rule) = self.acl_denied_for(&src_role) {
                    self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                    self.ring.push(format!(
                        "acl: packet from role {src_role} dropped by DENY rule {}",
                        rule.id
                    ));
                    return;
                }
                if dst_vip == self.local_vip {
                    let src = octets_to_vip(&peer.vip);
                    let _ = self.app_tx.send((src, body)).await;
                } else {
                    // Mesh relay: forward toward the destination's next hop.
                    let tunnel = self;
                    let body_clone = body.clone();
                    if let Some(next_hop) = tunnel.peer_by_vip(&dst_vip) {
                        if next_hop.public_hex != peer.public_hex {
                            let _ = tunnel.send_inner(dst_vip, KIND_DATA, &body_clone).await;
                        }
                    } else {
                        self.telemetry.drops.fetch_add(1, Ordering::Relaxed);
                    }
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
        (tunnel, rx, identity, telemetry)
    }

    #[tokio::test]
    async fn two_nodes_handshake_and_exchange_data() {
        let hub = MemoryHub::new();
        let (a, _rx_a, id_a, _tel_a) = make_node(&hub, 6101, "100.64.0.1", "edge").await;
        let (b, mut rx_b, id_b, _tel_b) = make_node(&hub, 6102, "100.64.0.2", "node").await;
        a.add_peer(&id_b.public_hex(), "100.64.0.2", Some(b.local_addr()), "node");
        b.add_peer(&id_a.public_hex(), "100.64.0.1", Some(a.local_addr()), "edge");
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
        a.add_peer(&id_b.public_hex(), "100.64.0.12", Some(b.local_addr()), "node");
        a.add_peer(&id_c.public_hex(), "100.64.0.13", None, "node");
        // Point A's route to C at B instead (next-hop relay).
        a.routes
            .lock()
            .unwrap()
            .insert([100, 64, 0, 13], id_b.public_hex());
        b.add_peer(&id_a.public_hex(), "100.64.0.11", Some(a.local_addr()), "node");
        b.add_peer(&id_c.public_hex(), "100.64.0.13", Some(c.local_addr()), "node");
        c.add_peer(&id_b.public_hex(), "100.64.0.12", Some(b.local_addr()), "node");
        a.spawn_loops();
        b.spawn_loops();
        c.spawn_loops();
        a.send_data("100.64.0.13", b"relayed payload").await.unwrap();
        let (_src, payload) = tokio::time::timeout(Duration::from_secs(5), rx_c.recv())
            .await
            .expect("relay timed out")
            .expect("channel closed");
        assert_eq!(payload, b"relayed payload");
    }

    #[tokio::test]
    async fn unknown_peer_handshake_is_dropped() {
        let hub = MemoryHub::new();
        let (a, _rx_a, id_a, _t1) = make_node(&hub, 6121, "100.64.0.21", "node").await;
        let (stranger, _rx_s, _id_s, _t2) =
            make_node(&hub, 6122, "100.64.0.22", "node").await;
        stranger.add_peer(&id_a.public_hex(), "100.64.0.21", Some(a.local_addr()), "node");
        a.spawn_loops();
        stranger.spawn_loops();
        let res = stranger.send_data("100.64.0.21", b"intruder").await;
        assert!(res.is_err());
        assert_eq!(a.connected_peer_count(), 0);
    }

    #[tokio::test]
    async fn forged_frame_cannot_hijack_endpoint() {
        let hub = MemoryHub::new();
        let (a, _rx_a, id_a, _t) = make_node(&hub, 6201, "100.64.0.21", "edge").await;
        let (b, mut rx_b, id_b, _t2) = make_node(&hub, 6202, "100.64.0.22", "db").await;
        a.add_peer(&id_b.public_hex(), "100.64.0.22", Some(b.local_addr()), "db");
        b.add_peer(&id_a.public_hex(), "100.64.0.21", Some(a.local_addr()), "edge");
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
        a.add_peer(&id_b.public_hex(), "100.64.0.32", Some(b.local_addr()), "db");
        b.add_peer(&id_a.public_hex(), "100.64.0.31", Some(a.local_addr()), "edge");
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
        a.send_data("100.64.0.32", b"session still alive").await.unwrap();
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
        let (b, mut rx_b, id_b, tel_b) =
            make_node(&hub, 6132, "100.64.0.32", "database").await;
        a.add_peer(&id_b.public_hex(), "100.64.0.32", Some(b.local_addr()), "database");
        b.add_peer(&id_a.public_hex(), "100.64.0.31", Some(a.local_addr()), "edge");
        a.spawn_loops();
        b.spawn_loops();

        // Baseline: without policy, the packet is delivered.
        a.send_data("100.64.0.32", b"before policy").await.unwrap();
        let (_src, payload) = tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
            .await
            .expect("baseline delivery timed out")
            .expect("channel closed");
        assert_eq!(payload, b"before policy");

        // Policy lands on B: role "edge" is denied mesh data.
        b.update_acls(&[AclRule {
            id: "deny-edge".to_string(),
            source_role: "edge".to_string(),
            dest_service: "*".to_string(),
            port: 0,
            action: "DENY".to_string(),
            priority: 1,
        }]);

        let drops_before = tel_b.snapshot().drops;
        a.send_data("100.64.0.32", b"after policy").await.unwrap();
        let blocked = tokio::time::timeout(Duration::from_millis(600), rx_b.recv()).await;
        assert!(blocked.is_err(), "denied packet must not be delivered");
        assert!(
            tel_b.snapshot().drops > drops_before,
            "drop counter must record the ACL drop"
        );
    }
}
