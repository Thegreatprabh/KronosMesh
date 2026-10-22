//! Service gateway: TCP service forwarding over the mesh, with ACL
//! enforcement at both ends.
//!
//! Until this module existed, ACL rules naming a concrete service
//! and port (edge -> postgres:5432) were stored and displayed but
//! enforced NOWHERE: the tunnel's data gate only ever decided the
//! wildcard "mesh-data" question. The gateway is the enforcement
//! point for service traffic:
//!
//! - A node configures local forwards ([[services]] in the daemon
//!   config): a loopback TCP listener whose connections are carried
//!   over the encrypted tunnel to a peer's gateway.
//! - The INITIATING gateway checks the policy for (its own role ->
//!   service:port) before a single mesh frame is sent.
//! - The RECEIVING gateway checks the policy again for (sender role
//!   -> service:port) before dialing the local service at
//!   127.0.0.1:port. A denied or unreachable target is answered with
//!   a stream RESET, never with data.
//!
//! Both checks call the same `acl_decision` the data plane uses, so
//! deny-override + default-deny semantics are identical everywhere.
//!
//! ## Reliability (v2 streams)
//!
//! The mesh transport is UDP: frames can be lost, duplicated and
//! reordered. TCP services (SSH, PostgreSQL, ...) assume the byte
//! stream under them is reliable and ordered, so the tunnel's stream
//! layer provides exactly that — per-direction sequence numbers,
//! cumulative ACKs, retransmission, and a bounded sender window (see
//! `tunnel.rs`). The gateway's part of the contract:
//!
//! - The TCP -> mesh pump AWAITS `send_stream_data`; when the
//!   window is full the pump stops reading the socket, so TCP's own
//!   flow control throttles the local sender. Nothing is ever
//!   dropped to make progress — there is no try_send on this path.
//! - The mesh -> TCP pump pulls ordered payloads from
//!   `next_stream_data`; the tunnel only releases bytes in sequence
//!   and only as fast as this pump consumes them (consumption IS the
//!   receive window), so a slow local reader backpressures the far
//!   sender end to end.
//! - Local EOF sends a stream CLOSE that is retransmitted until the
//!   peer acknowledges it complete: every queued byte is delivered
//!   before the peer's consumer sees end-of-stream.
//! - Directions close independently (TCP half-close): a stream
//!   half is torn down only when BOTH pumps have finished, so a
//!   client that sends a request and half-closes still receives the
//!   full reply. A RESET is the only immediate teardown.
//!
//! Remaining v2 limits, stated plainly: no idle timeout (a stream
//! lives as long as both TCP endpoints do), and both peers must run
//! a daemon with the v2 stream protocol — the frame format changed
//! (sequence numbers), so v1 and v2 gateways do not interoperate.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};

use rand_core::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

use crate::config::ServiceForward;
use crate::tunnel::{acl_decision, AclDecision, StreamEvent, Transport, Tunnel};

const CHUNK: usize = 16_384;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Dir {
    /// We initiated the stream (a local client connected to a forward).
    Out,
    /// A peer initiated it (we dialed a local service for them).
    In,
}

struct StreamHalf {
    aborts: Vec<AbortHandle>,
    /// Pumps still running (one per direction). The half is torn
    /// down when BOTH pumps have finished — never when just one
    /// direction ends (TCP half-close semantics).
    pumps_left: Arc<AtomicUsize>,
}

/// Live streams keyed by (peer VIP, stream id, direction).
type StreamMap = HashMap<(String, u32, Dir), StreamHalf>;

pub struct Gateway<T: Transport> {
    tunnel: Arc<Tunnel<T>>,
    local_role: String,
    streams: Arc<Mutex<StreamMap>>,
    next_id: AtomicU32,
}

impl<T: Transport> Gateway<T> {
    pub fn new(tunnel: Arc<Tunnel<T>>, local_role: String) -> Arc<Self> {
        Arc::new(Self {
            tunnel,
            local_role,
            streams: Arc::new(Mutex::new(HashMap::new())),
            // Stream ids only need to be unique per (peer, direction);
            // a random start keeps two nodes from mirroring counters.
            next_id: AtomicU32::new(rand_core::OsRng.next_u32()),
        })
    }

    fn policy_allows(&self, source_role: &str, service: &str, port: u16) -> bool {
        acl_decision(&self.tunnel.acl_snapshot(), source_role, service, port) == AclDecision::Allow
    }

    /// Registers a stream half before its pumps start, so a pump
    /// that ends instantly still finds (and cleans) its entry.
    fn register_stream(&self, peer_vip: &str, stream_id: u32, dir: Dir) {
        self.streams.lock().unwrap().insert(
            (peer_vip.to_string(), stream_id, dir),
            StreamHalf {
                aborts: Vec::new(),
                pumps_left: Arc::new(AtomicUsize::new(2)),
            },
        );
    }

    /// Attaches pump abort handles to a registered half. If the
    /// half is already gone (a pump ended and tore the stream down
    /// first), the pumps are aborted immediately instead.
    fn attach_aborts(&self, peer_vip: &str, stream_id: u32, dir: Dir, handles: Vec<AbortHandle>) {
        let key = (peer_vip.to_string(), stream_id, dir);
        let mut map = self.streams.lock().unwrap();
        match map.get_mut(&key) {
            Some(half) => half.aborts.extend(handles),
            None => {
                for h in handles {
                    h.abort();
                }
            }
        }
    }

    /// A pump finished. The stream half is torn down only when
    /// BOTH pumps are done: one direction ending must never kill
    /// the other direction's in-flight data (a client that sends a
    /// request and half-closes still expects the full reply). The
    /// one exception is a RESET: the peer is gone, so the sibling
    /// pump is aborted immediately instead of being left blocked on
    /// a silent local socket.
    fn pump_finished(&self, peer_vip: &str, stream_id: u32, dir: Dir, abort_sibling: bool) {
        if abort_sibling {
            self.teardown_stream(peer_vip, stream_id, dir);
            return;
        }
        let key = (peer_vip.to_string(), stream_id, dir);
        let last = {
            let map = self.streams.lock().unwrap();
            match map.get(&key) {
                Some(half) => half.pumps_left.fetch_sub(1, AtomicOrdering::SeqCst) == 1,
                None => false,
            }
        };
        if last {
            self.streams.lock().unwrap().remove(&key);
            self.tunnel.drop_in_stream(peer_vip, stream_id);
        }
    }

    /// Immediate teardown: aborts both pumps and drops the tunnel's
    /// inbound state. The outbound direction is NOT dropped here:
    /// if a CLOSE was sent, its retransmission lifecycle finishes
    /// the close reliably on its own.
    fn teardown_stream(&self, peer_vip: &str, stream_id: u32, dir: Dir) {
        let half = self
            .streams
            .lock()
            .unwrap()
            .remove(&(peer_vip.to_string(), stream_id, dir));
        if let Some(half) = half {
            for a in &half.aborts {
                a.abort();
            }
        }
        self.tunnel.drop_in_stream(peer_vip, stream_id);
    }

    /// Serves one configured forward until the listener dies.
    pub fn spawn_forward(self: &Arc<Self>, fwd: ServiceForward) {
        let gw = self.clone();
        tokio::spawn(async move {
            match TcpListener::bind(&fwd.listen).await {
                Ok(listener) => {
                    eprintln!(
                        "[kronos] gateway: {} listening on {} -> {}:{} via mesh",
                        fwd.name, fwd.listen, fwd.target_vip, fwd.target_port
                    );
                    while let Ok((stream, _)) = listener.accept().await {
                        gw.handle_local_conn(stream, &fwd);
                    }
                }
                Err(e) => eprintln!(
                    "[kronos] gateway: cannot bind {} for service {}: {e}",
                    fwd.listen, fwd.name
                ),
            }
        });
    }

    /// TCP -> mesh pump: reads the local socket and sends each chunk
    /// on the reliable stream. When the stream's send window is
    /// full, `send_stream_data` waits — the pump stops reading, and
    /// TCP flow control does the rest. On local EOF it sends the
    /// (reliably retransmitted) stream CLOSE and ends; the mesh ->
    /// TCP direction keeps flowing until the peer ends it.
    fn spawn_tcp_pump(
        self: &Arc<Self>,
        peer_vip: String,
        stream_id: u32,
        dir: Dir,
        mut rd: OwnedReadHalf,
    ) -> AbortHandle {
        let gw = self.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; CHUNK];
            loop {
                match rd.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if gw
                            .tunnel
                            .send_stream_data(&peer_vip, stream_id, &buf[..n])
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = gw.tunnel.send_stream_close(&peer_vip, stream_id).await;
            gw.pump_finished(&peer_vip, stream_id, dir, false);
        })
        .abort_handle()
    }

    /// Mesh -> TCP pump: pulls ordered payloads and writes them to
    /// the local socket. This pump's pace is the receive window:
    /// the tunnel releases (and acknowledges) stream bytes only as
    /// fast as they are consumed here. When the stream ends — the
    /// peer's CLOSE fully delivered, or a RESET — it shuts the
    /// socket's write side down and tears the half down.
    fn spawn_mesh_pump(
        self: &Arc<Self>,
        peer_vip: String,
        stream_id: u32,
        dir: Dir,
        mut wr: OwnedWriteHalf,
    ) -> AbortHandle {
        let gw = self.clone();
        tokio::spawn(async move {
            let mut consumer_gone = false;
            while let Some(bytes) = gw.tunnel.next_stream_data(&peer_vip, stream_id).await {
                if wr.write_all(&bytes).await.is_err() {
                    consumer_gone = true;
                    break;
                }
            }
            if consumer_gone {
                // The local endpoint vanished mid-stream. Tell
                // the peer to tear the stream down now instead of
                // retransmitting into the void until its state
                // ages out; the reset also retires our inbound
                // state, so a later stream can never inherit a
                // phantom sequence gap from this one.
                gw.tunnel.reset_stream(&peer_vip, stream_id).await;
            }
            // Half-close: shut down the socket's write side (the
            // local endpoint sees a clean EOF after the last byte),
            // then finish. The sibling pump keeps draining unless
            // the stream was reset (peer gone).
            let was_reset = gw.tunnel.stream_was_reset(&peer_vip, stream_id);
            let _ = wr.shutdown().await;
            gw.pump_finished(&peer_vip, stream_id, dir, was_reset);
        })
        .abort_handle()
    }

    fn handle_local_conn(self: &Arc<Self>, stream: TcpStream, fwd: &ServiceForward) {
        let gw = self.clone();
        let fwd = fwd.clone();
        tokio::spawn(async move {
            // Initiator-side policy: this node's own role must be
            // allowed to reach the service before any mesh traffic.
            if !gw.policy_allows(&gw.local_role, &fwd.name, fwd.target_port) {
                eprintln!(
                    "[kronos] gateway: local policy does not allow {} -> {}:{} (default deny); closing connection",
                    gw.local_role, fwd.name, fwd.target_port
                );
                return;
            }
            let stream_id = gw.next_id.fetch_add(1, AtomicOrdering::Relaxed);
            let (rd, wr) = stream.into_split();
            gw.register_stream(&fwd.target_vip, stream_id, Dir::Out);
            // The mesh pump starts BEFORE the OPEN is sent: it
            // creates the tunnel's inbound state for the peer's
            // direction, so a refusal RESET that races back can
            // never arrive "before" the stream exists locally.
            let mesh_handle = gw.spawn_mesh_pump(fwd.target_vip.clone(), stream_id, Dir::Out, wr);
            let tcp_handle = gw.spawn_tcp_pump(fwd.target_vip.clone(), stream_id, Dir::Out, rd);
            gw.attach_aborts(
                &fwd.target_vip,
                stream_id,
                Dir::Out,
                vec![mesh_handle, tcp_handle],
            );
            if let Err(e) = gw
                .tunnel
                .send_stream_open(&fwd.target_vip, stream_id, &fwd.name, fwd.target_port)
                .await
            {
                eprintln!(
                    "[kronos] gateway: stream open to {} failed: {e}",
                    fwd.target_vip
                );
                gw.tunnel.reset_stream(&fwd.target_vip, stream_id).await;
                gw.teardown_stream(&fwd.target_vip, stream_id, Dir::Out);
            }
        });
    }

    /// Consumes tunnel stream OPEN events (inbound streams where
    /// this node is the target). Stream data is pulled per stream by
    /// the pumps, never pushed through this loop.
    pub fn spawn_event_loop(self: &Arc<Self>, mut rx: mpsc::Receiver<StreamEvent>) {
        let gw = self.clone();
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                match event {
                    StreamEvent::Open {
                        src_vip,
                        src_role,
                        stream_id,
                        service,
                        port,
                    } => {
                        gw.handle_open(src_vip, src_role, stream_id, service, port)
                            .await;
                    }
                }
            }
        });
    }

    async fn handle_open(
        self: &Arc<Self>,
        src_vip: String,
        src_role: String,
        stream_id: u32,
        service: String,
        port: u16,
    ) {
        // Target-side policy: the sender's role must be allowed HERE
        // before the local service is touched at all.
        if !self.policy_allows(&src_role, &service, port) {
            eprintln!(
                "[kronos] gateway: policy does not allow {src_role} -> {service}:{port} (default deny); stream from {src_vip} refused"
            );
            self.tunnel.reset_stream(&src_vip, stream_id).await;
            return;
        }
        let stream = match TcpStream::connect(("127.0.0.1", port)).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "[kronos] gateway: local service {service} on 127.0.0.1:{port} unreachable: {e}"
                );
                self.tunnel.reset_stream(&src_vip, stream_id).await;
                return;
            }
        };
        let (rd, wr) = stream.into_split();
        self.register_stream(&src_vip, stream_id, Dir::In);
        let mesh_handle = self.spawn_mesh_pump(src_vip.clone(), stream_id, Dir::In, wr);
        let tcp_handle = self.spawn_tcp_pump(src_vip.clone(), stream_id, Dir::In, rd);
        self.attach_aborts(&src_vip, stream_id, Dir::In, vec![mesh_handle, tcp_handle]);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Identity;
    use crate::ebpf_loader::{EventRing, TelemetryCounters};
    use crate::tunnel::{MemoryHub, MemoryTransport};
    use crate::wire::AclRule;
    use std::net::SocketAddr;
    use std::time::Duration;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn rule(id: &str, role: &str, service: &str, port: u16, action: &str) -> AclRule {
        AclRule {
            id: id.to_string(),
            source_role: role.to_string(),
            dest_service: service.to_string(),
            port,
            action: action.to_string(),
            priority: 10,
        }
    }

    async fn make_node(
        hub: &Arc<MemoryHub>,
        port: u16,
        vip: &str,
        role: &str,
        rules: Vec<AclRule>,
    ) -> (Arc<Tunnel<MemoryTransport>>, Identity) {
        let dir = std::env::temp_dir().join(format!(
            "kronos-gw-{}-{}",
            std::process::id(),
            vip.replace('.', "-")
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let identity = Identity::load_or_create(&dir).unwrap();
        let (tunnel, _rx) = Tunnel::bind_with_transport(
            hub.register(addr(port)),
            Identity::load_or_create(&dir).unwrap(),
            vip,
            role,
            Arc::new(TelemetryCounters::default()),
            Arc::new(EventRing::new(64)),
        )
        .unwrap();
        // Data-plane traffic between the nodes needs its own allow,
        // scoped to the mesh-data question (a "*/*" rule would also
        // allow every service question, which is NOT what the stream
        // tests intend to grant). Stream checks use the given rules.
        let mut all = vec![rule("data-allow", "*", "mesh-data", 0, "ALLOW")];
        all.extend(rules);
        tunnel.update_acls(&all);
        (tunnel, identity)
    }

    /// A loopback TCP echo "service"; returns (port, accepted count).
    async fn echo_server() -> (u16, Arc<AtomicU32>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicU32::new(0));
        let counter = accepted.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                counter.fetch_add(1, AtomicOrdering::Relaxed);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if stream.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        });
        (port, accepted)
    }

    async fn linked_pair(
        a_rules: Vec<AclRule>,
        b_rules: Vec<AclRule>,
        base_port: u16,
        vip_a: &'static str,
        vip_b: &'static str,
    ) -> (Arc<Tunnel<MemoryTransport>>, Arc<Tunnel<MemoryTransport>>) {
        // Distinct VIPs per test: identity state dirs are keyed by VIP,
        // and parallel tests sharing one would clobber each other's
        // key material mid-handshake.
        let hub = MemoryHub::new();
        let (a, id_a) = make_node(&hub, base_port, vip_a, "edge", a_rules).await;
        let (b, id_b) = make_node(&hub, base_port + 1, vip_b, "node", b_rules).await;
        a.add_peer(&id_b.public_hex(), vip_b, Some(b.local_addr()), "node");
        b.add_peer(&id_a.public_hex(), vip_a, Some(a.local_addr()), "edge");
        a.spawn_loops();
        b.spawn_loops();
        (a, b)
    }

    #[tokio::test]
    async fn gateway_carries_a_service_stream_end_to_end() {
        let (echo_port, accepted) = echo_server().await;
        let allow = vec![rule("svc", "edge", "echo", echo_port, "ALLOW")];
        let (a, b) = linked_pair(allow.clone(), allow, 6311, "100.64.1.1", "100.64.1.2").await;

        let gw_b = Gateway::new(b.clone(), "node".to_string());
        gw_b.spawn_event_loop(b.take_stream_receiver().unwrap());
        let gw_a = Gateway::new(a.clone(), "edge".to_string());
        gw_a.spawn_event_loop(a.take_stream_receiver().unwrap());
        gw_a.spawn_forward(ServiceForward {
            name: "echo".to_string(),
            listen: "127.0.0.1:18711".to_string(),
            target_vip: "100.64.1.2".to_string(),
            target_port: echo_port,
        });
        tokio::time::sleep(Duration::from_millis(300)).await;

        let mut client = TcpStream::connect("127.0.0.1:18711").await.unwrap();
        client.write_all(b"hello mesh").await.unwrap();
        let mut buf = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut buf))
            .await
            .expect("echo timed out")
            .expect("echo read failed");
        assert_eq!(&buf, b"hello mesh");
        assert_eq!(accepted.load(AtomicOrdering::Relaxed), 1);
    }

    #[tokio::test]
    async fn target_side_deny_refuses_before_dialing_the_service() {
        let (echo_port, accepted) = echo_server().await;
        let a_rules = vec![rule("svc", "edge", "echo", echo_port, "ALLOW")];
        let b_rules = vec![rule("svc-deny", "edge", "echo", echo_port, "DENY")];
        let (a, b) = linked_pair(a_rules, b_rules, 6321, "100.64.2.1", "100.64.2.2").await;

        let gw_b = Gateway::new(b.clone(), "node".to_string());
        gw_b.spawn_event_loop(b.take_stream_receiver().unwrap());
        let gw_a = Gateway::new(a.clone(), "edge".to_string());
        gw_a.spawn_event_loop(a.take_stream_receiver().unwrap());
        gw_a.spawn_forward(ServiceForward {
            name: "echo".to_string(),
            listen: "127.0.0.1:18712".to_string(),
            target_vip: "100.64.2.2".to_string(),
            target_port: echo_port,
        });
        tokio::time::sleep(Duration::from_millis(300)).await;

        let mut client = TcpStream::connect("127.0.0.1:18712").await.unwrap();
        let _ = client.write_all(b"should not arrive").await;
        let mut buf = [0u8; 16];
        // The stream is refused at B: the client sees a disconnect,
        // never an echo, and the service was never dialed.
        let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
            .await
            .expect("refusal timed out")
            .unwrap_or(0);
        assert_eq!(n, 0, "denied stream must not deliver data");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(accepted.load(AtomicOrdering::Relaxed), 0);
    }

    #[tokio::test]
    async fn initiator_side_default_deny_sends_no_mesh_traffic() {
        let (echo_port, accepted) = echo_server().await;
        // A has NO rule for the service: default-deny must stop the
        // connection locally, before any frame reaches B.
        let a_rules: Vec<AclRule> = vec![];
        let b_rules = vec![rule("svc", "edge", "echo", echo_port, "ALLOW")];
        let (a, b) = linked_pair(a_rules, b_rules, 6331, "100.64.3.1", "100.64.3.2").await;

        let gw_b = Gateway::new(b.clone(), "node".to_string());
        gw_b.spawn_event_loop(b.take_stream_receiver().unwrap());
        let gw_a = Gateway::new(a.clone(), "edge".to_string());
        gw_a.spawn_event_loop(a.take_stream_receiver().unwrap());
        gw_a.spawn_forward(ServiceForward {
            name: "echo".to_string(),
            listen: "127.0.0.1:18713".to_string(),
            target_vip: "100.64.3.2".to_string(),
            target_port: echo_port,
        });
        tokio::time::sleep(Duration::from_millis(300)).await;

        let mut client = TcpStream::connect("127.0.0.1:18713").await.unwrap();
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
            .await
            .expect("local refusal timed out")
            .unwrap_or(0);
        assert_eq!(n, 0);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            accepted.load(AtomicOrdering::Relaxed),
            0,
            "no stream may reach the target when the initiator denies"
        );
    }

    // -- gateway over a lossy, reordering transport ----------------------

    use crate::tunnel::ChaosTransport;

    async fn make_node_chaos(
        hub: &Arc<MemoryHub>,
        port: u16,
        vip: &str,
        role: &str,
        rules: Vec<AclRule>,
        seed: u64,
    ) -> (Arc<Tunnel<ChaosTransport>>, Identity) {
        let dir = std::env::temp_dir().join(format!(
            "kronos-gwc-{}-{}",
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
        let mut all = vec![rule("data-allow", "*", "mesh-data", 0, "ALLOW")];
        all.extend(rules);
        tunnel.update_acls(&all);
        (tunnel, identity)
    }

    async fn linked_pair_chaos(
        a_rules: Vec<AclRule>,
        b_rules: Vec<AclRule>,
        base_port: u16,
        vip_a: &'static str,
        vip_b: &'static str,
    ) -> (Arc<Tunnel<ChaosTransport>>, Arc<Tunnel<ChaosTransport>>) {
        let hub = MemoryHub::new();
        let (a, id_a) = make_node_chaos(&hub, base_port, vip_a, "edge", a_rules, 0xC0FF_EE01).await;
        let (b, id_b) =
            make_node_chaos(&hub, base_port + 1, vip_b, "node", b_rules, 0xC0FF_EE02).await;
        a.add_peer(&id_b.public_hex(), vip_b, Some(b.local_addr()), "node");
        b.add_peer(&id_a.public_hex(), vip_a, Some(a.local_addr()), "edge");
        a.spawn_loops();
        b.spawn_loops();
        (a, b)
    }

    fn pattern(n: usize, seed: u8) -> Vec<u8> {
        (0..n)
            .map(|i| ((i * 31 + seed as usize * 17) % 251) as u8)
            .collect()
    }

    fn assert_bytes_exact(got: &[u8], want: &[u8]) {
        assert_eq!(got.len(), want.len(), "length mismatch");
        if let Some(i) = got.iter().zip(want).position(|(x, y)| x != y) {
            panic!(
                "byte mismatch at offset {i}: got {} want {}",
                got[i], want[i]
            );
        }
    }

    /// 256 KB through the gateway over the chaos transport (10%
    /// loss, 5% duplication, 20% reordering) must come back
    /// byte-exact — the SSH/PostgreSQL requirement.
    #[tokio::test]
    async fn gateway_bulk_transfer_over_chaos_is_byte_exact() {
        let (echo_port, _accepted) = echo_server().await;
        let allow = vec![rule("svc", "edge", "echo", echo_port, "ALLOW")];
        let (a, b) =
            linked_pair_chaos(allow.clone(), allow, 6441, "100.64.31.1", "100.64.31.2").await;
        let gw_b = Gateway::new(b.clone(), "node".to_string());
        gw_b.spawn_event_loop(b.take_stream_receiver().unwrap());
        let gw_a = Gateway::new(a.clone(), "edge".to_string());
        gw_a.spawn_event_loop(a.take_stream_receiver().unwrap());
        gw_a.spawn_forward(ServiceForward {
            name: "echo".to_string(),
            listen: "127.0.0.1:18714".to_string(),
            target_vip: "100.64.31.2".to_string(),
            target_port: echo_port,
        });
        tokio::time::sleep(Duration::from_millis(300)).await;

        let payload = pattern(256_000, 11);
        let client = TcpStream::connect("127.0.0.1:18714").await.unwrap();
        let (mut rd, mut wr) = client.into_split();
        let send_payload = payload.clone();
        let writer = tokio::spawn(async move {
            wr.write_all(&send_payload).await.unwrap();
        });
        let mut received = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(60), rd.read_exact(&mut received))
            .await
            .expect("bulk echo timed out over chaos")
            .expect("bulk echo read failed");
        writer.await.unwrap();
        assert_bytes_exact(&received, &payload);
    }

    /// A consumer that reads nothing for two seconds, then reads
    /// slowly: the tunnel's in-flight buffering (~256 KB per
    /// direction) is far smaller than the 512 KB payload, so
    /// backpressure MUST engage — and still not one byte is lost.
    #[tokio::test]
    async fn gateway_slow_consumer_loses_nothing() {
        let (echo_port, _accepted) = echo_server().await;
        let allow = vec![rule("svc", "edge", "echo", echo_port, "ALLOW")];
        let (a, b) =
            linked_pair_chaos(allow.clone(), allow, 6451, "100.64.32.1", "100.64.32.2").await;
        let gw_b = Gateway::new(b.clone(), "node".to_string());
        gw_b.spawn_event_loop(b.take_stream_receiver().unwrap());
        let gw_a = Gateway::new(a.clone(), "edge".to_string());
        gw_a.spawn_event_loop(a.take_stream_receiver().unwrap());
        gw_a.spawn_forward(ServiceForward {
            name: "echo".to_string(),
            listen: "127.0.0.1:18715".to_string(),
            target_vip: "100.64.32.2".to_string(),
            target_port: echo_port,
        });
        tokio::time::sleep(Duration::from_millis(300)).await;

        let payload = pattern(512_000, 13);
        let client = TcpStream::connect("127.0.0.1:18715").await.unwrap();
        let (mut rd, mut wr) = client.into_split();
        let send_payload = payload.clone();
        let writer = tokio::spawn(async move {
            wr.write_all(&send_payload).await.unwrap();
        });
        // Read nothing while the path saturates...
        tokio::time::sleep(Duration::from_secs(2)).await;
        // ...then drain slowly, 8 KB at a time.
        let mut received = Vec::with_capacity(payload.len());
        let mut buf = vec![0u8; 8192];
        let drain = async {
            while received.len() < payload.len() {
                match rd.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => received.extend_from_slice(&buf[..n]),
                    Err(e) => panic!("slow read failed: {e}"),
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(90), drain)
            .await
            .expect("slow-consumer drain timed out");
        writer.await.unwrap();
        assert_bytes_exact(&received, &payload);
    }

    /// Four streams in parallel over the chaos transport, each with
    /// its own byte pattern: no cross-talk, no loss.
    #[tokio::test]
    async fn gateway_simultaneous_streams_over_chaos() {
        let (echo_port, _accepted) = echo_server().await;
        let allow = vec![rule("svc", "edge", "echo", echo_port, "ALLOW")];
        let (a, b) =
            linked_pair_chaos(allow.clone(), allow, 6461, "100.64.33.1", "100.64.33.2").await;
        let gw_b = Gateway::new(b.clone(), "node".to_string());
        gw_b.spawn_event_loop(b.take_stream_receiver().unwrap());
        let gw_a = Gateway::new(a.clone(), "edge".to_string());
        gw_a.spawn_event_loop(a.take_stream_receiver().unwrap());
        gw_a.spawn_forward(ServiceForward {
            name: "echo".to_string(),
            listen: "127.0.0.1:18716".to_string(),
            target_vip: "100.64.33.2".to_string(),
            target_port: echo_port,
        });
        tokio::time::sleep(Duration::from_millis(300)).await;

        let mut tasks = Vec::new();
        for k in 0..4u8 {
            tasks.push(tokio::spawn(async move {
                let payload = pattern(48_000, 20 + k);
                let client = TcpStream::connect("127.0.0.1:18716").await.unwrap();
                let (mut rd, mut wr) = client.into_split();
                let send_payload = payload.clone();
                let writer = tokio::spawn(async move {
                    wr.write_all(&send_payload).await.unwrap();
                });
                let mut received = vec![0u8; payload.len()];
                tokio::time::timeout(Duration::from_secs(60), rd.read_exact(&mut received))
                    .await
                    .expect("parallel stream timed out")
                    .expect("parallel stream read failed");
                writer.await.unwrap();
                assert_bytes_exact(&received, &payload);
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
    }

    /// A client that vanishes mid-transfer must not wedge the
    /// gateway: a fresh connection right after echoes normally.
    #[tokio::test]
    async fn gateway_disconnect_mid_transfer_keeps_gateway_healthy() {
        let (echo_port, _accepted) = echo_server().await;
        let allow = vec![rule("svc", "edge", "echo", echo_port, "ALLOW")];
        let (a, b) =
            linked_pair_chaos(allow.clone(), allow, 6471, "100.64.34.1", "100.64.34.2").await;
        let gw_b = Gateway::new(b.clone(), "node".to_string());
        gw_b.spawn_event_loop(b.take_stream_receiver().unwrap());
        let gw_a = Gateway::new(a.clone(), "edge".to_string());
        gw_a.spawn_event_loop(a.take_stream_receiver().unwrap());
        gw_a.spawn_forward(ServiceForward {
            name: "echo".to_string(),
            listen: "127.0.0.1:18717".to_string(),
            target_vip: "100.64.34.2".to_string(),
            target_port: echo_port,
        });
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Client 1: blast 96 KB and disappear without reading.
        {
            let mut c1 = TcpStream::connect("127.0.0.1:18717").await.unwrap();
            let _ = c1.write_all(&pattern(96_000, 31)).await;
        }
        tokio::time::sleep(Duration::from_millis(700)).await;

        // Client 2: the gateway must still serve a clean echo.
        let mut c2 = TcpStream::connect("127.0.0.1:18717").await.unwrap();
        c2.write_all(b"still alive").await.unwrap();
        let mut buf = [0u8; 11];
        match tokio::time::timeout(Duration::from_secs(15), c2.read_exact(&mut buf)).await {
            Ok(r) => {
                r.expect("post-disconnect echo failed");
            }
            Err(e) => {
                eprintln!("A streams:\n{}", a.stream_debug_all());
                eprintln!("B streams:\n{}", b.stream_debug_all());
                panic!("post-disconnect echo timed out: {e:?}");
            }
        }
        assert_eq!(&buf, b"still alive");
    }
}
