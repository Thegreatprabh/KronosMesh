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
//!   a stream close, never with data.
//!
//! Both checks call the same `acl_decision` the data plane uses, so
//! deny-override + default-deny semantics are identical everywhere.
//!
//! v1 limits, stated plainly: streams have no flow control beyond the
//! bounded queues (intended for low-rate service traffic, not bulk
//! transfer), no idle timeout, and the frame transport is unordered —
//! if stream data ever outruns its OPEN frame, the receiver answers
//! CLOSE for the unknown stream instead of silently corrupting it,
//! so the failure is visible to the local client as a disconnect.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};

use rand_core::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

use crate::config::ServiceForward;
use crate::tunnel::{acl_decision, AclDecision, StreamEvent, Transport, Tunnel};

const CHUNK: usize = 16_384;
const STREAM_QUEUE: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Dir {
    /// We initiated the stream (a local client connected to a forward).
    Out,
    /// A peer initiated it (we dialed a local service for them).
    In,
}

struct StreamHalf {
    to_tcp: mpsc::Sender<Vec<u8>>,
    aborts: Vec<AbortHandle>,
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

    fn close_stream(&self, peer_vip: &str, stream_id: u32, dir: Dir) {
        let half = self
            .streams
            .lock()
            .unwrap()
            .remove(&(peer_vip.to_string(), stream_id, dir));
        if let Some(half) = half {
            for a in &half.aborts {
                a.abort();
            }
            // Dropping `half` closes to_tcp, ending the writer task.
        }
    }

    fn stream_alive(&self, peer_vip: &str, stream_id: u32, dir: Dir) -> bool {
        self.streams
            .lock()
            .unwrap()
            .contains_key(&(peer_vip.to_string(), stream_id, dir))
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
            let key = (fwd.target_vip.clone(), stream_id, Dir::Out);
            let (mut rd, mut wr) = stream.into_split();
            let (to_tcp_tx, mut to_tcp_rx) = mpsc::channel::<Vec<u8>>(STREAM_QUEUE);
            let writer = tokio::spawn(async move {
                while let Some(bytes) = to_tcp_rx.recv().await {
                    if wr.write_all(&bytes).await.is_err() {
                        break;
                    }
                }
                let _ = wr.shutdown().await;
            });
            let gw_reader = gw.clone();
            let fwd_reader = fwd.clone();
            let reader = tokio::spawn(async move {
                let mut buf = vec![0u8; CHUNK];
                loop {
                    match rd.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if !gw_reader.stream_alive(&fwd_reader.target_vip, stream_id, Dir::Out)
                            {
                                break; // the far end closed the stream
                            }
                            if gw_reader
                                .tunnel
                                .send_stream_data(&fwd_reader.target_vip, stream_id, &buf[..n])
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = gw_reader
                    .tunnel
                    .send_stream_close(&fwd_reader.target_vip, stream_id)
                    .await;
                gw_reader.close_stream(&fwd_reader.target_vip, stream_id, Dir::Out);
            });
            gw.streams.lock().unwrap().insert(
                key,
                StreamHalf {
                    to_tcp: to_tcp_tx,
                    aborts: vec![writer.abort_handle(), reader.abort_handle()],
                },
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
                gw.close_stream(&fwd.target_vip, stream_id, Dir::Out);
            }
        });
    }

    /// Consumes tunnel stream events (inbound streams where this node
    /// is the target).
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
                    StreamEvent::Data {
                        src_vip,
                        stream_id,
                        data,
                    } => {
                        let sink = {
                            let map = gw.streams.lock().unwrap();
                            map.get(&(src_vip.clone(), stream_id, Dir::In))
                                .or_else(|| map.get(&(src_vip.clone(), stream_id, Dir::Out)))
                                .map(|h| h.to_tcp.clone())
                        };
                        match sink {
                            Some(tx) => {
                                let _ = tx.try_send(data);
                            }
                            None => {
                                // Data for a stream we do not have:
                                // answer CLOSE so the sender tears the
                                // stream down visibly instead of
                                // feeding a void (e.g. when the frames
                                // overtook the OPEN).
                                let _ = gw.tunnel.send_stream_close(&src_vip, stream_id).await;
                            }
                        }
                    }
                    StreamEvent::Close { src_vip, stream_id } => {
                        gw.close_stream(&src_vip, stream_id, Dir::In);
                        gw.close_stream(&src_vip, stream_id, Dir::Out);
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
            let _ = self.tunnel.send_stream_close(&src_vip, stream_id).await;
            return;
        }
        let stream = match TcpStream::connect(("127.0.0.1", port)).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "[kronos] gateway: local service {service} on 127.0.0.1:{port} unreachable: {e}"
                );
                let _ = self.tunnel.send_stream_close(&src_vip, stream_id).await;
                return;
            }
        };
        let (mut rd, mut wr) = stream.into_split();
        let (to_tcp_tx, mut to_tcp_rx) = mpsc::channel::<Vec<u8>>(STREAM_QUEUE);
        let writer = tokio::spawn(async move {
            while let Some(bytes) = to_tcp_rx.recv().await {
                if wr.write_all(&bytes).await.is_err() {
                    break;
                }
            }
            let _ = wr.shutdown().await;
        });
        let gw = self.clone();
        let src = src_vip.clone();
        let reader = tokio::spawn(async move {
            let mut buf = vec![0u8; CHUNK];
            loop {
                match rd.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if !gw.stream_alive(&src, stream_id, Dir::In) {
                            break;
                        }
                        if gw
                            .tunnel
                            .send_stream_data(&src, stream_id, &buf[..n])
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = gw.tunnel.send_stream_close(&src, stream_id).await;
            gw.close_stream(&src, stream_id, Dir::In);
        });
        self.streams.lock().unwrap().insert(
            (src_vip, stream_id, Dir::In),
            StreamHalf {
                to_tcp: to_tcp_tx,
                aborts: vec![writer.abort_handle(), reader.abort_handle()],
            },
        );
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
}
