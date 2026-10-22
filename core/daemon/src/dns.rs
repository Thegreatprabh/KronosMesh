//! Mesh DNS: a small UDP resolver bound to this node's virtual IP
//! (port 53) while TUN host integration is enabled.
//!
//! - `<node>.mesh` and bare `<node>` A queries are answered from the
//!   live peer table — the same registry the control plane maintains —
//!   so `ping postgres-node.mesh` just works on a mesh host.
//! - Unknown names inside the mesh zone get an authoritative
//!   NXDOMAIN; they are never leaked to an outside resolver.
//! - Everything else is forwarded verbatim to a configured upstream
//!   resolver and the response relayed back, so the mesh resolver can
//!   serve as the host's only DNS endpoint.
//!
//! Query parsing, routing and response building are pure functions
//! (fully unit-tested); the server loop is a thin async shell. The
//! resolver implements A-record service for the mesh zone plus
//! transparent forwarding — it is not a general authoritative server
//! (no AAAA synthesis, no DNSSEC), and says so rather than faking it.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use tokio::net::UdpSocket;

use crate::wire::PeerNode;

/// Shared node-name -> VIP table, refreshed from registration and
/// heartbeat peer lists.
pub type NameTable = Arc<RwLock<HashMap<String, Ipv4Addr>>>;

pub fn new_name_table() -> NameTable {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Rebuilds the table from the current peer list plus this node.
pub fn update_names(table: &NameTable, peers: &[PeerNode], self_name: &str, self_vip: Ipv4Addr) {
    let mut map = HashMap::new();
    map.insert(self_name.to_lowercase(), self_vip);
    for p in peers {
        if let Ok(ip) = p.virtual_ip.parse::<Ipv4Addr>() {
            map.insert(p.node_name.to_lowercase(), ip);
        }
    }
    *table.write().unwrap() = map;
}

/// A parsed DNS question.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    /// Offset just past the question in the original message.
    pub end: usize,
}

/// Parses the header id + first question of a DNS message. Returns
/// None for anything malformed (including compression pointers in the
/// question name, which have no legitimate place there).
pub fn parse_question(msg: &[u8]) -> Option<(u16, DnsQuestion)> {
    if msg.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    if qdcount < 1 {
        return None;
    }
    let mut offset = 12;
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = *msg.get(offset)? as usize;
        if len == 0 {
            offset += 1;
            break;
        }
        if len > 63 {
            // Compression pointers (0xC0..) and over-long labels are
            // rejected in a question.
            return None;
        }
        let label = msg.get(offset + 1..offset + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        offset += 1 + len;
        if labels.len() > 32 {
            return None;
        }
    }
    if offset + 4 > msg.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([msg[offset], msg[offset + 1]]);
    let qclass = u16::from_be_bytes([msg[offset + 2], msg[offset + 3]]);
    Some((
        id,
        DnsQuestion {
            name: labels.join("."),
            qtype,
            qclass,
            end: offset + 4,
        },
    ))
}

/// What the resolver should do with a question.
#[derive(Debug, Clone, PartialEq)]
pub enum DnsRoute {
    /// Answer with this mesh address.
    Mesh(Ipv4Addr),
    /// The name is inside the mesh zone but unknown: NXDOMAIN.
    NxDomain,
    /// The name is a mesh name but the query is not for an A record:
    /// answer NOERROR with no records (we synthesize no other types).
    NoData,
    /// Not a mesh name: forward to the upstream resolver.
    Forward,
}

/// Normalizes a query name to (bare node name, is_mesh_zone).
fn mesh_key(name: &str) -> (String, bool) {
    let n = name.trim_end_matches('.').to_lowercase();
    if let Some(bare) = n.strip_suffix(".mesh") {
        (bare.to_string(), true)
    } else if !n.contains('.') {
        (n, true)
    } else {
        (n, false)
    }
}

pub fn route_query(name: &str, qtype: u16, table: &HashMap<String, Ipv4Addr>) -> DnsRoute {
    let (key, in_zone) = mesh_key(name);
    if !in_zone {
        return DnsRoute::Forward;
    }
    match table.get(&key) {
        Some(ip) => {
            if qtype == 1 {
                DnsRoute::Mesh(*ip)
            } else {
                DnsRoute::NoData
            }
        }
        None => DnsRoute::NxDomain,
    }
}

fn response_header(query: &[u8], rcode: u16, answers: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(query.len() + 16);
    out.extend_from_slice(&query[0..2]); // id
    let query_flags = u16::from_be_bytes([query[2], query[3]]);
    // QR=1, opcode + RD copied, RA=1, RCODE as given.
    let flags = 0x8000 | (query_flags & 0x7900) | 0x0080 | rcode;
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&answers.to_be_bytes()); // ancount
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

/// Builds an A-record response for a mesh name.
pub fn build_a_response(query: &[u8], question: &DnsQuestion, ip: Ipv4Addr) -> Vec<u8> {
    let mut out = response_header(query, 0, 1);
    out.extend_from_slice(&query[12..question.end]);
    out.extend_from_slice(&0xC00Cu16.to_be_bytes()); // name: pointer to the question
    out.extend_from_slice(&1u16.to_be_bytes()); // type A
    out.extend_from_slice(&1u16.to_be_bytes()); // class IN
    out.extend_from_slice(&30u32.to_be_bytes()); // TTL 30s (peer tables change)
    out.extend_from_slice(&4u16.to_be_bytes()); // rdlength
    out.extend_from_slice(&ip.octets());
    out
}

/// Builds an empty response (NXDOMAIN when rcode=3, NODATA when 0).
pub fn build_empty_response(query: &[u8], question: &DnsQuestion, rcode: u16) -> Vec<u8> {
    let mut out = response_header(query, rcode, 0);
    out.extend_from_slice(&query[12..question.end]);
    out
}

/// Runs the resolver until the process ends. Binding port 53 needs
/// root or CAP_NET_BIND_SERVICE; a failure is returned for the caller
/// to log — the mesh itself keeps working without DNS.
pub async fn serve(bind_ip: Ipv4Addr, table: NameTable, upstream: String) -> Result<()> {
    let socket = Arc::new(
        UdpSocket::bind(SocketAddr::from((bind_ip, 53)))
            .await
            .context("bind mesh DNS on the node VIP, port 53")?,
    );
    let upstream_addr = tokio::net::lookup_host(&upstream)
        .await
        .context("resolve DNS upstream")?
        .next()
        .context("DNS upstream resolved to nothing")?;
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, from) = socket.recv_from(&mut buf).await?;
        let query = buf[..n].to_vec();
        let socket = socket.clone();
        let table = table.clone();
        tokio::spawn(async move {
            if let Some(resp) = answer_query(&query, &table, upstream_addr).await {
                let _ = socket.send_to(&resp, from).await;
            }
        });
    }
}

async fn answer_query(
    query: &[u8],
    table: &NameTable,
    upstream_addr: SocketAddr,
) -> Option<Vec<u8>> {
    let (_id, question) = parse_question(query)?;
    let route = {
        let map = table.read().unwrap();
        route_query(&question.name, question.qtype, &map)
    };
    match route {
        DnsRoute::Mesh(ip) => Some(build_a_response(query, &question, ip)),
        DnsRoute::NxDomain => Some(build_empty_response(query, &question, 3)),
        DnsRoute::NoData => Some(build_empty_response(query, &question, 0)),
        DnsRoute::Forward => forward_upstream(query, upstream_addr).await,
    }
}

/// Transparent upstream forwarding: the raw query goes out on an
/// ephemeral socket and the raw response is relayed (after checking
/// it answers the id we sent — a mismatched datagram is dropped, not
/// relayed).
async fn forward_upstream(query: &[u8], upstream_addr: SocketAddr) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket.connect(upstream_addr).await.ok()?;
    socket.send(query).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let recv = tokio::time::timeout(std::time::Duration::from_secs(3), socket.recv(&mut buf)).await;
    let n = recv.ok()?.ok()?;
    if n < 2 || buf[0..2] != query[0..2] {
        return None;
    }
    buf.truncate(n);
    Some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_for(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&0x4242u16.to_be_bytes()); // id
        q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        q.extend_from_slice(&1u16.to_be_bytes()); // qd
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes()); // IN
        q
    }

    fn sample_table() -> HashMap<String, Ipv4Addr> {
        let mut m = HashMap::new();
        m.insert("edge-01".to_string(), "100.64.0.2".parse().unwrap());
        m.insert("db-01".to_string(), "100.64.0.3".parse().unwrap());
        m
    }

    #[test]
    fn parses_questions_and_rejects_garbage() {
        let q = query_for("edge-01.mesh", 1);
        let (id, question) = parse_question(&q).unwrap();
        assert_eq!(id, 0x4242);
        assert_eq!(question.name, "edge-01.mesh");
        assert_eq!(question.qtype, 1);
        assert_eq!(question.end, q.len());

        assert!(parse_question(&[0u8; 8]).is_none());
        assert!(parse_question(&[]).is_none());
        // A compression pointer in the question name is rejected.
        let mut evil = query_for("x.mesh", 1);
        evil[12] = 0xC0;
        assert!(parse_question(&evil).is_none());
    }

    #[test]
    fn routes_mesh_names_and_forwards_the_rest() {
        let t = sample_table();
        assert_eq!(
            route_query("edge-01.mesh", 1, &t),
            DnsRoute::Mesh("100.64.0.2".parse().unwrap())
        );
        // Bare node names resolve too; case and trailing dot ignored.
        assert_eq!(
            route_query("DB-01.", 1, &t),
            DnsRoute::Mesh("100.64.0.3".parse().unwrap())
        );
        assert_eq!(route_query("ghost.mesh", 1, &t), DnsRoute::NxDomain);
        assert_eq!(route_query("edge-01.mesh", 28, &t), DnsRoute::NoData);
        assert_eq!(route_query("example.com", 1, &t), DnsRoute::Forward);
        assert_eq!(route_query("sub.example.com", 1, &t), DnsRoute::Forward);
    }

    #[test]
    fn a_response_is_well_formed() {
        let q = query_for("edge-01.mesh", 1);
        let (_, question) = parse_question(&q).unwrap();
        let resp = build_a_response(&q, &question, "100.64.0.2".parse().unwrap());
        assert_eq!(&resp[0..2], &0x4242u16.to_be_bytes());
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_eq!(flags & 0x8000, 0x8000, "QR must be set");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1, "ancount");
        let tail = &resp[resp.len() - 4..];
        assert_eq!(tail, &[100, 64, 0, 2]);
    }

    #[test]
    fn nxdomain_carries_rcode_3_and_no_answers() {
        let q = query_for("ghost.mesh", 1);
        let (_, question) = parse_question(&q).unwrap();
        let resp = build_empty_response(&q, &question, 3);
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_eq!(flags & 0x000F, 3);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0);
    }

    #[test]
    fn name_table_updates_from_peers() {
        let table = new_name_table();
        let peers = vec![PeerNode {
            node_id: "n2".into(),
            node_name: "DB-01".into(),
            public_key: "pk".into(),
            fingerprint: "fp".into(),
            virtual_ip: "100.64.0.3".into(),
            endpoint: "1.2.3.4:51820".into(),
            role: "node".into(),
            online: true,
            nat_type: "open".into(),
            ebpf_probe_passed: false,
            last_seen: "2026-01-01T00:00:00Z".into(),
            tx_bytes: 0,
            rx_bytes: 0,
            avg_latency_ms: 0.0,
        }];
        update_names(&table, &peers, "edge-01", "100.64.0.2".parse().unwrap());
        let map = table.read().unwrap();
        assert_eq!(map.get("edge-01"), Some(&"100.64.0.2".parse().unwrap()));
        assert_eq!(map.get("db-01"), Some(&"100.64.0.3".parse().unwrap()));
    }
}
