//! HTTP client for the Go control plane, plus STUN-style public-endpoint
//! discovery (RFC 5389 binding requests) for NAT traversal metadata.

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

use crate::wire::{
    AclPolicyResponse, HeartbeatPayload, HeartbeatResponse, MeshTopology,
    NodeRegisterRequest, NodeRegisterResponse,
};

pub struct ControlClient {
    base_url: String,
    http: reqwest::Client,
}

impl ControlClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client construction cannot fail with these options"),
        }
    }

    /// Reads a response body under a hard size cap, then decodes
    /// it. A compromised or broken control plane must not be
    /// able to make the daemon buffer an unbounded body into
    /// memory (topology/ACL responses are small by design).
    async fn read_json_capped<T: serde::de::DeserializeOwned>(
        mut resp: reqwest::Response,
        what: &str,
    ) -> Result<T> {
        const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
        let mut body = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .with_context(|| format!("reading {what} response"))?
        {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                anyhow::bail!("{what} response exceeds {MAX_RESPONSE_BYTES} bytes");
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).with_context(|| format!("decoding {what} response"))
    }

    pub async fn register(
        &self,
        req: &NodeRegisterRequest,
        token: Option<&str>,
    ) -> Result<NodeRegisterResponse> {
        let mut rb = self
            .http
            .post(format!("{}/api/v1/nodes/register", self.base_url))
            .json(req);
        if let Some(t) = token {
            rb = rb.header("Authorization", format!("Bearer {t}"));
        }
        let resp = rb
            .send()
            .await
            .context("register request failed")?
            .error_for_status()
            .context("control plane rejected registration")?;
        Self::read_json_capped(resp, "register").await
    }

    pub async fn heartbeat(
        &self,
        node_id: &str,
        payload: &HeartbeatPayload,
        token: Option<&str>,
    ) -> Result<HeartbeatResponse> {
        let mut rb = self
            .http
            .post(format!(
                "{}/api/v1/nodes/{node_id}/heartbeat",
                self.base_url
            ))
            .json(payload);
        if let Some(t) = token {
            rb = rb.header("Authorization", format!("Bearer {t}"));
        }
        let resp = rb
            .send()
            .await
            .context("heartbeat request failed")?
            .error_for_status()
            .context("control plane rejected heartbeat")?;
        Self::read_json_capped(resp, "heartbeat").await
    }

    pub async fn fetch_acls(&self, token: Option<&str>) -> Result<AclPolicyResponse> {
        let mut rb = self.http.get(format!("{}/api/v1/acls", self.base_url));
        if let Some(t) = token {
            rb = rb.header("Authorization", format!("Bearer {t}"));
        }
        let resp = rb
            .send()
            .await
            .context("ACL fetch failed")?
            .error_for_status()
            .context("control plane rejected ACL fetch")?;
        Self::read_json_capped(resp, "ACL").await
    }

    pub async fn fetch_topology(&self, token: Option<&str>) -> Result<MeshTopology> {
        let mut rb = self.http.get(format!("{}/api/v1/topology", self.base_url));
        if let Some(t) = token {
            rb = rb.header("Authorization", format!("Bearer {t}"));
        }
        let resp = rb
            .send()
            .await
            .context("topology fetch failed")?
            .error_for_status()
            .context("control plane rejected topology fetch")?;
        Self::read_json_capped(resp, "topology").await
    }
}

/// Result of endpoint discovery: the externally visible address (if a
/// STUN server answered) and the derived NAT classification.
#[derive(Debug, Clone)]
pub struct DiscoveredEndpoint {
    pub endpoint: String,
    pub nat_type: String,
}

const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// Sends one STUN binding request and parses the (XOR-)MAPPED-ADDRESS.
/// Returns None on any failure (no server configured, timeout, malformed
/// or forged response); callers fall back to the local socket address.
///
/// The response is authenticated as far as STUN allows: it must arrive
/// from the exact server endpoint we queried and carry the fresh random
/// transaction ID of this request. (The previous implementation used a
/// single hardcoded transaction ID for every request and ignored the
/// response's source entirely, so any off-path datagram could have
/// steered the node's advertised endpoint.)
pub async fn stun_discover(server: &str) -> Option<SocketAddr> {
    use rand_core::RngCore;
    // Resolve first: the response is only trusted from this endpoint.
    let server_addr = tokio::net::lookup_host(server).await.ok()?.next()?;
    // A fresh random transaction ID per request (RFC 5389 section 6).
    let mut txid = [0u8; 12];
    rand_core::OsRng.fill_bytes(&mut txid);
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket
        .send_to(&build_stun_request(&txid), server_addr)
        .await
        .ok()?;
    let mut buf = [0u8; 512];
    let recv = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await;
    let (n, from) = recv.ok()?.ok()?;
    if from != server_addr {
        return None;
    }
    parse_stun_response(&buf[..n], &txid)
}

fn build_stun_request(transaction_id: &[u8; 12]) -> [u8; 20] {
    let mut req = [0u8; 20];
    req[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    req[2..4].copy_from_slice(&0u16.to_be_bytes());
    req[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    req[8..20].copy_from_slice(transaction_id);
    req
}

fn parse_stun_response(msg: &[u8], expected_txid: &[u8; 12]) -> Option<SocketAddr> {
    // RFC 5389 section 6: a response only counts if it answers OUR
    // request — binding-success type, the magic cookie, our exact
    // transaction ID — and its declared length accounts for the whole
    // datagram, no more and no less.
    if msg.len() < 20 {
        return None;
    }
    let msg_type = u16::from_be_bytes(msg[0..2].try_into().ok()?);
    if msg_type != STUN_BINDING_RESPONSE {
        return None;
    }
    if msg[4..8] != STUN_MAGIC_COOKIE.to_be_bytes() {
        return None;
    }
    if &msg[8..20] != expected_txid {
        return None;
    }
    let msg_len = u16::from_be_bytes(msg[2..4].try_into().ok()?) as usize;
    if !msg_len.is_multiple_of(4) || 20 + msg_len != msg.len() {
        return None;
    }
    let end = 20 + msg_len;
    let mut offset = 20;
    while offset + 4 <= end {
        let attr_type = u16::from_be_bytes(msg[offset..offset + 2].try_into().ok()?);
        let attr_len = u16::from_be_bytes(msg[offset + 2..offset + 4].try_into().ok()?) as usize;
        if offset + 4 + attr_len > end {
            return None;
        }
        let value = msg.get(offset + 4..offset + 4 + attr_len)?;
        if (attr_type == ATTR_MAPPED_ADDRESS || attr_type == ATTR_XOR_MAPPED_ADDRESS)
            && value.len() >= 8
            && value[1] == 0x01
        {
            // family 0x01 = IPv4
            let mut port = u16::from_be_bytes(value[2..4].try_into().ok()?);
            let mut ip = [value[4], value[5], value[6], value[7]];
            if attr_type == ATTR_XOR_MAPPED_ADDRESS {
                port ^= (STUN_MAGIC_COOKIE >> 16) as u16;
                let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
                for i in 0..4 {
                    ip[i] ^= cookie[i];
                }
            }
            return Some(SocketAddr::from((ip, port)));
        }
        offset += 4 + ((attr_len + 3) & !3);
    }
    None
}

/// Discovers the node's public endpoint. With a STUN server configured
/// and answering, the reflexive address is used and NAT is reported when
/// it differs from the local address; otherwise the local listen
/// address is reported with an honest "unknown" NAT classification.
pub async fn discover_endpoint(
    stun_server: Option<&str>,
    listen_port: u16,
) -> DiscoveredEndpoint {
    let local_ip = local_ipv4();
    if let Some(server) = stun_server {
        if let Some(public) = stun_discover(server).await {
            let nat_type = if public.ip().to_string() == local_ip {
                "open"
            } else {
                "nat"
            };
            return DiscoveredEndpoint {
                endpoint: public.to_string(),
                nat_type: nat_type.to_string(),
            };
        }
    }
    DiscoveredEndpoint {
        endpoint: format!("{local_ip}:{listen_port}"),
        nat_type: "unknown".to_string(),
    }
}

fn local_ipv4() -> String {
    // Connecting a UDP socket sends nothing; it just selects the route
    // and reveals the preferred local address.
    if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = sock.local_addr() {
                return addr.ip().to_string();
            }
        }
    }
    "127.0.0.1".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stun_request_is_well_formed() {
        let txid = [7u8; 12];
        let req = build_stun_request(&txid);
        assert_eq!(&req[0..2], &STUN_BINDING_REQUEST.to_be_bytes());
        assert_eq!(&req[4..8], &STUN_MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&req[8..20], &txid);
    }

    /// Builds a syntactically valid binding response carrying a
    /// XOR-MAPPED-ADDRESS for 203.0.113.7:51820 with the given txid.
    fn valid_response(txid: &[u8; 12]) -> Vec<u8> {
        let port_xor = 51820u16 ^ 0x2112;
        let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
        let ip = [203u8, 0, 113, 7];
        let mut xip = [0u8; 4];
        for i in 0..4 {
            xip[i] = ip[i] ^ cookie[i];
        }
        let mut msg = Vec::new();
        msg.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        msg.extend_from_slice(&12u16.to_be_bytes());
        msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(txid);
        msg.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        msg.extend_from_slice(&8u16.to_be_bytes());
        msg.extend_from_slice(&[0, 0x01]);
        msg.extend_from_slice(&port_xor.to_be_bytes());
        msg.extend_from_slice(&xip);
        msg
    }

    #[test]
    fn parses_xor_mapped_address() {
        // Hand-build a binding response with XOR-MAPPED-ADDRESS for
        // 203.0.113.7:51820. XOR port = 51820 ^ 0x2112; XOR ip = ip ^ cookie.
        let port_xor = 51820u16 ^ 0x2112;
        let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
        let ip = [203u8, 0, 113, 7];
        let mut xip = [0u8; 4];
        for i in 0..4 {
            xip[i] = ip[i] ^ cookie[i];
        }
        let mut msg = Vec::new();
        msg.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        msg.extend_from_slice(&12u16.to_be_bytes());
        msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(&[0x55u8; 12]);
        msg.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        msg.extend_from_slice(&8u16.to_be_bytes());
        msg.extend_from_slice(&[0, 0x01]);
        msg.extend_from_slice(&port_xor.to_be_bytes());
        msg.extend_from_slice(&xip);
        let addr = parse_stun_response(&msg, &[0x55u8; 12]).unwrap();
        assert_eq!(addr.to_string(), "203.0.113.7:51820");
    }

    #[test]
    fn rejects_forged_or_malformed_responses() {
        let txid = [0x42u8; 12];
        let good = valid_response(&txid);
        assert!(parse_stun_response(&good, &txid).is_some());

        // A response to a DIFFERENT request (wrong transaction ID) is
        // a forgery or a stray packet: never accepted.
        assert!(parse_stun_response(&good, &[0x99u8; 12]).is_none());
        let mut other_txid = good.clone();
        other_txid[8] ^= 0xFF;
        assert!(parse_stun_response(&other_txid, &txid).is_none());

        // Wrong magic cookie.
        let mut bad_cookie = good.clone();
        bad_cookie[5] ^= 0xFF;
        assert!(parse_stun_response(&bad_cookie, &txid).is_none());

        // A binding REQUEST is not a response.
        let mut as_request = good.clone();
        as_request[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
        assert!(parse_stun_response(&as_request, &txid).is_none());

        // Truncated datagram (declared length no longer accounts for it).
        assert!(parse_stun_response(&good[..good.len() - 4], &txid).is_none());

        // Trailing garbage (declared length shorter than the datagram).
        let mut padded = good.clone();
        padded.extend_from_slice(&[0u8; 4]);
        assert!(parse_stun_response(&padded, &txid).is_none());

        // Attribute claiming more bytes than the message holds.
        let mut overrun = good.clone();
        overrun[22..24].copy_from_slice(&100u16.to_be_bytes());
        assert!(parse_stun_response(&overrun, &txid).is_none());
    }

    #[test]
    fn rejects_garbage_responses() {
        assert!(parse_stun_response(&[0u8; 4], &[0u8; 12]).is_none());
        assert!(parse_stun_response(&[0xFFu8; 64], &[0u8; 12]).is_none());
    }
}
