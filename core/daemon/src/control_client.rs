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
        resp.json().await.context("decoding register response")
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
        resp.json().await.context("decoding heartbeat response")
    }

    pub async fn fetch_acls(&self) -> Result<AclPolicyResponse> {
        let resp = self
            .http
            .get(format!("{}/api/v1/acls", self.base_url))
            .send()
            .await
            .context("ACL fetch failed")?
            .error_for_status()
            .context("control plane rejected ACL fetch")?;
        resp.json().await.context("decoding ACL response")
    }

    pub async fn fetch_topology(&self) -> Result<MeshTopology> {
        let resp = self
            .http
            .get(format!("{}/api/v1/topology", self.base_url))
            .send()
            .await
            .context("topology fetch failed")?
            .error_for_status()
            .context("control plane rejected topology fetch")?;
        resp.json().await.context("decoding topology response")
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
/// response); callers fall back to the local socket address.
pub async fn stun_discover(server: &str) -> Option<SocketAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket
        .send_to(&build_stun_request(0xA5A5_1234_5678_9ABC_DEF0_1122_3344), server)
        .await
        .ok()?;
    let mut buf = [0u8; 512];
    let recv = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await;
    let (n, _) = recv.ok()?.ok()?;
    parse_stun_response(&buf[..n])
}

fn build_stun_request(transaction_id: u128) -> [u8; 20] {
    let mut req = [0u8; 20];
    req[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    req[2..4].copy_from_slice(&0u16.to_be_bytes());
    req[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    req[8..20].copy_from_slice(&transaction_id.to_be_bytes()[4..16]);
    req
}

fn parse_stun_response(msg: &[u8]) -> Option<SocketAddr> {
    if msg.len() < 20 {
        return None;
    }
    let msg_type = u16::from_be_bytes(msg[0..2].try_into().ok()?);
    if msg_type != STUN_BINDING_RESPONSE {
        return None;
    }
    let msg_len = u16::from_be_bytes(msg[2..4].try_into().ok()?) as usize;
    let end = (20 + msg_len).min(msg.len());
    let mut offset = 20;
    while offset + 4 <= end {
        let attr_type = u16::from_be_bytes(msg[offset..offset + 2].try_into().ok()?);
        let attr_len = u16::from_be_bytes(msg[offset + 2..offset + 4].try_into().ok()?) as usize;
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
        let req = build_stun_request(7);
        assert_eq!(&req[0..2], &STUN_BINDING_REQUEST.to_be_bytes());
        assert_eq!(&req[4..8], &STUN_MAGIC_COOKIE.to_be_bytes());
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
        let addr = parse_stun_response(&msg).unwrap();
        assert_eq!(addr.to_string(), "203.0.113.7:51820");
    }

    #[test]
    fn rejects_garbage_responses() {
        assert!(parse_stun_response(&[0u8; 4]).is_none());
        assert!(parse_stun_response(&[0xFFu8; 64]).is_none());
    }
}
