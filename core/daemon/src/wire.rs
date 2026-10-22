//! Cross-service wire contracts. These structs are the single source of
//! truth for the JSON exchanged between the Rust daemon, the Go control
//! plane, and the TypeScript dashboard. Field names are snake_case on
//! the wire in all three languages (serde here, json tags in Go,
//! interfaces in TypeScript). Contract fixtures under `contracts/` at
//! the repo root pin these shapes in both test suites.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeRegisterRequest {
    pub node_name: String,
    pub public_key: String,
    pub fingerprint: String,
    pub virtual_ip: String,
    pub endpoint: String,
    pub role: String,
    pub nat_type: String,
    pub ebpf_enabled: bool,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeRegisterResponse {
    pub node_id: String,
    pub assigned_virtual_ip: String,
    pub peers: Vec<PeerNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PeerNode {
    pub node_id: String,
    pub node_name: String,
    pub public_key: String,
    pub fingerprint: String,
    pub virtual_ip: String,
    pub endpoint: String,
    pub role: String,
    pub online: bool,
    pub nat_type: String,
    pub ebpf_enabled: bool,
    pub last_seen: String,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub avg_latency_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HeartbeatPayload {
    pub node_id: String,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub packets_tx: u64,
    pub packets_rx: u64,
    pub peers_connected: u32,
    pub avg_latency_ms: f64,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HeartbeatResponse {
    pub acknowledged: bool,
    pub peers: Vec<PeerNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AclRule {
    pub id: String,
    pub source_role: String,
    pub dest_service: String,
    pub port: u16,
    pub action: String, // "ALLOW" | "DENY"
    pub priority: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AclPolicyResponse {
    pub version: u64,
    pub rules: Vec<AclRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TopologyLink {
    pub a: String,
    pub b: String,
    pub latency_ms: f64,
    pub encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MeshTopology {
    pub nodes: Vec<PeerNode>,
    pub links: Vec<TopologyLink>,
    pub generated_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts");

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!("{FIXTURE_DIR}/{name}"))
            .unwrap_or_else(|_| panic!("missing contract fixture {name}"))
    }

    #[test]
    fn register_request_matches_fixture_fields() {
        let v: serde_json::Value =
            serde_json::from_str(&fixture("node_register_request.json")).unwrap();
        let req: NodeRegisterRequest = serde_json::from_value(v.clone()).unwrap();
        let back = serde_json::to_value(&req).unwrap();
        assert_eq!(v, back, "register request drifted from the shared fixture");
    }

    #[test]
    fn heartbeat_matches_fixture_fields() {
        let v: serde_json::Value =
            serde_json::from_str(&fixture("heartbeat_payload.json")).unwrap();
        let hb: HeartbeatPayload = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(v, serde_json::to_value(&hb).unwrap());
    }

    #[test]
    fn acl_policy_matches_fixture_fields() {
        let v: serde_json::Value =
            serde_json::from_str(&fixture("acl_policy_response.json")).unwrap();
        let pol: AclPolicyResponse = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(v, serde_json::to_value(&pol).unwrap());
    }

    #[test]
    fn topology_matches_fixture_fields() {
        let v: serde_json::Value =
            serde_json::from_str(&fixture("mesh_topology.json")).unwrap();
        let topo: MeshTopology = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(v, serde_json::to_value(&topo).unwrap());
    }
}
