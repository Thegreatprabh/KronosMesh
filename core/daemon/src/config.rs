//! Daemon configuration: TOML file + environment overrides, and the
//! node's persistent cryptographic identity.
//!
//! Identity: an X25519 static keypair generated on first run and stored
//! in `<state_dir>/identity.json` (0600 on Unix). The private key never
//! leaves the node; the control plane only ever sees the public key and
//! its BLAKE2b fingerprint.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::{fingerprint, hex_decode, hex_encode};

#[derive(Debug, Clone)]
pub struct Config {
    pub node_name: String,
    pub role: String,
    pub listen_port: u16,
    pub control_url: String,
    pub state_dir: PathBuf,
    pub interface: String,
    pub mtu: u16,
    pub heartbeat_secs: u64,
    pub acl_sync_secs: u64,
    pub ebpf_object: Option<String>,
    pub stun_server: Option<String>,
    pub advertise_endpoint: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            node_name: default_node_name(),
            role: "node".to_string(),
            listen_port: 51820,
            control_url: "http://127.0.0.1:8080".to_string(),
            state_dir: PathBuf::from(".kronos"),
            interface: "kronos0".to_string(),
            mtu: 1280,
            heartbeat_secs: 10,
            acl_sync_secs: 30,
            ebpf_object: None,
            stun_server: None,
            advertise_endpoint: None,
        }
    }
}

fn default_node_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "kronos-node".to_string())
}

#[derive(Debug, Default, Deserialize)]
struct FileConfig {
    node_name: Option<String>,
    role: Option<String>,
    listen_port: Option<u16>,
    control_url: Option<String>,
    state_dir: Option<String>,
    interface: Option<String>,
    mtu: Option<u16>,
    heartbeat_secs: Option<u64>,
    acl_sync_secs: Option<u64>,
    ebpf_object: Option<String>,
    stun_server: Option<String>,
    advertise_endpoint: Option<String>,
}

impl Config {
    /// Loads config from an optional TOML path, then applies KRONOS_*
    /// environment overrides (environment wins over file, file wins over
    /// defaults).
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let mut cfg = Self::default();
        if let Some(path) = path {
            if path.exists() {
                let text = std::fs::read_to_string(path)
                    .with_context(|| format!("reading config {}", path.display()))?;
                let file: FileConfig = toml::from_str(&text)
                    .with_context(|| format!("parsing config {}", path.display()))?;
                if let Some(v) = file.node_name { cfg.node_name = v; }
                if let Some(v) = file.role { cfg.role = v; }
                if let Some(v) = file.listen_port { cfg.listen_port = v; }
                if let Some(v) = file.control_url { cfg.control_url = v; }
                if let Some(v) = file.state_dir { cfg.state_dir = PathBuf::from(v); }
                if let Some(v) = file.interface { cfg.interface = v; }
                if let Some(v) = file.mtu { cfg.mtu = v; }
                if let Some(v) = file.heartbeat_secs { cfg.heartbeat_secs = v; }
                if let Some(v) = file.acl_sync_secs { cfg.acl_sync_secs = v; }
                if file.ebpf_object.is_some() { cfg.ebpf_object = file.ebpf_object; }
                if file.stun_server.is_some() { cfg.stun_server = file.stun_server; }
                if file.advertise_endpoint.is_some() {
                    cfg.advertise_endpoint = file.advertise_endpoint;
                }
            }
        }
        if let Ok(v) = std::env::var("KRONOS_NODE_NAME") { cfg.node_name = v; }
        if let Ok(v) = std::env::var("KRONOS_ROLE") { cfg.role = v; }
        if let Ok(v) = std::env::var("KRONOS_LISTEN_PORT") {
            cfg.listen_port = v.parse().context("KRONOS_LISTEN_PORT must be a number")?;
        }
        if let Ok(v) = std::env::var("KRONOS_CONTROL_URL") { cfg.control_url = v; }
        if let Ok(v) = std::env::var("KRONOS_STATE_DIR") { cfg.state_dir = PathBuf::from(v); }
        if let Ok(v) = std::env::var("KRONOS_EBPF_OBJECT") { cfg.ebpf_object = Some(v); }
        if let Ok(v) = std::env::var("KRONOS_STUN_SERVER") { cfg.stun_server = Some(v); }
        if let Ok(v) = std::env::var("KRONOS_ADVERTISE_ENDPOINT") {
            cfg.advertise_endpoint = Some(v);
        }
        Ok(cfg)
    }
}

// ---------------------------------------------------------------------------
// Persistent identity + assigned state
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    private_key: String,
    public_key: String,
}

pub struct Identity {
    secret: StaticSecret,
    pub public: PublicKey,
}

impl Identity {
    pub fn load_or_create(state_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(state_dir)
            .with_context(|| format!("creating state dir {}", state_dir.display()))?;
        let path = state_dir.join("identity.json");
        if path.exists() {
            let text = std::fs::read_to_string(&path)?;
            let file: IdentityFile = serde_json::from_str(&text)
                .context("identity.json is corrupt")?;
            let key_bytes = hex_decode(&file.private_key)?;
            let arr: [u8; 32] = key_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("stored private key has wrong length"))?;
            let secret = StaticSecret::from(arr);
            let public = PublicKey::from(&secret);
            if hex_encode(public.as_bytes()) != file.public_key {
                return Err(anyhow::anyhow!("stored public key does not match private key"));
            }
            Ok(Self { secret, public })
        } else {
            let secret = StaticSecret::random_from_rng(rand_core::OsRng);
            let public = PublicKey::from(&secret);
            let file = IdentityFile {
                private_key: hex_encode(secret.as_bytes()),
                public_key: hex_encode(public.as_bytes()),
            };
            std::fs::write(&path, serde_json::to_string_pretty(&file)?)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            }
            Ok(Self { secret, public })
        }
    }

    pub fn secret(&self) -> StaticSecret {
        self.secret.clone()
    }

    pub fn public_hex(&self) -> String {
        hex_encode(self.public.as_bytes())
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(self.public.as_bytes())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeState {
    pub node_id: String,
    pub virtual_ip: String,
}

impl NodeState {
    pub fn load(state_dir: &Path) -> Option<Self> {
        let text = std::fs::read_to_string(state_dir.join("node_state.json")).ok()?;
        serde_json::from_str(&text).ok()
    }

    pub fn save(&self, state_dir: &Path) -> Result<()> {
        std::fs::create_dir_all(state_dir)?;
        std::fs::write(
            state_dir.join("node_state.json"),
            serde_json::to_string_pretty(self)?,
        )?;
        Ok(())
    }
}

/// Derives the node's proposed virtual IP inside 100.64.0.0/10 (CGNAT
/// space, the same range Tailscale uses) from its public key, so two
/// nodes with different keys essentially never collide. The control
/// plane has the final say and may assign a different address.
pub fn proposed_virtual_ip(public_key: &[u8; 32]) -> String {
    let h = fingerprint(public_key);
    let a = u8::from_str_radix(&h[0..2], 16).unwrap_or(0);
    let b = u8::from_str_radix(&h[2..4], 16).unwrap_or(0);
    let c = u8::from_str_radix(&h[4..6], 16).unwrap_or(0);
    format!("100.{}.{}.{}", 64 + (a % 64), b, c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_persists_across_loads() {
        let dir = std::env::temp_dir().join(format!("kronos-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let id1 = Identity::load_or_create(&dir).unwrap();
        let id2 = Identity::load_or_create(&dir).unwrap();
        assert_eq!(id1.public_hex(), id2.public_hex());
        assert_eq!(id1.fingerprint().len(), 64);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proposed_virtual_ip_is_in_cgnat_range() {
        let ip = proposed_virtual_ip(&[9u8; 32]);
        let parts: Vec<u8> = ip.split('.').map(|p| p.parse().unwrap()).collect();
        assert_eq!(parts.len(), 4, "virtual ip must have 4 octets: {ip}");
        assert_eq!(parts[0], 100);
        assert!((64..128).contains(&parts[1]));
    }

    #[test]
    fn config_defaults_and_env_override() {
        std::env::set_var("KRONOS_NODE_NAME", "test-node-xyz");
        let cfg = Config::load(None).unwrap();
        assert_eq!(cfg.node_name, "test-node-xyz");
        assert_eq!(cfg.listen_port, 51820);
        std::env::remove_var("KRONOS_NODE_NAME");
    }
}
