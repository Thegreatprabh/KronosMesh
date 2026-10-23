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

/// One configured service forward for the gateway: connections to
/// `listen` (a loopback address on this host) are carried over the
/// mesh to the target node's gateway, which dials 127.0.0.1 on
/// `target_port` after its own policy check. Configured via
/// [[services]] tables in the TOML config.
#[derive(Debug, Clone)]
pub struct ServiceForward {
    pub name: String,
    pub listen: String,
    pub target_vip: String,
    pub target_port: u16,
}

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
    /// Permit sending bearer tokens to an http:// control plane whose
    /// host is NOT loopback (KRONOS_ALLOW_INSECURE_HTTP=1). Off by
    /// default: node tokens must not cross an untrusted network in
    /// plaintext. The explicit opt-in exists for trusted networks,
    /// e.g. an isolated Docker bridge between node and plane.
    pub allow_insecure_http: bool,
    /// Host TUN integration (KRONOS_TUN=1): create a real network
    /// interface (named by `interface`, MTU by `mtu`) that carries
    /// host traffic for the mesh range. Linux only; needs root or
    /// CAP_NET_ADMIN. Off by default - the application sink remains
    /// the fallback data path.
    pub tun: bool,
    /// Mesh DNS (KRONOS_DNS, default on when TUN is on): answer DNS
    /// on this node's VIP for `<node>.mesh` names from the live peer
    /// table and forward everything else to `dns_upstream`.
    pub dns: bool,
    /// Upstream resolver for non-mesh DNS names (KRONOS_DNS_UPSTREAM).
    pub dns_upstream: String,
    /// Service forwards served by this node's gateway ([[services]]).
    pub services: Vec<ServiceForward>,
    /// Operator/admin token for the control plane (KRONOS_CONTROL_TOKEN).
    /// Used to provision this node when the plane runs with
    /// KRONOS_ADMIN_TOKEN set; the per-node token issued at registration
    /// takes over for heartbeats afterwards.
    pub control_token: Option<String>,
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
            allow_insecure_http: false,
            tun: false,
            dns: true,
            dns_upstream: "1.1.1.1:53".to_string(),
            services: Vec::new(),
            control_token: None,
        }
    }
}

fn default_node_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "kronos-node".to_string())
}

#[derive(Debug, Deserialize)]
struct FileService {
    name: String,
    listen: String,
    target_vip: String,
    target_port: u16,
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
    allow_insecure_http: Option<bool>,
    tun: Option<bool>,
    dns: Option<bool>,
    dns_upstream: Option<String>,
    services: Option<Vec<FileService>>,
    control_token: Option<String>,
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
                if let Some(v) = file.allow_insecure_http { cfg.allow_insecure_http = v; }
                if let Some(v) = file.tun { cfg.tun = v; }
                if let Some(v) = file.dns { cfg.dns = v; }
                if file.dns_upstream.is_some() { cfg.dns_upstream = file.dns_upstream.clone().unwrap(); }
                if let Some(list) = file.services {
                    cfg.services = list
                        .into_iter()
                        .map(|f| ServiceForward {
                            name: f.name,
                            listen: f.listen,
                            target_vip: f.target_vip,
                            target_port: f.target_port,
                        })
                        .collect();
                }
                if file.control_token.is_some() {
                    cfg.control_token = file.control_token;
                }
            }
        }
        if let Ok(v) = std::env::var("KRONOS_NODE_NAME") { if !v.trim().is_empty() { cfg.node_name = v; } }
        if let Ok(v) = std::env::var("KRONOS_ROLE") { if !v.trim().is_empty() { cfg.role = v; } }
        if let Ok(v) = std::env::var("KRONOS_LISTEN_PORT") {
            cfg.listen_port = v.parse().context("KRONOS_LISTEN_PORT must be a number")?;
        }
        if let Ok(v) = std::env::var("KRONOS_CONTROL_URL") { if !v.trim().is_empty() { cfg.control_url = v; } }
        if let Ok(v) = std::env::var("KRONOS_STATE_DIR") { cfg.state_dir = PathBuf::from(v); }
        if let Ok(v) = std::env::var("KRONOS_EBPF_OBJECT") { cfg.ebpf_object = Some(v); }
        if let Ok(v) = std::env::var("KRONOS_STUN_SERVER") { cfg.stun_server = Some(v); }
        if let Ok(v) = std::env::var("KRONOS_ADVERTISE_ENDPOINT") {
            cfg.advertise_endpoint = Some(v);
        }
        if let Some(b) = env_bool("KRONOS_TUN") {
            cfg.tun = b;
        }
        if let Some(b) = env_bool("KRONOS_DNS") {
            cfg.dns = b;
        }
        if let Ok(v) = std::env::var("KRONOS_DNS_UPSTREAM") { if !v.trim().is_empty() { cfg.dns_upstream = v; } }
        if let Some(b) = env_bool("KRONOS_ALLOW_INSECURE_HTTP") {
            cfg.allow_insecure_http = b;
        }
        if let Ok(v) = std::env::var("KRONOS_CONTROL_TOKEN") { if !v.is_empty() {
            cfg.control_token = Some(v);
        }
        }
        Ok(cfg)
    }
}

/// Parses a boolean environment variable with ONE convention
/// for every flag: 1/true/yes/on enable, 0/false/no/off disable
/// (case-insensitive), anything else (including empty) leaves
/// the current value untouched. Before this helper, KRONOS_TUN
/// used the enabling set while KRONOS_DNS treated everything
/// except 0/false as ON — `KRONOS_DNS=off` turned DNS on.
fn env_bool(name: &str) -> Option<bool> {
    let v = std::env::var(name).ok()?;
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Decides whether bearer tokens may be sent to the control plane at
/// `url`. https is always fine; http is fine for loopback endpoints
/// (same-host deployments and local development). Any other http
/// endpoint would put node/operator tokens on the wire in plaintext,
/// so it needs the explicit KRONOS_ALLOW_INSECURE_HTTP opt-in.
pub fn control_url_allows_tokens(url: &str, allow_insecure_http: bool) -> bool {
    let parsed = match reqwest::Url::parse(url) {
        Ok(u) => u,
        Err(_) => return false,
    };
    match parsed.scheme() {
        "https" => true,
        "http" => {
            if allow_insecure_http {
                return true;
            }
            // host_str serializes IPv6 hosts with brackets: "[::1]".
            let host = parsed
                .host_str()
                .unwrap_or("")
                .trim_start_matches('[')
                .trim_end_matches(']');
            if host.eq_ignore_ascii_case("localhost") {
                return true;
            }
            match host.parse::<std::net::IpAddr>() {
                Ok(ip) => ip.is_loopback(),
                Err(_) => false,
            }
        }
        _ => false,
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

/// Writes `contents` to `path` atomically with owner-only
/// permissions FROM THE START: any stale temp file is removed,
/// the new temp file is created with mode 0600 (unix) before
/// any secret bytes land in it, fsynced, then renamed over the
/// destination, followed by a directory fsync. A crash leaves
/// the old or the new complete file — and the secret is never
/// briefly world-readable under the process umask. (The
/// failure class the INIT freshness file was hardened against
/// in v1.5.0; the credential files were missed then.)
pub fn write_file_atomic(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("json.tmp");
    let _ = std::fs::remove_file(&tmp);
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
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
            write_file_atomic(&path, &serde_json::to_string_pretty(&file)?)?;
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
    /// Bearer credential issued by the control plane. Persisted in the
    /// state dir (file mode 0600) so restarts keep their identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_token: Option<String>,
}

impl NodeState {
    pub fn load(state_dir: &Path) -> Option<Self> {
        let text = std::fs::read_to_string(state_dir.join("node_state.json")).ok()?;
        serde_json::from_str(&text).ok()
    }

    pub fn save(&self, state_dir: &Path) -> Result<()> {
        std::fs::create_dir_all(state_dir)?;
        let path = state_dir.join("node_state.json");
        // The state file carries a credential: atomic write,
        // owner-only from the first byte (see the helper).
        write_file_atomic(&path, &serde_json::to_string_pretty(self)?)
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
    fn secret_file_write_is_atomic_and_owner_only() {
        // Round 8: credential files are created 0600 from the
        // first byte and renamed into place — never written
        // world-readable and chmodded afterwards.
        let dir = std::env::temp_dir().join(format!(
            "kronos-atomic-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("identity.json");
        write_file_atomic(&path, "{\"v\": 1}").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"v\": 1}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "credential file must be owner-only");
        }
        // Overwrite replaces content atomically and keeps the mode.
        write_file_atomic(&path, "{\"v\": 2}").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"v\": 2}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert!(!dir.join("identity.json.tmp").exists(), "temp file must be renamed away");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn control_url_token_transport_policy() {
        // https is fine anywhere.
        assert!(control_url_allows_tokens("https://cp.example.com:8080", false));
        // http is fine on loopback only.
        assert!(control_url_allows_tokens("http://127.0.0.1:8080", false));
        assert!(control_url_allows_tokens("http://localhost:8080", false));
        assert!(control_url_allows_tokens("http://[::1]:8080", false));
        // Remote plaintext http would leak bearer tokens: refused.
        assert!(!control_url_allows_tokens("http://192.168.1.20:8080", false));
        assert!(!control_url_allows_tokens("http://control-plane:8080", false));
        assert!(!control_url_allows_tokens("http://cp.example.com", false));
        // The explicit trusted-network opt-in re-allows it.
        assert!(control_url_allows_tokens("http://control-plane:8080", true));
        assert!(control_url_allows_tokens("http://192.168.1.20:8080", true));
        // Unparseable or exotic schemes never carry tokens.
        assert!(!control_url_allows_tokens("not a url", true));
        assert!(!control_url_allows_tokens("ftp://127.0.0.1", true));
    }

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
