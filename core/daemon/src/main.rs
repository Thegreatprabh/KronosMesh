//! kronos-daemon CLI.
//!
//!   kronos-daemon up       — join the mesh and run until Ctrl+C
//!   kronos-daemon status   — local identity + mesh summary
//!   kronos-daemon peers    — peer table from the control plane
//!   kronos-daemon bench    — measure handshake time + sealed-packet
//!                            throughput between two in-process nodes

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kronos_daemon::config::{proposed_virtual_ip, Config, Identity, NodeState};
use kronos_daemon::control_client::{discover_endpoint, ControlClient};
use kronos_daemon::ebpf_loader::{EbpfLoader, EventRing, TelemetryCounters};
use kronos_daemon::tunnel::{MemoryHub, Tunnel};
use kronos_daemon::wire::{AclRule, HeartbeatPayload, NodeRegisterRequest};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(name = "kronos-daemon", version, about = "KronosMesh zero-trust mesh node daemon")]
struct Cli {
    /// Path to a TOML config file.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Join the mesh and run the daemon.
    Up,
    /// Show local identity and mesh status.
    Status,
    /// List mesh peers from the control plane.
    Peers,
    /// Benchmark handshake + transport throughput (in-process nodes).
    Bench {
        /// How long to run the throughput phase, in seconds.
        #[arg(long, default_value_t = 5)]
        seconds: u64,
        /// Payload size per packet, in bytes.
        #[arg(long, default_value_t = 1200)]
        payload: usize,
    },
}

fn main() -> Result<()> {
    tracing_subscriber_init();
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    let cfg = Config::load(cli.config.as_deref())?;
    match cli.command {
        Commands::Up => runtime.block_on(run_up(cfg)),
        Commands::Status => runtime.block_on(run_status(cfg)),
        Commands::Peers => runtime.block_on(run_peers(cfg)),
        Commands::Bench { seconds, payload } => {
            runtime.block_on(run_bench(seconds, payload))
        }
    }
}

fn tracing_subscriber_init() {
    // Minimal stderr logging without extra dependencies: tracing's
    // default fmt layer requires tracing-subscriber; to keep the
    // dependency list exact, log lines go through eprintln in the
    // supervisor and this hook stays intentionally silent.
}

async fn run_up(cfg: Config) -> Result<()> {
    let identity = Identity::load_or_create(&cfg.state_dir)?;
    let telemetry = Arc::new(TelemetryCounters::default());
    let ring = Arc::new(EventRing::new(256));

    let ebpf_status = EbpfLoader::probe(cfg.ebpf_object.as_deref(), &ring);
    eprintln!(
        "[kronos] data plane: {:?} — {}",
        ebpf_status.mode, ebpf_status.reason
    );

    let proposed_ip = proposed_virtual_ip(identity.public.as_bytes());
    let existing = NodeState::load(&cfg.state_dir);
    // Fallback address if the control plane cannot be reached: our
    // previously assigned VIP, else the proposed one.
    let local_vip = existing
        .as_ref()
        .map(|s| s.virtual_ip.clone())
        .unwrap_or_else(|| proposed_ip.clone());

    let client = ControlClient::new(&cfg.control_url);
    let discovered = discover_endpoint(cfg.stun_server.as_deref(), cfg.listen_port).await;
    // The advertised endpoint is where peers should dial us: the
    // explicit override wins, then the discovered (STUN / route-probed)
    // address. The socket's local address is never advertised — bound
    // to 0.0.0.0 it resolves to 127.0.0.1, which is unreachable from
    // other machines and other containers.
    let advertised_endpoint = cfg
        .advertise_endpoint
        .clone()
        .unwrap_or_else(|| discovered.endpoint.clone());
    eprintln!("[kronos] advertising endpoint {advertised_endpoint}");
    // Registration runs BEFORE the tunnel is bound. The control plane
    // is the authority on virtual IPs: when the requested address is
    // already taken it assigns a different one, and the tunnel must
    // bind the ASSIGNED address. (The previous order bound the tunnel
    // first, so after a collision the running tunnel kept the requested
    // address while the state file and the mesh used the assigned one —
    // traffic for this node was routed to an address it never held.)
    // We ask for our previous address when we have one (restart
    // stability); the plane keeps it when it is still ours or free.
    let register_req = NodeRegisterRequest {
        node_name: cfg.node_name.clone(),
        public_key: identity.public_hex(),
        fingerprint: identity.fingerprint(),
        virtual_ip: local_vip.clone(),
        endpoint: advertised_endpoint,
        role: cfg.role.clone(),
        nat_type: discovered.nat_type.clone(),
        ebpf_probe_passed: ebpf_status.probe_passed,
        version: VERSION.to_string(),
    };
    // Credential for this registration: an operator token from config
    // wins (provisioning), otherwise the node token saved from our first
    // registration. The plane rejects re-registrations without one.
    let register_token = cfg
        .control_token
        .clone()
        .or_else(|| existing.as_ref().and_then(|s| s.node_token.clone()));
    let registration = match client.register(&register_req, register_token.as_deref()).await {
        Ok(r) => {
            eprintln!(
                "[kronos] registered with control plane as {} (vip {})",
                r.node_id, r.assigned_virtual_ip
            );
            // If the plane issued (or rotated) a token, persist it; else
            // keep the one we presented.
            let effective_token = r.node_token.clone().or(register_token.clone());
            NodeState {
                node_id: r.node_id.clone(),
                virtual_ip: r.assigned_virtual_ip.clone(),
                node_token: effective_token.clone(),
            }
            .save(&cfg.state_dir)?;
            Some((r, effective_token))
        }
        Err(e) => {
            eprintln!(
                "[kronos] control plane unreachable or registration rejected ({e}); running peer-to-peer only"
            );
            None
        }
    };

    // Bind the tunnel on the address the mesh will actually route to:
    // the control plane's assignment when registration succeeded, else
    // the local fallback for peer-to-peer-only operation.
    let assigned_vip = registration
        .as_ref()
        .map(|(r, _)| r.assigned_virtual_ip.as_str());
    let bind_vip = effective_vip(assigned_vip, &local_vip);
    if let Some(assigned) = assigned_vip {
        if assigned != local_vip {
            eprintln!(
                "[kronos] requested vip {local_vip} unavailable; binding the assigned vip {assigned} instead"
            );
        }
    }
    let (tunnel, mut app_rx) = Tunnel::bind(
        cfg.listen_port,
        Identity::load_or_create(&cfg.state_dir)?,
        &bind_vip,
        &cfg.role,
        telemetry.clone(),
        ring.clone(),
    )
    .await
    .context("binding tunnel socket")?;
    tunnel.set_freshness_dir(&cfg.state_dir);
    if let Some((r, _)) = &registration {
        tunnel.update_peers(&r.peers);
    }
    tunnel.spawn_loops();
    eprintln!(
        "[kronos] node {} listening on {} (virtual {})",
        cfg.node_name,
        tunnel.local_addr(),
        bind_vip
    );

    // Application sink: decrypted payloads addressed to this node are
    // logged (a TUN consumer would take them from here in fast-path
    // deployments).
    tokio::spawn(async move {
        while let Some((src, data)) = app_rx.recv().await {
            eprintln!(
                "[kronos] packet from {src}: {} bytes",
                data.len()
            );
        }
    });

    let (node_id, node_token) = match &registration {
        Some((r, tok)) => (Some(r.node_id.clone()), tok.clone()),
        None => (None, None),
    };
    let heartbeat_client = ControlClient::new(&cfg.control_url);
    let hb_tunnel = tunnel.clone();
    let hb_telemetry = telemetry.clone();
    let heartbeat_secs = cfg.heartbeat_secs;
    let heartbeat_handle = tokio::spawn(async move {
        if let Some(node_id) = node_id {
            let node_token = node_token;
            let mut interval = tokio::time::interval(Duration::from_secs(heartbeat_secs));
            loop {
                interval.tick().await;
                let snap = hb_telemetry.snapshot();
                let payload = HeartbeatPayload {
                    node_id: node_id.clone(),
                    tx_bytes: snap.bytes_out,
                    rx_bytes: snap.bytes_in,
                    packets_tx: snap.packets_out,
                    packets_rx: snap.packets_in,
                    peers_connected: hb_tunnel.connected_peer_count(),
                    avg_latency_ms: hb_tunnel.avg_latency_ms(),
                    uptime_secs: hb_tunnel.uptime_secs(),
                    established_peers: hb_tunnel.established_peer_keys(),
                };
                match heartbeat_client
                    .heartbeat(&node_id, &payload, node_token.as_deref())
                    .await
                {
                    Ok(resp) => hb_tunnel.update_peers(&resp.peers),
                    Err(e) => eprintln!("[kronos] heartbeat failed: {e}"),
                }
            }
        }
    });

    let acl_client = ControlClient::new(&cfg.control_url);
    let acl_dir = cfg.state_dir.clone();
    let acl_secs = cfg.acl_sync_secs;
    let acl_tunnel = tunnel.clone();
    let acl_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(acl_secs));
        let mut last_version = 0u64;
        loop {
            interval.tick().await;
            if let Ok(policy) = acl_client.fetch_acls().await {
                if policy.version != last_version {
                    last_version = policy.version;
                    // Enforce in the data plane, and keep the on-disk
                    // cache for inspection/restart continuity.
                    acl_tunnel.update_acls(&policy.rules);
                    let _ = std::fs::write(
                        acl_dir.join("acls.json"),
                        serde_json::to_string_pretty(&policy)
                            .unwrap_or_default(),
                    );
                    eprintln!(
                        "[kronos] ACL policy updated to version {} ({} rules)",
                        policy.version,
                        policy.rules.len()
                    );
                }
            }
        }
    });

    tokio::signal::ctrl_c().await?;
    eprintln!("[kronos] shutting down");
    heartbeat_handle.abort();
    acl_handle.abort();
    Ok(())
}

async fn run_status(cfg: Config) -> Result<()> {
    let identity = Identity::load_or_create(&cfg.state_dir)?;
    println!("node name     : {}", cfg.node_name);
    println!("role          : {}", cfg.role);
    println!("public key    : {}", identity.public_hex());
    println!("fingerprint   : {}", identity.fingerprint());
    println!(
        "proposed vip  : {}",
        proposed_virtual_ip(identity.public.as_bytes())
    );
    if let Some(state) = NodeState::load(&cfg.state_dir) {
        println!("node id       : {}", state.node_id);
        println!("assigned vip  : {}", state.virtual_ip);
    }
    let client = ControlClient::new(&cfg.control_url);
    match client.fetch_topology().await {
        Ok(topo) => {
            let online = topo.nodes.iter().filter(|n| n.online).count();
            println!(
                "mesh          : {} nodes ({} online), {} links",
                topo.nodes.len(),
                online,
                topo.links.len()
            );
        }
        Err(e) => println!("mesh          : control plane unreachable ({e})"),
    }
    Ok(())
}

async fn run_peers(cfg: Config) -> Result<()> {
    let client = ControlClient::new(&cfg.control_url);
    let topo = client
        .fetch_topology()
        .await
        .context("fetching topology from the control plane")?;
    println!(
        "{:<18} {:<15} {:<22} {:<8} {:<6} FINGERPRINT",
        "NAME", "VIRTUAL IP", "ENDPOINT", "ROLE", "STATE"
    );
    for node in &topo.nodes {
        println!(
            "{:<18} {:<15} {:<22} {:<8} {:<6} {}",
            node.node_name,
            node.virtual_ip,
            node.endpoint,
            node.role,
            if node.online { "online" } else { "offline" },
            &node.fingerprint[..16]
        );
    }
    Ok(())
}

async fn run_bench(seconds: u64, payload_size: usize) -> Result<()> {
    let dir_a = std::env::temp_dir().join(format!("kronos-bench-a-{}", std::process::id()));
    let dir_b = std::env::temp_dir().join(format!("kronos-bench-b-{}", std::process::id()));
    let hub = MemoryHub::new();
    let mk = |dir: &PathBuf, port: u16, vip: &str| {
        let identity = Identity::load_or_create(dir).unwrap();
        let pub_hex = identity.public_hex();
        let (tunnel, rx) = Tunnel::bind_with_transport(
            hub.register(std::net::SocketAddr::from(([127, 0, 0, 1], port))),
            Identity::load_or_create(dir).unwrap(),
            vip,
            "node",
            Arc::new(TelemetryCounters::default()),
            Arc::new(EventRing::new(64)),
        )
        .unwrap();
        (tunnel, rx, pub_hex)
    };
    let (a, _rx_a, a_pub) = mk(&dir_a, 6201, "100.64.0.1");
    let (b, mut rx_b, b_pub) = mk(&dir_b, 6202, "100.64.0.2");
    // Bench nodes are standalone: no control plane syncs policy to
    // them, and the data plane is default-deny. The bench therefore
    // applies an explicit local allow-all policy to its own two nodes —
    // the same step an operator performs before sending traffic.
    let bench_policy = [AclRule {
        id: "bench-allow-all".to_string(),
        source_role: "*".to_string(),
        dest_service: "*".to_string(),
        port: 0,
        action: "ALLOW".to_string(),
        priority: 1,
    }];
    a.update_acls(&bench_policy);
    b.update_acls(&bench_policy);
    a.add_peer(&b_pub, "100.64.0.2", Some(b.local_addr()), "node");
    b.add_peer(&a_pub, "100.64.0.1", Some(a.local_addr()), "node");
    a.spawn_loops();
    b.spawn_loops();

    // Handshake timing (cold, includes full Noise_IK exchange).
    let hs_start = Instant::now();
    a.send_data("100.64.0.2", b"handshake probe").await?;
    let _ = rx_b.recv().await;
    let handshake_ms = hs_start.elapsed().as_secs_f64() * 1000.0;

    // Throughput phase: stream packets for `seconds`.
    let payload = vec![0xABu8; payload_size];
    let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let recv_counter = counter.clone();
    let recv_task = tokio::spawn(async move {
        while let Some((_src, data)) = rx_b.recv().await {
            recv_counter.fetch_add(
                data.len() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
    });
    let start = Instant::now();
    let mut sent_packets = 0u64;
    while start.elapsed() < Duration::from_secs(seconds) {
        a.send_data("100.64.0.2", &payload).await?;
        sent_packets += 1;
    }
    let elapsed = start.elapsed().as_secs_f64();
    tokio::time::sleep(Duration::from_millis(200)).await;
    recv_task.abort();
    let received_bytes = counter.load(std::sync::atomic::Ordering::Relaxed);
    let mbps = (received_bytes as f64 * 8.0) / elapsed / 1_000_000.0;
    let pps = sent_packets as f64 / elapsed;
    println!("KronosMesh bench (in-process transport, {payload_size}-byte payloads)");
    println!("  handshake (Noise_IK, cold) : {handshake_ms:.2} ms");
    println!("  packets sent               : {sent_packets}");
    println!("  throughput                 : {mbps:.1} Mbps");
    println!("  packet rate                : {pps:.0} packets/sec");
    println!("  note: measures crypto + protocol path on this machine,");
    println!("        not NIC throughput.");
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
    Ok(())
}

/// The virtual IP the tunnel binds: the control plane's assignment
/// when registration succeeded (the plane is authoritative — a
/// collision may have moved us off the requested address), else the
/// locally persisted / proposed fallback for peer-to-peer-only runs.
fn effective_vip(assigned: Option<&str>, fallback: &str) -> String {
    assigned.unwrap_or(fallback).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assigned_vip_wins_over_requested() {
        // Collision case: we asked for the fallback address, the plane
        // assigned another — the tunnel must bind the assigned one.
        assert_eq!(
            effective_vip(Some("100.64.0.9"), "100.64.0.2"),
            "100.64.0.9"
        );
    }

    #[test]
    fn fallback_vip_used_when_registration_failed() {
        assert_eq!(effective_vip(None, "100.64.0.2"), "100.64.0.2");
    }
}
