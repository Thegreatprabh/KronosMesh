# KronosMesh

![KronosMesh mesh animation](assets/mesh-banner.svg)

**Zero-Trust Mesh VPN and Cryptographic Overlay Network.**
An open-source alternative to Tailscale and Cloudflare Tunnels  -  connect servers and computers anywhere in the world into one secure, encrypted, private network, with **no paid third-party cloud dependency**. You run the control plane; your traffic never touches anyone else's infrastructure.

**Current status:** working mesh VPN with Linux host integration. Nodes authenticate, encrypt and relay traffic peer-to-peer; with TUN enabled (`KRONOS_TUN=1`, Linux) the daemon owns a real network interface — host traffic for mesh addresses flows through the tunnel, routes are installed and removed automatically, and a built-in mesh DNS answers `<node>.mesh` names. A service gateway carries TCP services (e.g. postgres, ssh) between nodes with ACL policy enforced on both ends. Without TUN, the daemon still runs as a userspace overlay delivering payloads to an application sink. Cryptographic processing is userspace on every platform (an eBPF/XDP capability probe runs at startup; a kernel fast path is roadmap). See *Honest status*.

[![CI](https://github.com/Thegreatprabh/KronosMesh/actions/workflows/ci.yml/badge.svg)](https://github.com/Thegreatprabh/KronosMesh/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/Rust-1.87%2B-orange)
![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8)
![eBPF](https://img.shields.io/badge/eBPF-XDP%20probe-blueviolet)
![License](https://img.shields.io/badge/License-MIT-green)

![KronosMesh Console](assets/dashboard-preview.png)

---

## Why KronosMesh?

Legacy VPNs fail in predictable ways:

- **Hub-and-spoke latency**  -  traffic hairpins through a central gateway even when two peers sit in the same city.
- **Perimeter trust**  -  once you are "inside" the VPN, you can reach everything. One compromised laptop becomes a skeleton key.
- **Vendor lock-in**  -  hosted coordination servers mean your network's control plane belongs to someone else, and stops working when their cloud does.

KronosMesh is built the other way:

- **Peer-to-peer data plane**  -  nodes talk directly (with mesh relaying when direct paths fail); the control plane only coordinates identity and policy, never carries your packets.
- **Zero trust by construction**  -  every node has an X25519 identity verified by BLAKE2b fingerprint at registration; every packet is sealed with ChaCha20-Poly1305 after a Noise_IK handshake; ACL policy is role-based (`source role -> destination service : port`) and enforced where the traffic flows: wildcard rules are decided inside the tunnel's data plane, service-specific rules at the service gateway on both the sending and the receiving node. Any matching DENY rule drops traffic regardless of rule priority, and traffic with no matching ALLOW is denied by default (deny-override + default-deny - see How it works).
- **Self-hosted everything**  -  the control plane is a single Go binary with an in-memory store (optional Redis mirror with restart recovery). No accounts, no SaaS, no phone-home.
- **Fast where it counts**  -  a Rust data plane (Noise_IK + ChaCha20-Poly1305 in userspace today; an eBPF/XDP capability probe runs at startup and a kernel fast path is on the roadmap), with relaying built in.

## Architecture

```mermaid
flowchart TB
    subgraph CP["Control Plane (Go + Gin)"]
        API["REST API<br/>register - heartbeat - topology - ACLs"]
        STORE["Hybrid Store<br/>in-memory authoritative<br/>+ Redis full-state mirror + startup recovery"]
        REAPER["Stale-node reaper"]
        API --> STORE
        REAPER --> STORE
    end

    subgraph UI["Operator Console (React + Tailwind)"]
        DASH["Live SVG topology - Node inspector<br/>ACL matrix - Crypto inspector"]
    end

    subgraph DP["Data Plane  -  per node (Rust + Tokio)"]
        UDP["UDP listener<br/>WireGuard-style frames"]
        NOISE["Noise_IK handshake<br/>X25519 - ChaCha20-Poly1305 - BLAKE2s"]
        GW["Service gateway<br/>TCP forwards - ACL both ends"]
        TUN["TUN interface (Linux)<br/>host routes - mesh DNS"]
        XDP["eBPF/XDP probe (Linux)<br/>userspace data plane"]
        UDP --> NOISE
        NOISE --> GW
        NOISE --> TUN
        UDP --> XDP
    end

    DASH -->|"REST /api/v1"| API
    DP -->|"register + heartbeat"| API
    DP <-->|"encrypted packets, peer-to-peer"| DP
```

## Performance

Measured with the built-in benchmark (`kronos-daemon bench`) on a 2-vCPU cloud VM, release build. The bench runs two real daemon cores in-process (Noise_IK handshake + full seal/open path on every packet, 1200-byte payloads)  -  it measures KronosMesh's cryptographic protocol path on commodity hardware, not a synthetic micro-benchmark.

| Metric | KronosMesh (measured) | OpenVPN (typical, userspace TLS) | WireGuard® (typical, kernel) |
|---|---|---|---|
| Handshake | **26.6 ms** (cold, full Noise_IK) | ~100-300 ms (TLS) | ~1 RTT after first packet |
| Crypto-path throughput | **641 Mbps** | ~200-500 Mbps | multi-Gbps |
| Packet rate | **77,969 pps** |  -  |  -  |
| CPU model | 1 core saturated, AEAD in userspace | userspace | kernel |

> Competitor figures are widely published typical ranges for orientation, not measurements from this project. Reproduce ours: `cargo run --release -p kronos-daemon -- bench --seconds 10`.

## Quickstart (60 seconds)

```bash
git clone https://github.com/Thegreatprabh/KronosMesh.git
cd KronosMesh
export KRONOS_ADMIN_TOKEN="a-long-random-secret"   # required, 16+ chars - the control plane refuses to start without it
docker compose up --build
```

That starts Redis, the control plane (`:8080`), the dashboard (`:5173`), and two mesh nodes. Open **http://localhost:5173**  -  you should see both nodes online, linked by an encrypted tunnel (sessions are established automatically). Application data is **default-deny**: before the nodes can exchange data, publish an ALLOW rule - in the dashboard's ACL panel (paste the same admin token when asked), or via the API - e.g. `* -> * ALLOW` for a first test.

### Manual setup

```bash
# 1. Control plane - an operator token is required (startup is fail-closed)
cd control-plane
KRONOS_ADMIN_TOKEN="a-long-random-secret" go run .   # listens on :8080, no Redis required
# (throwaway local dev only: KRONOS_DEV_OPEN_ADMIN=1 go run .  runs unauthenticated)

# 2. A node (each machine) - first registration presents a single-use
#    enrollment token (the node never receives the admin token).
#    Mint one per node (or pre-seed KRONOS_ENROLLMENT_TOKENS instead):
ENROLL=$(curl -s -X POST localhost:8080/api/v1/enrollment-tokens -H "Authorization: Bearer a-long-random-secret" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
cd core/daemon
KRONOS_CONTROL_TOKEN="$ENROLL" cargo run --release -- up   # identity on first run; the enrollment token is consumed by this registration, afterwards the issued node token is used automatically
cargo run --release -- status           # identity, fingerprint, mesh summary
cargo run --release -- peers            # peer table from the control plane

# 3. Dashboard
cd apps/dashboard && npm install && npm run dev   # http://localhost:5173
```

Node configuration is TOML + environment (environment wins):

```toml
# kronos.toml
node_name = "edge-blr-01"
role = "edge"
control_url = "http://127.0.0.1:8080"
listen_port = 51820
tun = true            # Linux host integration (or KRONOS_TUN=1)

# Service gateway: local clients connect to 127.0.0.1:15432 and are
# carried over the mesh to the db node's gateway, which dials its own
# 127.0.0.1:5432 - after policy checks on BOTH ends.
[[services]]
name = "postgres"
listen = "127.0.0.1:15432"
target_vip = "100.64.0.12"
target_port = 5432
```

| Env var | Meaning |
|---|---|
| `KRONOS_NODE_NAME` / `KRONOS_ROLE` | Node identity metadata |
| `KRONOS_CONTROL_URL` | Control plane base URL |
| `KRONOS_LISTEN_PORT` | UDP listen port (default 51820) |
| `KRONOS_STATE_DIR` | Identity/state directory (default `.kronos`) |
| `KRONOS_STUN_SERVER` | Optional STUN server for public-endpoint discovery |
| `KRONOS_ADVERTISE_ENDPOINT` | Explicit `host:port` to register with the control plane (overrides discovery; the right knob behind NAT/port mapping) |
| `KRONOS_EBPF_OBJECT` | Optional compiled eBPF object to validate at startup |
| `KRONOS_ADMIN_TOKEN` | *(control plane)* **Required** operator token (16+ chars): gates ACL changes, enrollment-token minting and node revocation; the plane refuses to start without it. It is the operator's credential only - nodes never receive it; provision them with enrollment tokens instead |
| `KRONOS_ENROLLMENT_TOKENS` | *(control plane)* Comma-separated plaintext single-use enrollment tokens to pre-seed at startup (stored hashed; only the count is logged). Each authorizes exactly one first-time node registration and is consumed by it. Alternatively mint tokens at runtime via `POST /api/v1/enrollment-tokens` |
| `KRONOS_STATE_FILE` | *(control plane)* Registry snapshot path used when `REDIS_ADDR` is not set (default `kronos-state.json`): structural changes are written there atomically and restored at startup. With neither Redis nor a state file, a restart starts empty and nodes must re-provision |
| `KRONOS_DEV_OPEN_ADMIN` | *(control plane)* `1` explicitly selects the unauthenticated posture - local development only, never in production |
| `KRONOS_CONTROL_TOKEN` | *(daemon)* Token presented at registration - a single-use enrollment token (or the admin token) when provisioning a new node, afterwards the issued node token is persisted automatically and presented instead |
| `KRONOS_CORS_ORIGINS` | *(control plane)* Comma-separated browser origins allowed to call the API (default: local dashboard origins) |
| `KRONOS_TLS_CERT` / `KRONOS_TLS_KEY` | *(control plane)* PEM paths; when both are set the control plane serves HTTPS |
| `KRONOS_REQUIRE_TLS` | *(control plane)* `1` makes TLS mandatory: startup fails without a certificate pair, so production cannot silently serve bearer tokens over plaintext |
| `KRONOS_ALLOW_INSECURE_HTTP` | *(daemon)* `1` permits sending node tokens to a non-loopback `http://` control plane (trusted networks only, e.g. an isolated Docker bridge); by default the daemon refuses - use `https://` or loopback |
| `KRONOS_TUN` | *(daemon)* `1` enables the Linux TUN host integration (needs root or CAP_NET_ADMIN): the node's VIP is assigned to the interface named by the `interface` config (`kronos0`), the mesh range is routed into it, and routes/device are removed at shutdown |
| `KRONOS_DNS` / `KRONOS_DNS_UPSTREAM` | *(daemon)* Mesh DNS on the node's VIP:53 while TUN is on (default on; set `KRONOS_DNS=0` to disable); non-mesh names are forwarded to the upstream (default `1.1.1.1:53`) |

## How it works

**Identity.** On first run each daemon generates an X25519 static keypair, stored in its state directory (`0600`). The node's fingerprint  -  BLAKE2b-256 of the public key  -  is its identity. At registration the control plane *recomputes* the fingerprint from the presented public key and rejects mismatches: a node cannot claim another node's identity. Registration also issues the node a **bearer token** (returned exactly once; the daemon persists it in its state directory at `0600`): heartbeats and re-registrations must present it, so a stranger who knows a node's public key - which is public information - cannot hijack its endpoint, spoof its telemetry, or (without an admin token) change its role. First-time registrations require the operator's admin token (`KRONOS_ADMIN_TOKEN`, mandatory at startup unless the explicit `KRONOS_DEV_OPEN_ADMIN=1` local-development opt-in is set) or a single-use enrollment token issued by the operator for that one node, and all ACL changes require the admin token; browser access is restricted to a CORS allowlist. Membership is not permanent: the operator can revoke a node at any time (`DELETE /api/v1/nodes/:id`), which invalidates its token immediately and returns its virtual IP to the pool - a stolen node key or token is therefore not trusted forever, and a revoked node that reappears must be provisioned from scratch. The daemon persists only tokens the plane issued to it (never a presented provisioning credential); if a node's `node_state.json` is lost while its identity key survives, it can re-register with the admin token but receives no new node token — heartbeats are then rejected and the daemon logs a warning; revoke the node and restart it so it registers fresh and is issued a new token. The read endpoints are credentialed too: topology and the ACL policy disclose every node's name, role, public key and live endpoint, so they require the admin token or any registered node's token — daemons poll with their node token, and the dashboard sends the operator token the user enters (before one is entered it shows its labelled demo data, never live mesh data).

**Handshake.** Peers run a Noise_IK handshake (the initiator already knows the responder's static key from the control plane's peer list): `-> e, es, s, ss` / `<- e, ee, se`, with HKDF-BLAKE2s key schedule and ChaCha20-Poly1305 throughout  -  the same primitive family as WireGuard®, implemented here from the Noise Protocol Framework spec. Unknown keys are dropped silently, exactly like WireGuard®. INIT messages carry a millisecond timestamp that must be strictly greater than the last one accepted from that peer (floors are persisted across restarts, and INITs older than two minutes are always rejected), so a captured handshake cannot be replayed to replace a live session. If both sides initiate at once, a deterministic public-key tie-break picks one winner instead of leaving mismatched sessions. The initiator rotates the session (rekey) every two minutes, and handshake attempts that time out are retried instead of wedging the peer.

**Transport.** WireGuard-style frames (`type | indices | counter | AEAD ciphertext`) over UDP, a 2048-packet sliding replay window, keepalives, and roaming (endpoints are re-learned from authenticated traffic). Payloads are protected twice: the per-hop Noise session, and an end-to-end seal between the origin and the final destination whose key is derived from their static X25519 keys — directionally (each direction derives its own key) and with the frame kind bound into the authentication data, so a relay cannot re-label a sealed body as a different kind of frame either. If a destination is not a direct peer, intermediate nodes relay the packet with its body still sealed end-to-end  -  a relay sees only the routing header (kind, source, destination, TTL) protected by its hop session, and cannot read, forge or re-address the payload; at the destination, policy is evaluated against the source only *after* the end-to-end body authenticates, so a node that claims another node's virtual IP is dropped at that check rather than inheriting its role. A TTL bounds forwarding so loops die. Two honest limits: the end-to-end key is static-static DH, so that layer authenticates the origin and blinds relays but has no forward secrecy of its own (forward secrecy comes from the ephemeral per-hop Noise sessions); the end-to-end keys are also never rotated — they live as long as the pair's static keys do — and relays necessarily see routing metadata. The transport AEAD is bound to the frame header as associated data, so a frame cannot be transplanted into another session or frame type. v1.5 changed the wire protocol (the spec-exact `Noise_IK_25519_ChaChaPoly_BLAKE2s` protocol name, header-bound transport AEAD, end-to-end payload sealing, cookie challenges): all nodes in a mesh must run v1.5 or later; earlier builds cannot interoperate. v1.5.1 changed the end-to-end key derivation again (directional keys, kind binding), so sealed payloads additionally require every node on v1.5.1 or later — a mixed v1.5.0/v1.5.1 mesh still handshakes, but its end-to-end bodies will not authenticate and are dropped. Nodes also proactively establish sessions with every known peer, so a running mesh is actually connected, not just registered. The receive path is flood-hardened: frame size/type checks and a bounded cap on concurrent frame handlers run before expensive work, and handshakes are gated WireGuard-style: past the per-source INIT rate limit, the responder issues a COOKIE challenge bound to the source address and drops the INIT; a legitimate initiator retries with a MAC proof (mac2) attached, while a flood from spoofed addresses never receives the cookie and never reaches the X25519 work - it costs the responder one HMAC instead of two elliptic-curve multiplications. Once the *aggregate* proof-less INIT budget is exhausted, every source needs a proof, even a fresh one (WireGuard's cookie mode under load), so rotating source addresses cannot buy unbounded handshake CPU either; and an invalid proof is treated exactly like no proof, so a forged cookie planted in an initiator's cache by a spoofed COOKIE frame cannot block its handshakes.

**Data plane modes.** On Linux the daemon probes for XDP capability at startup (kernel support, privileges, optional eBPF object validation via the real `bpf()` syscall) and reports exactly what it found and why; a minimal XDP program load is attempted as the probe. The `bpf()` syscall number is selected per CPU architecture at compile time (x86_64, x86, aarch64, riscv64, arm are defined; anything else reports itself unsupported instead of invoking a wrong syscall), and CI runs the daemon test suite on both x86_64 and ARM64. Packet processing itself runs in the userspace data plane in this release - on every platform, with identical semantics - and a kernel fast path is on the roadmap. `kronos-daemon up` prints the probe verdict at startup, and nodes report the probe outcome (`ebpf_probe_passed`) and the fast-path state as separate fields end to end, so no API or dashboard consumer can mistake a passed probe for kernel packet processing.

**Zero-trust enforcement.** ACL policy is not just stored centrally  -  daemons sync it continuously and enforce it where traffic flows, through one shared decision function (`acl_decision`) so the semantics can never drift between enforcement points. Rules with destination `*` or `mesh-data` and port `0` (wildcard) are decided in the tunnel itself for raw mesh data. Service-specific rules (a named service on a concrete port, e.g. `edge -> postgres:5432`) are decided by the **service gateway** on both ends of a stream: the initiating node checks its own role before sending anything, and the target node checks the sender's role again before dialing the local service. The model is **deny-override with default-deny**: every matching rule is considered (priority only decides which DENY gets reported, never the outcome); any matching DENY drops the traffic even when a better-priority ALLOW also matches; and traffic with **no matching ALLOW is denied by default** - a fresh mesh passes no application data until the operator publishes an ALLOW rule. Drops are counted in telemetry and logged. Port `0` means "any port" throughout the system. The dashboard labels every rule with the point that enforces it (DATA PLANE or SERVICE GATEWAY).

**Service gateway.** Configured forwards (`[[services]]`) listen on loopback TCP ports and carry each connection as an encrypted stream (OPEN/DATA/CLOSE/ACK/RESET frames inside the same Noise sessions, relayed like data when the target is not a direct peer). The receiving gateway dials `127.0.0.1:<port>` only after its policy check passes; a denied or unreachable target is answered with a stream RESET, so the local client sees a refused connection rather than a hang. Because the transport is UDP, the stream layer implements the reliability TCP services assume: per-direction sequence numbers, cumulative acknowledgements, retransmission of unacknowledged frames, and a bounded sender window. Backpressure is end-to-end — a sender whose window is full waits (its gateway stops reading the local socket, so TCP flow control throttles the application), a receiver acknowledges only what it has actually queued for the local service, and no byte is ever dropped to make progress. Directions close independently (half-close): a close is retransmitted until the peer acknowledges it complete, and a stream is torn down only when both directions have finished, so a client that half-closes after its request still receives the full reply. The test suite proves this over a chaos transport that drops, duplicates and reorders datagrams (bulk transfers byte-exact, slow consumers, parallel streams, mid-transfer disconnects). Remaining limits: no idle timeout for live peers (streams of a peer that has gone completely silent are reaped by housekeeping), and both peers must run the v2 stream protocol (the frame format gained sequence numbers in v1.4).

**Host integration (Linux).** With `KRONOS_TUN=1` the daemon creates a TUN device, assigns the node's virtual IP, brings the interface up with the tunnel MTU, and routes the whole mesh range (`100.64.0.0/10`) into it; on shutdown the route and device are removed again. Packets the kernel routes in are forwarded to their destination VIP through the tunnel; decrypted IP packets addressed to this node are written back to the device for normal host delivery - `ping`, `ssh` and every other IP tool work against mesh addresses with no application changes. A mesh DNS resolver listens on the node's VIP (port 53): `<node>.mesh` and bare node names are answered from the live peer table, unknown mesh names get NXDOMAIN (never leaked upstream), and all other queries are forwarded to a configurable upstream resolver. `scripts/tun-netns-e2e.sh` exercises the whole path (two namespaces, control plane, ping + DNS across the mesh) and runs in CI.

**Pointing the host's resolver at mesh DNS.** The daemon does not modify host resolver configuration automatically. With systemd-resolved, route only the mesh domain to the node VIP (split DNS):

```sh
sudo resolvectl dns kronos0 <node-vip>          # e.g. 100.64.0.2
sudo resolvectl domain kronos0 '~mesh'
```

Without systemd-resolved, add the node VIP as a nameserver in `/etc/resolv.conf` (all queries then pass through the mesh resolver, which forwards non-mesh names upstream), or query it directly to verify: `dig @<node-vip> node-b.mesh`. The interface name is `KRONOS_INTERFACE` if you changed it. To undo the systemd-resolved settings: `sudo resolvectl revert kronos0`.

**Endpoint discovery.** Public-endpoint discovery uses STUN binding requests with a fresh random transaction ID per request; a response is accepted only if it arrives from the exact server endpoint queried and passes strict validation (message type, magic cookie, transaction ID, declared length accounting for the whole datagram, attribute bounds) - forged or stray datagrams cannot steer the endpoint a node advertises.

**Control plane.** Gin REST API: node registration with CGNAT-range (`100.64.0.0/10`) virtual-IP assignment (requested addresses are validated to be inside the range), heartbeat telemetry, mesh topology whose link encryption flags come from the nodes' own heartbeat session reports - never assumed - and versioned ACL policy that daemons sync continuously. Nodes that stop heartbeating are reaped to `offline` after 45 s. Membership is revocable: `DELETE /api/v1/nodes/:id` (admin-only, also exposed as *Revoke node* in the dashboard's node inspector) removes a node at once - its token stops authenticating, its key is forgotten, and its virtual IP returns to the pool; if the machine ever comes back it is a brand-new identity that must be provisioned again. First registration is provisioned without handing out the operator credential: the admin mints single-use enrollment tokens (`POST /api/v1/enrollment-tokens`, admin-only; or pre-seeds them with `KRONOS_ENROLLMENT_TOKENS`) and gives one to each new node, which presents it as its registration token; the token is consumed by the registration that succeeds and can never enroll a second node. The store is in-memory and authoritative; with `REDIS_ADDR` set, every structural write is mirrored to Redis as full state and the registry, policy and outstanding enrollment set are rebuilt from that mirror at startup (recovered nodes return offline until they heartbeat), so a control-plane restart no longer loses the mesh. Without Redis, the same recovery runs from an atomic JSON state file (see `KRONOS_STATE_FILE`) written on every structural change - node register/delete, ACL changes, enrollment add/consume. Startup is fail-closed on operator auth (see `KRONOS_ADMIN_TOKEN`) and can be made fail-closed on transport too: with `KRONOS_REQUIRE_TLS=1` the plane refuses to start without a certificate pair, and in plaintext mode it logs a loud warning that bearer tokens cross the wire unencrypted. Daemons enforce the other half: a node refuses to send its tokens to a non-loopback `http://` control plane unless the operator explicitly opts in for a trusted network (`KRONOS_ALLOW_INSECURE_HTTP=1`). The HTTP server runs with explicit timeouts and a 64 KB request-body cap, and serves HTTPS when `KRONOS_TLS_CERT`/`KRONOS_TLS_KEY` are set.

**Shared contracts.** One JSON contract (`contracts/` at the repo root) pins the payloads shared by the daemon, the control plane, and the dashboard. Both the Rust and Go test suites assert their types against those fixtures, so the three codebases cannot silently drift.

## Repository layout

```
kronos-mesh/
|-- core/daemon/        Rust data plane: Noise_IK crypto, UDP tunnel + relay,
|                       eBPF loader with userspace fallback, control client, CLI
|-- control-plane/      Go control plane: registry, topology, ACL policy (Gin)
|-- apps/dashboard/     React console: topology map, ACL matrix, crypto inspector
|-- contracts/          Cross-language JSON contract fixtures
|-- scripts/            tun-netns-e2e.sh - two-namespace host-networking E2E (real Linux)
|-- docker-compose.yml  redis + control plane + dashboard + 2 mesh nodes
`-- Makefile            build-all - dev - test - docker-up - clean
```

## Verification

Every layer is tested, and the suites run in CI:

- **Rust**  -  Noise_IK handshake round-trips, HMAC/HKDF-BLAKE2s vectors cross-checked against reference implementations, fingerprint vectors shared with Go, replay/tamper rejection, 2-node exchange and 3-node relay over an in-memory transport, STUN response validation (forged/wrong-transaction/cookie/length responses rejected), eBPF object validation, per-architecture `bpf()` syscall selection, ACL deny-override/default-deny semantics for both the data gate and service questions, service-gateway streams end-to-end over the in-memory transport (including target-side and initiator-side denials), reliable stream delivery over a chaos transport (10% loss / 5% duplication / 20% reordering: byte-exact bulk transfers, close overtaking data, blocked senders woken by RESET), service-gateway transfers over the same chaos transport (bulk, slow consumer, parallel streams, mid-transfer disconnect), TUN setup rollback under injected failures at the first and last setup steps, a real TUN device ICMP roundtrip against the host kernel and DNS delivery through the real device (both skip where `/dev/net/tun` is unavailable), mesh DNS parsing/routing/response building, the control-URL token-transport policy, assigned-VIP resolution, INIT rate-limit window/pruning, the frame-handler flood cap, end-to-end origin sealing (a forged source VIP is dropped at authentication, relays forward payloads opaquely), spoofed-PING reflection refusal, WireGuard-style cookie challenges under INIT flood (challenge issued, proof math, mac2 retry completing a handshake mid-flood), and INIT-freshness persistence (atomic temp+rename writes; a corrupt state file fails closed with boot-time replay floors). The suite also runs on ARM64 in CI.
- **Go**  -  registration/IP allocation, heartbeat + reaper, ACL versioning, full HTTP flows, node revocation, single-use enrollment tokens (including consume-on-commit and failed-registration cases), fail-closed admin startup, fail-closed TLS-required startup, Redis and state-file restart recovery (nodes, policy, credential hashes, enrollment set), and contract-fixture shape equality with the Rust types.
- **Dashboard**  -  strict TypeScript (`tsc --noEmit`) + production Vite build. Connection state is explicit: LIVE, STALE (last live data kept, with the classified failure - network/HTTP/parse), or DEMO (only before the first successful live load, always labelled).
- **CI**  -  beyond the suites above: a security job runs `cargo audit` (Rust) and `govulncheck` (Go) on every push, the TUN/DNS host-integration tests also run as root, a dedicated job executes `scripts/tun-netns-e2e.sh` on a real runner, and a CLI end-to-end job builds the control plane and daemon, then exercises `bench`, `up`, `peers` and `status` against the live control plane — two network namespaces, TUN devices, ICMP and mesh DNS across the encrypted mesh, plus a 256 KB service-gateway transfer verified byte-exact under `tc netem` 10% packet loss with jitter.

## Honest status

- The framing and handshake are KronosMesh's own implementation of the Noise_IK pattern with WireGuard-style packet layout; it is **not** wire-compatible with the WireGuard® protocol itself.
- eBPF today is a capability probe + object validation, not a packet fast path: all traffic runs through the userspace data plane, and the telemetry fast-path counter stays at zero until a real XDP program ships (roadmap).
- INIT freshness floors persist across restarts and INITs older than two minutes are rejected outright; the residual replay exposure after a responder restart is bounded to that two-minute window and cannot be exploited to read traffic (session keys still require the peer's static secret).
- Control-plane state survives restarts when persistence is configured, and one of two mechanisms must be on: with `REDIS_ADDR` set, a write-through Redis mirror with startup recovery; without Redis, an atomic JSON state file (`KRONOS_STATE_FILE`, default `kronos-state.json` in the working directory) rewritten on every structural change and restored at startup. Either way the in-memory store remains authoritative, and recovered nodes return offline until they heartbeat with their persisted node token. If the Redis mirror is unreachable *and* the state file cannot be written (for example a read-only working directory), a restart starts empty: the registry has forgotten every node, heartbeats from previously registered nodes are rejected as unknown, and each node must be re-provisioned - with a fresh single-use enrollment token (or the admin token) - before it can register again; a node cannot silently re-register on identity alone. Still roadmap: Ed25519-signed policy bundles.
- TUN host integration is Linux-only today (macOS/Windows utun/Wintun support is roadmap), and the mesh DNS answers A records for mesh names plus transparent forwarding - it synthesizes no AAAA records and does no DNSSEC. The service gateway (v2 streams) provides reliable, ordered, backpressured delivery over the UDP mesh — proven against a loss/dup/reorder chaos transport — with two stated limits: no idle timeout for live peers (silent-peer streams are reaped), and stream interop requires both peers on v1.4+ (sequence numbers were added to the stream frame format). TUN setup is rollback-safe (a failed step removes the partial configuration), and host resolver configuration for mesh DNS is a documented manual step (systemd-resolved split DNS or resolv.conf) — the daemon never edits it automatically.
- The control-plane API is plain HTTP unless you configure the TLS options - for any non-local deployment set `KRONOS_REQUIRE_TLS=1` with certificates (or terminate TLS at a trusted reverse proxy and keep the plane's port reachable only from it); daemons already refuse to send tokens to remote plaintext endpoints by default.

## License

MIT  -  see [LICENSE](LICENSE). WireGuard® is a registered trademark of Jason A. Donenfeld; KronosMesh is not affiliated with or endorsed by WireGuard® or Tailscale Inc.
