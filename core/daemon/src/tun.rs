//! Host TUN integration (Linux).
//!
//! Decrypted mesh payloads used to end in an application-level sink
//! inside the daemon: the mesh carried data between daemons, but the
//! host operating system knew nothing about it. With TUN enabled the
//! daemon owns a real network interface, so ordinary host traffic
//! addressed to mesh virtual IPs flows through the encrypted tunnel:
//!
//! - outbound: packets the kernel routes into the mesh range
//!   (100.64.0.0/10) arrive on the device and are handed to the tunnel
//!   addressed to their destination VIP;
//! - inbound: decrypted payloads that are IPv4 packets addressed to
//!   this node's VIP are written to the device, and the host stack
//!   delivers them exactly like traffic on any other interface.
//!
//! Device creation uses the same hand-rolled syscall approach as the
//! eBPF probe (no new dependencies). Address and route management go
//! through the `ip` command (iproute2); everything configured is
//! removed again at shutdown. On non-Linux platforms the module is a
//! stub that reports the feature as unavailable — it never pretends.

use std::net::Ipv4Addr;

/// The CGNAT range the mesh allocates from (contracts/meshnet.json).
pub const MESH_RANGE_STR: &str = "100.64.0.0/10";

/// True when `ip` lies in the mesh range 100.64.0.0/10.
pub fn in_mesh_range(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xC0) == 0x40
}

/// The destination address of an IPv4 packet, or None when the buffer
/// is not a (complete-header) IPv4 packet.
pub fn ipv4_dst(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 || (packet[0] >> 4) != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ))
}

/// The source address of an IPv4 packet, or None like `ipv4_dst`.
pub fn ipv4_src(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 || (packet[0] >> 4) != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ))
}

// ---------------------------------------------------------------------------
// Linux implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use anyhow::{bail, Context, Result};
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::unix::io::AsRawFd;
    use std::process::Command;
    use std::sync::{Arc, Mutex};

    // ioctl() syscall numbers are architecture-specific (same lesson
    // as the bpf() number in ebpf_loader).
    #[cfg(target_arch = "x86_64")]
    const SYS_IOCTL: i64 = 16;
    #[cfg(target_arch = "aarch64")]
    const SYS_IOCTL: i64 = 29;
    #[cfg(target_arch = "riscv64")]
    const SYS_IOCTL: i64 = 29;
    #[cfg(target_arch = "arm")]
    const SYS_IOCTL: i64 = 54;
    #[cfg(target_arch = "x86")]
    const SYS_IOCTL: i64 = 54;
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "arm",
        target_arch = "x86"
    )))]
    const SYS_IOCTL: i64 = -1;

    const TUNSETIFF: u64 = 0x4004_54ca;
    const IFF_TUN: u16 = 0x0001;
    const IFF_NO_PI: u16 = 0x1000;

    extern "C" {
        fn syscall(num: i64, ...) -> i64;
    }

    #[repr(C)]
    struct IfReq {
        name: [u8; 16],
        flags: u16,
        _pad: [u8; 22],
    }

    /// A created TUN device. The reader side is a blocking file (the
    /// pump runs on its own thread); writes go through a shared handle
    /// so the application sink can inject decrypted packets.
    pub struct TunDevice {
        name: String,
        file: File,
        writer: Arc<Mutex<File>>,
    }

    impl TunDevice {
        pub fn create(requested_name: &str) -> Result<Self> {
            if SYS_IOCTL < 0 {
                bail!(
                    "TUN is unsupported on this CPU architecture: no \
                     ioctl() syscall number is defined for it"
                );
            }
            if requested_name.len() >= 16 {
                bail!("interface name {requested_name:?} is too long (max 15 bytes)");
            }
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/net/tun")
                .context(
                    "cannot open /dev/net/tun (is the tun kernel module loaded, \
                     and is the device passed into this container?)",
                )?;
            let mut req = IfReq {
                name: [0u8; 16],
                flags: IFF_TUN | IFF_NO_PI,
                _pad: [0u8; 22],
            };
            req.name[..requested_name.len()].copy_from_slice(requested_name.as_bytes());
            let rc = unsafe {
                syscall(
                    SYS_IOCTL,
                    file.as_raw_fd() as i64,
                    TUNSETIFF as i64,
                    &mut req as *mut IfReq as i64,
                )
            };
            if rc != 0 {
                bail!(
                    "TUNSETIFF for {requested_name} failed: {} \
                     (creating a TUN device needs root or CAP_NET_ADMIN)",
                    std::io::Error::last_os_error()
                );
            }
            // The kernel returns the effective interface name.
            let end = req.name.iter().position(|&b| b == 0).unwrap_or(16);
            let name = String::from_utf8_lossy(&req.name[..end]).into_owned();
            let writer = Arc::new(Mutex::new(file.try_clone()?));
            Ok(Self { name, file, writer })
        }

        /// Creates a device and fully configures it (address, up,
        /// mesh route). On any failure the partial setup is rolled
        /// back (see `configure`) and the device is dropped, so the
        /// caller either gets a working interface or nothing.
        pub fn setup(requested_name: &str, vip: Ipv4Addr, mtu: u16) -> Result<Self> {
            let device = Self::create(requested_name)?;
            let name = device.name().to_string();
            if let Err(e) = configure(&name, vip, mtu) {
                drop(device);
                return Err(e);
            }
            Ok(device)
        }

        pub fn name(&self) -> &str {
            &self.name
        }

        /// A shared handle for injecting packets (mesh -> host).
        pub fn writer_handle(&self) -> Arc<Mutex<File>> {
            self.writer.clone()
        }

        /// Writes one packet to the device (it enters the host stack
        /// as if it had just arrived on the interface).
        pub fn write_packet(&self, packet: &[u8]) -> std::io::Result<()> {
            self.writer.lock().unwrap().write_all(packet)
        }

        /// Blocking read of one packet from the device (host -> mesh).
        pub fn read_packet(&self, buf: &mut [u8]) -> std::io::Result<usize> {
            (&self.file).read(buf)
        }
    }

    /// Writes one packet through a shared writer handle (the shape
    /// the application sink holds).
    pub fn write_packet_handle(writer: &Arc<Mutex<File>>, packet: &[u8]) -> std::io::Result<()> {
        writer.lock().unwrap().write_all(packet)
    }

    fn run_ip(args: &[&str]) -> Result<()> {
        let out = Command::new("ip")
            .args(args)
            .output()
            .context("cannot run `ip` (is iproute2 installed?)")?;
        if !out.status.success() {
            bail!(
                "`ip {}` failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    /// Assigns the VIP, brings the interface up with the tunnel MTU,
    /// and routes the whole mesh range into it.
    ///
    /// Failure handling: if ANY step fails, everything this call (or
    /// a previous partial attempt) set up is rolled back — the
    /// route and the interface are removed — before the error is
    /// returned. A half-configured interface (address assigned but
    /// no route, or up with no address) is never left behind for the
    /// operator or a later retry to trip over.
    pub fn configure(name: &str, vip: Ipv4Addr, mtu: u16) -> Result<()> {
        let attempt = (|| -> Result<()> {
            run_ip(&["addr", "add", &format!("{vip}/32"), "dev", name])
                .context("assign TUN address")?;
            run_ip(&["link", "set", name, "up", "mtu", &mtu.to_string()])
                .context("bring TUN interface up")?;
            run_ip(&["route", "add", MESH_RANGE_STR, "dev", name]).context("add mesh route")?;
            Ok(())
        })();
        if let Err(e) = attempt {
            teardown(name);
            return Err(e);
        }
        Ok(())
    }

    /// Removes the mesh route and the interface (best effort; closing
    /// the device would remove it too — this is explicit and logged).
    pub fn teardown(name: &str) {
        let _ = run_ip(&["route", "del", MESH_RANGE_STR, "dev", name]);
        let _ = run_ip(&["link", "del", name]);
    }

    /// Spawns the host -> mesh pump on a blocking thread: every packet
    /// the kernel routes into the device whose destination is another
    /// mesh node is forwarded into `sink` (a tunnel send queue drained
    /// by an async task in the caller). Packets for our own VIP are
    /// local deliveries the kernel would not have routed here; other
    /// traffic is dropped by design (only the mesh range is routed
    /// into the device at all).
    pub fn spawn_pump(
        device: TunDevice,
        local_vip: Ipv4Addr,
        sink: tokio::sync::mpsc::Sender<(Ipv4Addr, Vec<u8>)>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65535];
            loop {
                match device.read_packet(&mut buf) {
                    Ok(0) => {
                        // Never silent: host->mesh traffic has
                        // stopped while everything else (heartbeats,
                        // status, the interface itself) still looks
                        // healthy — the operator must see this.
                        eprintln!(
                            "[kronos] TUN pump: device read returned 0 (closed); host traffic into the mesh has stopped"
                        );
                        return;
                    }
                    Ok(n) => {
                        let packet = &buf[..n];
                        if let Some(dst) = ipv4_dst(packet) {
                            if dst != local_vip && in_mesh_range(&dst) {
                                // Drop rather than stall the kernel
                                // queue when the tunnel is backed up.
                                let _ = sink.try_send((dst, packet.to_vec()));
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "[kronos] TUN pump: device read failed: {e}; host traffic into the mesh has stopped"
                        );
                        return;
                    }
                }
            }
        })
    }
}

#[cfg(target_os = "linux")]
pub use imp::{configure, spawn_pump, teardown, write_packet_handle, TunDevice};

#[cfg(not(target_os = "linux"))]
mod stub {
    use super::*;
    use anyhow::{bail, Result};
    use std::fs::File;
    use std::sync::{Arc, Mutex};

    pub struct TunDevice {
        _private: (),
    }

    impl TunDevice {
        pub fn create(_requested_name: &str) -> Result<Self> {
            bail!("TUN host integration is implemented for Linux only in this release")
        }
        pub fn setup(_requested_name: &str, _vip: Ipv4Addr, _mtu: u16) -> Result<Self> {
            bail!("TUN host integration is implemented for Linux only in this release")
        }
        pub fn name(&self) -> &str {
            ""
        }
        pub fn writer_handle(&self) -> Arc<Mutex<File>> {
            unreachable!("TunDevice cannot be constructed on this platform")
        }
        pub fn write_packet(&self, _packet: &[u8]) -> std::io::Result<()> {
            unreachable!("TunDevice cannot be constructed on this platform")
        }
    }

    pub fn configure(_name: &str, _vip: Ipv4Addr, _mtu: u16) -> Result<()> {
        bail!("TUN host integration is implemented for Linux only in this release")
    }

    pub fn write_packet_handle(
        _writer: &std::sync::Arc<std::sync::Mutex<std::fs::File>>,
        _packet: &[u8],
    ) -> std::io::Result<()> {
        unreachable!("TunDevice cannot be constructed on this platform")
    }

    pub fn teardown(_name: &str) {}

    pub fn spawn_pump(
        _device: TunDevice,
        _local_vip: Ipv4Addr,
        _sink: tokio::sync::mpsc::Sender<(Ipv4Addr, Vec<u8>)>,
    ) -> std::thread::JoinHandle<()> {
        unreachable!("TunDevice cannot be constructed on this platform")
    }
}

#[cfg(not(target_os = "linux"))]
pub use stub::{configure, spawn_pump, teardown, write_packet_handle, TunDevice};

/// Host-network tests mutate shared kernel state — a TUN device,
/// an address, and the mesh route — and some kernels refuse the
/// same route prefix via two devices at once, so tests that touch
/// real host networking must hold this lock for their whole run
/// instead of racing each other. Poison-tolerant: a panicking
/// sibling test must not cascade.
#[cfg(test)]
pub(crate) static HOST_NET_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) fn host_net_test_lock() -> std::sync::MutexGuard<'static, ()> {
    HOST_NET_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mesh_range_is_exactly_a_slash_10() {
        assert!(in_mesh_range(&"100.64.0.0".parse().unwrap()));
        assert!(in_mesh_range(&"100.127.255.255".parse().unwrap()));
        assert!(in_mesh_range(&"100.100.126.182".parse().unwrap()));
        assert!(!in_mesh_range(&"100.128.0.0".parse().unwrap()));
        assert!(!in_mesh_range(&"100.63.255.255".parse().unwrap()));
        assert!(!in_mesh_range(&"10.64.0.1".parse().unwrap()));
    }

    #[test]
    fn ipv4_address_extraction() {
        let mut pkt = [0u8; 20];
        pkt[0] = 0x45;
        pkt[12..16].copy_from_slice(&[100, 64, 0, 5]);
        pkt[16..20].copy_from_slice(&[100, 64, 0, 9]);
        assert_eq!(
            ipv4_src(&pkt).unwrap(),
            "100.64.0.5".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            ipv4_dst(&pkt).unwrap(),
            "100.64.0.9".parse::<Ipv4Addr>().unwrap()
        );
        // IPv6 (version nibble 6) and truncated buffers are not IPv4.
        pkt[0] = 0x60;
        assert!(ipv4_dst(&pkt).is_none());
        pkt[0] = 0x45;
        assert!(ipv4_dst(&pkt[..19]).is_none());
        assert!(ipv4_dst(&[]).is_none());
    }

    /// Real-device integration test: creates a TUN interface, assigns
    /// an address, installs the mesh route, and proves the host stack
    /// roundtrip — an ICMP echo request written to the device (as the
    /// tunnel would deliver it) is answered by the kernel, and the
    /// reply is routed back into the device (as the pump would read
    /// it). Skips cleanly where /dev/net/tun or CAP_NET_ADMIN is
    /// unavailable (most CI sandboxes), so it only ever fails on a
    /// genuine regression in an environment that supports it.
    #[test]
    #[cfg(target_os = "linux")]
    fn real_tun_device_icmp_roundtrip() {
        let _host_net = super::host_net_test_lock();
        let name = format!("krt{}", std::process::id() % 100_000);
        let vip: Ipv4Addr = "100.127.0.1".parse().unwrap();
        let device = match TunDevice::create(&name) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("SKIP real_tun_device_icmp_roundtrip: {e}");
                return;
            }
        };
        let dev_name = device.name().to_string();
        if let Err(e) = configure(&dev_name, vip, 1400) {
            eprintln!("SKIP real_tun_device_icmp_roundtrip (configure): {e}");
            teardown(&dev_name);
            return;
        }
        icmp_roundtrip(device, vip).unwrap();
        teardown(&dev_name);
    }

    /// Failure injection for the setup rollback: a configure()
    /// that fails partway — at the FIRST step or at the LAST —
    /// must leave nothing behind: the interface itself is removed,
    /// not left half-configured for the operator or a retry.
    #[test]
    #[cfg(target_os = "linux")]
    fn tun_configure_failure_rolls_back_everything() {
        let _host_net = super::host_net_test_lock();
        fn link_exists(name: &str) -> bool {
            std::process::Command::new("ip")
                .args(["link", "show", "dev", name])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        }
        let pid = std::process::id() % 100_000;

        // Scenario 1: re-configuring a live interface fails at
        // step 1 (address already assigned).
        let name1 = format!("krf{pid}a");
        let vip1: Ipv4Addr = "100.127.1.1".parse().unwrap();
        let dev1 = match TunDevice::create(&name1) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("SKIP tun_configure_failure_rolls_back_everything: {e}");
                return;
            }
        };
        let n1 = dev1.name().to_string();
        configure(&n1, vip1, 1400).expect("first configure must succeed");
        assert!(link_exists(&n1));
        let again = configure(&n1, vip1, 1400);
        assert!(
            again.is_err(),
            "second configure must fail (address exists)"
        );
        assert!(
            !link_exists(&n1),
            "rollback must remove the interface after a step-1 failure"
        );
        drop(dev1);

        // Scenario 2: pre-install the mesh route by hand so
        // configure() passes steps 1-2 and fails at step 3 (the
        // route add reports File exists).
        let name2 = format!("krf{pid}b");
        let vip2: Ipv4Addr = "100.127.1.2".parse().unwrap();
        let dev2 = match TunDevice::create(&name2) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("SKIP rollback scenario 2: {e}");
                return;
            }
        };
        let n2 = dev2.name().to_string();
        let up = std::process::Command::new("ip")
            .args(["link", "set", &n2, "up"])
            .output()
            .expect("ip link set up");
        assert!(up.status.success(), "manual link-up must succeed");
        let pre = std::process::Command::new("ip")
            .args(["route", "add", "100.64.0.0/10", "dev", &n2])
            .output()
            .expect("ip route add");
        assert!(pre.status.success(), "manual route add must succeed");
        let again2 = configure(&n2, vip2, 1400);
        assert!(again2.is_err(), "configure must fail at the route step");
        assert!(
            !link_exists(&n2),
            "rollback must remove the interface after a step-3 failure"
        );
        drop(dev2);
    }

    #[cfg(target_os = "linux")]
    fn icmp_roundtrip(device: TunDevice, vip: Ipv4Addr) -> Result<(), String> {
        use std::io::Write as _;
        fn csum(data: &[u8]) -> u16 {
            let mut sum: u32 = 0;
            let mut i = 0;
            while i + 1 < data.len() {
                sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
                i += 2;
            }
            if i < data.len() {
                sum += (data[i] as u32) << 8;
            }
            while sum >> 16 != 0 {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            !(sum as u16)
        }
        fn build_ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, payload: &[u8]) -> Vec<u8> {
            let total = (20 + payload.len()) as u16;
            let mut h = Vec::with_capacity(20);
            h.push(0x45);
            h.push(0);
            h.extend_from_slice(&total.to_be_bytes());
            h.extend_from_slice(&1u16.to_be_bytes());
            h.extend_from_slice(&0u16.to_be_bytes());
            h.push(64);
            h.push(proto);
            h.extend_from_slice(&[0, 0]);
            h.extend_from_slice(&src);
            h.extend_from_slice(&dst);
            let c = csum(&h);
            h[10..12].copy_from_slice(&c.to_be_bytes());
            h.extend_from_slice(payload);
            h
        }
        // Reader thread: scan device packets for the kernel's reply.
        let writer = device.writer_handle();
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let reader = std::thread::spawn(move || {
            let mut buf = vec![0u8; 2048];
            for _ in 0..16 {
                match device.read_packet(&mut buf) {
                    Ok(n) => {
                        let pkt = &buf[..n];
                        // The echo reply: IPv4/ICMP, type 0, addressed
                        // back to our injected source.
                        if ipv4_dst(pkt) == Some("100.64.9.9".parse().unwrap())
                            && pkt.len() >= 28
                            && pkt[9] == 1
                            && pkt[20] == 0
                        {
                            let _ = tx.send(pkt.to_vec());
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        });
        // ICMP echo request 100.64.9.9 -> vip (proto 1, type 8),
        // written to the device exactly as the tunnel sink writes
        // decrypted payloads.
        let mut icmp = vec![8u8, 0, 0, 0, 0x12, 0x34, 0, 1];
        icmp.extend_from_slice(b"abcdefgh");
        let c = csum(&icmp);
        icmp[2..4].copy_from_slice(&c.to_be_bytes());
        let request = build_ipv4([100, 64, 9, 9], vip.octets(), 1, &icmp);
        writer
            .lock()
            .unwrap()
            .write_all(&request)
            .map_err(|e| format!("write request: {e}"))?;
        let reply = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| "no ICMP echo reply observed on the device".to_string())?;
        let _ = reader;
        if ipv4_src(&reply) != Some(vip) {
            return Err(format!("reply source is not the TUN address: {reply:?}"));
        }
        if reply.len() != request.len() {
            return Err("reply length differs from the request".to_string());
        }
        Ok(())
    }
}
