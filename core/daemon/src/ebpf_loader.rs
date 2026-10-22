//! eBPF/XDP capability probe with a userspace data plane.
//!
//! On Linux the loader probes the environment (kernel, BPF filesystem,
//! privileges), validates a supplied eBPF object (ELF header + e_machine
//! == EM_BPF), and attempts a real `bpf()` syscall program load of a
//! minimal XDP program. The probe answers one question — *could* this
//! host run an XDP fast path — and reports exactly what it found. In
//! this release all packet processing runs in the userspace UDP data
//! plane regardless of the probe verdict; a kernel fast path is roadmap
//! work, and the status reporting says so (mode stays
//! UserspaceFallback, `enabled` stays false).
//!
//! Telemetry counters and the event ring buffer live here and are shared
//! with the tunnel.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

#[derive(Debug, Default)]
pub struct TelemetryCounters {
    pub packets_in: AtomicU64,
    pub packets_out: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub drops: AtomicU64,
    pub fastpath_hits: AtomicU64,
    pub userspace_packets: AtomicU64,
    pub handshakes_completed: AtomicU64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TelemetrySnapshot {
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub drops: u64,
    pub fastpath_hits: u64,
    pub userspace_packets: u64,
    pub handshakes_completed: u64,
}

impl TelemetryCounters {
    pub fn snapshot(&self) -> TelemetrySnapshot {
        TelemetrySnapshot {
            packets_in: self.packets_in.load(Ordering::Relaxed),
            packets_out: self.packets_out.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
            drops: self.drops.load(Ordering::Relaxed),
            fastpath_hits: self.fastpath_hits.load(Ordering::Relaxed),
            userspace_packets: self.userspace_packets.load(Ordering::Relaxed),
            handshakes_completed: self.handshakes_completed.load(Ordering::Relaxed),
        }
    }
}

/// Bounded event log for loader/tunnel events (the "ring buffer" that a
/// future eBPF perf-event consumer would feed; today the userspace data
/// plane writes mode transitions and handshake events here).
pub struct EventRing {
    capacity: usize,
    events: Mutex<VecDeque<(Instant, String)>>,
}

impl EventRing {
    pub fn new(capacity: usize) -> Self {
        Self { capacity, events: Mutex::new(VecDeque::with_capacity(capacity)) }
    }

    pub fn push(&self, event: impl Into<String>) {
        let mut guard = self.events.lock().unwrap();
        if guard.len() == self.capacity {
            guard.pop_front();
        }
        guard.push_back((Instant::now(), event.into()));
    }

    pub fn recent(&self, n: usize) -> Vec<String> {
        let guard = self.events.lock().unwrap();
        guard.iter().rev().take(n).map(|(_, s)| s.clone()).collect()
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataPlaneMode {
    /// Kernel XDP fast path. Reserved for the roadmap fast path; never
    /// constructed in this release (the probe confirms capability only).
    FastPath,
    /// All packets processed by the userspace data plane.
    UserspaceFallback,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct EbpfStatus {
    pub mode: DataPlaneMode,
    pub enabled: bool,
    pub reason: String,
    pub kernel: String,
    pub object_path: Option<String>,
    pub object_validated: bool,
}

fn kernel_version() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(text) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
            return text.trim().to_string();
        }
    }
    "unknown".to_string()
}

/// Validates that a file is a plausible eBPF ELF object (magic + class +
/// e_machine == EM_BPF (247)). Returns Ok(()) or a human-readable reason.
pub fn validate_ebpf_object(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() < 20 {
        return Err("object too small to be an ELF file".to_string());
    }
    if &bytes[0..4] != b"\x7fELF" {
        return Err("object is not an ELF file".to_string());
    }
    // e_machine: little-endian u16 at offset 18 (eBPF objects are LE).
    let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
    if machine != 247 {
        return Err(format!("ELF e_machine is {machine}, expected 247 (EM_BPF)"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux_bpf {
    use std::ffi::CString;

    pub const SYS_BPF: i64 = 321; // x86_64
    pub const BPF_PROG_LOAD: u32 = 5;
    pub const BPF_PROG_TYPE_XDP: u32 = 6;

    extern "C" {
        fn syscall(num: i64, ...) -> i64;
    }

    /// A minimal, valid XDP program: return XDP_PASS (2) for every packet.
    /// Insn encoding (8 bytes each): MOV64_IMM r0, 2 ; EXIT.
    pub const XDP_PASS_PROG: [[u8; 8]; 2] = [
        [0xb7, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00],
        [0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    ];

    #[repr(C)]
    struct BpfAttrProgLoad {
        prog_type: u32,
        insn_cnt: u32,
        insns: u64,
        license: u64,
        log_level: u32,
        log_size: u32,
        log_buf: u64,
        kern_version: u32,
        prog_flags: u32,
        prog_name: [u8; 16],
        prog_ifindex: u32,
        expected_attach_type: u32,
        _pad: [u8; 64],
    }

    impl Default for BpfAttrProgLoad {
        fn default() -> Self {
            // All fields are integers or byte arrays; zeroed is valid.
            unsafe { std::mem::zeroed() }
        }
    }

    /// Attempts to load the XDP_PASS program into the kernel. On success
    /// returns the program fd (caller closes it); on failure returns the
    /// errno so the caller can explain the fallback.
    pub fn try_load_xdp_probe() -> Result<i32, i32> {
        let license = CString::new("MIT").unwrap();
        let mut name = [0u8; 16];
        name[..9].copy_from_slice(b"kronoswd\0");
        let attr = BpfAttrProgLoad {
            prog_type: BPF_PROG_TYPE_XDP,
            insn_cnt: XDP_PASS_PROG.len() as u32,
            insns: XDP_PASS_PROG.as_ptr() as u64,
            license: license.as_ptr() as u64,
            prog_name: name,
            ..Default::default()
        };
        let fd = unsafe {
            syscall(
                SYS_BPF,
                BPF_PROG_LOAD,
                &attr as *const BpfAttrProgLoad as u64,
                std::mem::size_of::<BpfAttrProgLoad>() as u32,
            )
        };
        if fd >= 0 {
            Ok(fd as i32)
        } else {
            Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1))
        }
    }

    pub fn close_fd(fd: i32) {
        unsafe {
            libc_close(fd);
        }
    }

    extern "C" {
        #[link_name = "close"]
        fn libc_close(fd: i32) -> i32;
    }
}

pub struct EbpfLoader;

impl EbpfLoader {
    /// Probes the environment and decides the data-plane mode. Never
    /// panics; every failure path lands in UserspaceFallback with a
    /// concrete reason.
    pub fn probe(object_path: Option<&str>, ring: &EventRing) -> EbpfStatus {
        let kernel = kernel_version();
        #[cfg(target_os = "linux")]
        {
            let mut object_validated = false;
            if let Some(path) = object_path {
                match std::fs::read(path) {
                    Ok(bytes) => match validate_ebpf_object(&bytes) {
                        Ok(()) => object_validated = true,
                        Err(why) => {
                            let reason = format!("eBPF object {path} rejected: {why}");
                            ring.push(reason.clone());
                            return EbpfStatus {
                                mode: DataPlaneMode::UserspaceFallback,
                                enabled: false,
                                reason,
                                kernel,
                                object_path: Some(path.to_string()),
                                object_validated: false,
                            };
                        }
                    },
                    Err(e) => {
                        let reason = format!("eBPF object {path} unreadable: {e}");
                        ring.push(reason.clone());
                        return EbpfStatus {
                            mode: DataPlaneMode::UserspaceFallback,
                            enabled: false,
                            reason,
                            kernel,
                            object_path: Some(path.to_string()),
                            object_validated: false,
                        };
                    }
                }
            }
            match linux_bpf::try_load_xdp_probe() {
                Ok(fd) => {
                    linux_bpf::close_fd(fd);
                    // The probe program is closed immediately and never
                    // attached: capability is confirmed, but this release
                    // filters nothing in the kernel. Report exactly that -
                    // an earlier version claimed "fast-path filtering
                    // active" here, which was not true.
                    let reason = "kernel accepted the XDP probe program \
                                  (capability confirmed); data plane is \
                                  userspace in this release - kernel fast \
                                  path is roadmap"
                        .to_string();
                    ring.push(
                        "ebpf: probe ok (capability confirmed); userspace data plane"
                            .to_string(),
                    );
                    EbpfStatus {
                        mode: DataPlaneMode::UserspaceFallback,
                        enabled: false,
                        reason,
                        kernel,
                        object_path: object_path.map(|s| s.to_string()),
                        object_validated,
                    }
                }
                Err(errno) => {
                    let reason = format!(
                        "XDP probe load failed (errno {errno}); running the \
                         userspace data plane — typical in containers without \
                         CAP_BPF/CAP_NET_ADMIN"
                    );
                    ring.push(format!("ebpf: fallback engaged ({reason})"));
                    EbpfStatus {
                        mode: DataPlaneMode::UserspaceFallback,
                        enabled: false,
                        reason,
                        kernel,
                        object_path: object_path.map(|s| s.to_string()),
                        object_validated,
                    }
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let reason = "eBPF/XDP is Linux-only; userspace data plane active"
                .to_string();
            ring.push("ebpf: non-Linux platform, userspace mode".to_string());
            EbpfStatus {
                mode: DataPlaneMode::UserspaceFallback,
                enabled: false,
                reason,
                kernel,
                object_path: object_path.map(|s| s.to_string()),
                object_validated: false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_validation_accepts_ebpf_elf_and_rejects_others() {
        let mut elf = vec![0u8; 64];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[18] = 247;
        elf[19] = 0;
        assert!(validate_ebpf_object(&elf).is_ok());
        assert!(validate_ebpf_object(b"not an elf at all, padded to length").is_err());
        let mut wrong_machine = elf.clone();
        wrong_machine[18] = 62; // EM_X86_64
        assert!(validate_ebpf_object(&wrong_machine).is_err());
        assert!(validate_ebpf_object(&[1, 2, 3]).is_err());
    }

    #[test]
    fn probe_never_panics_and_reports_a_mode() {
        let ring = EventRing::new(16);
        let status = EbpfLoader::probe(None, &ring);
        assert!(!status.reason.is_empty());
        assert!(!status.kernel.is_empty());
    }

    #[test]
    fn ring_buffer_is_bounded() {
        let ring = EventRing::new(4);
        for i in 0..10 {
            ring.push(format!("event {i}"));
        }
        let recent = ring.recent(10);
        assert_eq!(recent.len(), 4);
        assert_eq!(recent[0], "event 9");
    }

    #[test]
    fn telemetry_snapshot_counts() {
        let t = TelemetryCounters::default();
        t.packets_in.fetch_add(5, Ordering::Relaxed);
        t.bytes_in.fetch_add(500, Ordering::Relaxed);
        let snap = t.snapshot();
        assert_eq!(snap.packets_in, 5);
        assert_eq!(snap.bytes_in, 500);
    }
}
