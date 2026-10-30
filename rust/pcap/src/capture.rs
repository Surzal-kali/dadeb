//! libpcap wire capture — the BPF lane behind the `capture` feature.
//! File analysis stays dependency-free; sniffing links real libpcap via the
//! crates.io `pcap` binding (aliased `libpcap` here to avoid the package-name
//! clash). python-parity framing lives in `tools::sniff_to_pcap`.

use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct CapturedPacket {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum CaptureError {
    Open(String),
    Filter(String),
    Recv(String),
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open(m) => write!(f, "open failed: {m}"),
            Self::Filter(m) => write!(f, "bpf filter failed: {m}"),
            Self::Recv(m) => write!(f, "receive failed: {m}"),
        }
    }
}

/// python-shaped sniff_to_pcap error text (packetcraft.py mapping:
/// PermissionError -> the root message, everything else -> generic error).
pub fn sniff_error_text(e: &CaptureError) -> String {
    let msg = match e {
        CaptureError::Open(m) | CaptureError::Filter(m) | CaptureError::Recv(m) => m,
    };
    let lower = msg.to_lowercase();
    if matches!(e, CaptureError::Open(_))
        && (lower.contains("permission")
            || lower.contains("operation not permitted")
            || lower.contains("not privileged")
            || lower.contains("cap_net_raw"))
    {
        format!("sniff_to_pcap requires root/raw-socket capability: {msg}.")
    } else {
        format!("sniff_to_pcap error: {msg}")
    }
}

/// Capture up to `count` packets matching `bpf` on `interface`, stopping at
/// `timeout` overall. Empty BPF = no filter.
pub fn sniff(
    interface: &str,
    bpf: &str,
    count: usize,
    timeout: Duration,
) -> Result<Vec<CapturedPacket>, CaptureError> {
    let mut cap = libpcap::Capture::from_device(interface)
        .map_err(|e| CaptureError::Open(e.to_string()))?
        .promisc(true)
        .snaplen(262_144)
        .timeout(500) // ms — pcap binding takes i32, not a Duration
        .open()
        .map_err(|e| CaptureError::Open(e.to_string()))?;
    if !bpf.trim().is_empty() {
        cap.filter(bpf, true)
            .map_err(|e| CaptureError::Filter(e.to_string()))?;
    }

    let deadline = Instant::now() + timeout;
    let mut out = Vec::new();
    while out.len() < count {
        if Instant::now() >= deadline {
            break;
        }
        match cap.next_packet() {
            Ok(pkt) => {
                let ts = &pkt.header.ts;
                out.push(CapturedPacket {
                    ts_sec: ts.tv_sec as u32,
                    ts_usec: ts.tv_usec as u32,
                    data: pkt.data.to_vec(),
                });
            }
            Err(libpcap::Error::TimeoutExpired) => {} // read-timeout slice; deadline check next loop
            Err(e) => return Err(CaptureError::Recv(e.to_string())),
        }
    }
    Ok(out)
}

#[cfg(all(test, feature = "capture"))]
mod tests {
    use super::*;

    #[test]
    fn bogus_device_errors() {
        // a nonsense device name must surface as an Open error with text,
        // never panic — the honest shape sniff_to_pcap renders.
        let err = sniff("definitely-not-an-iface-0000", "tcp", 1, Duration::from_secs(2)).unwrap_err();
        let text = sniff_error_text(&err);
        assert!(
            text.starts_with("sniff_to_pcap error:") || text.starts_with("sniff_to_pcap requires"),
            "{text}"
        );
        assert!(text.contains(':'), "{text}");
    }

    #[test]
    fn permission_style_message_maps_to_root_hint() {
        let e = CaptureError::Open("socket: Operation not permitted".to_string());
        assert_eq!(
            sniff_error_text(&e),
            "sniff_to_pcap requires root/raw-socket capability: socket: Operation not permitted."
        );
    }

    #[test]
    fn bad_bpf_errors() {
        let err = sniff("lo", "tcp port ((", 1, Duration::from_secs(2)).unwrap_err();
        if cap_net_raw() {
            // raw capability present: open succeeds, BPF compile is the failure
            assert!(matches!(err, CaptureError::Filter(_)), "{err}");
        } else {
            // no raw capability: packet-socket creation fails BEFORE the BPF
            // compiles — the honest shape is the root-capability open error.
            assert!(matches!(err, CaptureError::Open(_)), "{err}");
            assert!(sniff_error_text(&err).contains("requires root"), "{err}");
        }
    }

    /// CAP_NET_RAW (cap 13) probe off /proc/self/status — test-environment
    /// gate only; live capture paths report the real libpcap error text.
    fn cap_net_raw() -> bool {
        (|| -> std::io::Result<bool> {
            let status = std::fs::read_to_string("/proc/self/status")?;
            let eff = status
                .lines()
                .find_map(|l| l.strip_prefix("CapEff:"))
                .unwrap_or("0");
            let mask = u64::from_str_radix(eff.trim(), 16).unwrap_or(0);
            Ok(mask & (1 << 13) != 0)
        })()
        .unwrap_or(false)
    }

    // Real-wire test — needs root + a live interface; run by hand:
    //   cargo test -p pcap --features capture live_loopback -- --ignored
    #[test]
    #[ignore]
    fn live_loopback_capture() {
        let pkts = sniff("lo", "icmp", 2, Duration::from_secs(10)).expect("capture");
        assert_eq!(pkts.len(), 2);
    }
}