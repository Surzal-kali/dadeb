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

/// A finished capture: the frames plus the interface's datalink type, which
/// the pcap writer must stamp into the file header (an `any` sniff is
/// LINUX_SLL, not Ethernet).
#[derive(Debug, Clone)]
pub struct Sniffed {
    pub linktype: u32,
    pub packets: Vec<CapturedPacket>,
}

/// Write captured packets to a new pcap file, preserving each packet's own
/// capture timestamp. `PcapWriter::write_record` stamps whatever clock value
/// its caller passes, which is right for synthetic packets (save_pcap stamps
/// `now`) — live captures must keep the kernel-provided ts, serializing
/// every frame at the same wall-clock moment loses ordering evidence.
#[cfg(feature = "capture")]
pub fn write_capture_records(
    path: &std::path::Path,
    linktype: u32,
    packets: &[CapturedPacket],
) -> std::io::Result<usize> {
    let mut w = crate::format::PcapWriter::create_with_linktype(path, linktype)?;
    for p in packets {
        w.write_record(p.ts_sec, p.ts_usec, &p.data)?;
    }
    w.flush()?;
    let count = w.count();
    drop(w);
    Ok(count)
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

/// Idle back-off between empty non-blocking reads. Bounds deadline overshoot
/// and costs nothing in loss: the kernel ring keeps buffering meanwhile.
const IDLE_POLL: Duration = Duration::from_millis(10);

/// Capture up to `count` packets matching `bpf` on `interface`, stopping at
/// `timeout` overall. Empty BPF = no filter.
///
/// The deadline is HARD: the handle is non-blocking and the loop checks the
/// clock between reads. (A blocking `next_packet` is only woken by packets or
/// the read timeout, and with a BPF filter that drops everything the read
/// timeout is not reliably delivered — a quiet filter could pin the agent's
/// tool call far past `timeout`.)
pub fn sniff(
    interface: &str,
    bpf: &str,
    count: usize,
    timeout: Duration,
) -> Result<Sniffed, CaptureError> {
    let mut cap = libpcap::Capture::from_device(interface)
        .map_err(|e| CaptureError::Open(e.to_string()))?
        .promisc(true)
        .snaplen(262_144)
        .immediate_mode(true) // deliver per-packet, not per ring block
        .timeout(500) // ms — pcap binding takes i32, not a Duration
        .open()
        .map_err(|e| CaptureError::Open(e.to_string()))?
        .setnonblock()
        .map_err(|e| CaptureError::Open(e.to_string()))?;
    if !bpf.trim().is_empty() {
        cap.filter(bpf, true)
            .map_err(|e| CaptureError::Filter(e.to_string()))?;
    }

    let linktype = cap.get_datalink().0 as u32;
    let deadline = Instant::now() + timeout;
    let mut out = Vec::new();
    while out.len() < count {
        let now = Instant::now();
        if now >= deadline {
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
            // non-blocking: nothing buffered right now
            Err(libpcap::Error::TimeoutExpired) => {
                std::thread::sleep(IDLE_POLL.min(deadline - now));
            }
            Err(e) => return Err(CaptureError::Recv(e.to_string())),
        }
    }
    Ok(Sniffed {
        linktype,
        packets: out,
    })
}

#[cfg(all(test, feature = "capture"))]
mod tests {
    use super::*;

    #[test]
    fn write_capture_records_keeps_each_packet_ts() {
        // sniff_to_pcap used to stamp every record with wall-clock `now`,
        // throwing away kernel-provided per-packet timestamps.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ts.pcap");
        let packets = vec![
            CapturedPacket { ts_sec: 1_700_000_000, ts_usec: 111, data: vec![0x01, 0x02] },
            CapturedPacket { ts_sec: 1_700_000_005, ts_usec: 999_999, data: vec![0x33] },
        ];
        let n = write_capture_records(&path, 1, &packets).unwrap();
        assert_eq!(n, 2);
        let mut r = crate::format::PcapReader::open(&path).unwrap();
        let a = r.next_record().unwrap().unwrap();
        assert_eq!((a.ts_sec, a.ts_usec), (1_700_000_000, 111));
        let b = r.next_record().unwrap().unwrap();
        assert_eq!((b.ts_sec, b.ts_usec), (1_700_000_005, 999_999));
        assert!(r.next_record().unwrap().is_none());
    }

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

    // Real-wire tests — need root (CAP_NET_RAW) + a live interface; run by
    // hand:  cargo test -p pcap --features capture -- --ignored

    #[test]
    #[ignore]
    fn deadline_is_hard_when_filter_matches_nothing() {
        // Regression: a blocking read with a never-matching filter overran a
        // 3 s timeout indefinitely.
        let t = Instant::now();
        let got = sniff("lo", "udp port 1", 5, Duration::from_secs(2)).expect("capture");
        assert!(got.packets.is_empty());
        assert!(t.elapsed() < Duration::from_secs(3), "overran: {:?}", t.elapsed());
    }

    // Real-wire test — needs root + a live interface; run by hand:
    //   cargo test -p pcap --features capture live_loopback -- --ignored
    #[test]
    #[ignore]
    fn live_loopback_capture() {
        let got = sniff("lo", "icmp", 2, Duration::from_secs(10)).expect("capture");
        assert_eq!(got.packets.len(), 2);
        assert_eq!(got.linktype, crate::dissect::LINKTYPE_ETHERNET); // Linux lo is DLT_EN10MB
    }
}