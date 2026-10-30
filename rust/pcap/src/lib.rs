//! pcap crate — Rust port of the harness's pcap forensic lane
//! (`utils/packetcraft.py`: save_pcap / load_pcap / list_pcaps / sniff_to_pcap)
//! plus the rustening centerpiece: streaming dissection + regex/substring
//! search over capture FILES (scratch's projection machinery replayed
//! frame-wise, in a noisier playground).
//!
//! Lane boundaries (deliberate):
//! - **This crate** — file codec (streaming, BE+LE), frame dissection
//!   (Ether/VLAN/ARP/IPv4/IPv6/TCP/UDP/ICMP/DNS/HTTP-shaped), projection
//!   (filter + context + paging, python-shaped text), the pcap file tools,
//!   and (behind the `capture` feature) libpcap wire capture.
//! - **scapy (python)** keeps ALL crafting / modifying / interactive
//!   dissection (`dissect_packet` shells out per-frame) and the send lane.
//!   Wire capture is libpcap (opt-in `capture` feature).
//!
//! Divergences from python, all deliberate:
//! - no service-name resolution (`/etc/services`): ports stay numeric — a
//!   capture dissection must not depend on the dissecting box's services file
//! - timestamps are UTC (python used local time)
//! - load_pcap's filter/regex/context/paging are FIRST-CLASS (python load_pcap
//!   has no filter) — new capability, same error/text shapes
//! - `grepped_surfaces` from the scratch map is dropped: selection is
//!   frame-level (any surface may hit a frame); per-frame surfaces live in
//!   the structured [`SearchOutcome`] rows instead.

mod config;
mod dissect;
mod format;
mod projection;
mod tools;

#[cfg(feature = "capture")]
mod capture;

pub use config::PcapConfig;
pub use dissect::{
    dissect_frame, dissect_frame_linktype, hex_bytes, hex_string, LINKTYPE_ETHERNET, LINKTYPE_IPV4,
    LINKTYPE_IPV6, LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2, LINKTYPE_LOOP, LINKTYPE_NULL,
    LINKTYPE_RAW,
};
pub use format::{
    count_records, dissected_frames, GlobalHeader, PcapFormatError, PcapReader, PcapWriter, Record,
};
pub use projection::{
    compile_regex, search_frames, OutcomeEntry, SearchMeta, SearchOpts, SearchOutcome,
};
pub use tools::{list_pcaps, load_pcap, pcap_search, safe_name, save_pcap};

#[cfg(feature = "capture")]
pub use capture::{sniff, CaptureError, CapturedPacket, Sniffed};
pub use tools::sniff_to_pcap;
