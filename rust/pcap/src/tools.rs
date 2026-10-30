//! The python-parity text tools: save_pcap / load_pcap (+ filter extension) /
//! list_pcaps / sniff_to_pcap. Error strings ride INSIDE the returned text
//! exactly like `utils/packetcraft.py` (its try/except blocks return
//! `"save_pcap error: {e}"`-shaped strings, not raised exceptions).
//!
//! sniff_to_pcap is the python-shaped wrapper over `capture::sniff` (feature
//! `capture`); non-capture builds return the stubbed honest error.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::dissect::{dissect_frame_linktype, hex_string};
use crate::format::{PcapReader, PcapWriter};
use crate::projection::{no_match_note, search_frames, SearchOpts, SearchOutcome};
use crate::PcapConfig;

// ---------- tiny UTC civil-date math (no chrono; UTC-vs-local divergence) ----------

/// Howard Hinnant's civil_from_days: days since 1970-01-01 -> (y, m, d).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn epoch_parts(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, mo, d) = civil_from_days(days);
    (
        y,
        mo,
        d,
        (rem / 3600) as u32,
        ((rem % 3600) / 60) as u32,
        (rem % 60) as u32,
    )
}

fn now_epoch_us() -> (i64, u32) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    (now.as_secs() as i64, now.subsec_micros())
}

fn stamp_compact() -> String {
    let (s, _) = now_epoch_us();
    let (y, mo, d, h, mi, sec) = epoch_parts(s);
    format!("cap_{y:04}{mo:02}{d:02}_{h:02}{mi:02}{sec:02}.pcap")
}

fn stamp_display(secs: i64) -> String {
    let (y, mo, d, h, mi, s) = epoch_parts(secs);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}")
}

fn size_str(size: u64) -> String {
    if size < 1024 {
        format!("{size} B")
    } else if size < 1024 * 1024 {
        format!("{:.1} KiB", size as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", size as f64 / 1024.0 / 1024.0)
    }
}

fn abs_display(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

// ---------- name + path resolution ----------

/// `_safe_pcap_name`: basename only, `.pcap` appended when missing, empty
/// rejected (`filename is empty after sanitizing`).
pub fn safe_name(filename: &str) -> Result<String, String> {
    // python parity: os.path.basename() on a trailing-slash path is EMPTY
    // ("a/b/" -> "") — rejected, not trimmed.
    let trimmed = filename.trim();
    let name = trimmed.rsplit(['/', '\\']).next().unwrap_or("");
    if name.is_empty() {
        return Err("filename is empty after sanitizing".to_string());
    }
    if !name.to_lowercase().ends_with(".pcap") {
        return Ok(format!("{name}.pcap"));
    }
    Ok(name.to_string())
}

fn resolve_path(filename: &str, cfg: &PcapConfig) -> PathBuf {
    if filename.contains('/') || filename.contains('\\') {
        PathBuf::from(filename)
    } else {
        cfg.dir.join(filename)
    }
}

// ---------- save_pcap ----------

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    crate::dissect::hex_bytes(hex)
}

pub fn save_pcap(hexes: &[String], filename: &str, cfg: &PcapConfig) -> String {
    if hexes.is_empty() {
        return "save_pcap: no packets to save (hexes list is empty).".to_string();
    }
    let error = |e: String| format!("save_pcap error: {e}");
    let out = (|| -> Result<String, String> {
        std::fs::create_dir_all(&cfg.dir).map_err(|e| e.to_string())?;
        let name = if filename.trim().is_empty() {
            stamp_compact()
        } else {
            safe_name(filename)?
        };
        let out_path = cfg.dir.join(&name);

        let mut packets = Vec::with_capacity(hexes.len());
        for (i, h) in hexes.iter().enumerate() {
            let bytes =
                hex_to_bytes(h).map_err(|e| format!("packet {}: {e}", i + 1))?;
            if bytes.is_empty() {
                return Err(format!("packet {}: empty packet", i + 1));
            }
            packets.push(bytes);
        }

        let (ts, us) = now_epoch_us();
        let mut w = PcapWriter::create(&out_path).map_err(|e| e.to_string())?;
        for p in &packets {
            w.write_record(ts as u32, us, p).map_err(|e| e.to_string())?;
        }
        w.flush().map_err(|e| e.to_string())?;
        std::mem::drop(w);

        let file_bytes = std::fs::read(&out_path).map_err(|e| e.to_string())?;
        let sha = Sha256::digest(&file_bytes);
        Ok(format!(
            "Saved {} packet(s) to {}\n  size: {} bytes\n  sha256: {:x}\n  packets: {}\nUse load_pcap('{}') to read them back, or dissect_packet on any packet's hex for a full breakdown.",
            packets.len(),
            abs_display(&out_path).display(),
            file_bytes.len(),
            sha,
            packets.len(),
            name,
        ))
    })();
    out.unwrap_or_else(error)
}

// ---------- load_pcap ----------

/// Unfiltered python-parity page: stream to `[offset, offset+limit)`, render
/// the exact load_pcap text shape (en dash included).
fn load_pcap_plain(fpath: &Path, file_size: u64, offset: usize, limit: usize) -> Result<String, String> {
    let name = fpath.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let mut reader = PcapReader::open(fpath).map_err(|e| format!("load_pcap error: {e}"))?;
    let linktype = reader.header().network;
    let mut total = 0usize;
    let mut skipped = 0usize;
    let mut page: Vec<(String, String)> = Vec::new();
    loop {
        let rec = reader.next_record().map_err(|e| format!("load_pcap error: {e}"))?;
        let Some(rec) = rec else { break };
        if total >= offset && skipped < limit {
            let view = dissect_frame_linktype(&rec.data, linktype);
            page.push((view.summary, hex_string(&rec.data)));
            skipped += 1;
        }
        total += 1;
    }

    if total == 0 {
        // python parity: `if total == 0: return f"No packets in {fpath}."` —
        // a header-only capture (tcpdump that caught nothing) is routine.
        return Ok(format!("No packets in {}.", abs_display(fpath).display()));
    }
    // python renders `off + len(page) - 1`, which for an empty page past the
    // end is `offset - 1` (offset > 0 here since total > 0 and page empty
    // implies offset >= total); computed without usize underflow.
    let last = (offset + page.len()).saturating_sub(1);
    let mut lines = vec![
        format!(
            "Loaded {total} packet(s) from {name} (showing {offset}–{last} of {total}):"
        ),
        format!("  size: {file_size} bytes"),
        String::new(),
    ];
    for (i, (summary, hex)) in page.iter().enumerate() {
        lines.push(format!("  [{}] {summary}  hex={hex}", offset + i + 1));
    }
    if offset + page.len() < total {
        let next_off = offset + page.len();
        lines.push(format!(
            "\n  ... {} more — load_pcap('{}', offset={next_off}, limit={limit}) for the next page.",
            total - next_off,
            name
        ));
    } else {
        lines.push(format!("\n  End of capture ({total} packets total)."));
    }
    lines.push("Use dissect_packet with any hex above for a full field breakdown.".to_string());
    Ok(lines.join("\n"))
}

/// Filtered page from the search pipeline (context/paging aware).
fn load_pcap_filtered(
    fpath: &Path,
    file_size: u64,
    opts: &SearchOpts,
    outcome: &SearchOutcome,
) -> Result<String, String> {
    if outcome.entries.is_empty() {
        return Ok(no_match_note(opts));
    }
    let name = fpath.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let displayed = outcome.entries.len();
    let mut lines = vec![
        format!(
            "Loaded {} matched packet(s) from {name} (filtered from {}):",
            outcome.meta.matches, outcome.meta.total
        ),
        format!("  size: {file_size} bytes"),
        String::new(),
    ];
    for entry in &outcome.entries {
        match entry {
            crate::projection::OutcomeEntry::Frame { index, summary, hex, .. } => {
                lines.push(format!("  [{}] {summary}  hex={hex}", index + 1));
            }
            crate::projection::OutcomeEntry::Gap => lines.push("  ...".to_string()),
        }
    }
    let consumed = opts.offset + displayed;
    if outcome.meta.paged && consumed < outcome.meta.expanded {
        let next_off = consumed;
        let pattern = opts
            .filter
            .clone()
            .or_else(|| opts.regex.clone())
            .map(|p| format!("'{p}'"))
            .unwrap_or_default();
        let filter_arg = if opts.filter.is_some() {
            format!("filter={pattern}, ")
        } else if opts.regex.is_some() {
            format!("regex={pattern}, ")
        } else {
            String::new()
        };
        lines.push(format!(
            "\n  ... {} more — load_pcap('{}', {filter_arg}offset={next_off}, limit={}) for the next page.",
            outcome.meta.expanded - next_off,
            name,
            opts.limit
        ));
    } else {
        lines.push(format!(
            "\n  End of matches ({} matched of {} packets total).",
            outcome.meta.matches, outcome.meta.total
        ));
    }
    lines.push("Use dissect_packet with any hex above for a full field breakdown.".to_string());
    Ok(lines.join("\n"))
}

/// load_pcap with the filter/regex/context extension as first-class args
/// (python load_pcap has no filter — this is the new capability, same error
/// surface). Errors return INSIDE the text like the python tool.
///
/// Python parity: `limit=50` default and `lim = max(1, int(limit))` — a text
/// lane with unlimited output hexes every frame straight into model context,
/// so 0 remaps to the 50-frame default and any explicit limit has a 1 floor.
pub fn load_pcap(
    filename: &str,
    offset: usize,
    limit: usize,
    filter: Option<&str>,
    regex: Option<&str>,
    context_frames: usize,
    cfg: &PcapConfig,
) -> String {
    let fpath = resolve_path(filename, cfg);
    if !fpath.exists() {
        return format!("load_pcap: file not found: {}", abs_display(&fpath).display());
    }
    let file_size = match fpath.metadata() {
        Ok(m) => m.len(),
        Err(e) => return format!("load_pcap error: {e}"),
    };
    if file_size > (cfg.max_file_mb as u64) * 1024 * 1024 {
        return format!(
            "load_pcap: {} is {:.1} MiB (cap is {} MiB). Use tcpdump/tshark directly or raise PCAP_MAX_FILE_MB.",
            fpath.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
            file_size as f64 / 1024.0 / 1024.0,
            cfg.max_file_mb
        );
    }

    let limit = if limit == 0 { 50 } else { limit };
    let opts = SearchOpts {
        filter: filter.map(|s| s.to_string()),
        regex: regex.map(|s| s.to_string()),
        context_frames,
        offset,
        limit,
    };
    if filter.is_none() && regex.is_none() {
        // pure paging lane: python-parity windowed walk, no search machinery
        return match load_pcap_plain(&fpath, file_size, offset, limit) {
            Ok(s) => s,
            Err(e) => e,
        };
    }
    match search_frames(&fpath, &opts)
        .map_err(|e| format!("load_pcap error: {e}"))
        .and_then(|o| load_pcap_filtered(&fpath, file_size, &opts, &o))
    {
        Ok(s) => s,
        Err(e) => e,
    }
}

/// Structured search lane: same resolution as load_pcap, returns the
/// SearchOutcome (JSON-friendly) instead of text.
pub fn pcap_search(
    filename: &str,
    opts: &SearchOpts,
    cfg: &PcapConfig,
) -> Result<SearchOutcome, String> {
    let fpath = resolve_path(filename, cfg);
    search_frames(&fpath, opts)
}

// ---------- list_pcaps ----------

pub fn list_pcaps(cfg: &PcapConfig) -> String {
    if let Err(e) = std::fs::create_dir_all(&cfg.dir) {
        return format!("list_pcaps error: {e}");
    }
    let mut files: Vec<(PathBuf, std::fs::Metadata)> = match std::fs::read_dir(&cfg.dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path().is_file()
                    && e.path()
                        .extension()
                        .map(|x| x.to_string_lossy().to_lowercase() == "pcap")
                        .unwrap_or(false)
            })
            .filter_map(|e| {
                let md = e.metadata().ok()?;
                Some((e.path(), md))
            })
            .collect(),
        Err(e) => return format!("list_pcaps error: {e}"),
    };
    files.sort_by_key(|(_, md)| std::cmp::Reverse(md.modified().ok()));

    if files.is_empty() {
        return format!(
            "No pcap files in {}. Use sniff_to_pcap or save_pcap to create one.",
            abs_display(&cfg.dir).display()
        );
    }

    let mut lines = vec![
        format!(
            "Pcap captures in {} ({} file(s)):",
            abs_display(&cfg.dir).display(),
            files.len()
        ),
        String::new(),
    ];
    for (p, md) in &files {
        let count = crate::format::count_records(p)
            .map(|c| c.to_string())
            .unwrap_or_else(|_| "?".to_string());
        let mtime = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| stamp_display(d.as_secs() as i64))
            .unwrap_or_else(|| "              ".to_string());
        lines.push(format!(
            "  {}  {}  {} pkts  {}",
            p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
            size_str(md.len()),
            count,
            mtime
        ));
    }
    lines.push(
        "\nUse load_pcap('<name>.pcap') to page through packets, or dissect_packet on any hex for a full breakdown.".to_string(),
    );
    lines.join("\n")
}

// ---------- sniff_to_pcap ----------

#[cfg(feature = "capture")]
pub fn sniff_to_pcap(
    filter: &str,
    count: usize,
    timeout_secs: u64,
    interface: &str,
    filename: &str,
    cfg: &PcapConfig,
) -> String {
    let iface = if interface.trim().is_empty() {
        cfg.default_interface.clone()
    } else {
        interface.to_string()
    };
    let cap_count = count.min(cfg.max_packets_per_file);

    let crate::capture::Sniffed { linktype, packets } = match crate::capture::sniff(
        &iface,
        filter,
        cap_count,
        std::time::Duration::from_secs(timeout_secs.max(1)),
    ) {
        Ok(p) => p,
        Err(e) => return crate::capture::sniff_error_text(&e),
    };
    if packets.is_empty() {
        return format!(
            "No packets captured on {iface} (filter='{filter}'). No pcap file written."
        );
    }

    if let Err(e) = std::fs::create_dir_all(&cfg.dir) {
        return format!("sniff_to_pcap error: {e}");
    }
    let name = if filename.trim().is_empty() {
        stamp_compact()
    } else {
        match safe_name(filename) {
            Ok(n) => n,
            Err(e) => return format!("sniff_to_pcap error: {e}"),
        }
    };
    let out_path = cfg.dir.join(&name);

    let write = (|| -> std::io::Result<String> {
        crate::capture::write_capture_records(&out_path, linktype, &packets)?;
        let file_bytes = std::fs::read(&out_path)?;
        let sha = Sha256::digest(&file_bytes);
        let mut lines = vec![
            format!(
                "Captured and saved {} packet(s) to {}",
                packets.len(),
                abs_display(&out_path).display()
            ),
            format!("  interface: {iface}"),
            format!("  filter: '{filter}'"),
            format!("  size: {} bytes", file_bytes.len()),
            format!("  sha256: {sha:x}"),
            format!("  packets: {}", packets.len()),
            String::new(),
            format!(
                "Packet summaries (first {}):",
                packets.len().min(20)
            ),
        ];
        for (i, p) in packets.iter().enumerate().take(20) {
            let view = dissect_frame_linktype(&p.data, linktype);
            lines.push(format!("  [{}] {}  hex={}", i + 1, view.summary, hex_string(&p.data)));
        }
        if packets.len() > 20 {
            lines.push(format!(
                "  ... ({} more — use load_pcap to page through)",
                packets.len() - 20
            ));
        }
        lines.push(format!(
            "\nUse load_pcap('{name}') to page through all packets, or dissect_packet on any hex for a full breakdown."
        ));
        Ok(lines.join("\n"))
    })();
    match write {
        Ok(s) => s,
        Err(e) => format!("sniff_to_pcap error: {e}"),
    }
}

#[cfg(not(feature = "capture"))]
pub fn sniff_to_pcap(
    _filter: &str,
    _count: usize,
    _timeout_secs: u64,
    _interface: &str,
    _filename: &str,
    _cfg: &PcapConfig,
) -> String {
    "sniff_to_pcap requires the 'capture' crate feature (libpcap). \
     Rebuild with --features capture."
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(dir: &Path) -> PcapConfig {
        PcapConfig::with_dir(dir)
    }

    fn frame(tag: &[u8]) -> String {
        let mut f = vec![0u8; 14];
        f[12..14].copy_from_slice(&0x9999u16.to_be_bytes());
        f.extend_from_slice(tag);
        hex_string(&f)
    }

    #[test]
    fn load_pcap_limit_zero_means_default_50_not_unlimited() {
        // Python parity: `limit=50` default and `lim = max(1, int(limit))`.
        // A text lane that treats 0 as unlimited hexes every frame of a big
        // capture straight into model context.
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path());
        let hexes: Vec<String> = (0..60).map(|i| frame(&[i as u8])).collect();
        let out = save_pcap(&hexes, "big.pcap", &c);
        assert!(out.contains("Saved 60 packet(s)"), "{out}");

        let loaded = load_pcap("big.pcap", 0, 0, None, None, 0, &c);
        assert!(loaded.contains("[50]"), "frame 50 must be the page end: {loaded}");
        assert!(!loaded.contains("[51]"), "frame 51 must NOT be shown: {loaded}");
        assert!(
            loaded.contains("offset=50, limit=50"),
            "next-page hint must point at the following page: {loaded}"
        );

        // explicit limit keeps its value (page of 3, hint carries limit=3)
        let p3 = load_pcap("big.pcap", 0, 3, None, None, 0, &c);
        assert!(p3.contains("[3]"), "{p3}");
        assert!(!p3.contains("[4]"), "{p3}");
        assert!(p3.contains("offset=3, limit=3"), "{p3}");
    }

    #[test]
    fn safe_name_rules() {
        assert_eq!(safe_name("cap.pcap"), Ok("cap.pcap".to_string()));
        assert_eq!(safe_name("cap"), Ok("cap.pcap".to_string()));
        assert_eq!(safe_name("CAP.PCAP"), Ok("CAP.PCAP".to_string()));
        assert_eq!(safe_name("a/b/c"), Ok("c.pcap".to_string()));
        assert_eq!(safe_name("a/b/"), Err("filename is empty after sanitizing".to_string()));
        assert_eq!(safe_name("  "), Err("filename is empty after sanitizing".to_string()));
        assert_eq!(safe_name("a\\b\\win"), Ok("win.pcap".to_string()));
    }

    #[test]
    fn save_and_load_roundtrip_text_shapes() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path());
        let out = save_pcap(&[frame(b"one"), frame(b"two")], "t.pcap", &c);
        assert!(out.starts_with("Saved 2 packet(s) to "), "{out}");
        assert!(out.contains("\n  size: "), "{out}");
        assert!(out.contains("\n  sha256: "), "{out}");
        assert!(out.contains("\n  packets: 2\n"), "{out}");
        assert!(out.ends_with("Use load_pcap('t.pcap') to read them back, or dissect_packet on any packet's hex for a full breakdown."), "{out}");

        let loaded = load_pcap("t.pcap", 0, 1, None, None, 0, &c);
        let lines: Vec<&str> = loaded.lines().collect();
        assert_eq!(lines[0], "Loaded 2 packet(s) from t.pcap (showing 0–0 of 2):");
        assert_eq!(lines[1].trim_start(), lines[1].trim_start(), "noop");
        assert!(lines[1].starts_with("  size: "));
        assert_eq!(lines[3], format!("  [1] Ether / Raw  hex={}", frame(b"one")));
        assert!(loaded.contains("... 1 more — load_pcap('t.pcap', offset=1, limit=1) for the next page."));
        assert!(loaded.ends_with("Use dissect_packet with any hex above for a full field breakdown."));

        let end = load_pcap("t.pcap", 1, 50, None, None, 0, &c);
        assert!(end.contains("\n  End of capture (2 packets total)."), "{end}");
    }

    #[test]
    fn load_header_only_pcap_is_no_packets_not_a_panic() {
        // Regression: `offset - 1` underflowed on an empty page.
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path());
        PcapWriter::create(dir.path().join("empty.pcap")).unwrap();
        let out = load_pcap("empty.pcap", 0, 50, None, None, 0, &c);
        assert!(out.starts_with("No packets in ") && out.ends_with("empty.pcap."), "{out}");
    }

    #[test]
    fn load_offset_past_end_matches_python_text() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path());
        let _ = save_pcap(&[frame(b"a"), frame(b"b")], "p.pcap", &c);
        let out = load_pcap("p.pcap", 5, 50, None, None, 0, &c);
        assert!(out.starts_with("Loaded 2 packet(s) from p.pcap (showing 5–4 of 2):"), "{out}");
    }

    #[test]
    fn load_honors_file_linktype() {
        // An `any`-interface (LINUX_SLL) capture must dissect as SLL.
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path());
        let mut f = vec![0, 0, 0, 1, 0, 6, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0, 0, 0x08, 0x00];
        f.extend_from_slice(&[0x45, 0, 0, 28, 0, 1, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2]);
        f.extend_from_slice(&[8, 0, 0, 0, 0, 1, 0, 1]);
        let mut w = PcapWriter::create_with_linktype(dir.path().join("any.pcap"), 113).unwrap();
        w.write_record(1, 0, &f).unwrap();
        drop(w);
        let out = load_pcap("any.pcap", 0, 50, None, None, 0, &c);
        assert!(out.contains("[1] SLL / IP / ICMP 10.0.0.1 > 10.0.0.2 echo-request 0"), "{out}");
        let hit = load_pcap("any.pcap", 0, 50, Some("echo-request"), None, 0, &c);
        assert!(hit.starts_with("Loaded 1 matched packet(s)"), "{hit}");
    }

    #[test]
    fn save_errors_in_text() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path());
        assert_eq!(
            save_pcap(&[], "x.pcap", &c),
            "save_pcap: no packets to save (hexes list is empty)."
        );
        let bad = save_pcap(&["zzzz-not-hex".to_string()], "x.pcap", &c);
        assert_eq!(bad, "save_pcap error: packet 1: invalid hex");
    }

    #[test]
    fn load_missing_file_text() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path());
        let out = load_pcap("nope.pcap", 0, 50, None, None, 0, &c);
        assert!(out.starts_with("load_pcap: file not found: "), "{out}");
    }

    #[test]
    fn size_guard_text() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cfg(dir.path());
        c.max_file_mb = 0; // 0 MiB cap: any file overflows
        let _ = save_pcap(&[frame(b"x")], "big.pcap", &c);
        let out = load_pcap("big.pcap", 0, 50, None, None, 0, &c);
        assert!(
            out.starts_with("load_pcap: big.pcap is 0.0 MiB (cap is 0 MiB). Use tcpdump/tshark")
                || out.contains("(cap is 0 MiB). Use tcpdump/tshark directly or raise PCAP_MAX_FILE_MB."),
            "{out}"
        );
    }

    #[test]
    fn filtered_load_shapes() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path());
        let mut hexes = Vec::new();
        for tag in ["quiet", "needle-here", "quiet2", "needle-again", "quiet3", "quiet4"] {
            hexes.push(frame(tag.as_bytes()));
        }
        let _ = save_pcap(&hexes, "f.pcap", &c);

        let out = load_pcap("f.pcap", 0, 50, Some("needle"), None, 0, &c);
        assert!(out.starts_with("Loaded 2 matched packet(s) from f.pcap (filtered from 6):"), "{out}");
        assert!(out.contains("  [2] Ether / Raw  hex="), "{out}");
        assert!(out.contains("  ..."), "{out}\n-- gap marker expected: frames 2 and 4 are non-contiguous");
        assert!(out.contains("\n  End of matches (2 matched of 6 packets total)."), "{out}");

        let none = load_pcap("f.pcap", 0, 50, Some("absent-marker"), None, 0, &c);
        assert_eq!(none, "[no packets matched filter: 'absent-marker']");

        // paging: limit 3 of the expanded 3-entry include (2,3,4 w/ context 1)
        let paged = load_pcap("f.pcap", 0, 2, Some("needle"), None, 3, &c);
        assert!(paged.contains("for the next page."), "{paged}");
    }

    #[test]
    fn regex_compile_error_surfaces() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path());
        let _ = save_pcap(&[frame(b"x")], "r.pcap", &c);
        let out = load_pcap("r.pcap", 0, 50, None, Some("([bad"), 0, &c);
        assert!(
            out.starts_with("load_pcap error: invalid regex pattern '([bad':"),
            "{out}"
        );
    }

    #[test]
    fn list_pcaps_shapes() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path());
        assert_eq!(
            list_pcaps(&c),
            format!(
                "No pcap files in {}. Use sniff_to_pcap or save_pcap to create one.",
                dir.path().display()
            )
        );
        let _ = save_pcap(&[frame(b"a")], "l1.pcap", &c);
        let out = list_pcaps(&c);
        assert!(out.starts_with("Pcap captures in "), "{out}");
        assert!(out.contains("  l1.pcap  "), "{out}");
        assert!(out.contains(" 1 pkts  "), "{out}");
        assert!(out.ends_with(
            "Use load_pcap('<name>.pcap') to page through packets, or dissect_packet on any hex for a full breakdown."
        ));
    }

    #[test]
    fn timestamped_default_name() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path());
        let out = save_pcap(&[frame(b"z")], "", &c);
        // cap_YYYYmmdd_HHMMSS.pcap
        let name_start = out.find("Saved 1 packet(s) to ").unwrap()
            + "Saved 1 packet(s) to ".len();
        let path = &out[name_start..out.find('\n').unwrap()];
        let fname = Path::new(path).file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(fname.len(), 4 + 8 + 1 + 6 + 5, "{fname}");
        assert!(fname.starts_with("cap_") && fname.ends_with(".pcap"), "{fname}");
        assert!(fname.chars().skip(4).take(8).all(|ch| ch.is_ascii_digit()), "{fname}");
        assert!(fname.chars().nth(12) == Some('_'), "{fname}");
        assert!(fname.chars().skip(13).take(6).all(|ch| ch.is_ascii_digit()), "{fname}");
    }
}