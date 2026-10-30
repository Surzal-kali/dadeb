//! pcapinfo — CLI companion for the pcap crate (scratch's pycompat pattern).
//!
//!   pcapinfo summary <hex>                          dissect one frame
//!   pcapinfo write <file> <hex> [<hex>...]          write frames to a pcap file
//!   pcapinfo count <file>                           record count (streaming)
//!   pcapinfo read <file> [--offset N] [--limit N]   python-shaped page text
//!                 [--filter P] [--regex RX] [--context N]
//!   pcapinfo search <file> [--filter P] [--regex RX] [--context N] [--json]
//!   pcapinfo list <dir>                             list_pcaps text
//!   pcapinfo bpf <filter>                           BPF compile check (capture feature)

use pcap::{PcapConfig, SearchOpts};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else {
        usage();
        return;
    };
    let rest = &args[1..];
    match cmd.as_str() {
        "summary" => summary(rest),
        "write" => write(rest),
        "count" => count(rest),
        "read" => read(rest, false),
        "search" => read(rest, true),
        "list" => list(rest),
        "bpf" => bpf(rest),
        _ => usage(),
    }
}

fn usage() {
    eprintln!(
        "usage: pcapinfo <summary|write|count|read|search|list|bpf> ...\n  summary <hex>\n  write <file> <hex> [<hex>...]\n  count <file>\n  read <file> [--offset N] [--limit N] [--filter P] [--regex RX] [--context N]\n  search <file> [--filter P] [--regex RX] [--context N] [--offset N] [--limit N] [--json]\n  list <dir>\n  bpf <filter>"
    );
    std::process::exit(2);
}

fn summary(rest: &[String]) {
    let Some(hex) = rest.first() else {
        usage();
        return;
    };
    let bytes = pcap::hex_bytes(hex).unwrap_or_else(|e| {
        eprintln!("invalid hex: {e}");
        std::process::exit(1);
    });
    let v = pcap::dissect_frame(&bytes);
    println!("summary: {}", v.summary);
    for (k, val) in &v.fields {
        println!("  {k} = {val}");
    }
    if !v.ascii.is_empty() {
        println!("ascii: {}", v.ascii.replace('\n', " | "));
    }
    println!("hex: {}", pcap::hex_string(&bytes));
}

fn write(rest: &[String]) {
    let Some(path) = rest.first() else {
        usage();
        return;
    };
    let mut w = match pcap::PcapWriter::create(path) {
        Ok(w) => w,
        Err(e) => die(&e.to_string()),
    };
    for (i, hex) in rest[1..].iter().enumerate() {
        let bytes = match pcap::hex_bytes(hex) {
            Ok(b) => b,
            Err(e) => die(&format!("packet {}: {e}", i + 1)),
        };
        if let Err(e) = w.write_record(1700000000 + i as u32, 0, &bytes) {
            die(&e.to_string());
        }
    }
    w.flush().unwrap();
    println!("wrote {} frame(s) to {}", w.count(), path);
}

fn count(rest: &[String]) {
    let Some(path) = rest.first() else {
        usage();
        return;
    };
    match pcap::count_records(path) {
        Ok(n) => println!("{n}"),
        Err(e) => die(&e.to_string()),
    }
}

fn read(rest: &[String], structured: bool) {
    let Some(path) = rest.iter().find(|a| !a.starts_with("--")).cloned() else {
        usage();
        return;
    };
    let mut opts = SearchOpts::default();
    let mut offset = 0usize;
    let mut limit = 50usize;
    let mut json = false;
    parse_flags(rest, &mut opts, &mut offset, &mut limit, &mut json);

    if structured {
        match pcap::pcap_search(&path, &opts, &PcapConfig::with_dir(".")) {
            Ok(out) => {
                if json {
                    println!("{}", serde_json::to_string_pretty(&json_outcome(&out)).unwrap());
                } else {
                    for e in &out.entries {
                        match e {
                            pcap::OutcomeEntry::Frame { index, summary, ascii, .. } => {
                                println!("[{}] {}", index + 1, summary);
                                if !ascii.is_empty() {
                                    println!("     ascii: {}", ascii.replace('\n', " | "));
                                }
                            }
                            pcap::OutcomeEntry::Gap => println!("  ..."),
                        }
                    }
                    let m = &out.meta;
                    println!(
                        "-- matches {} of {} total, context ±{}, offset {}/{}, {}",
                        m.matches,
                        m.total,
                        m.context_frames,
                        m.offset,
                        m.limit,
                        if m.paged { "paged" } else { "complete" }
                    );
                }
            }
            Err(e) => die(&e),
        }
    } else {
        let cfg = PcapConfig::with_dir(".");
        let text = pcap::load_pcap(
            &path,
            offset,
            limit,
            opts.filter.as_deref(),
            opts.regex.as_deref(),
            opts.context_frames,
            &cfg,
        );
        println!("{text}");
    }
}

fn parse_flags(
    args: &[String],
    opts: &mut SearchOpts,
    offset: &mut usize,
    limit: &mut usize,
    json: &mut bool,
) {
    let mut i = 0;
    while i < args.len() {
        let take = |i: &mut usize, args: &[String]| -> Option<String> {
            let v = args.get(*i + 1).cloned();
            *i += 1;
            v
        };
        match args[i].as_str() {
            "--filter" => {
                if let Some(v) = take(&mut i, args) {
                    opts.filter = Some(v);
                }
            }
            "--regex" => {
                if let Some(v) = take(&mut i, args) {
                    opts.regex = Some(v);
                }
            }
            "--context" => {
                if let Some(v) = take(&mut i, args) {
                    opts.context_frames = v.parse().unwrap_or(0);
                }
            }
            "--offset" => {
                if let Some(v) = take(&mut i, args) {
                    *offset = v.parse().unwrap_or(0);
                }
            }
            "--limit" => {
                if let Some(v) = take(&mut i, args) {
                    *limit = v.parse().unwrap_or(50);
                }
            }
            "--json" => *json = true,
            _ => {}
        }
        i += 1;
    }
}

fn json_outcome(out: &pcap::SearchOutcome) -> serde_json::Value {
    use serde_json::json;
    let m = &out.meta;
    json!({
        "meta": {
            "filter": m.filter,
            "regex": m.regex,
            "context_frames": m.context_frames,
            "offset": m.offset,
            "limit": m.limit,
            "paged": m.paged,
            "matches": m.matches,
            "total": m.total,
            "expanded": m.expanded,
            "displayed": m.displayed,
        },
        "entries": out.entries.iter().map(|e| match e {
            pcap::OutcomeEntry::Frame { index, ts_sec, ts_usec, summary, fields, ascii, hex } => json!({
                "kind": "frame", "index": index, "ts_sec": ts_sec, "ts_usec": ts_usec,
                "summary": summary,
                "fields": fields.iter().map(|(k, v)| json!({k: v})).collect::<Vec<_>>(),
                "ascii": ascii, "hex": hex,
            }),
            pcap::OutcomeEntry::Gap => json!({"kind": "gap"}),
        }).collect::<Vec<_>>(),
    })
}

fn list(rest: &[String]) {
    let Some(dir) = rest.first() else {
        usage();
        return;
    };
    let cfg = PcapConfig::with_dir(dir);
    println!("{}", pcap::list_pcaps(&cfg));
}

#[cfg(feature = "capture")]
fn bpf(rest: &[String]) {
    let Some(f) = rest.first() else {
        usage();
        return;
    };
    match bpf_compile(f) {
        Ok(()) => println!("BPF filter compiles: '{f}'"),
        Err(e) => die(&e),
    }
}

#[cfg(not(feature = "capture"))]
fn bpf(_rest: &[String]) {
    println!("bpf check requires the 'capture' feature (libpcap).");
}

/// BPF compile check: libpcap validates filters only against a capture, so
/// open the always-present loopback device purely for the compile step.
#[cfg(feature = "capture")]
fn bpf_compile(f: &str) -> Result<(), String> {
    let mut cap = libpcap::Capture::from_device("lo")
        .map_err(|e| e.to_string())?
        .open()
        .map_err(|e| format!("open lo for bpf compile: {e}"))?;
    cap.filter(f, true).map(|_| ()).map_err(|e| format!("invalid BPF: {e}"))
}

fn die(msg: &str) -> ! {
    eprintln!("pcapinfo error: {msg}");
    std::process::exit(1);
}