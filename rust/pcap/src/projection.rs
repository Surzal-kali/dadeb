//! Projection — scratch's machinery replayed frame-wise:
//! substring filter (list lane, beats regex), regex (string lane, only when
//! no filter), `context_frames` (match ± N neighbors with `...` gap markers),
//! offset/limit paging. Python-shaped error strings; no-match note shape.

use regex::Regex;

use crate::dissect::{dissect_frame_linktype, hex_string, FrameView};
use crate::format::PcapReader;

#[derive(Debug, Clone, Default)]
pub struct SearchOpts {
    /// substring filter, case-insensitive over all surfaces (list lane)
    pub filter: Option<String>,
    /// regex alternative (string lane) — only used when `filter` is None
    pub regex: Option<String>,
    /// match ± N neighboring frames, with `...` at gaps
    pub context_frames: usize,
    pub offset: usize,
    /// 0 = no limit
    pub limit: usize,
}

#[derive(Debug, Clone)]
pub struct SearchMeta {
    pub filter: Option<String>,
    pub regex: Option<String>,
    pub context_frames: usize,
    pub offset: usize,
    pub limit: usize,
    pub paged: bool,
    /// frames that actually matched
    pub matches: usize,
    /// total frames in the file
    pub total: usize,
    /// frames+gaps in the full expanded include set (matches ± context)
    pub expanded: usize,
    /// entries in the returned window (frames + gaps)
    pub displayed: usize,
}

#[derive(Debug, Clone)]
pub enum OutcomeEntry {
    Frame {
        /// 0-based file position (1-based in python text rendering)
        index: usize,
        ts_sec: u32,
        ts_usec: u32,
        summary: String,
        fields: Vec<(String, String)>,
        ascii: String,
        hex: String,
    },
    /// `...` context separator between non-contiguous frames
    Gap,
}

#[derive(Debug, Clone)]
pub struct SearchOutcome {
    pub entries: Vec<OutcomeEntry>,
    pub meta: SearchMeta,
}

/// python-parity compile failure: `invalid regex pattern '<p>': <reason>`
/// (crate message text differs from python's `re.error` shape — documented).
pub fn compile_regex(pattern: &str) -> Result<Regex, String> {
    regex::RegexBuilder::new(pattern)
        .case_insensitive(true)
        .build()
        .map_err(|e| format!("invalid regex pattern '{pattern}': {e}"))
}

fn surfaces(view: &FrameView) -> Vec<String> {
    let fields = view
        .fields
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("\n");
    vec![view.summary.clone(), fields, view.ascii.clone()]
}

/// `_item_matches` semantics: a substring filter is the list lane — a miss
/// EXCLUDES the frame even if the regex lane would have hit.
fn frame_matches(view: &FrameView, filter_lower: Option<&str>, re: Option<&Regex>) -> bool {
    match (filter_lower, re) {
        (Some(needle), _) => surfaces(view).iter().any(|s| s.to_lowercase().contains(needle)),
        (None, Some(re)) => surfaces(view).iter().any(|s| re.is_match(s)),
        (None, None) => true,
    }
}

pub fn search_frames<P: AsRef<std::path::Path>>(
    path: P,
    opts: &SearchOpts,
) -> Result<SearchOutcome, String> {
    if let Some(re) = &opts.regex {
        compile_regex(re)?;
    }

    // pass 1: total count + matching frame indices
    let mut reader = PcapReader::open(&path).map_err(|e| e.to_string())?;
    let linktype = reader.header().network;
    let mut total = 0usize;
    let mut match_indices = Vec::new();
    let filter_lower = opts.filter.as_ref().map(|f| f.to_lowercase());
    let re = match &opts.regex {
        Some(p) => Some(compile_regex(p).map_err(|e| e.to_string())?),
        None => None,
    };
    loop {
        let rec = reader.next_record().map_err(|e| e.to_string())?;
        let Some(rec) = rec else { break };
        if frame_matches(&dissect_frame_linktype(&rec.data, linktype), filter_lower.as_deref(), re.as_ref()) {
            match_indices.push(total);
        }
        total += 1;
    }

    // expanded display list: matches ± context, `...` between non-contiguous
    let context = opts.context_frames;
    let mut include = std::collections::BTreeSet::new();
    for &m in &match_indices {
        for i in m.saturating_sub(context)..=(m + context).min(total.saturating_sub(1)) {
            include.insert(i);
        }
    }
    let mut entries_plan: Vec<Option<usize>> = Vec::new(); // None = Gap
    let mut last: Option<usize> = None;
    for &i in &include {
        match last {
            Some(prev) if i != prev + 1 => entries_plan.push(None),
            _ => {}
        }
        entries_plan.push(Some(i));
        last = Some(i);
    }

    let expanded_len = entries_plan.len();
    let start = opts.offset.min(expanded_len);
    let end = if opts.limit == 0 {
        expanded_len
    } else {
        (opts.offset.checked_add(opts.limit).unwrap_or(expanded_len)).min(expanded_len)
    };
    let paged = opts.offset > 0 || (opts.limit > 0 && expanded_len > opts.limit);

    // window plan (frame indices to capture, positions for gap emission)
    let mut wanted: Vec<(usize, bool)> = Vec::new(); // (frame_idx, is_gap_before)
    for entry in &entries_plan[start..end] {
        match entry {
            Some(idx) => wanted.push((*idx, false)),
            None => match wanted.last_mut() {
                Some(_) => wanted.push((usize::MAX, true)), // gap marker rides last
                None => {}                                  // leading gap dropped
            },
        }
    }

    // pass 2: stream to the wanted frames (monotonic walk)
    let mut reader = PcapReader::open(&path).map_err(|e| e.to_string())?;
    let mut entries = Vec::new();
    let mut idx = 0usize;
    let mut wanted_iter = wanted.iter();
    let mut next = wanted_iter.next().copied();
    loop {
        let Some((want_idx, _)) = next else { break };
        if want_idx == usize::MAX {
            entries.push(OutcomeEntry::Gap);
            next = wanted_iter.next().copied();
            continue;
        }
        let Some(rec) = reader.next_record().map_err(|e| e.to_string())? else { break };
        if idx == want_idx {
            let view = dissect_frame_linktype(&rec.data, linktype);
            entries.push(OutcomeEntry::Frame {
                index: idx,
                ts_sec: rec.ts_sec,
                ts_usec: rec.ts_usec,
                summary: view.summary,
                fields: view.fields,
                ascii: view.ascii,
                hex: hex_string(&rec.data),
            });
            next = wanted_iter.next().copied();
        } else if idx > want_idx {
            // can't happen (monotonic plan), but stay honest instead of looping
            entries.push(OutcomeEntry::Gap);
            next = wanted_iter.next().copied();
        }
        idx += 1;
    }

    let displayed = entries.len();
    Ok(SearchOutcome {
        entries,
        meta: SearchMeta {
            filter: opts.filter.clone(),
            regex: opts.regex.clone(),
            context_frames: opts.context_frames,
            offset: opts.offset,
            limit: opts.limit,
            paged,
            matches: match_indices.len(),
            total,
            expanded: expanded_len,
            displayed,
        },
    })
}

/// The no-match note (python list-lane shape: `[no packets matched filter: '<p>']`).
pub fn no_match_note(opts: &SearchOpts) -> String {
    let pattern = opts
        .filter
        .clone()
        .or_else(|| opts.regex.clone())
        .unwrap_or_default();
    format!("[no packets matched filter: '{pattern}']")
}

#[cfg(test)]
mod tests {
    use super::*;

    // build a 6-frame capture; frames 2 and 4 carry the marker "needle"
    fn marker_frame(tag: &str) -> Vec<u8> {
        let mut f = vec![0u8; 14];
        f[12..14].copy_from_slice(&0x9999u16.to_be_bytes());
        f.extend_from_slice(tag.as_bytes());
        f
    }

    fn setup(dir: &std::path::Path) -> std::path::PathBuf {
        let path = dir.join("s.pcap");
        let mut w = crate::format::PcapWriter::create(&path).unwrap();
        for i in 0..6 {
            let tag = if i == 2 || i == 4 { "needle-hit" } else { "quiet" };
            w.write_record(1700000000 + i as u32, 0, &marker_frame(tag)).unwrap();
        }
        path
    }

    #[test]
    fn substring_beats_regex() {
        let dir = tempfile::tempdir().unwrap();
        let path = setup(dir.path());
        // needle substring present AND regex \d+ present (quiet hex has digits? hex is
        // zeros -> "0000..."? our marker frames have hex "0000..." so \d matches).
        // Substring "needlemark" misses frames 2/4? no — frames 2/4 HAVE it.
        // Here: filter excludes even though regex would hit = use a regex that
        // hits 'quiet' frames and a substring that hits nothing.
        let opts = SearchOpts {
            filter: Some("zzz-nothing".into()),
            regex: Some("quiet".into()),
            context_frames: 0,
            offset: 0,
            limit: 0,
        };
        let out = search_frames(&path, &opts).unwrap();
        assert_eq!(out.meta.matches, 0, "substring miss excludes despite regex hit");
        assert!(out.entries.is_empty());
    }

    #[test]
    fn regex_lane_used_when_no_filter() {
        let dir = tempfile::tempdir().unwrap();
        let path = setup(dir.path());
        let opts = SearchOpts {
            filter: None,
            regex: Some("needle.hi".into()),
            context_frames: 0,
            offset: 0,
            limit: 0,
        };
        let out = search_frames(&path, &opts).unwrap();
        assert_eq!(out.meta.matches, 2);
        assert_eq!(out.meta.total, 6);
    }

    #[test]
    fn context_frames_with_gap_markers() {
        let dir = tempfile::tempdir().unwrap();
        let path = setup(dir.path());
        let opts = SearchOpts {
            filter: Some("needle".into()),
            regex: None,
            context_frames: 1, // frames 1,2,3 + 3,4,5 -> 1..5 contiguous, no gap
            offset: 0,
            limit: 0,
        };
        let out = search_frames(&path, &opts).unwrap();
        let kinds: Vec<&str> = out
            .entries
            .iter()
            .map(|e| match e {
                OutcomeEntry::Frame { .. } => "f",
                OutcomeEntry::Gap => "...",
            })
            .collect();
        assert_eq!(kinds, vec!["f", "f", "f", "f", "f"]);
        assert_eq!(out.meta.matches, 2);

        // context 0 -> gap between 2 and 4
        let opts = SearchOpts {
            filter: Some("needle".into()),
            regex: None,
            context_frames: 0,
            offset: 0,
            limit: 0,
        };
        let out = search_frames(&path, &opts).unwrap();
        let kinds: Vec<&str> = out
            .entries
            .iter()
            .map(|e| match e {
                OutcomeEntry::Frame { .. } => "f",
                OutcomeEntry::Gap => "...",
            })
            .collect();
        assert_eq!(kinds, vec!["f", "...", "f"]);
    }

    #[test]
    fn paging_meta_only_when_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let path = setup(dir.path());
        let full = search_frames(
            &path,
            &SearchOpts {
                filter: None,
                regex: None,
                context_frames: 0,
                offset: 0,
                limit: 0,
            },
        )
        .unwrap();
        assert!(!full.meta.paged);
        assert_eq!(full.meta.total, 6);
        assert_eq!(full.entries.len(), 6);

        let paged = search_frames(
            &path,
            &SearchOpts {
                filter: None,
                regex: None,
                context_frames: 0,
                offset: 2,
                limit: 2,
            },
        )
        .unwrap();
        assert!(paged.meta.paged);
        assert_eq!(paged.entries.len(), 2);
        let idxs: Vec<usize> = paged
            .entries
            .iter()
            .filter_map(|e| match e {
                OutcomeEntry::Frame { index, .. } => Some(*index),
                _ => None,
            })
            .collect();
        assert_eq!(idxs, vec![2, 3]);
    }

    #[test]
    fn compile_error_python_shaped() {
        let err = compile_regex("([bad").unwrap_err();
        assert!(err.starts_with("invalid regex pattern '([bad':"), "{err}");
    }

    #[test]
    fn no_match_note_shape() {
        let opts = SearchOpts {
            filter: Some("login failed".into()),
            regex: None,
            context_frames: 0,
            offset: 0,
            limit: 0,
        };
        assert_eq!(no_match_note(&opts), "[no packets matched filter: 'login failed']");
    }

    #[test]
    fn unfiltered_entries_carry_hex_and_ascii() {
        let dir = tempfile::tempdir().unwrap();
        let path = setup(dir.path());
        let out = search_frames(
            &path,
            &SearchOpts {
                filter: Some("needle".into()),
                regex: None,
                context_frames: 0,
                offset: 0,
                limit: 0,
            },
        )
        .unwrap();
        let Some(OutcomeEntry::Frame { hex, summary, ascii, index, .. }) = out.entries.first() else {
            panic!("expected frame");
        };
        assert_eq!(*index, 2);
        assert_eq!(summary, "Ether / Raw");
        assert_eq!(ascii, "needle-hit");
        assert!(hex.starts_with("0000000000000000000000009999"), "{hex}");
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(hex.len(), 2 * (14 + "needle-hit".len()));
    }
}