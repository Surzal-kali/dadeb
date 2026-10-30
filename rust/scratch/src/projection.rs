//! Generic result projection — port of `ScratchStore._apply_projection` and
//! its helpers (`_item_matches`, `_item_matches_regex`, `_grep_string`).
//!
//! Operates on the deserialized JSON structure of a retrieved payload and
//! handles three field types exactly like the Python:
//!
//! - **List fields** (`open_ports`, `rows`, `recent_lines`): paged and
//!   filtered. `filter_pattern` is a case-insensitive substring match;
//!   `regex_pattern` uses `re.search`. When BOTH are given the substring
//!   filter wins for lists (Python's `if pattern_lower: ... elif compiled_re:`).
//! - **Long string fields** (`body_head`, `body`, `log_text`): line-based
//!   grep — only matching lines are returned (plus `context_lines` adjacent
//!   lines, `grep -C` semantics). Here regex takes PRECEDENCE over substring
//!   (Python's `_grep_string` checks `if compiled_re: ... elif pattern_lower:`).
//! - **Short strings / non-list, non-string**: returned as-is.
//!
//! Tool-family digest adapters can produce richer projections, but this
//! fallback ensures every stored result is retrievable without a custom
//! adapter.
//!
//! The `_scratch_projection` meta block is appended to the projected object
//! when any key was paged or grepped, byte-compatible with the Python's.
//!
//! Documented divergences: Python's negative-offset slicing wraps from the
//! tail (`filtered[offset:]` with `offset < 0`); the port takes `usize`, so
//! negative paging is unsupported. Python compares `len(value)` in characters,
//! the port in bytes (threshold 200 is approximate for multibyte text).

use std::collections::BTreeSet;

use regex::{Regex, RegexBuilder};
use serde_json::{json, Map, Value};

/// Threshold for treating a string as grepable text vs. a short scalar —
/// strings under this length are returned as-is (no point grepping 3 lines).
/// Python reads this per-call; the port threads it via [`crate::ScratchConfig`].
pub const DEFAULT_GREP_MIN_CHARS: usize = 200;

const PROJECTION_NOTE: &str = "list fields were paged/filtered; text fields were grep-filtered \
     to matching lines. Use offset/limit for more list items, or adjust filter/regex for \
     different text matches.";

/// Case-insensitive regex compile — mirrors `re.compile(pattern, re.IGNORECASE)`.
/// The error string mirrors the Python's error envelope shape
/// (`invalid regex pattern '...': <reason>`).
pub fn compile_regex(pattern: &str) -> Result<Regex, String> {
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .build()
        .map_err(|e| format!("invalid regex pattern '{pattern}': {e}"))
}

/// Keys that were paged / grepped during a projection pass — the caller uses
/// these to build the `_scratch_projection` meta block.
#[derive(Debug, Default, Clone)]
pub struct ProjectionMeta {
    pub paged_keys: Vec<String>,
    pub grepped_keys: Vec<String>,
}

impl ProjectionMeta {
    pub fn is_empty(&self) -> bool {
        self.paged_keys.is_empty() && self.grepped_keys.is_empty()
    }
}

/// Apply paging/filtering/regex to a retrieved result **in place**.
///
/// `offset`/`limit` of 0 mean "unset" (Python's `if offset:` / `if limit and
/// limit > 0`). `filter_pattern` is matched case-insensitively as a substring;
/// `regex` (precompiled, case-insensitive) overrides it for string fields but
/// not for list items.
pub fn apply_projection(
    result: &mut Map<String, Value>,
    offset: usize,
    limit: usize,
    filter_pattern: Option<&str>,
    regex: Option<&Regex>,
    context_lines: usize,
    grep_min_chars: usize,
) -> ProjectionMeta {
    let pattern_lower = filter_pattern.map(|p| p.to_lowercase());
    let mut meta = ProjectionMeta::default();

    // Pre-collect keys so we can mutate the map while iterating (python
    // iterates `result.items()` while building a separate `out` dict).
    let keys: Vec<String> = result.keys().cloned().collect();
    for key in keys {
        // A projection op only applies to a field when it was requested.
        let projection_active =
            offset > 0 || limit > 0 || pattern_lower.is_some() || regex.is_some();
        let value = result.get(&key).cloned();
        match value {
            Some(Value::Array(items)) if projection_active => {
                let mut filtered = items;
                if let Some(pl) = &pattern_lower {
                    filtered.retain(|item| item_matches_sub(item, pl));
                } else if let Some(re) = regex {
                    filtered.retain(|item| item_matches_regex(item, re));
                }
                let total = filtered.len();
                if offset > 0 {
                    filtered = filtered.into_iter().skip(offset).collect();
                }
                if limit > 0 {
                    filtered.truncate(limit);
                }
                result.insert(key.clone(), Value::Array(filtered));
                if offset > 0 || (limit > 0 && total > limit) {
                    meta.paged_keys.push(key);
                }
            }
            Some(Value::String(s))
                if (pattern_lower.is_some() || regex.is_some()) && s.len() >= grep_min_chars =>
            {
                let grepped = grep_string(&s, pattern_lower.as_deref(), regex, context_lines);
                result.insert(key.clone(), Value::String(grepped));
                meta.grepped_keys.push(key);
            }
            _ => {} // short strings / non-list, non-string: as-is
        }
    }

    if !meta.is_empty() {
        let mut m = Map::new();
        if !meta.paged_keys.is_empty() {
            m.insert("paged_keys".into(), json!(meta.paged_keys));
            m.insert("offset".into(), json!(offset));
            m.insert("limit".into(), json!(limit));
        }
        if !meta.grepped_keys.is_empty() {
            m.insert("grepped_keys".into(), json!(meta.grepped_keys));
            m.insert(
                "filter".into(),
                json!(filter_pattern
                    .map(str::to_string)
                    .or_else(|| regex.map(|re| re.as_str().to_string()))),
            );
            m.insert("context_lines".into(), json!(context_lines));
        }
        m.insert("note".into(), json!(PROJECTION_NOTE));
        result.insert("_scratch_projection".into(), Value::Object(m));
    }

    meta
}

/// Case-insensitive substring match on a list item (str or dict) — mirrors
/// `_item_matches`.
fn item_matches_sub(item: &Value, pattern_lower: &str) -> bool {
    match item {
        Value::String(s) => s.to_lowercase().contains(pattern_lower),
        Value::Object(map) => map
            .values()
            .any(|v| value_as_str(v).to_lowercase().contains(pattern_lower)),
        other => value_as_str(other).to_lowercase().contains(pattern_lower),
    }
}

/// Regex match on a list item — mirrors `_item_matches_regex`
/// (`compiled_re.search(str(v)) is not None`).
fn item_matches_regex(item: &Value, re: &Regex) -> bool {
    match item {
        Value::String(s) => re.is_match(s),
        Value::Object(map) => map.values().any(|v| re.is_match(&value_as_str(v))),
        other => re.is_match(&value_as_str(other)),
    }
}

/// Python `str(v)` equivalent for containment matching: strings are used
/// bare, everything else falls back to its JSON serialization. (Python's
/// `str(dict)` uses repr quoting; for substring containment of real values
/// the JSON form matches the same cases.)
fn value_as_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Line-based grep on a long string field — mirrors `_grep_string`.
///
/// Returns matching lines joined with `\n`. When `context_lines` > 0,
/// includes that many lines before/after each match with `...` separators at
/// gaps (`grep -C` semantics). When no lines match, returns a short
/// "no matches" note so the caller knows the filter ran but found nothing
/// (vs. the filter silently doing nothing).
pub fn grep_string(
    text: &str,
    pattern_lower: Option<&str>,
    regex: Option<&Regex>,
    context_lines: usize,
) -> String {
    let lines: Vec<&str> = text.split('\n').collect();
    let match_indices: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| {
            if let Some(re) = regex {
                re.is_match(line)
            } else if let Some(pl) = pattern_lower {
                line.to_lowercase().contains(pl)
            } else {
                false
            }
        })
        .map(|(i, _)| i)
        .collect();

    if match_indices.is_empty() {
        let display = pattern_lower
            .map(str::to_string)
            .or_else(|| regex.map(|re| re.as_str().to_string()))
            .unwrap_or_default();
        return format!("[no lines matched filter: '{display}']");
    }

    if context_lines == 0 {
        return match_indices
            .iter()
            .map(|&i| lines[i])
            .collect::<Vec<_>>()
            .join("\n");
    }

    // Build the set of indices to include (match ± context), preserving order.
    let mut include: BTreeSet<usize> = BTreeSet::new();
    for &idx in &match_indices {
        let lo = idx.saturating_sub(context_lines);
        let hi = (idx + context_lines).min(lines.len() - 1);
        include.extend(lo..=hi);
    }

    let mut result_lines: Vec<&str> = Vec::new();
    let mut prev: usize = 0;
    let mut first = true;
    for &i in &include {
        if !first && i > prev + 1 {
            result_lines.push("...");
        }
        result_lines.push(lines[i]);
        prev = i;
        first = false;
    }
    result_lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn project(
        v: Value,
        offset: usize,
        limit: usize,
        filter: Option<&str>,
        regex: Option<&str>,
        context_lines: usize,
    ) -> (Value, ProjectionMeta) {
        let mut map = match v {
            Value::Object(m) => m,
            other => panic!("test helper needs an object, got {other:?}"),
        };
        let re = regex.map(|p| compile_regex(p).unwrap());
        let meta = apply_projection(
            &mut map,
            offset,
            limit,
            filter,
            re.as_ref(),
            context_lines,
            DEFAULT_GREP_MIN_CHARS,
        );
        (Value::Object(map), meta)
    }

    #[test]
    fn substring_filter_on_lists_is_case_insensitive() {
        let (out, meta) = project(
            json!({"rows": [{"host": "WEB01"}, {"host": "db01"}]}),
            0,
            0,
            Some("web"),
            None,
            0,
        );
        assert_eq!(out["rows"].as_array().unwrap().len(), 1);
        // The matching item is appended VERBATIM (python `out.append(item)`)
        // — no case rewriting.
        assert_eq!(out["rows"][0]["host"], "WEB01");
        // Filter-only list shaping adds no meta (python: paged needs offset or
        // a limit that truncated; no string was grepped).
        assert!(meta.is_empty());
        let (_, meta) = project(json!({"rows": ["a"]}), 0, 2, Some("a"), None, 0);
        // total(1) <= limit(2): filtered, but not marked paged.
        assert!(meta.is_empty());
    }

    #[test]
    fn filter_wins_over_regex_for_list_items() {
        let (out, _) = project(
            json!({"rows": ["csrf", "authz"]}),
            0,
            0,
            Some("authz"),
            Some("csrf|authz"),
            0,
        );
        // Substring filter is applied (regex skipped) for lists.
        assert_eq!(out["rows"], json!(["authz"]));
    }

    #[test]
    fn regex_wins_over_filter_for_strings() {
        let text = "line csrf\ngot AUTHZ here\nplain\n".repeat(20);
        let (out, meta) = project(
            json!({"body": text}),
            0,
            0,
            Some("nomatchsub"),
            Some(r"authz"),
            0,
        );
        let body = out["body"].as_str().unwrap();
        assert!(body.contains("AUTHZ"));
        assert!(!body.contains("plain"));
        assert_eq!(meta.grepped_keys, vec!["body"]);
    }

    #[test]
    fn paging_offsets_and_limits_lists() {
        let (out, meta) = project(
            json!({"rows": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]}),
            2,
            3,
            None,
            None,
            0,
        );
        assert_eq!(out["rows"], json!([3, 4, 5]));
        assert_eq!(meta.paged_keys, vec!["rows"]);
        assert_eq!(out["_scratch_projection"]["limit"], json!(3));
        assert_eq!(out["_scratch_projection"]["offset"], json!(2));
    }

    #[test]
    fn grep_with_context_lines_joins_gaps_with_ellipsis() {
        // 10 lines, matches on the first and sixth line; a long non-matching
        // tail line pushes the field over the 200-char grep threshold without
        // touching the include-set. Context 1 keeps {0,1} ∪ {4,5,6} — the gap
        // at indices 2-3 gets the "..." separator.
        let text = "hit\nsecond\nthird\nfourth\nlast\nhit\nsecond\nthird\nfourth\nlast\n"
            .to_string()
            + &"z".repeat(150);
        let (out, _) = project(json!({"body": text}), 0, 0, Some("hit"), None, 1);
        let body = out["body"].as_str().unwrap();
        assert_eq!(body, "hit\nsecond\n...\nlast\nhit\nsecond");
    }

    #[test]
    fn no_matches_returns_the_note_string() {
        let text = "alpha\nbeta\n".repeat(100);
        let (out, _) = project(json!({"body": text}), 0, 0, Some("zzznope"), None, 0);
        assert_eq!(out["body"], json!("[no lines matched filter: 'zzznope']"));
    }

    #[test]
    fn short_strings_pass_through_unprojected() {
        let (out, _) = project(
            json!({"body": "csrf token here", "other": "csrf csrf csrf"}),
            0,
            0,
            Some("csrf"),
            None,
            0,
        );
        // Below the grep threshold, both stay as-is.
        assert_eq!(out["body"], "csrf token here");
        assert_eq!(out["other"], "csrf csrf csrf");
    }

    #[test]
    fn invalid_regex_compiles_to_python_shaped_error() {
        // Shape must match the Python error envelope; the reason text comes
        // from the regex crate instead of re.error.
        let err = compile_regex("csrf(").unwrap_err();
        assert!(err.starts_with("invalid regex pattern 'csrf(':"));
    }

    #[test]
    fn top_level_non_list_non_string_values_pass_through_and_list_items_match_by_str() {
        let (out, _) = project(
            json!({"rows": ["csrf", 1], "count": 7, "ok": true, "body": "x".repeat(300)}),
            0,
            0,
            Some("1"),
            None,
            0,
        );
        // List items: strings substring-match the lowered line, non-strings
        // match via their JSON text ("str(item)" in python) — so 1 survives,
        // "csrf" does not.
        assert_eq!(out["rows"], json!([1]));
        // Top-level scalars are neither list nor string → untouched.
        assert_eq!(out["count"], json!(7));
        assert_eq!(out["ok"], json!(true));
        // "1" never matches the x-run → grep's no-match note.
        assert_eq!(out["body"], json!("[no lines matched filter: '1']"));
    }

    #[test]
    fn no_projection_ops_leave_everything_untouched() {
        let (out, meta) = project(
            json!({"rows": ["csrf"], "body": "csrf".repeat(100)}),
            0,
            0,
            None,
            None,
            0,
        );
        assert!(meta.is_empty());
        assert_eq!(out["rows"], json!(["csrf"]));
        assert_eq!(out["body"], json!("csrf".repeat(100)));
    }
}
