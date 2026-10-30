//! Store configuration knobs — the env-backed mirrors of
//! `utils/scratch_store.py`'s module constants.
//!
//! Python reads these at import (`SCRATCH_TTL_HOURS`, `SCRATCH_MAX_PAYLOAD_MB`,
//! `SCRATCH_MAX_AGENT_MB`) and reads `SCRATCH_GREP_MIN_CHARS` per projection
//! call; here every knob is captured once at [`ScratchConfig::from_env`] (or
//! `open()`'s default) and threaded through the store explicitly, so tests can
//! override without touching process env.
//!
//! Divergence: a malformed env value logs a warning and falls back to the
//! default instead of raising at import — a typo must never take down the
//! store lane (the Python raises and kills every consumer of the module).

pub const DEFAULT_TTL_HOURS: f64 = 24.0;
pub const DEFAULT_MAX_PAYLOAD_MB: usize = 256;
pub const DEFAULT_MAX_AGENT_MB: usize = 1024;
pub const DEFAULT_GREP_MIN_CHARS: usize = 200;

#[derive(Debug, Clone)]
pub struct ScratchConfig {
    /// Entry time-to-live in hours (`SCRATCH_TTL_HOURS`, default 24).
    pub ttl_hours: f64,
    /// Per-entry serialized-payload cap in bytes
    /// (`SCRATCH_MAX_PAYLOAD_MB` × MiB, default 256 MiB).
    pub max_payload_bytes: usize,
    /// Per-agent total-byte budget (`SCRATCH_MAX_AGENT_MB` × MiB, 1 GiB).
    pub max_agent_bytes: usize,
    /// Strings shorter than this are returned as-is by the grep projection
    /// (`SCRATCH_GREP_MIN_CHARS`, default 200).
    pub grep_min_chars: usize,
}

impl Default for ScratchConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

impl ScratchConfig {
    /// Explicit constructor for tests and callers that own their knobs.
    pub fn new(
        ttl_hours: f64,
        max_payload_bytes: usize,
        max_agent_bytes: usize,
        grep_min_chars: usize,
    ) -> Self {
        Self {
            ttl_hours,
            max_payload_bytes,
            max_agent_bytes,
            grep_min_chars,
        }
    }

    /// Env-backed construction with the Python module's defaults.
    pub fn from_env() -> Self {
        Self {
            ttl_hours: env_f64("SCRATCH_TTL_HOURS", DEFAULT_TTL_HOURS),
            max_payload_bytes: env_usize_mib("SCRATCH_MAX_PAYLOAD_MB", DEFAULT_MAX_PAYLOAD_MB),
            max_agent_bytes: env_usize_mib("SCRATCH_MAX_AGENT_MB", DEFAULT_MAX_AGENT_MB),
            grep_min_chars: env_usize("SCRATCH_GREP_MIN_CHARS", DEFAULT_GREP_MIN_CHARS),
        }
    }
}

fn env_f64(key: &str, default: f64) -> f64 {
    match std::env::var(key) {
        Ok(v) if !v.trim().is_empty() => parse_f64(&v).unwrap_or_else(|| {
            eprintln!("[scratch] invalid {key}={v:?}; falling back to default {default}");
            default
        }),
        _ => default,
    }
}

/// Strictly validated f64 for store knobs: finite and non-negative only.
/// A bare `.parse::<f64>()` accepts `"nan"`, `"inf"`, and `-1` — all of them
/// poison the TTL arithmetic (`now - nan > 0` is never true, so nothing ever
/// expires; a negative TTL expires everything immediately).
fn parse_f64(raw: &str) -> Option<f64> {
    raw.trim()
        .parse::<f64>()
        .ok()
        .filter(|x| x.is_finite() && *x >= 0.0)
}

fn env_usize(key: &str, default: usize) -> usize {
    match std::env::var(key) {
        Ok(v) if !v.trim().is_empty() => v.trim().parse().unwrap_or_else(|_| {
            eprintln!("[scratch] invalid {key}={v:?}; falling back to default {default}");
            default
        }),
        _ => default,
    }
}

fn env_usize_mib(key: &str, default_mb: usize) -> usize {
    env_usize(key, default_mb).saturating_mul(1024 * 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_f64_rejects_nan_inf_and_negative() {
        assert_eq!(parse_f64("nan"), None);
        assert_eq!(parse_f64("NaN"), None);
        assert_eq!(parse_f64("inf"), None);
        assert_eq!(parse_f64("-inf"), None);
        assert_eq!(parse_f64("-1"), None);
        assert_eq!(parse_f64("0.0"), Some(0.0));
        assert_eq!(parse_f64("24.5"), Some(24.5));
        assert_eq!(parse_f64("  48  "), Some(48.0));
    }
}