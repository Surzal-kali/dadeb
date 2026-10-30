//! Configuration knobs mirroring `utils/packetcraft.py`'s env block
//! (lines 60-105): `PCAP_DIR`, `PCAP_MAX_PACKETS_PER_FILE` (100_000),
//! `PCAP_MAX_FILE_MB` (512), `PACKET_CRAFT` (interface, default `eth0`).
//!
//! Same contract as scratch's `PcapConfig`: malformed env values warn to
//! stderr and fall back to the default; explicit-path constructors make tests
//! immune to the host environment. NOTE (env hazard, carried from scratch):
//! the deb lane hijacks `WORKSPACE_ROOT` to the system profile — tests MUST
//! use `PcapConfig::with_dir(tempdir)`.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct PcapConfig {
    pub dir: PathBuf,
    /// `PCAP_MAX_PACKETS_PER_FILE` — refuses to save past this.
    pub max_packets_per_file: usize,
    /// `PCAP_MAX_FILE_MB` — load_pcap size guard.
    pub max_file_mb: usize,
    /// `PACKET_CRAFT` — default interface for sniff_to_pcap.
    ///
    /// File-only lanes never touch this; there is deliberately no warning
    /// when it is unset (a plain analysis load must not print to stderr).
    pub default_interface: String,
}

fn env_usize(name: &str, default: usize) -> usize {
    match std::env::var(name) {
        Ok(raw) => match raw.trim().parse::<usize>() {
            Ok(v) => v,
            Err(_) => {
                eprintln!("warning: malformed env {name}={raw:?}: using default {default}");
                default
            }
        },
        Err(_) => default,
    }
}

impl PcapConfig {
    pub fn from_env() -> Self {
        Self::new()
    }

    pub fn new() -> Self {
        let dir = match std::env::var("PCAP_DIR") {
            Ok(v) if !v.trim().is_empty() => PathBuf::from(v),
            _ => match std::env::var("WORKSPACE_ROOT") {
                Ok(root) if !root.trim().is_empty() => Path::new(&root).join("pcaps"),
                _ => PathBuf::from(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../pcaps",
                )),
            },
        };
        Self {
            dir,
            max_packets_per_file: env_usize("PCAP_MAX_PACKETS_PER_FILE", 100_000),
            max_file_mb: env_usize("PCAP_MAX_FILE_MB", 512),
            default_interface: std::env::var("PACKET_CRAFT")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "eth0".to_string()),
        }
    }

    /// Tests: pin every knob, ignore the environment entirely.
    pub fn with_dir<P: Into<PathBuf>>(dir: P) -> Self {
        Self {
            dir: dir.into(),
            max_packets_per_file: 100_000,
            max_file_mb: 512,
            default_interface: "eth0".to_string(),
        }
    }
}

impl Default for PcapConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_dir_defaults_to_plain_eth0() {
        let cfg = PcapConfig::with_dir("/tmp/does-not-matter");
        assert_eq!(cfg.default_interface, "eth0");
    }
}