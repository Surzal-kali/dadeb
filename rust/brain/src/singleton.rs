//! The Brain's start-up OS dance — ported from listeners/thebrain.py
//! start_brain().
//!
//! This is the "how does Rust talk to the OS" milestone. The Python os/fcntl
//! calls split two ways in Rust:
//!   * portable file ops -> `std::fs` (create_dir_all, remove_file, metadata/ino,
//!     set_permissions);
//!   * Unix-only syscalls -> the `nix` crate (umask, flock). nix does the
//!     `unsafe { libc::... }` internally and hands back safe functions, so the
//!     unsafe stays confined to the crate — same philosophy as the FFI seam.
//!
//! What it reproduces from start_brain():
//!   * an exclusive advisory flock singleton guard (catches a reparented orphan
//!     still listening on an unlinked socket, which a connect-probe can't see);
//!   * a connect-probe before unlinking a leftover socket, so a LIVE sidecar is
//!     never clobbered;
//!   * per-lane socket permissions via a umask swap around bind (atomic — no
//!     bind-then-chmod race);
//!   * unlink-on-exit, but only if the socket on disk is still the inode WE
//!     bound.

use nix::fcntl::{Flock, FlockArg};
use nix::sys::stat::{umask, Mode};
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use tokio::net::UnixListener;

/// (umask, socket_perm, lock_perm) for a socket dir, chosen from its mode bits.
/// Faithful to socket_lane_perms() in thebrain.py:
///   group-writable -> 0o007 / 0o770 / 0o660  (system profile, daharness group)
///   world-writable -> 0o000 / 0o777 / 0o666  (legacy container lanes)
///   owner-only     -> 0o077 / 0o700 / 0o600  (single-user dev checkout)
pub fn socket_lane_perms(dir_mode: u32) -> (u32, u32, u32) {
    if dir_mode & 0o020 != 0 {
        (0o007, 0o770, 0o660)
    } else if dir_mode & 0o002 != 0 {
        (0o000, 0o777, 0o666)
    } else {
        (0o077, 0o700, 0o600)
    }
}

/// Held for the Brain's whole life. Dropping it releases the advisory lock (the
/// fd closes) and unlinks the socket — but ONLY if the socket on disk is still
/// the inode we bound, so a newer sidecar's socket is never clobbered. Mirrors
/// the finally-block cleanup in start_brain().
pub struct SingletonGuard {
    _lock: Flock<File>, // advisory lock, released when this fd closes
    socket_path: PathBuf,
    bound_ino: u64,
}

impl Drop for SingletonGuard {
    fn drop(&mut self) {
        if let Ok(meta) = fs::metadata(&self.socket_path) {
            if meta.ino() == self.bound_ino {
                let _ = fs::remove_file(&self.socket_path);
                eprintln!("[rust-brain] cleaned up {}", self.socket_path.display());
            }
        }
    }
}

/// Acquire the singleton lock, clear a stale socket, and bind at the lane's
/// trust level. Returns the bound listener plus the guard to keep alive for the
/// process's lifetime.
pub fn acquire_and_bind(socket_path: &Path) -> io::Result<(UnixListener, SingletonGuard)> {
    let sock_dir = socket_path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(sock_dir)?;

    let dir_mode = fs::metadata(sock_dir)?.permissions().mode();
    let (lane_umask, _sock_perm, lock_perm) = socket_lane_perms(dir_mode);

    // --- singleton guard: exclusive advisory lock ---------------------------
    // The connect-probe below only catches a second Brain while the first's
    // socket FILE still exists. A reparented orphan listening on an unlinked
    // inode is invisible to that — but it still holds this flock, which the
    // kernel releases on death (even SIGKILL), so it never goes stale.
    let lock_file = open_lockfile(sock_dir, lock_perm)?;
    let lock = match Flock::lock(lock_file, FlockArg::LockExclusiveNonblock) {
        Ok(guard) => guard,
        Err((_file, errno)) => {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!(
                    "another Brain holds the lock ({errno}); refusing to start a \
                     second Brain (orphan on an unlinked socket?)"
                ),
            ));
        }
    };

    // --- stale socket: probe before unlinking -------------------------------
    if socket_path.exists() {
        if StdUnixStream::connect(socket_path).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!(
                    "{} already has a live listener; refusing to start a second Brain",
                    socket_path.display()
                ),
            ));
        }
        // Not live -> stale file; remove it (may fail if a different uid owns it).
        fs::remove_file(socket_path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "stale socket {} could not be removed ({e}); remove it manually",
                    socket_path.display()
                ),
            )
        })?;
    }

    // --- bind at the lane's trust level -------------------------------------
    // A Unix socket is created with mode 0o777 & ~umask, so swapping the umask
    // around bind lands the final mode atomically — no bind-then-chmod race
    // window (e.g. umask 0o007 -> a 0o770 socket). Restore the umask either way.
    let previous = umask(Mode::from_bits_truncate(lane_umask as _));
    let bound = UnixListener::bind(socket_path);
    umask(previous);
    let listener = bound?;

    let bound_ino = fs::metadata(socket_path)?.ino();

    Ok((
        listener,
        SingletonGuard {
            _lock: lock,
            socket_path: socket_path.to_path_buf(),
            bound_ino,
        },
    ))
}

/// Open the lockfile in the socket dir; fall back to a uid-scoped /tmp lock if
/// the shared dir is unwritable (poisoned ownership / immutable bit / MAC), so
/// a bad shared lock can't wedge the sidecar — the singleton then applies
/// per-uid. Best-effort chmod to the lane's lock permission.
fn open_lockfile(sock_dir: &Path, lock_perm: u32) -> io::Result<File> {
    let shared = sock_dir.join("brain.lock");
    let (file, path) = match File::create(&shared) {
        Ok(f) => (f, shared),
        Err(_) => {
            let uid = nix::unistd::geteuid().as_raw();
            let fallback = PathBuf::from(format!("/tmp/brain.lock-{uid}"));
            let f = File::create(&fallback)?;
            (f, fallback)
        }
    };
    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(lock_perm));
    Ok(file)
}
