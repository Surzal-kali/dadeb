//! Milestone 2 of the Rust Brain port: the Python tool-worker IPC seam.
//!
//! Milestone 1 stood up the transport: a tokio Unix-socket server, length-
//! prefixed framing (codec.rs) wire-compatible with the Python Brain, and the
//! `event_type|session_id|payload` triplet parsed into a typed `Event` (event.rs)
//! dispatched through an exhaustive `match`.
//!
//! Milestone 2 (this commit) wires the stub arms to a real backend: tool events
//! are forwarded to a long-lived Python worker (worker.rs -> worker.py) over the
//! SAME codec, and its reply is relayed back to the client. The brain is now a
//! transparent proxy for the tool-execution half; tools stay in Python.
//!
//! Still scoped out for later milestones:
//!   * the OS-level singleton dance (flock, stale-inode unlink, per-lane umask);
//!   * the execution tracker / kill switch / per-tool ceilings (the brain-side
//!     control plane — `Other` events land here when that work begins).

mod codec;
mod event;
mod worker;

use bytes::Bytes;
use codec::brain_codec;
use event::{Event, ParseError};
use futures::{SinkExt, StreamExt};
use std::path::{Path, PathBuf};
use tokio::net::{UnixListener, UnixStream};
use tokio_util::codec::Framed;

/// Client-facing socket: `$BRAIN_SOCKET`, else `./run/brain.sock`. Mirrors
/// `brain_socket_path()` in the Python tree, so clients reach the same inode.
fn socket_path() -> PathBuf {
    std::env::var_os("BRAIN_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("run/brain.sock"))
}

/// Backend worker socket: `$BRAIN_WORKER_SOCKET`, else `./run/brain-worker.sock`.
/// The brain is a CLIENT to this; worker.py binds it.
fn worker_socket_path() -> PathBuf {
    std::env::var_os("BRAIN_WORKER_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("run/brain-worker.sock"))
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let path = socket_path();
    let worker_path = worker_socket_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Real stale-socket handling (flock guard + inode-probe + per-lane umask) is
    // milestone-3 work; for now just clear a leftover so bind() doesn't EADDRINUSE.
    let _ = std::fs::remove_file(&path);

    let listener = UnixListener::bind(&path)?;
    eprintln!("[rust-brain] listening on {}", path.display());
    eprintln!("[rust-brain] tool worker at {}", worker_path.display());

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                // One task per connection, on the multi-thread runtime — this is
                // where real (non-GIL-serialized) parallelism lives. Each task
                // gets its own handle to the worker path.
                let worker_path = worker_path.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, worker_path).await {
                        eprintln!("[rust-brain] connection error: {e}");
                    }
                });
            }
            Err(e) => eprintln!("[rust-brain] accept failed: {e}"),
        }
    }
}

/// One request per connection: read a single frame, dispatch, write one frame,
/// then drop the stream (close). Mirrors `handle_client` in thebrain.py.
async fn handle_client(stream: UnixStream, worker_path: PathBuf) -> std::io::Result<()> {
    let mut framed = Framed::new(stream, brain_codec());

    let frame = match framed.next().await {
        Some(Ok(bytes)) => bytes,
        Some(Err(e)) => {
            eprintln!("[rust-brain] dropped connection: {e}");
            return Ok(());
        }
        None => return Ok(()),
    };

    let response = match std::str::from_utf8(&frame) {
        Ok(message) => dispatch(message, &worker_path).await,
        Err(_) => "Error: non-UTF8 payload".to_string(),
    };

    framed.send(Bytes::from(response)).await?;
    Ok(())
}

/// Parse, then exhaustively match to ROUTE the event. Tool events go to the
/// Python worker; everything else is handled (or rejected) here on the brain.
async fn dispatch(message: &str, worker_path: &Path) -> String {
    let event = match Event::parse(message) {
        Ok(ev) => ev,
        // Same reply the Python handle_client gives — rejected before it ever
        // reaches the worker.
        Err(ParseError::Malformed(_)) => return "Error: Malformed event".to_string(),
    };

    match event {
        // Tool events execute in Python. Forward the ORIGINAL validated message
        // verbatim (no re-serialization) and relay the worker's reply — the
        // brain is a transparent proxy for the tool-execution half.
        ev @ (Event::ScanTools { .. } | Event::CallTool { .. }) => {
            match worker::forward(worker_path, message).await {
                Ok(reply) => reply,
                Err(e) => worker_unreachable_reply(&ev, &e),
            }
        }

        // Handler-table / control-plane events (the EVENT_HANDLERS table and the
        // legacy C fallthrough in Python dispatch). Not yet designed in Rust;
        // this is where the execution tracker / kill switch will land.
        Event::Other {
            event_type,
            session_id,
            payload,
        } => {
            format!("TODO handler({event_type:?}, session={session_id}, payload={payload:?})")
        }
    }
}

/// Build the reply when the worker can't be reached, in the shape the client
/// expects for that event type: a JSON error envelope for CALL_TOOL (clients
/// `json.loads` it), a plain `ERROR:` string for SCAN_TOOLS. Proper JSON
/// serialization (serde) is worth adding once the brain emits more envelopes;
/// one hand-built fallback doesn't justify the dep yet.
fn worker_unreachable_reply(event: &Event, err: &std::io::Error) -> String {
    let detail = err.to_string().replace('"', "'"); // keep the JSON well-formed
    match event {
        Event::CallTool { tool_id, .. } => format!(
            "{{\"status\":\"error\",\"tool_id\":{tool_id:?},\"error\":\"brain worker unreachable: {detail}\"}}"
        ),
        _ => format!("ERROR: brain worker unreachable: {detail}"),
    }
}
