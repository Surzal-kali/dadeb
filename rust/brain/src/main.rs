//! Rust Brain port — transport, framing, typed dispatch, the Python tool-worker
//! IPC seam, and the start-up OS singleton dance.
//!
//! Milestones so far:
//!   1. transport + framing (codec.rs) + typed `Event` dispatch (event.rs);
//!   2. tool events forwarded to a long-lived Python worker (worker.rs ->
//!      worker.py) over the same codec; the brain is a transparent proxy for
//!      the tool-execution half (tools stay in Python);
//!   3. the OS singleton dance (singleton.rs): flock guard, stale-socket probe,
//!      per-lane umask/permissions, unlink-on-exit — ported from
//!      listeners/thebrain.py start_brain(), with SIGTERM/SIGINT routed to a
//!      graceful shutdown so the cleanup actually runs.
//!
//! Still in Python (by design): tool execution, the registry + per-session
//! isolation, the scope gate, and the execution tracker / kill switch — all in
//! the worker, next to where the threads and child processes actually live.

mod codec;
mod event;
mod singleton;
mod worker;

use bytes::Bytes;
use codec::brain_codec;
use event::{Event, ParseError};
use futures::{SinkExt, StreamExt};
use std::path::{Path, PathBuf};
use tokio::net::{UnixListener, UnixStream};
use tokio_util::codec::Framed;

/// Client-facing socket: `$BRAIN_SOCKET`, else `./run/brain.sock`. Mirrors
/// `brain_socket_path()` in the Python tree so clients reach the same inode.
fn socket_path() -> PathBuf {
    std::env::var_os("BRAIN_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("run/brain.sock"))
}

/// Backend worker socket: `$BRAIN_WORKER_SOCKET`, else `./run/brain-worker.sock`.
fn worker_socket_path() -> PathBuf {
    std::env::var_os("BRAIN_WORKER_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("run/brain-worker.sock"))
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let path = socket_path();
    let worker_path = worker_socket_path();

    // Singleton guard + stale-socket handling + lane-correct bind, all in one.
    // `_guard` MUST stay in scope for the whole run: dropping it releases the
    // flock and unlinks our socket.
    let (listener, _guard) = singleton::acquire_and_bind(&path)?;
    eprintln!("[rust-brain] listening on {}", path.display());
    eprintln!("[rust-brain] tool worker at {}", worker_path.display());

    // Accept loop vs. shutdown signal. On SIGTERM/SIGINT we break out so main
    // returns, `_guard` drops, and its Drop unlinks the socket + releases the
    // lock — the Rust analog of thebrain.py routing both signals through task
    // cancellation so its `finally` cleanup runs. (A bare process exit on an
    // unhandled signal would skip Drop and leak the socket file.)
    tokio::select! {
        _ = accept_loop(listener, worker_path) => {}
        _ = shutdown_signal() => {
            eprintln!("[rust-brain] shutdown signal received; cleaning up");
        }
    }
    Ok(())
}

/// Accept connections forever, one task per connection on the multi-thread
/// runtime — where real (non-GIL-serialized) parallelism lives.
async fn accept_loop(listener: UnixListener, worker_path: PathBuf) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
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

/// Resolve when the process is asked to terminate (SIGTERM, what bootstrap.stop()
/// sends) or interrupted (SIGINT / Ctrl-C).
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    let mut intr = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = intr.recv() => {}
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
        Err(ParseError::Malformed(_)) => return "Error: Malformed event".to_string(),
    };

    match event {
        // Tool events execute in Python. Forward the ORIGINAL validated message
        // verbatim (no re-serialization) and relay the worker's reply.
        ev @ (Event::ScanTools { .. } | Event::CallTool { .. }) => {
            match worker::forward(worker_path, message).await {
                Ok(reply) => reply,
                Err(e) => worker_unreachable_reply(&ev, &e),
            }
        }

        // Handler-table / control-plane events: not yet designed in Rust.
        Event::Other {
            event_type,
            session_id,
            payload,
        } => {
            format!("TODO handler({event_type:?}, session={session_id}, payload={payload:?})")
        }
    }
}

/// Reply when the worker can't be reached, in the shape the client expects for
/// that event type: a JSON error envelope for CALL_TOOL (clients `json.loads`
/// it), a plain `ERROR:` string for SCAN_TOOLS.
fn worker_unreachable_reply(event: &Event, err: &std::io::Error) -> String {
    let detail = err.to_string().replace('"', "'"); // keep the JSON well-formed
    match event {
        Event::CallTool { tool_id, .. } => format!(
            "{{\"status\":\"error\",\"tool_id\":{tool_id:?},\"error\":\"brain worker unreachable: {detail}\"}}"
        ),
        _ => format!("ERROR: brain worker unreachable: {detail}"),
    }
}
