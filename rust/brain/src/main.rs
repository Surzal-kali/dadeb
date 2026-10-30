//! Milestone 1 of the Rust Brain port: transport + framing + typed dispatch.
//!
//! What this IS (deliberately narrow — see rust/brain/README.md):
//!   * a tokio Unix-domain-socket server, ONE request per connection, matching
//!     the shape of `handle_client` in listeners/thebrain.py (read one frame,
//!     dispatch, write one frame, close);
//!   * length-prefixed framing (codec.rs), wire-compatible with the Python
//!     Brain so existing clients connect unchanged;
//!   * the text triplet parsed into a typed `Event` (event.rs) and dispatched
//!     through an EXHAUSTIVE `match`.
//!
//! What this is NOT yet (the parts we scoped out, on purpose):
//!   * tool execution — stays in Python behind a worker-process IPC hop. The
//!     SAME codec + Event will carry that link; `dispatch()` returns stubs here.
//!   * the OS-level singleton dance (flock, stale-inode unlink, per-lane umask).
//!   * the execution tracker / kill switch / ceilings.

mod codec;
mod event;

use bytes::Bytes;
use codec::brain_codec;
use event::{Event, ParseError};
use futures::{SinkExt, StreamExt};
use std::path::PathBuf;
use tokio::net::{UnixListener, UnixStream};
use tokio_util::codec::Framed;

/// Resolve the socket path: `$BRAIN_SOCKET`, else `./run/brain.sock` — the
/// checkout's run/ dir, mirroring `brain_socket_path()` in the Python tree.
fn socket_path() -> PathBuf {
    std::env::var_os("BRAIN_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("run/brain.sock"))
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let path = socket_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // The real stale-socket handling (flock singleton guard + inode-probe before
    // unlink + per-lane umask) is milestone-2 work. For now just clear a leftover
    // file so bind() doesn't fail with EADDRINUSE.
    let _ = std::fs::remove_file(&path);

    let listener = UnixListener::bind(&path)?;
    eprintln!("[rust-brain] listening on {}", path.display());

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                // One task per connection. Unlike the Python asyncio loop (one
                // thread + GIL), these run on the multi-thread runtime — this
                // accept loop is where real parallelism will live once dispatch
                // does real work.
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream).await {
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
async fn handle_client(stream: UnixStream) -> std::io::Result<()> {
    let mut framed = Framed::new(stream, brain_codec());

    // Exactly one message. `None` = client closed without sending; a decode
    // error (e.g. a frame over the 10 MiB ceiling) ends the connection, the same
    // outcome as the Python IncompleteReadError / ValueError drop.
    let frame = match framed.next().await {
        Some(Ok(bytes)) => bytes,
        Some(Err(e)) => {
            eprintln!("[rust-brain] dropped connection: {e}");
            return Ok(());
        }
        None => return Ok(()),
    };

    let response = match std::str::from_utf8(&frame) {
        Ok(message) => dispatch(message),
        Err(_) => "Error: non-UTF8 payload".to_string(),
    };

    framed.send(Bytes::from(response)).await?;
    Ok(())
}

/// Parse, then exhaustively match. This is the payoff: every `Event` variant is
/// handled or the build fails. Real behaviour lands in later milestones; for now
/// each arm returns a clearly-marked stub so the whole wire path is end-to-end
/// testable today (see smoke.py).
fn dispatch(message: &str) -> String {
    let event = match Event::parse(message) {
        Ok(ev) => ev,
        // Matches the Python "Error: Malformed event" reply in handle_client.
        Err(ParseError::Malformed(_)) => return "Error: Malformed event".to_string(),
    };

    match event {
        Event::ScanTools { session_id, path } => {
            format!("TODO scan_tools(session={session_id}, path={path:?}) — Python worker IPC")
        }
        Event::CallTool {
            session_id,
            tool_id,
            args,
        } => {
            format!(
                "TODO call_tool(session={session_id}, tool={tool_id:?}, args={args:?}) \
                 — Python worker IPC"
            )
        }
        Event::Other {
            event_type,
            session_id,
            payload,
        } => {
            format!("TODO handler({event_type:?}, session={session_id}, payload={payload:?})")
        }
    }
}
