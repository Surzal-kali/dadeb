//! Client side of the Rust brain -> Python tool-worker link.
//!
//! The split we decided on: the brain owns the socket, framing, and dispatch
//! routing; actual tool execution stays in Python (the ~218 @framework_tool
//! callables, the per-session stateful clients). This module is how the brain
//! hands a tool event to the long-lived Python worker and gets its reply back.
//!
//! The payoff of milestone 1: the brain<->worker hop reuses `brain_codec()`, so
//! it is byte-for-byte identical to the client<->brain hop. One framing layer,
//! used on both links — the worker speaks the exact same protocol the clients do.

use crate::codec::brain_codec;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use std::path::Path;
use std::time::Duration;
use tokio::net::UnixStream;
use tokio_util::codec::Framed;

/// Tool-execution ceiling the worker applies (tool_exec's BRAIN_EXEC_CEILING);
/// the backstop below must sit ABOVE it.
const DEFAULT_EXEC_CEILING: f64 = 3600.0;

/// Coarse backstop so a wedged worker can't pin a brain connection forever. This is NOT
/// the per-tool execution ceiling (that's the execution tracker's job in tool_exec) and
/// it must never pre-empt it: a brain that backstops before the ceiling would report
/// "worker unreachable" while the tool is still executing, and the tracker's graceful
/// kill + verdict would never reach the client. Default: BRAIN_EXEC_CEILING + 30s slack
/// so the tracker always fires first. BRAIN_WORKER_TIMEOUT (seconds) overrides — 0
/// disables the backstop entirely (a wedged worker then pins its connection, an
/// operator's explicit choice).
fn backstop_timeout() -> Option<Duration> {
    if let Some(raw) = std::env::var_os("BRAIN_WORKER_TIMEOUT") {
        if let Ok(secs) = raw.to_string_lossy().trim().parse::<f64>() {
            return if secs > 0.0 {
                Some(Duration::from_secs_f64(secs))
            } else {
                None
            };
        }
        // Invalid override falls through to the ceiling-derived default.
    }
    let ceiling = std::env::var_os("BRAIN_EXEC_CEILING")
        .map(|raw| raw.to_string_lossy().trim().parse::<f64>().unwrap_or(0.0))
        .unwrap_or(0.0);
    Some(Duration::from_secs_f64(
        if ceiling > 0.0 { ceiling } else { DEFAULT_EXEC_CEILING } + 30.0,
    ))
}

/// Forward one already-validated message to the Python worker and return its
/// reply as a string.
///
/// Connect-per-request (one request per connection) — the same lifecycle as the
/// client-facing side. The worker PROCESS is long-lived and holds the registry
/// across requests; only the connections are per-call. A connection pool is a
/// later optimization, unnecessary while multi-second tool calls dominate the
/// latency budget.
pub async fn forward(worker_path: &Path, message: &str) -> std::io::Result<String> {
    let exchange = async {
        let stream = UnixStream::connect(worker_path).await?;
        let mut framed = Framed::new(stream, brain_codec());

        // Send the message verbatim; read exactly one framed reply.
        framed.send(Bytes::from(message.to_owned())).await?;
        match framed.next().await {
            Some(Ok(reply)) => Ok(String::from_utf8_lossy(&reply).into_owned()),
            Some(Err(e)) => Err(e),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "worker closed the connection without replying",
            )),
        }
    };

    match backstop_timeout() {
        Some(timeout) => match tokio::time::timeout(timeout, exchange).await {
            Ok(result) => result,
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("worker did not reply within {timeout:?}"),
            )),
        },
        None => exchange.await,
    }
}
