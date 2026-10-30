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

/// Coarse backstop so a wedged worker can't pin a brain connection forever.
/// This is NOT the per-tool execution ceiling (that's the execution tracker's
/// job, a later milestone) — just a guard on the whole connect+exchange.
const WORKER_TIMEOUT: Duration = Duration::from_secs(60);

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

    match tokio::time::timeout(WORKER_TIMEOUT, exchange).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("worker did not reply within {WORKER_TIMEOUT:?}"),
        )),
    }
}
