//! Length-prefixed framing for the Brain socket.
//!
//! Faithful to listeners/thebrain.py `pack_message` / `read_message`:
//!   - 4-byte BIG-ENDIAN length header ("!I" in Python struct terms)
//!   - the length counts the payload only, not the 4 header bytes
//!   - a hard ceiling (MAX_MESSAGE_SIZE) rejects a bogus/oversized declared
//!     length before it can drive an unbounded read (the Python `ValueError`
//!     guard in read_message)
//!
//! tokio_util's `LengthDelimitedCodec` implements exactly this wire shape; we
//! only configure it. The ~40 lines of pack_message/read_message collapse into
//! this one builder, and the result is byte-for-byte compatible with the
//! Python Brain — existing clients connect unchanged.

use tokio_util::codec::LengthDelimitedCodec;

/// 10 MiB — the same guard as Python's `MAX_MESSAGE_SIZE`.
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Build the Brain's wire codec: 4-byte big-endian length prefix, payload-only
/// length, 10 MiB frame ceiling.
pub fn brain_codec() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_offset(0)
        .length_field_length(4) // 4-byte header
        .big_endian() // network order == Python "!"
        .max_frame_length(MAX_MESSAGE_SIZE)
        .new_codec()
}
