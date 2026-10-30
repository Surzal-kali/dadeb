//! Wire event parsing for the Brain protocol.
//!
//! The Python Brain (listeners/thebrain.py) speaks a text triplet inside each
//! frame:  `event_type|session_id|payload`  — split on '|' at most twice, so
//! the payload may itself contain '|'. `dispatch()` then branches on
//! `event_type` with an if-ladder.
//!
//! Here we parse that triplet into a typed `Event` up front, so dispatch becomes
//! an EXHAUSTIVE `match` the compiler checks — add a variant and every match
//! site that forgot to handle it fails to build. That is the structural win over
//! the stringly-typed ladder.

/// A parsed Brain request. One frame == one `Event`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// `SCAN_TOOLS|<session>|<path>` — prime/extend the tool registry.
    /// An empty path means "framework root" in the Python default; dispatch
    /// decides that, not the parser.
    ScanTools { session_id: i32, path: String },

    /// `CALL_TOOL|<session>|<tool_id>[|<args_json>]` — invoke a registered tool.
    /// In the Python wire form the payload after the session id is itself
    /// `tool_id|args`, split once more; `args` is absent when the caller sent a
    /// bare tool id.
    CallTool {
        session_id: i32,
        tool_id: String,
        args: Option<String>,
    },

    /// Any other `event_type`: the handler-table events and the legacy C
    /// fallthrough in the Python dispatch(). Kept as a catch-all so the match
    /// over `Event` stays total without pretending to know every event name.
    Other {
        event_type: String,
        session_id: i32,
        payload: String,
    },
}

/// Why a frame could not be parsed into an `Event`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Fewer than three '|'-separated fields, or a non-integer session id.
    /// Mirrors the Python "Malformed event" branch in handle_client.
    Malformed(String),
}

impl Event {
    /// Parse one decoded message body into an `Event`.
    ///
    /// Equivalent of the Python:
    ///   `event_type, session_id, payload = message.split('|', 2)`
    /// plus the `int(session_id)` coercion, both of which raise on bad input.
    pub fn parse(message: &str) -> Result<Self, ParseError> {
        // splitn(3, ..) mirrors split('|', 2): at most 3 pieces, the last of
        // which keeps any remaining '|'.
        let mut parts = message.splitn(3, '|');
        let event_type = parts.next().unwrap_or("");

        let (session_raw, payload) = match (parts.next(), parts.next()) {
            (Some(s), Some(p)) => (s, p),
            // Missing the session field and/or the payload field entirely.
            _ => return Err(ParseError::Malformed(message.to_string())),
        };

        let session_id: i32 = session_raw
            .trim()
            .parse()
            .map_err(|_| ParseError::Malformed(message.to_string()))?;

        Ok(match event_type {
            "SCAN_TOOLS" => Event::ScanTools {
                session_id,
                path: payload.to_string(),
            },
            "CALL_TOOL" => {
                // Python: payload.split('|', 1) -> (tool_id, args_str?)
                let mut cp = payload.splitn(2, '|');
                let tool_id = cp.next().unwrap_or("").to_string();
                let args = cp.next().map(str::to_string);
                Event::CallTool {
                    session_id,
                    tool_id,
                    args,
                }
            }
            other => Event::Other {
                event_type: other.to_string(),
                session_id,
                payload: payload.to_string(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scan_tools() {
        assert_eq!(
            Event::parse("SCAN_TOOLS|0|auxiliaries").unwrap(),
            Event::ScanTools { session_id: 0, path: "auxiliaries".into() }
        );
    }

    #[test]
    fn call_tool_with_and_without_args() {
        assert_eq!(
            Event::parse("CALL_TOOL|3|nmap.scan|{\"target\":\"x\"}").unwrap(),
            Event::CallTool {
                session_id: 3,
                tool_id: "nmap.scan".into(),
                args: Some("{\"target\":\"x\"}".into()),
            }
        );
        assert_eq!(
            Event::parse("CALL_TOOL|0|list_sessions").unwrap(),
            Event::CallTool { session_id: 0, tool_id: "list_sessions".into(), args: None }
        );
    }

    #[test]
    fn payload_keeps_inner_pipes() {
        // Only the first two '|' split the triplet; the rest belong to payload.
        match Event::parse("FOO|1|a|b|c").unwrap() {
            Event::Other { payload, .. } => assert_eq!(payload, "a|b|c"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn malformed_is_rejected() {
        assert!(matches!(Event::parse("SCAN_TOOLS|0"), Err(ParseError::Malformed(_))));
        assert!(matches!(Event::parse("no pipes here"), Err(ParseError::Malformed(_))));
        assert!(matches!(Event::parse("CALL_TOOL|notanint|x"), Err(ParseError::Malformed(_))));
    }
}
