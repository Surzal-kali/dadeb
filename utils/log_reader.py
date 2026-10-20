import os
from constants import framework_tool

# Chunk size for the backward tail read. Bigger = fewer syscalls on a huge
# log; small enough that we don't overshoot massively when only a few lines
# are requested. 8 KiB is a good middle ground (a typical log line is ~100 B,
# so one chunk already covers ~80 lines).
_TAIL_CHUNK = 8192


def _tail_lines(path: str, lines: int) -> str:
    """Return the last ``lines`` lines of ``path`` without loading the whole
    file into memory.

    Seeks to the end of the file, then reads backwards in fixed-size chunks
    accumulating byte fragments until at least ``lines`` newline boundaries
    have been seen (or the start of the file is reached). This matters for the
    MSF console log: msfrpcd has no rotation, so the file grows unbounded over
    a long engagement, and ``readlines()`` would slurp every byte -- including
    hours of stale output -- into the interpreter just to throw all but the
    tail away.
    """
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        if size == 0:
            return ""

        collected = bytearray()
        pos = size
        newline_count = 0
        # If the file does not end with a newline, count its final line too.
        f.seek(pos - 1)
        if f.read(1) != b"\n":
            newline_count = 1

        while pos > 0 and newline_count < lines:
            read_size = min(_TAIL_CHUNK, pos)
            pos -= read_size
            f.seek(pos)
            chunk = f.read(read_size)
            collected[0:0] = chunk  # prepend in O(n); fine for tail sizes
            newline_count += chunk.count(b"\n")

        text = collected.decode("utf-8", errors="replace")
        # Slice to exactly the requested number of lines (we may have
        # over-read by a fraction of a chunk).
        all_lines = text.splitlines()
        return "\n".join(all_lines[-lines:]) + "\n"


@framework_tool("Read framework logs (Brain and MSF)")
def read_logs(log_type: str, lines: int = 50):
    """
    Read the last N lines of the specified log file.

    Uses a backward seek-from-end read so a large un-rotated log (e.g. the MSF
    console log, which has no rotation) is never fully loaded into memory --
    only the tail is read.

    Args:
        log_type: 'brain' for the Brain sidecar logs, 'msf' for the MSF console logs.
        lines: Number of lines to retrieve from the end of the file.
    """
    log_map = {
        "brain": "/tmp/brain.log",
        "msf": "/tmp/msfconsole_mcp.log"
    }

    path = log_map.get(log_type.lower())
    if not path:
        return f"Error: Invalid log_type '{log_type}'. Use 'brain' or 'msf'."

    if not os.path.exists(path):
        return f"Error: Log file {path} does not exist."

    try:
        return _tail_lines(path, lines)
    except Exception as e:
        return f"Error reading log file: {e}"


