"""Brain socket lane-shaping regression: the bind follows the socket dir.

2026-10-20 pass — the old code chmod'd the socket dir to 0777 and bound at
umask 0, widening /run/daharness (unit says 0770) and shipping a world-
connectable socket everywhere. The fix: one decision point
(listeners.thebrain.socket_lane_perms) mapping the dir's own bits to
(umask, socket perm, lock perm). These tests pin that decision AND bind a
real Brain (startup scan stubbed — discovery is covered in
test_tool_addition_lane.py) so a regression here fails as a unit test, not
only as an operator report on the deb box.
"""

import asyncio
import contextlib
import socket
import stat
from pathlib import Path

import pytest

try:
    import listeners.thebrain as tb
except OSError:
    # Module-level CDLL of listeners/plugins/frameit.so is deliberate
    # fail-loud (see l2_import_floor audit notes) — the suite degrades
    # honestly here with the build command, same as the tools' error paths.
    pytest.skip(
        "listeners.thebrain needs frameit.so built: "
        "gcc -shared -o listeners/plugins/frameit.so -fPIC listeners/plugins/frameit.c",
        allow_module_level=True,
    )


# --- lane decision (pure) -----------------------------------------------------

@pytest.mark.parametrize(
    "dir_mode,expected",
    [
        (0o2770, (0o007, 0o770, 0o660)),  # system profile: setgid state root
        (0o770, (0o007, 0o770, 0o660)),
        (0o0770, (0o007, 0o770, 0o660)),
        # A dir that is BOTH group- and world-writable is the group lane:
        # group-writable wins (socket group = creator's group, which the
        # operator is already in; the deb grants are group-based).
        (0o777, (0o007, 0o770, 0o660)),
        (0o1777, (0o007, 0o770, 0o660)),
        (0o707, (0o000, 0o777, 0o666)),  # world-writable, no group write
        (0o1770, (0o007, 0o770, 0o660)),  # sticky + group-writable
        (0o755, (0o077, 0o700, 0o600)),  # dev checkout, default umask 0022
        (0o750, (0o077, 0o700, 0o600)),  # group r-x, no group write
    ],
)
def test_socket_lane_perms(dir_mode, expected):
    assert tb.socket_lane_perms(dir_mode) == expected


# --- real bind (scan stubbed) --------------------------------------------------

@pytest.mark.parametrize(
    "dir_mode,sock_perm,lock_perm",
    [
        (0o2770, 0o770, 0o660),
        (0o707, 0o777, 0o666),  # world lane: writable without any group write
        (0o755, 0o700, 0o600),
    ],
)
def test_start_brain_binds_at_lane_trust(tmp_path, monkeypatch, dir_mode, sock_perm, lock_perm):
    sock_dir = tmp_path / "run"
    sock_dir.mkdir()
    sock_dir.chmod(dir_mode)
    sock_path = sock_dir / "brain.sock"

    monkeypatch.setattr(tb, "socket_path", str(sock_path))
    monkeypatch.setattr(tb, "_startup_scan", lambda: None)

    async def drive():
        task = asyncio.create_task(tb.start_brain())
        for _ in range(400):
            if sock_path.exists():
                break
            await asyncio.sleep(0.05)
        else:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            pytest.fail(f"Brain socket never appeared at {sock_path}")

        try:
            assert (sock_path.stat().st_mode & 0o777) == sock_perm, stat.filemode(
                sock_path.stat().st_mode
            )
            lock = sock_dir / "brain.lock"
            assert (lock.stat().st_mode & 0o777) == lock_perm, stat.filemode(
                lock.stat().st_mode
            )
            # A lane the socket trusts must actually be able to connect.
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            with probe:
                probe.settimeout(2.0)
                probe.connect(str(sock_path))
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

        # Clean shutdown unlinks the socket (inode-guarded finally).
        return not sock_path.exists()

    # Main thread of the test process — add_signal_handler inside start_brain
    # needs one, asyncio.run provides it.
    unlinked = asyncio.run(drive())
    assert unlinked, "start_brain left its socket bound after cancellation"