# /etc/profile.d/daharness.sh — operator-shell plumbing for the system
# profile (installed by the daharness deb; a no-op on dev trees, which do
# not install this file).
#
# The systemd units read /etc/daharness/daharness.env via EnvironmentFile;
# operator shells do not. Without this, an interactive lane resolves the
# constants fallbacks (code-tree roots): the brain socket points at
# /usr/share/daharness/run/brain.sock where nothing ever binds, and the
# state root points at the read-only code directory — so a healthy install
# reports "brain down" and "ids.db cannot be made" from its own operator's
# shell. This exports the system-profile roots unless the shell already
# carries them: a user-profile lane (own WORKSPACE_ROOT/BRAIN_SOCKET, the
# deltas documented in the conffile) wins by exporting first.
#
# Seeing the service lane's state still requires group membership — the deb
# does NOT auto-enroll anyone (Docker pattern). The operator opts in manually:
#   sudo usermod -aG daharness $USER   (then re-login or `newgrp daharness`)
_dh_conf=/etc/daharness/daharness.env
if [ -r "$_dh_conf" ]; then
    if [ -z "${WORKSPACE_ROOT:-}" ]; then
        WORKSPACE_ROOT=$(sed -n 's/^WORKSPACE_ROOT=//p' "$_dh_conf" | tail -n1 | tr -d '"')
        [ -n "$WORKSPACE_ROOT" ] && export WORKSPACE_ROOT
    fi
    if [ -z "${BRAIN_SOCKET:-}" ]; then
        BRAIN_SOCKET=$(sed -n 's/^BRAIN_SOCKET=//p' "$_dh_conf" | tail -n1 | tr -d '"')
        [ -n "$BRAIN_SOCKET" ] && export BRAIN_SOCKET
    fi
fi
unset _dh_conf
# Lane DB credentials: engagement.py's defaults are the init bundle's
# PLACEHOLDER passwords; the live cluster rolls random hex per lane (minted
# by `daharness-pg init` into /etc/daharness/pg.env — the same file the
# systemd units source via EnvironmentFile, and the file pg.env(1)'s
# operators sourced by hand). Without it the operator REPL authenticates
# with the placeholder and the engagement lane reports "DB unavailable"
# from a healthy cluster (live 2026-11-19: arm succeeded locally but the
# lane could never register). pg.env is root:daharness 0640 — a member of
# the daharness group can read it, everyone else degrades to the current
# behavior (lane off, SQLite mirror). Guarded: any HARNESS_DB_* value the
# shell already carries wins — this only fills a silence.
if [ -r /etc/daharness/pg.env ] && [ -z "${HARNESS_DB_PASSWORD_REPL:-}" ]; then
    . /etc/daharness/pg.env
    # pg.env declares bare KEY=VALUE (EnvironmentFile style, no `export`):
    # sourcing only assigns shell vars — re-export them so child processes
    # (the REPL python) actually inherit the credentials (live 2026-11-19:
    # sh saw the values, python saw None).
    export HARNESS_DB_HOST HARNESS_DB_PORT HARNESS_DB_NAME \
        HARNESS_DB_PASSWORD_REPL HARNESS_DB_PASSWORD_BRAIN \
        HARNESS_DB_PASSWORD_GATEWAY HARNESS_DB_PASSWORD_OPERATOR 2>/dev/null
fi