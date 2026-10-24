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