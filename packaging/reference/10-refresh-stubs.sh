#!/bin/bash
# before-notebook.d hook: refresh the framework tool stubs + pyright config
# from the runtime bind mount, every container start.
#
# ⚠ SOURCED by run-hooks.sh, never executed — an `exit` here does not exit the
# hook, it exits start.sh itself. That was the restart-loop bug: the container
# died cleanly (exitCode=0) right after the hook ran, ~hook-duration later,
# forever (RestartCount 14→38 while the server never came up). Early-outs use
# `return`; the tail line tolerates both invocation styles. Never `cd` outside
# a subshell — start.sh execs the server with the inherited cwd.
#
# Why both a build copy and a boot refresh: bind mounts don't exist during
# docker build, so the image carries a frozen stub set generated from a COPY'd
# framework tree; at boot the LIVE mount is authoritative, so this hook
# regenerates over the baked copies (new tools land without waiting for a
# rebuild). Failure is non-fatal: the baked stubs keep LSP working, just
# potentially stale — failure is logged and non-fatal.
#
# Outputs:
#   /opt/conda/share/framework-stubs/     ← pyrightconfig stubPath points here
#   /home/jovyan/work/pyrightconfig.json  ← notebooks dir is a host bind-mount;
#       the image-baked copy would be shadowed, so we (re)write it here.
# Only placed when absent — an operator-pinned file in work/ wins. The baked
# source lives in jupyter.Dockerfile's pyrightconfig.d heredoc.

LOG=/tmp/refresh-stubs.log
{
  echo "=== refresh-stubs $(date -Is) ==="

  if [ -d /home/jovyan/framework/scripts ] && [ -f /home/jovyan/framework/tool_repl.py ]; then
    # Subshell: keep start.sh's cwd untouched.
    (
      cd /home/jovyan/framework || return 1
      FRAMEWORK_STUBS_DIR=/opt/conda/share/framework-stubs \
        PYTHONDONTWRITEBYTECODE=1 \
        python scripts/gen_repl_stubs.py
      echo "live-tree regeneration exit: $?"
    )
  else
    echo "framework bind mount incomplete; keeping baked stubs"
  fi

  if [ ! -f /home/jovyan/work/pyrightconfig.json ]; then
    if [ -f /opt/conda/share/jupyter/pyrightconfig.d/pyrightconfig.json ]; then
      cp /opt/conda/share/jupyter/pyrightconfig.d/pyrightconfig.json \
         /home/jovyan/work/pyrightconfig.json
      echo "copied baked pyrightconfig.json into work/"
    fi
  fi
} >> "$LOG" 2>&1

# Sourced → return; executed directly (manual debugging) → exit. Never an
# unconditional `exit`: run-hooks.sh sources this file.
return 0 2>/dev/null || exit 0