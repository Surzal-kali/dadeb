"""replkit — the operator REPL package.

Everything that used to live in the monolithic top-level ``tool_repl.py``,
split into focused modules. The top-level ``tool_repl.py`` remains as a
thin backwards-compat shim (the *filename* is load-bearing: kernelspecs,
docker init scripts, the systemd unit and the journal's lane inference all
launch or match ``tool_repl.py`` by name) — it re-exports every public and
load-bearing private name from the modules here.

Module map
----------
:mod:`replkit.safe_args`      — SAFE_ARGS table (bare-`run` defaults) + sweep skip-set.
:mod:`replkit.aliases`        — curated alias table + derivation + collision merge.
:mod:`replkit.envelope`       — find/pluck/grep/keys/scratch result-tree helpers.
:mod:`replkit.completer`      — prompt_toolkit completer for the ``repl>`` prompt.
:mod:`replkit.core`           — discovery, execution, flag-arg parsing, printers.
:mod:`replkit.brain_lane`     — direct Brain-socket helpers (SHARED-session lane).
:mod:`replkit.operator_cli`  — scope-gate + engagement-cobweb operator commands.
:mod:`replkit.wrappers`      — per-tool async wrappers (signature + docstring).
:mod:`replkit.namespace`      — build_ipython_namespace (kernel/embed user_ns).
:mod:`replkit.ipython_embed`  — the ``ipython`` command (toolbars, F-keys, styles).
:mod:`replkit.kernel_lane`    — ZMQ kernel launch + kernelspec install.
:mod:`replkit.commands`       — interactive loop (repl_loop) + one-shot commands.
:mod:`replkit.cli`            — main() argv dispatch.

Import order matters here: modules import each other directly (never from
the top-level shim — keep the shim a leaf so importing it never pulls the
optional heavyweight lanes: ipykernel, IPython are imported lazily inside
functions, prompt_toolkit/IPython imports are guarded per-module).
"""