"""``main()`` argv dispatch — the one-shot CLI modes.

We do NOT use argparse for the ``run`` subcommand because tool flags like
``--target``, ``--port`` etc would collide with argparse's own flags —
sys.argv is parsed directly and dispatched manually.
"""

import asyncio
import sys

from replkit.commands import oneshot_info, oneshot_run, repl_loop
from replkit.core import (
    discover_tools,
    print_manifest,
    run_selftest,
)
from replkit.operator_cli import _engagement_command, _scope_command


def main():
    args = sys.argv[1:]
    if not args:
        # Interactive REPL
        print("Discovering tools...")
        manifests = discover_tools()
        print(f"Found {len(manifests)} tools. Type 'help' for commands.\n")
        asyncio.run(repl_loop(manifests))
        return

    if args[0] == "--kernel":
        # Kernelspec frontends append -f <connection_file>; everything after
        # --kernel goes straight to IPKernelApp.
        from replkit.kernel_lane import _launch_kernel
        _launch_kernel(sys.argv[2:])
        return

    if args[0] == "--install-kernelspec":
        from replkit.kernel_lane import _install_kernelspec
        _install_kernelspec()
        return

    mode = args[0]

    if mode == "run":
        if len(args) < 2:
            print("Usage: python tool_repl.py run <tool_id> [--flag value ...]")
            print("       python tool_repl.py run <tool_id> --json '{...}'")
            print("       python tool_repl.py run <tool_id>   (uses safe defaults)")
            sys.exit(1)
        tool_id = args[1]
        arg_tokens = args[2:]
        sys.exit(asyncio.run(oneshot_run(tool_id, arg_tokens)))

    elif mode == "info":
        if len(args) < 2:
            print("Usage: python tool_repl.py info <tool_id>")
            sys.exit(1)
        sys.exit(asyncio.run(oneshot_info(args[1])))

    elif mode == "selftest":
        # Thin CLI passthrough for the pytest macro — same lane the REPL's
        # ``selftest`` command uses; ``--force`` muscle memory is accepted
        # and ignored by run_selftest.
        from replkit.core import run_selftest as _st
        sys.exit(run_selftest(args[1:]))

    elif mode == "scope":
        # Operator-only scope gate control — the ONLY path to arm/disarm.
        # scope_on/scope_off are deliberately not in the kernel namespace,
        # so an agent in execute_code cannot toggle the gate.
        rest = " ".join(args[1:])
        _scope_command(rest)
        return

    elif mode == "engagement":
        # Operator-only engagement cobweb control — the ONLY path to arm,
        # disarm, and purge (same authority model as scope).
        #   python tool_repl.py engagement on blue.htb [roe note...]
        #   python tool_repl.py engagement off
        #   python tool_repl.py engagement status
        #   python tool_repl.py engagement purge blue.htb
        rest = " ".join(args[1:])
        _engagement_command(rest)
        return

    elif mode == "search":
        if len(args) < 2:
            print("Usage: python tool_repl.py search <query>")
            sys.exit(1)
        query = " ".join(args[1:])

        async def _search():
            from daharness.registry import OllamaEmbeddingFunction, ToolRegistry as RealRegistry
            real_reg = RealRegistry(embedding_model=OllamaEmbeddingFunction())
            results = await real_reg.find_tools(query)
            if not results:
                print("No results.")
            for m in results:
                dist = f"  dist={m.distance}" if m.distance is not None else ""
                print_manifest(m, verbose=True)
                print(f"    {dist}")

        asyncio.run(_search())

    else:
        print(f"Unknown mode: {mode}")
        print("Modes: run, info, selftest, search, scope, engagement")
        print("Kernel lane: --kernel, --install-kernelspec")
        print("Or run without arguments for the interactive REPL.")
        sys.exit(1)