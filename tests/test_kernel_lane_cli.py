"""Kernelspec CLI dispatch (deb-lane lesson, 2026-10-20).

``daharness-kernel`` prepends --kernel for the unit lane, so the operator's
``--install-kernelspec`` arrived AFTER it and was fed straight into
IPKernelApp (a dead end), while ``daharness --install-kernelspec`` died on
argparse's 'invalid choice'. The wrapper shape now routes to the installer
and the services wrapper prints the redirect.
"""

import asyncio
import sys

import bootstrap
from replkit import cli as repl_cli


def _patch_lane(monkeypatch, calls):
    import replkit.kernel_lane as lane

    def install():
        calls.append("install")

    def launch(argv):
        calls.append(("launch", list(argv)))

    monkeypatch.setattr(lane, "_install_kernelspec", install)
    monkeypatch.setattr(lane, "_launch_kernel", launch)


def test_kernel_wrapper_install_shape(monkeypatch):
    """`daharness-kernel --install-kernelspec` == --kernel --install-kernelspec."""
    calls = []
    _patch_lane(monkeypatch, calls)
    monkeypatch.setattr(sys, "argv",
                        ["tool_repl.py", "--kernel", "--install-kernelspec"])
    repl_cli.main()
    assert calls == ["install"]


def test_bare_install_flag(monkeypatch):
    """`daharness-repl --install-kernelspec` keeps working (dev-tree shape)."""
    calls = []
    _patch_lane(monkeypatch, calls)
    monkeypatch.setattr(sys, "argv", ["tool_repl.py", "--install-kernelspec"])
    repl_cli.main()
    assert calls == ["install"]


def test_frontend_shape_still_launches(monkeypatch):
    """Kernelspec frontends append -f <connection_file> after --kernel; that
    shape must keep driving IPKernelApp, never the installer."""
    calls = []
    _patch_lane(monkeypatch, calls)
    monkeypatch.setattr(sys, "argv",
                        ["tool_repl.py", "--kernel", "-f", "conn-1.json"])
    repl_cli.main()
    assert calls == [("launch", ["-f", "conn-1.json"])]


def test_services_wrapper_redirects(monkeypatch, capsys):
    """`daharness --install-kernelspec` is not the services wrapper's job:
    print the kernel-lane redirect and exit without touching argparse."""
    def _no_parse():
        raise AssertionError("reached argparse instead of the redirect")

    monkeypatch.setattr(bootstrap, "_build_cli", _no_parse)
    monkeypatch.setattr(sys, "argv",
                        ["bootstrap.py", "--install-kernelspec"])
    try:
        asyncio.run(bootstrap.run_framework())
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("expected sys.exit(2) on the redirect")
    out = capsys.readouterr().out
    assert "daharness-kernel --install-kernelspec" in out