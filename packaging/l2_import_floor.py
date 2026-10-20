#!/usr/bin/env python3
"""Layer-2 import floor — deb staging QA driver.

Runs one subprocess per ship entry (15s timeout each) and classifies:

  ok         - imports clean
  lazy       - ModuleNotFoundError for a third-party root (expected when the
               interpreter lacks deps, e.g. the bare-venv --no-deps run)
  self_fail  - ModuleNotFoundError pointing INSIDE the tree (typos, missing
               submodules, broken relative imports) = real failure
  other_fail - SyntaxError / OSError / ctypes load failures at import time =
               ship landmines (these kill the Brain's _startup_scan)

The layer-2 landmine this caught: listeners/plugins/frameit.so is a
gitignored build artifact; without it every listeners.* import dies (the
CDLL in listeners/thebrain.py is unguarded and module-level). On a git
checkout, compile it first: gcc -shared -o frameit.so -fPIC frameit.c

Usage:
  python3 packaging/l2_import_floor.py                 # driver + floor python = current interpreter, tree = repo root
  DAHARNESS_FLOOR_PY=/tmp/venv/bin/python python3 packaging/l2_import_floor.py
  DAHARNESS_FLOOR_PY=/usr/bin/python3 \
  DAHARNESS_TREE=/usr/share/daharness   python3 packaging/l2_import_floor.py  

Bare-venv leg (this box): create the venv first — python3 -m venv /tmp/da-l2
&& pip install --no-deps -e . — then set DAHARNESS_FLOOR_PY to its python.
VM leg: point DAHARNESS_TREE at the installed tree (default /usr/share/
daharness) and leave DAHARNESS_FLOOR_PY unset to floor the system python."""
import json, os, subprocess, sys, pathlib

DRIVER_TREE = pathlib.Path(__file__).resolve().parent.parent
PY = os.environ.setdefault("DAHARNESS_FLOOR_PY", sys.executable)
TREE = pathlib.Path(os.environ.setdefault("DAHARNESS_TREE", str(DRIVER_TREE)))
REPORT = os.environ.setdefault("DAHARNESS_FLOOR_REPORT", "/tmp/da-l2-floor.json")
TIMEOUT_S = int(os.environ.get("DAHARNESS_FLOOR_TIMEOUT", "15"))

ROOTS = {"auxiliaries", "payloads", "listeners", "utils", "encoders",
         "evasion", "owui-tools", "engagement", "daharness"}
SKIP_DIRS = {"venv", ".venv", "__pycache__", ".git", "tests", "docs",
             "packaging", "dockered", "node_modules", "dist", "build",
             "daharness.egg-info", "run", ".memory"}
SKIP_FILES = {"conf.py", "setup.py"}  # build machinery, not shipped entries


def ship_modules():
    out = []
    for p in sorted(TREE.rglob("*.py")):
        rel = p.relative_to(TREE)
        parts = rel.parts
        if any(seg in SKIP_DIRS for seg in parts[:-1]):
            continue
        if parts[0] in SKIP_DIRS or p.name in SKIP_FILES:
            continue
        parts = [seg for seg in parts if seg not in SKIP_DIRS]
        if p.stem == "__init__":
            mod = ".".join(parts[:-1])
        else:
            mod = ".".join(list(parts)[:-1] + [p.stem])
        if mod:
            out.append((mod, str(rel)))
    return out


def classify(err):
    err_low = err.lower()
    for name in list(ROOTS) + ["bootstrap", "constants", "memories",
                               "tool_repl", "api_gateway"]:
        if (f"no module named '{name}." in err_low
                or f"no module named '{name}'" in err_low):
            return "self_fail"
    if "syntaxerror" in err_low:
        return "other_fail"
    if any(k in err_low for k in ("oserror", "ctypes", "name '", "attributeerror",
                                  "typeerror", "valueerror", "runtimeerror",
                                  "permission denied", "filenotfounderror")):
        return "other_fail"
    if "modulenotfounderror" in err_low:
        return "lazy"
    return "other_fail"


def main():
    mods = ship_modules()
    results, missing_roots = [], set()
    for mod, rel in mods:
        cmd = [PY, "-c",
               "import sys, importlib; sys.path.insert(0, '.'); "
               "importlib.import_module(sys.argv[1])", mod]
        try:
            run = subprocess.run(cmd, cwd=str(TREE), capture_output=True,
                                 text=True, timeout=TIMEOUT_S,
                                 env={"PYTHONDONTWRITEBYTECODE": "1"})
            ok = run.returncode == 0
            err = run.stderr.strip().splitlines()[-1] if run.stderr.strip() else ""
        except subprocess.TimeoutExpired:
            ok, err = False, f"TIMEOUT>{TIMEOUT_S}s (import-time side effect / hang)"
        if not ok:
            if "No module named" in err:
                frag = err.split("'")
                missing_roots.add(frag[-2].split(".")[0] if len(frag) >= 2 else "unknown")
            else:
                missing_roots.add(err[:60] or "unknown")
        results.append({"module": mod, "file": rel,
                        "status": "ok" if ok else classify(err), "err": err[:200]})
    bad = [x for x in results if x["status"] not in ("ok", "lazy")]
    summary = {
        "python": PY, "tree": str(TREE), "total": len(mods),
        "ok": sum(1 for x in results if x["status"] == "ok"),
        "lazy": sum(1 for x in results if x["status"] == "lazy"),
        "lazy_roots": sorted(missing_roots),
        "bad": bad,
    }
    if any("frameit.so" in x["err"] for x in bad):
        summary["hint"] = (
            "the C plugin is a gitignored build artifact; compile it first: "
            "gcc -shared -o listeners/plugins/frameit.so -fPIC "
            "listeners/plugins/frameit.c")
    pathlib.Path(REPORT).write_text(json.dumps(results, indent=1))
    print(json.dumps(summary, indent=1))
    print(f"full report: {REPORT}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()