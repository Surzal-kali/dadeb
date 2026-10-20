"""Shared wordlist discovery and launch-time preflight checks.

Both :mod:`payloads.ffuf` (path fuzzing) and :mod:`payloads.hydra` (credential
brute-force) consume wordlists under ``/usr/share/wordlists``.  Rather than
each tool re-implementing the lookup, this module owns:

- :data:`WORDLIST_SOURCES` — the declared wordlist folders to walk, keyed by
  the source label (tag) each discovered file carries.  Kali's wordlist
  metapackage fills ``/usr/share/wordlists`` almost entirely with *symlinks*
  to per-package folders (dirb, dirbuster, metasploit, wfuzz, ...), and
  ``Path.rglob`` does not descend through symlinked directories — the
  original single-root walk saw only a handful of lists.  So discovery walks
  the main root plus each source folder directly, and every entry records the
  source label it came from.
- :data:`WORDLISTS_ROOT` — the primary root (env-overridable); the first
  entry of :data:`WORDLIST_SOURCES`.
- :func:`preflight_wordlists` — a launch-time sanity check called from
  ``bootstrap.FrameworkLoader.launch_all`` that confirms at least one
  wordlist source exists and actually contains ``.txt`` files.  A missing or
  empty tree is the #1 cause of silent ffuf/hydra failures (ffuf exits with
  "could not read wordlist", hydra errors on ``-P``/``-L`` paths); surfacing
  this at launch time turns a runtime mystery into a startup warning.
- :func:`discover_wordlists` — a generator that walks every declared source
  for files matching a glob, returning dicts with ``path``, ``size``,
  ``lines`` (best effort), a ``source`` label, and a category hint derived
  from the parent directory name.

The ``list_wordlists`` :func:`~payloads.wordlists.list_wordlists` tool wraps
:func:`discover_wordlists` for the secretary model so it can pick the right
wordlist path before calling ``run_ffuf`` / ``run_hydra``.
"""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional

# Primary Kali/Debian wordlist root.  Override with the WORDLISTS_ROOT env
# var (used by tests and non-standard installs).
WORDLISTS_ROOT: Path = Path(
    os.getenv("WORDLISTS_ROOT", "/usr/share/wordlists")
).resolve()

# Declared wordlist folders, keyed by the source label (tag) each discovered
# entry carries.  Keys are bin/package-derived labels — they become the
# ``source`` field on every entry and are accepted by the ``source`` filter of
# ``list_wordlists``.  Values are absolute folder locations (a value may name
# a single ``.txt`` file's directory; the walk still applies its glob).
#
# Roots that don't exist on this box are skipped silently, so the same map is
# correct on Kali (most folders present), Debian (usually none but the main
# root), and test containers (none at all).  Override/extend via env:
#   WORDLIST_SOURCES="key1=/abs/dir1,key2=/abs/dir2"
#
# The main root is always walked.  Everything else is the usual Kali
# per-package wordlist folder that ``/usr/share/wordlists`` symlinks to —
# walking the real folder works even where the symlink is dangling.
_DEFAULT_SOURCES: List[tuple] = [
    # main root: rockyou + per-package symlinks
    ("wordlists", str(WORDLISTS_ROOT)),
    ("dirb", "/usr/share/dirb/wordlists"),
    ("dirbuster", "/usr/share/dirbuster/wordlists"),
    ("wfuzz", "/usr/share/wfuzz/wordlist"),
    ("metasploit", "/usr/share/metasploit-framework/data/wordlists"),
    ("legion", "/usr/share/legion/wordlists"),
    ("fern-wifi", "/usr/share/fern-wifi-cracker/extras/wordlists"),
    ("seclists", "/usr/share/seclists"),
    ("dnsrecon", "/usr/share/dnsrecon"),
]

WORDLIST_SOURCES: Dict[str, str] = {}
if os.getenv("WORDLIST_SOURCES"):
    # Env override form: "key=/abs/dir,key2=/abs/dir2" (merged over defaults).
    for chunk in os.environ["WORDLIST_SOURCES"].split(","):
        key, _, val = chunk.partition("=")
        if key and val:
            WORDLIST_SOURCES[key.strip()] = val.strip()
else:
    for _key, _val in _DEFAULT_SOURCES:
        WORDLIST_SOURCES[_key] = _val
    # Re-point the main root at the (possibly env-overridden) resolved root
    # so tests that monkeypatch WORDLISTS_ROOT keep the first entry in sync.
    WORDLIST_SOURCES["wordlists"] = str(WORDLISTS_ROOT)

# Well-known wordlists that ffuf/hydra runs commonly target.  Used by the
# preflight to report which "headline" lists are present vs absent, so a
# missing rockyou.txt (gzip-only on Kali) is flagged explicitly rather than
# buried in a 6 000-entry count.
#
# NOTE: wordlist availability is BOX-VARIABLE.  A wordlist present on one
# box (e.g. directory-list-2.3-medium on this box) may be absent on another
# (it was absent on the Sept-10 box).  The preflight and list_wordlists
# tool report what is actually present on THIS box — never assume a
# wordlist exists without checking.  Aliases below cover the common set;
# absent ones are reported in ``common_absent`` so the operator knows to
# install them (e.g. ``apt install seclists`` or clone the repo).
COMMON_WORDLISTS: Dict[str, str] = {
    "rockyou.txt": "SecLists/Passwords/Leaked-Databases/rockyou.txt",
    "dirb_common": "SecLists/Discovery/Web-Content/dirb/common.txt",
    "directory_list_2.3_small": "SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt",
    "directory_list_2.3_medium": "SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",
    "raft_small_dirs": "SecLists/Discovery/Web-Content/raft-small-directories.txt",
    "names_top": "SecLists/Usernames/top-usernames-shortlist.txt",
    "burp_parameter_names": "SecLists/Discovery/Web-Content/burp-parameter-names.txt",
}

# Short, pre-existing SecLists defaults used as "just in case" fallbacks when a
# caller omits the wordlist argument.  These are deliberately small so a
# forgotten argument runs a quick sane pass instead of failing (ffuf: "could
# not read wordlist") or erroring (hydra: no cred source).  Override via env:
#   DEFAULT_FFUF_WORDLIST / DEFAULT_HYDRA_LOGIN_LIST / DEFAULT_HYDRA_PASSWORD_LIST
DEFAULT_FFUF_WORDLIST: str = os.getenv(
    "DEFAULT_FFUF_WORDLIST",
    "SecLists/Discovery/Web-Content/common.txt",  # 4 751 lines; canonical ffuf quick default
)
DEFAULT_HYDRA_LOGIN_LIST: str = os.getenv(
    "DEFAULT_HYDRA_LOGIN_LIST",
    "SecLists/Usernames/top-usernames-shortlist.txt",  # 17 lines: root, admin, ...
)
DEFAULT_HYDRA_PASSWORD_LIST: str = os.getenv(
    "DEFAULT_HYDRA_PASSWORD_LIST",
    "SecLists/Passwords/Common-Credentials/top-passwords-shortlist.txt",  # 25 lines
)


def resolve_wordlist(rel_path: str, root: Optional[Path] = None) -> Optional[str]:
    """Resolve a wordlist path against the declared wordlist sources.

    Accepts an absolute path that already exists (honoured as-is), or a
    relative path resolved against every declared source in turn — first the
    primary root (:data:`WORDLISTS_ROOT`), then the per-package folders
    (``dirb/common.txt`` style paths resolve against the ``dirb`` source).
    ``root`` (when given) is tried first.  Returns the absolute ``str`` path
    if the file exists anywhere, otherwise ``None`` — never raises, so
    callers can fall back to a clear error message that points at
    ``list_wordlists``.
    """
    # An existing absolute path is honoured as-is.
    p = Path(rel_path)
    if p.is_absolute() and p.is_file():
        return str(p)

    bases: List[Path] = []
    if root is not None:
        bases.append(root)
    bases.extend(
        Path(v) for k, v in sorted(WORDLIST_SOURCES.items()) if k != "wordlists"
    )
    bases.append(WORDLISTS_ROOT)

    for base in bases:
        candidate = base / rel_path
        if candidate.is_file():
            return str(candidate)
    return None


def resolve_default_wordlist(kind: str, root: Optional[Path] = None) -> Optional[str]:
    """Resolve the framework default wordlist for ``kind``.

    ``kind`` is one of ``"ffuf"``, ``"hydra_logins"``, ``"hydra_passwords"``.
    Each default is a small candidate list resolved in order — a SecLists
    path first (canonical, when ``seclists`` is installed), then a per-package
    Kali path that exists on stock Kali installs.  Returns the absolute path
    string of the first existing candidate, otherwise ``None``.
    """
    mapping = {
        "ffuf": [
            DEFAULT_FFUF_WORDLIST,
            "dirb/common.txt",  # ~4 600 lines; stock Kali dirb package
        ],
        "hydra_logins": [
            DEFAULT_HYDRA_LOGIN_LIST,
            "metasploit/hci_oracle_passwords.csv",  # small username-ish list
            "wordlists-fasttrack.txt",  # placeholder, resolved below if present
        ],
        "hydra_passwords": [
            DEFAULT_HYDRA_PASSWORD_LIST,
            "metasploit/adobe_top100_pass.txt",  # 100 lines; stock Kali msf data
        ],
    }
    candidates = mapping.get(kind)
    if not candidates:
        return None
    for cand in candidates:
        resolved = resolve_wordlist(cand, root=root)
        if resolved:
            return resolved
    return None



def _category_from_path(path: Path, root: Path) -> str:
    """Derive a category label from the path's directory segments under root.

    Directory segments below a known source prefix (``SecLists/`` or the
    per-package ``<root>/wordlists/`` layouts, e.g.
    ``/usr/share/dirbuster/wordlists``) are joined with ``/`` so deeply
    nested trees keep their distinguishing segments, e.g.
    ``/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt`` ->
    ``Discovery/Web-Content``.  Unknown roots use every directory segment
    below root.  Returns ``"wordlists"`` as a fallback.
    """
    resolved = Path(os.path.realpath(path))
    real_root = os.path.realpath(root) if root.exists() else str(root)
    try:
        rel = resolved.relative_to(real_root)
    except ValueError:
        return "wordlists"
    parts = rel.parts
    # Drop the filename; what remains are the directory segments.
    dirs = list(parts[:-1])
    # Strip the source-packet prefix the walk itself already tags via
    # ``source``: "SecLists/..." and the ".../wordlists" tail of per-package
    # trees (dirb/dirbuster/wfuzz layout).
    if dirs and dirs[0] == "SecLists":
        dirs = dirs[1:]
    if dirs and dirs[-1].lower() in ("wordlists", "wordlist"):
        dirs = dirs[:-1]
    if not dirs:
        return "wordlists"
    return "/".join(dirs)


def discover_wordlists(
    root: Optional[Path] = None,
    pattern: str = "*.txt",
    include_hidden: bool = False,
    sources: Optional[Dict[str, str]] = None,
) -> Iterator[Dict[str, Any]]:
    """Walk every declared wordlist source, yielding matching files.

    Each yielded dict has ``path`` (absolute, ``str``), ``size`` (bytes),
    ``source`` (the label of the root it came from, e.g. ``"dirbuster"``),
    and ``category`` (a short label).

    Passing ``root`` walks just that path under the ``"wordlists"`` label
    (preserved for callers and tests that target a single tree).  Otherwise
    every entry of :data:`WORDLIST_SOURCES` (or the ``sources`` override) is
    walked in sorted key order.

    Uses :func:`os.walk` with ``followlinks=True``: Kali's wordlist tree is
    mostly *symlinked directories* and ``Path.rglob`` does not descend
    through them.  Symlink loops (a dir linking to its own ancestor) are
    pruned by comparing the walk's seen-realpaths.  Duplicate files reached
    via more than one source are yielded once, under the first source —
    dedup by ``os.path.realpath``.
    """
    if sources is None:
        if root is not None:
            sources = {"wordlists": str(root)}
        else:
            sources = dict(WORDLIST_SOURCES)

    skip_dirs = {".git", ".github", ".svn", "__pycache__", "node_modules", ".bin"}

    seen_files: set = set()  # file realpaths (dedup across overlapping sources)
    seen_dirs: set = set()  # dir realpaths (symlink-loop guard)
    for label in sorted(sources):
        base = Path(sources[label])
        if not base.exists():
            continue
        base_real = os.path.realpath(base)
        if base_real in seen_dirs:
            continue
        seen_dirs.add(base_real)
        for dirpath, dirnames, filenames in os.walk(base, followlinks=True):
            # Prune junk + hidden dirs; track dir realpaths so a symlink
            # pointing at an already-walked ancestor is never re-entered.
            kept: List[str] = []
            for d in sorted(dirnames):
                if d in skip_dirs or (not include_hidden and d.startswith(".")):
                    continue
                real_d = os.path.realpath(os.path.join(dirpath, d))
                if real_d in seen_dirs:
                    continue
                seen_dirs.add(real_d)
                kept.append(d)
            dirnames[:] = kept
            for fn in sorted(filenames):
                if not include_hidden and fn.startswith("."):
                    continue
                if pattern == "*.txt" and not fn.endswith(".txt"):
                    continue
                if pattern != "*.txt" and not fnmatch.fnmatch(fn, pattern):
                    continue
                full = Path(dirpath) / fn
                real = os.path.realpath(full)
                if real in seen_files:
                    continue
                if not os.path.isfile(real):
                    continue
                try:
                    size = os.path.getsize(real)
                except OSError:
                    continue
                # 0-byte files (e.g. SecLists CMS/trickest-cms-wordlist/
                # vanilla.txt) contain no entries and must never feed
                # ffuf/hydra — ffuf exits with "could not read wordlist".
                if size == 0:
                    continue
                seen_files.add(real)
                yield {
                    "path": str(full),
                    "size": size,
                    "source": label,
                    "category": _category_from_path(full, base),
                }


def preflight_wordlists(root: Optional[Path] = None) -> Dict[str, Any]:
    """Launch-time sanity check for the declared wordlist sources.

    Returns a report dict:

    - ``ok`` (bool): True only when at least one declared source exists AND
      contains at least one ``.txt`` file.
    - ``root`` (str): the primary root path (first declared source).
    - ``txt_count`` (int): total ``.txt`` files found across all sources.
    - ``sources_seen`` / ``sources_absent`` (list[str]): which declared
      source labels exist on this box vs don't (absent is normal — e.g.
      ``seclists`` before ``apt install seclists``).
    - ``per_source`` (dict[str, int]): per-label ``.txt`` counts.
    - ``common_present`` / ``common_absent`` (list[str]): which of
      :data:`COMMON_WORDLISTS` resolved to an existing file.
    - ``warnings`` (list[str]): human-readable problems.

    Idempotent and read-only — safe to call from ``launch_all``.
    """
    report: Dict[str, Any] = {
        "ok": False,
        "root": str(root or WORDLISTS_ROOT),
        "txt_count": 0,
        "sources_seen": [],
        "sources_absent": [],
        "per_source": {},
        "common_present": [],
        "common_absent": [],
        "warnings": [],
    }

    declared: Dict[str, str] = (
        {"wordlists": str(root)} if root is not None else dict(WORDLIST_SOURCES)
    )

    for label in sorted(declared):
        if Path(declared[label]).exists():
            report["sources_seen"].append(label)
        else:
            report["sources_absent"].append(label)

    if root is not None and not Path(root).exists():
        report["warnings"].append(
            f"Wordlist root {root} does not exist; ffuf/hydra wordlist "
            "paths will fail. Install SecLists or set WORDLISTS_ROOT."
        )
        return report
    if not report["sources_seen"]:
        report["warnings"].append(
            "No declared wordlist source exists on this box; ffuf/hydra "
            "wordlist paths will fail. Install wordlists (Kali) / seclists, "
            "or set WORDLIST_SOURCES."
        )
        return report

    txt_files = list(
        discover_wordlists(root=root) if root is not None else discover_wordlists()
    )
    report["txt_count"] = len(txt_files)
    for e in txt_files:
        report["per_source"][e["source"]] = report["per_source"].get(e["source"], 0) + 1
    if not txt_files:
        report["warnings"].append(
            f"No .txt wordlists found under any declared source "
            f"({', '.join(report['sources_seen'])}); ffuf/hydra runs have "
            "nothing to consume."
        )
        return report

    report["ok"] = True
    report["root"] = str(declared.get("wordlists", WORDLISTS_ROOT))
    if not report["per_source"].get("wordlists"):
        report["root"] = next(
            (k for k in sorted(declared) if k in report["per_source"]),
            report["root"],
        )

    for name, rel in COMMON_WORDLISTS.items():
        # Resolve against the sources actually in scope for this report (an
        # explicit ``root`` or the declared map), not the ambient globals,
        # else callers pointing discovery at a test/isolated tree get
        # misleading common_* answers from the real box's folders.
        found = False
        for base_s in sorted(declared):
            base_p = Path(declared[base_s])
            if (base_p / rel).is_file() or (base_p / rel.split("/", 1)[-1]).is_file():
                found = True
                break
        if found:
            report["common_present"].append(name)
        else:
            report["common_absent"].append(name)

    # rockyou.txt is the single most-used password list; flag its absence
    # loudly because Kali ships it gzip-compressed and a decompression step
    # is a common tripping point.
    if "rockyou.txt" in report["common_absent"]:
        primary = Path(declared.get("wordlists", WORDLISTS_ROOT))
        gz_candidates = [
            primary / "rockyou.txt.gz",  # stock Kali metapackage layout
            primary / "SecLists" / "Passwords" / "Leaked-Databases" / "rockyou.txt.gz",
        ]
        for gz in gz_candidates:
            if gz.is_file():
                report["warnings"].append(
                    f"rockyou.txt is absent but {gz} exists — gunzip it "
                    "before pointing hydra -P / ffuf -w at it."
                )
                break
    return report


__all__ = [
    "WORDLISTS_ROOT",
    "WORDLIST_SOURCES",
    "COMMON_WORDLISTS",
    "discover_wordlists",
    "preflight_wordlists",
    "resolve_wordlist",
    "resolve_default_wordlist",
]
