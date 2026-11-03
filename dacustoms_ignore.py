"""Ignore-spec loader for the dacustoms lane.

Reads the operator's own ``.gitignore`` files and answers one question:
*can the customs tooling (doctor's syntax check, the registry's
discovery scan) see this file?*

Why gitignore-dialect and not a private knob: the stdlib ``venv`` module
already ships a ``.gitignore`` containing ``*`` inside every venv it
creates, so a customs dir holding a venv is ALREADY fully git-ignored
with zero operator work.  Speaking git's dialect makes the version-
control view the single source of truth — whatever the operator chose to
stop tracking (venvs, node_modules, scratch notebooks, editor droppings)
is exactly what a syntax checker has no business grading.  Operators who
version-control differently can shape the file to their tooling and the
doctor follows.

Supported subset (the dialect that matters for ignore-shaped dirs):

  - ``# comment``, blank lines, trailing whitespace
  - ``name``             bare segment, matches at any depth (no ``/``)
  - ``dir/``             directories only, any depth
  - ``/name``            anchored at the customs root
  - ``sub/name``         path-relative match at any depth
  - ``!negation``        rule override (last match wins, git-style)

Patterns layered by directory, like git: a ``.gitignore`` deeper in the
tree scopes its patterns to its own directory, and later/deeper rules
override earlier ones.

Deliberately NOT implemented: ``**`` globstar recursion — patterns using
it are counted and surfaced (via the ``unsupported`` list) rather than
silently mis-translated.  The walk stays fail-open toward CHECKING a
file: an untranslatable pattern never causes operator code to be
silently skipped from the syntax check.
"""

import logging
import re
from pathlib import Path

__all__ = [
    "UnsupportedPatternError",
    "parse_gitignore_line",
    "load_ignore_matcher",
    "ignore_spec_sources",
]

_log = logging.getLogger(__name__)


class UnsupportedPatternError(ValueError):
    """A gitignore pattern this pragmatic translator refuses (e.g. ``**``)."""


def parse_gitignore_line(line: str) -> tuple[str, bool, bool, bool] | None:
    """Parse one .gitignore line into (pattern, anchored, dir_only, negation).

    Returns ``None`` for blank lines and comments (both ignorable input,
    deliberately not distinguished at this layer).  Raises
    UnsupportedPatternError for shapes the translator doesn't handle.
    """
    stripped = line.rstrip()
    if not stripped or stripped.lstrip().startswith("#"):
        return None
    negation = False
    if stripped.startswith("!"):
        negation = True
        stripped = stripped[1:]
    anchored = stripped.startswith("/")
    if anchored:
        stripped = stripped[1:]
    dir_only = stripped.endswith("/")
    if dir_only:
        stripped = stripped[:-1]
    if not stripped:
        return None
    if "**" in stripped:
        raise UnsupportedPatternError(stripped)
    return (stripped, anchored, dir_only, negation)


def _translate(pat: str) -> str:
    """One gitignore pattern -> regex source over relative POSIX paths.

    Pragmatic subset: ``*`` and ``?`` do not cross ``/`` (git semantics),
    ``[...]`` classes pass through, everything else is escaped.  ``**``
    never reaches here (parse_gitignore_line refuses it first).
    """
    i, n = 0, len(pat)
    rx: list[str] = []
    while i < n:
        c = pat[i]
        if c == "*":
            rx.append(r"[^/]*")
            i += 1
        elif c == "?":
            rx.append(r"[^/]")
            i += 1
        elif c == "[":
            j = pat.find("]", i + 1)
            if j == -1:
                raise UnsupportedPatternError(pat)
            rx.append(re.escape(pat[i:j + 1]))
            i += j + 1
        elif c == "\\":
            # Escaped literal (git: backslash escapes the next char).
            if i + 1 < n:
                rx.append(re.escape(pat[i + 1]))
                i += 2
            else:
                rx.append(re.escape(c))
                i += 1
        else:
            rx.append(re.escape(c))
            i += 1
    return "".join(rx)


def _rule_regex(pat: str) -> re.Pattern[str]:
    """Compile one dir-scoped, non-dir-only pattern.

    Slash-bearing patterns are anchored to the ignore file's directory
    (git semantics — the caller passes the base prefix already applied
    for anchored/'sub/name' shapes; bare patterns float to any depth).
    """
    body = _translate(pat)
    if "/" in pat:
        return re.compile(rf"^{body}(?:/.*)?$")
    # Bare segment name: matches a directory component at any depth.
    return re.compile(rf"(?:^|/){body}(?:/|$)")


class _Rule:
    __slots__ = ("regex", "dir_only", "negation")

    def __init__(self, regex: re.Pattern[str], dir_only: bool, negation: bool):
        self.regex = regex
        self.dir_only = dir_only
        self.negation = negation


def load_ignore_matcher(customs_dir: Path):
    """Build a git-semantics matcher for the customs dir.

    Walks ``customs_dir`` for every ``.gitignore`` (deepest-last, so later
    rules override earlier ones like git's layering) and returns:

        matcher(rel_posix, is_dir=False) -> bool   # True = ignore
        sources: list[str]       # contributing .gitignore files (relpaths)
        unsupported: list[str]   # refused patterns (e.g. ``**``), verbatim

    ``sources`` exists so the doctor can surface which files shaped the
    check; ``unsupported`` stays honest about dialect it didn't speak.
    Read-only — never mutates the tree.
    """
    rules: list[_Rule] = []
    sources: list[str] = []
    unsupported: list[str] = []

    gitignores = sorted(
        customs_dir.rglob(".gitignore"),
        key=lambda p: (len(p.relative_to(customs_dir).parts), str(p)),
    )
    for gi in gitignores:
        try:
            lines = gi.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            # Unreadable ignore file: fail-open toward CHECKING files
            # (never silently hide operator code over a permissions hiccup).
            _log.debug("swallowed OSError reading %s: %s", gi, exc)
            continue
        # A .gitignore scopes its patterns to its own directory (git's
        # rule): prefix every pattern with the dir's rel path.
        rel_base = gi.parent.relative_to(customs_dir)
        base = "" if rel_base == Path(".") else rel_base.as_posix() + "/"
        contributed = False
        for line in lines:
            try:
                parsed = parse_gitignore_line(line)
            except UnsupportedPatternError:
                unsupported.append(line.strip())
                continue
            if parsed is None:
                continue
            pat, anchored, dir_only, negation = parsed
            # git scoping, per gitignore(5): patterns match relative to
            # the DIRECTORY CONTAINING the .gitignore. A pattern is
            # anchored to that dir when it has a leading slash; a bare
            # or trailing-slash-only pattern matches at that dir AND any
            # level below it; an interior-slash pattern is relative to
            # that dir only. The trailing slash makes it dir-only and
            # prune-shaped (dir + everything under it). The leading /
            # with base: '/venv' in a sub .gitignore means "that dir's
            # venv" — the base IS the anchor, so we prefix it.
            slashy = "/" in pat
            try:
                if dir_only:
                    body = _translate((base if slashy or anchored else "") + pat)
                    # Dir rule: prune the dir + every path beneath it.
                    rx = re.compile(rf"(?:^|/){body}(?:/.*|$)")
                elif anchored or slashy:
                    body = _translate(base + pat)
                    rx = re.compile(rf"^{body}(?:/.*)?$")
                else:
                    # Bare file pattern from a deeper .gitignore: floats
                    # WITHIN that dir's subtree only when the file lives
                    # there, else across the whole customs tree.
                    body = _translate((base if base else "") + pat) if base else _translate(pat)
                    rx = (
                        re.compile(rf"^{body}(?:/.*)?$")
                        if base
                        else re.compile(rf"(?:^|/){body}(?:/|$)")
                    )
            except UnsupportedPatternError:
                unsupported.append(line.strip())
                continue
            rules.append(_Rule(rx, dir_only, negation))
            contributed = True
        if contributed:
            sources.append(str(gi.relative_to(customs_dir)))

    def matcher(rel_posix: str, is_dir: bool = False) -> bool:
        ignored = False
        for rule in rules:
            # dir_only rules prune their directory AND everything under
            # it (git models this by not descending; we approximate by
            # also testing every ancestor prefix of the path).
            if rule.dir_only:
                segs = rel_posix.split("/")
                prefixes = ["/".join(segs[:i + 1]) for i in range(len(segs))]
                if any(rule.regex.search(p) for p in prefixes):
                    ignored = not rule.negation
                continue
            if rule.regex.search(rel_posix):
                ignored = not rule.negation
        return ignored

    return matcher, sources, unsupported


def ignore_spec_sources(customs_dir: Path) -> list[str]:
    """Which .gitignore files under ``customs_dir`` contributed rules.

    Convenience for the doctor's report surface — a quick way to answer
    "which ignore layers shaped this check?" without the matcher.
    """
    _, sources, _ = load_ignore_matcher(customs_dir)
    return sources