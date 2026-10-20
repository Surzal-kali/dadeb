"""prompt_toolkit completer for the ``repl>`` prompt.

Context-aware completion tiers:
  1. First word  → REPL commands (run, list, info, …)
  2. After a tool-accepting command → discovered tool IDs (from manifests)
  3. After a tool_id in ``run`` → ``--flag`` names from the tool's schema
  4. After ``scope`` → gate subcommands, then their ``--flags``
     (tables mirrored from ``replkit.operator_cli``)

Ghost text (grayed inline suggestion) is shown for single prefix-match
completions; Tab opens the multi-match dropdown. Falls back to a plain
object base when prompt_toolkit isn't installed (the module imports
cleanly either way).
"""

from typing import List

from daharness.models import ToolManifest

from replkit.operator_cli import (
    SCOPE_ON_FLAGS,
    SCOPE_SEARCH_FLAGS,
    SCOPE_SUBCOMMANDS,
)

_PROMPT_TOOLKIT = False
try:
    from prompt_toolkit.completion import Completer, Completion
    _PROMPT_TOOLKIT = True
except ImportError:
    Completer = object  # type: ignore[misc,assignment]


class ToolReplCompleter(Completer if _PROMPT_TOOLKIT else object):
    """Context-aware completer for the tool REPL.

    (See module docstring for the tier layout.) Ghost text appears for
    single prefix-matches; Tab opens the full dropdown.
    """

    COMMANDS = [
        "list", "run", "info", "resolve", "search",
        "sessions", "reindex", "selftest", "replkit", "help", "quit", "exit", "ipython", "scope",
    ]
    # Commands whose first argument is a tool_id.
    TOOL_COMMANDS = {"run", "info", "resolve"}

    def __init__(self, manifests: List[ToolManifest]):
        self.manifests = manifests

    def refresh(self, manifests: List[ToolManifest]) -> None:
        self.manifests = manifests

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        parts = text.split()
        ends_space = text.endswith(" ")

        # ── Tier 1: command name ──────────────────────────────────────────
        if not parts or (len(parts) == 1 and not ends_space):
            word = parts[0] if parts else ""
            for c in sorted(self.COMMANDS):
                if c.startswith(word):
                    yield Completion(c, start_position=-len(word))
            return

        cmd = parts[0].lower()

        # ── Tier 2: tool_id after a tool-accepting command ─────────────────
        if cmd in self.TOOL_COMMANDS:
            if len(parts) == 1 or (len(parts) == 2 and not ends_space):
                word = parts[1] if len(parts) > 1 else ""
                for m in sorted(self.manifests, key=lambda m: m.module_id):
                    if word.lower() in m.module_id.lower():
                        yield Completion(
                            m.module_id, start_position=-len(word),
                            display_meta=m.transport.value,
                        )
                return

        # ── Tier 2.5: ``scope`` subcommands + their flags ─────────────────
        # The operator-only gate surface gets the same schema-aware
        # completion the tool layer has — subcommand word, then --flags.
        # Tables are mirrored from replkit.operator_cli (single source — the
        # old hand-duplicated dict pair is gone).
        if cmd == "scope":
            if len(parts) == 1 or (len(parts) == 2 and not ends_space):
                word = parts[1] if len(parts) > 1 else ""
                for sub in sorted(SCOPE_SUBCOMMANDS):
                    if sub.startswith(word):
                        yield Completion(
                            sub, start_position=-len(word),
                            display_meta=SCOPE_SUBCOMMANDS[sub],
                        )
                return
            sub = parts[1].lower()
            current = "" if ends_space else parts[-1]
            flags = (SCOPE_SEARCH_FLAGS if sub == "search"
                     else SCOPE_ON_FLAGS if sub == "on" else {})
            if flags and current.startswith("--"):
                # Auto-complete flag name as the user types --
                flag_word = current[2:]
                for flag in sorted(flags):
                    if flag[2:].startswith(flag_word):
                        yield Completion(
                            flag, start_position=-len(current),
                            display_meta=flags[flag],
                        )
                return
            if flags and ends_space and complete_event.completion_requested:
                # Tab after a space → show all flags for this subcommand
                for flag in sorted(flags):
                    yield Completion(flag, start_position=0,
                                     display_meta=flags[flag])
                return
            return

        # ── Tier 3: --flag names after a tool_id in ``run`` ────────────────
        if cmd == "run" and len(parts) >= 2:
            tool_id = parts[1]
            manifest = next(
                (m for m in self.manifests if m.module_id == tool_id), None
            )
            if not manifest or not manifest.parameters:
                return
            props = manifest.parameters.get("properties", {})
            current = "" if ends_space else parts[-1]

            if current.startswith("--"):
                # Auto-complete flag name as user types --
                flag_word = current[2:]
                no_mode = flag_word.startswith("no-")
                check = flag_word[3:] if no_mode else flag_word
                for pname in sorted(props):
                    if not check or pname.startswith(check):
                        ptype = props[pname].get("type", "string")
                        pdesc = (props[pname].get("description") or "")[:60]
                        label = f"--no-{pname}" if no_mode else f"--{pname}"
                        yield Completion(
                            label, start_position=-len(current),
                            display_meta=f"{ptype}  {pdesc}",
                        )
            elif ends_space and complete_event.completion_requested:
                # Tab after a space → show all available flags for this tool
                for pname in sorted(props):
                    ptype = props[pname].get("type", "string")
                    pdesc = (props[pname].get("description") or "")[:60]
                    yield Completion(
                        f"--{pname}", start_position=0,
                        display_meta=f"{ptype}  {pdesc}",
                    )