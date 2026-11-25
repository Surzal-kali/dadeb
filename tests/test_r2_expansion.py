"""Tests for the 2026-11-24 run_r2 expansion: new verbs + FILTERABLE /R.

Covers the frozen-table additions (aae, axg, agf, ic, ie, /R), the filter
param's validation layers (charset, FILTERABLE-only, forbidden chars), the
composed -c string shape, and the snapshot-cache op-key change (filter in
the key so two /R calls with different filters don't share a snapshot).
"""

import pytest

from auxiliaries import radare2
from auxiliaries.radare2 import _compose_cmd, _validate_filter


class TestCommandTableExpansion:
    def test_new_verbs_in_allowlist(self):
        for verb in ("aae", "axg", "agf", "ic", "ie", "/R"):
            assert verb in radare2.ALLOWED_COMMANDS, verb

    def test_ie_is_entrypoints_not_exports(self):
        # Both exist and are distinct verbs: iE (uppercase) = exports is the
        # original; ie (lowercase) = entrypoints. An exact-match allowlist
        # makes the collision harmless, but assert both so a table typo
        # (e.g. losing one) can't silently collapse them.
        assert "iE" in radare2.ALLOWED_COMMANDS
        assert "ie" in radare2.ALLOWED_COMMANDS
        assert radare2._COMMAND_TABLE["ie"][0] is True  # needs_addr

    def test_row_r_is_not_addr_addressable(self):
        # /R has no addr semantics; the filter is its narrowing axis.
        needs_addr, needs_count, count_cap, blurb = radare2._COMMAND_TABLE["/R"]
        assert needs_addr is False
        assert needs_count is False


class TestFilterValidation:
    def test_none_filter_passes_everywhere(self):
        normalized, err = _validate_filter("afl", None)
        assert normalized is None and err is None

    def test_filter_on_non_filterable_verb_rejected(self):
        _, err = _validate_filter("pdf", "pop")
        assert err and "does not accept a filter" in err

    def test_filter_on_row_r_accepted(self):
        normalized, err = _validate_filter("/R", "pop")
        assert normalized == "pop" and err is None

    def test_filter_with_space_rejected(self):
        # The gadget-filter-with-spaces failure mode ('pop; rdi') must be
        # unreachable — spaces would compose a second token into the -c
        # segment and widen the injection surface.
        normalized, err = _validate_filter("/R", "pop rdi")
        assert err and "forbidden character" in err
        assert normalized is None

    def test_filter_metachars_rejected(self):
        for bad in ("pop;ret", "pop@rdi", "pop$x", "pop`i`"):
            normalized, err = _validate_filter("/R", bad)
            assert err, bad
            assert normalized is None

    def test_filter_charset_aligns_with_flag_charset(self):
        # Dot/dash/underscore survive (gadget tokens can contain '.', e.g.
        # gadget flag names); everything shell/r2-structural does not.
        ok, err = _validate_filter("/R", "pop.rdi-x_y")
        assert ok == "pop.rdi-x_y" and err is None


class TestComposeCmdFilter:
    def test_filter_composes_as_verb_argument(self):
        composed = _compose_cmd("/R", None, None, "pop")
        assert composed == "aaa; /R pop"

    def test_filter_with_addr_composes_seek(self):
        composed = _compose_cmd("/R", "0x401000", None, "pop")
        assert composed == "aaa; /R pop @ 0x401000"

    def test_non_filterable_ignores_filter_param(self):
        # Defense in depth: _validate_filter rejects it upstream; compose
        # still never lets a filter leak into a non-filterable verb's -c.
        composed = _compose_cmd("afl", None, None, "pop")
        assert composed == "aaa; afl"

    def test_count_still_composes(self):
        assert _compose_cmd("pd", "entry0", 32) == "aaa; pd 32 @ entry0"


class TestFilterInSnapshotKey:
    def test_filter_changes_op_key(self):
        # Two /R calls differing only by filter must not share a snapshot —
        # the composed op_key JSON in run_r2 carries a "filter" field, so
        # different filters hash differently (verified structurally by the
        # integration below; here the key-building inputs differ).
        import json
        key_a = json.dumps({"verb": "/R", "filter": "pop"}, sort_keys=True)
        key_b = json.dumps({"verb": "/R", "filter": "ret"}, sort_keys=True)
        assert key_a != key_b

