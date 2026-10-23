"""dacustoms — operator-authored tools for daharness.

This is the package __init__.py for your ~/.dacustoms directory.  Without it
the meta-path finder can't resolve ``dacustoms.*`` imports and your tool_ids
lose their prefix.

Put your tool modules here.  They're discovered automatically and their
tool_ids are stamped ``dacustoms.<module>.<function>`` — a clear marker that
these are user-authored, not shipped with the framework.

Two ways to add a tool:

1. **@framework_tool function** (recommended — semantically discoverable):

   ::

       from constants import framework_tool

       @framework_tool("Scan a custom protocol on the target.")
       def my_scan(target, port=8080):
           # your logic here
           return {"status": "ok", "result": ...}

2. **argparse CLI script** (discovered statically, runs as a subprocess):

   ::

       \"\"\"My custom CLI tool — does X on the target.\"\"\"
       import argparse

       def main():
           p = argparse.ArgumentParser()
           p.add_argument("--target", required=True)
           p.add_argument("--port", type=int, default=80)
           args = p.parse_args()
           # your logic here

       if __name__ == "__main__":
           main()

Rules (the framework enforces these):

- **No side effects at module level.** The Brain's startup scan imports your
  module — ``argparse.parse_args()`` at module level will kill the scan (the
  guard catches ``SystemExit``, but your module still won't register).  Wrap
  argparse in ``if __name__ == "__main__":``.
- **The scope gate is not weakened.** Your tools that send traffic are
  subject to the same scope gate as shipped tools.  A customs module is
  operator-authored code — same trust level as your own shell.
- **Namespace collision is impossible.** Your tool_ids are prefixed
  ``dacustoms.`` — they can never collide with upstream tool_ids even after a
  reorg or rename.

Check your modules for breakage::

    # from the framework root
    python -c "from auxiliaries.framework_status import _check_customs; import json; print(json.dumps(_check_customs(), indent=2))"

    # or through the framework doctor
    framework_doctor(provider='customs')
"""