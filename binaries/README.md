# Binary Drop Folder

Drop analysis targets (ELF, PE, Mach-O, shared libs, object files) here.
This directory is **gitignored** — binaries never get committed.

Discover what's available:
```python
from auxiliaries.radare2 import list_r2_targets
list_r2_targets()
```

Then analyze by bare name (auto-resolved from this folder):
```python
from auxiliaries.radare2 import run_r2
run_r2("crackme", "iI")
run_r2("crackme", "pdf", addr="main")
```

Override the root via `R2_BINARY_TARGETS_ROOT` env var.
