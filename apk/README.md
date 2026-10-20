# APK Drop Folder

Drop analysis targets (`.apk`, `.xapk`, `.apkm`, `.apks`, `.aab`, `.aar`,
`.jar`, `.zip`, raw `.dex`, `.class`, `.arsc`) here.
This directory is **gitignored** — targets and decompiled output never get
committed.

Discover what's available:
```python
from auxiliaries.jadx import list_apk_targets
list_apk_targets()
```

Then drive jadx by bare name (auto-resolved from this folder):
```python
from auxiliaries.jadx import run_jadx
run_jadx("app.apk", "manifest")                                    # fast manifest pull
run_jadx("app.apk", "class", single_class="com.example.Foo")       # one class, no full decompile
run_jadx("app.apk", "decompile")                                   # full decompile (cached workspace)
run_jadx("app.apk", "grep", pattern="api_key|token|secret")        # search decompiled sources
run_jadx("app.apk", "read", path="sources/com/example/MainActivity.java")
run_jadx("app.apk", "tree")
```

Decompiled trees are cached under `apk/decompiled/<name>/` and reused until
the source file changes (or `force=True`).

Requires jadx (Java 11+ JRE) — binary resolved via `$JADX_BIN` env, then PATH.
Override the drop-folder root via `JADX_APK_TARGETS_ROOT` env var.