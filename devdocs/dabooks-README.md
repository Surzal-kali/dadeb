# Dabooks — JupyterLab Work Dir

The notebook side of the workbench. This folder is bind-mounted into the
jupyter container as `/home/jovyan/work` — the server's `root_dir` — so every
notebook and file Jupyter saves lands directly in the framework repo tree and
is version-controlled alongside the code it drives (no separate `git init`,
no volume limbo).

    host:  <repo>/dabooks   →   container: /home/jovyan/work
    (dockered/docker-compose.yaml → services.jupyter.volumes)

## Mount rules

- The work dir is a **bind mount**: changing its path in docker-compose.yaml
  takes a container recreate (`docker compose up -d`), not `--build` —
  rebuilds only apply to [jupyter.Dockerfile](../dockered/jupyter.Dockerfile)
  changes (pip layers, patches, kernelspec).
- The framework tree is mounted separately at `/home/jovyan/framework`. The
  `daharness` kernel is what runs `tool_repl.py` from there, so notebook code
  cells drive the exact same tool lane as the Brain sidecar and `tool_repl`.
  JUPYTER_TOKEN gates the server (token in `dockered/.env`).

## What's versioned

Every `*.ipynb` here is tracked on purpose — notebooks are JSON, so diffs are
reviewable. Clear cell outputs (`Edit → Clear All Outputs`) before committing
to keep the diffs readable. [genesis.ipynb](genesis.ipynb) is the seed
notebook: empty, kernelspec pre-set to `daharness (framework tools)`.

Runtime noise is gitignored (see [.gitignore](../.gitignore)):

- `.memory/` — framework vector memory (ChromaDB). `memories.py` resolves it
  relative to the notebook CWD, so it materializes here at runtime. Never
  commit it; wiping it loses the framework's memory, not your notebooks.
- `.ipynb_checkpoints/` — Jupyter's auto-recovery saves.
- `scratch.*` — kernel scratch files.

`README.md` carries an explicit `!dabooks/README.md` un-ignore exception so a
future dir-wide ignore rule can't silently drop this file.

## Usage

- JupyterLab: http://localhost:8888 — auth is `JUPYTER_TOKEN` from
  `dockered/.env`.
- New notebooks: pick the default `daharness (framework tools)` kernel for
  framework tool access; plain Python kernels work fine for framework-free
  scratch.
- Headless execution, no browser:
  `docker exec dockered-jupyter-1 jupyter nbconvert --to notebook --execute <nb.ipynb> --kernel daharness`
