# Astria collector

Collector (A11): program operator Windows untuk pengumpulan dari host dan USB/AndroidQF.

> Status: kerangka awal, belum ada kode. Repo ini adalah submodule dari workspace `triase-dfir` (folder `collector/`). Rancangan: `notes/2026-11-06-triase-dfir-app-collector.md` di repo root. Lajur developer: 1.

## Tech stack

Python 3.14, PyInstaller onedir, uv

## Perintah

```text
uv sync
uv run pytest
```

## Alur git

Branch `{type}/{yyyyMMdd}-{taskId}-{nama}`; commit `{type}({yyyyMMddHHmm}): [{taskId}] {pesan}`, satu baris, tanpa trailer. `main` hanya berubah lewat pull request (merge rebase); jangan push langsung ke `main` dan jangan `--no-verify`.
