# Duplicate Detector Web App

A minimal full stack example that exposes the `duplicate_detector.py` module through a FastAPI backend plus a lightweight browser UI.

## Project layout

- `duplicate_detector.py` reusable duplicate detection helpers
- `backend/` FastAPI application and dependencies
- `frontend/` static HTML interface that talks to the API

## Backend setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r backend/requirements.txt
uvicorn backend.main:app --reload
```

The server listens on `http://localhost:8000`. Interactive documentation is available at `http://localhost:8000/docs`.

## Frontend usage

Serve the static files (one option):

```bash
python -m http.server 5500 --directory frontend
```

Visit `http://localhost:5500/index.html` in your browser, fill the form with the directory to analyse, and trigger a scan. The page can also be opened directly from the file system, but a static server avoids CORS quirks on some browsers.

## Available API endpoints

- `POST /scan` run a scan (`path`, `method`, `extensions`, `recursive`)
- `GET /stats` return the last stored stats snapshot
- `GET /export?format=json|csv` download the last report (files land in `backend/exports/`)
- `GET /health` lightweight health probe

All responses are JSON except the export endpoint, which streams the generated file.

## Notes

- The API normalises extensions so both `.pdf` and `pdf` inputs are accepted.
- Every successful scan persists a copy in `backend/data/last_scan.json` so other features can reuse the latest payload.
- Library and API logs follow the NDJSON contract described in `3_espec_log.md`; they stream to stdout, rotate as NDJSON in `logs/duplicate-detector*.log`, and mirror as texto legible en `logs/duplicate-detector*.txt` (override via `DUPLY_LOG_DIR`).
- The Python library exposes plan helpers: `generate_action_plan` writes `plan.json`, `dry_run_plan` reports the impact, and `apply_plan` executes actions while emitting `undo.json`.
- Results are cached in memory; restarting the server clears history.
- `duplicate_detector.py` keeps doing the heavy work, so any improvements there will be reflected automatically.



