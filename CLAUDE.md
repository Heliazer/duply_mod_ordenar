# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Duplicate Detector is a full-stack web application for finding and managing duplicate files. The core logic is in a reusable Python library (`duplicate_detector.py`) exposed through a FastAPI backend with a browser-based frontend.

## Commands

### Development Setup

```bash
# Create and activate virtual environment (Linux/Mac)
python -m venv .venv
source .venv/bin/activate

# Windows activation
.venv\Scripts\activate

# Install dependencies
pip install -r backend/requirements.txt
```

### Running the Backend

```bash
# Start the FastAPI server (auto-reload enabled)
uvicorn backend.main:app --reload

# Server runs at http://localhost:8000
# Interactive API docs at http://localhost:8000/docs
```

### Running the Frontend

```bash
# Serve static files (one option)
python -m http.server 5500 --directory frontend

# Access at http://localhost:5500/index.html
# Can also open frontend/index.html directly in browser
```

### Running the CLI

```bash
# Direct execution
python duplicate_detector.py <directory> [method]

# Methods: hash, name, size, hybrid
# Example:
python duplicate_detector.py /path/to/scan hybrid
```

## Architecture

### Core Components

1. **`duplicate_detector.py`** - Reusable library with all detection logic
   - `DuplicateDetector` class: Main detector with pluggable hash methods (md5/sha256)
   - Scan methods: `find_duplicates_by_hash()`, `find_duplicates_by_name()`, `find_duplicates_by_size()`, `find_duplicates_hybrid()`
   - Directory comparison: `compare_directories()`
   - Action planning: `generate_action_plan()`, `dry_run_plan()`, `apply_plan()`
   - Export: `export_results()` (JSON/CSV formats)

2. **`backend/main.py`** - FastAPI wrapper
   - Singleton `DuplicateDetector` instance shared across requests
   - In-memory state: last scan results cached until server restart
   - Data persistence: `backend/data/last_scan.json` written on each successful scan

3. **`frontend/index.html`** - Browser UI
   - Single-page static HTML with embedded CSS/JavaScript
   - Communicates with backend via fetch API

### Detection Methods

- **hash**: Full content-based comparison using MD5/SHA256
- **name**: Filename-based detection (case-insensitive option)
- **size**: File size comparison
- **hybrid**: Two-phase (size bucketing → hash verification) - most efficient for large datasets

### Logging Architecture

All components use **structured NDJSON logging** per specification in `3_espec_log.md`:

- **Format**: One JSON object per line, UTF-8, UTC timestamps
- **Channels**:
  - `logs/duplicate-detector.log` - NDJSON format (library events)
  - `logs/duplicate-detector.txt` - Human-readable mirror
  - `logs/duplicate-detector.api.log` - NDJSON format (API events only)
  - `logs/duplicate-detector.api.txt` - Human-readable mirror
- **Log directory**: Override via `DUPLY_LOG_DIR` environment variable
- **Correlation**: `scan_id` (UUID per scan), `request_id` (UUID per API request)
- **Components**: Logs tagged with `component` field: `library`, `api`, or `cli`

### Plan System

The library includes a plan-based workflow for duplicate management:

1. **Generate plan**: `generate_action_plan()` creates JSON describing actions to take
   - Survivor policies: `keep_first`, `keep_oldest`, `keep_newest`
   - Actions: `move_to_quarantine`, `delete`
   - Collision strategies: `rename`, `skip`, `overwrite`
2. **Preview**: `dry_run_plan()` simulates execution without filesystem changes
3. **Execute**: `apply_plan()` performs operations and generates `undo.json`

Plans are stored as JSON files and can be version-controlled or reviewed before execution.

### Data Flow

```
User → Frontend → POST /scan → FastAPI → DuplicateDetector → NDJSON logs
                                    ↓
                            last_scan.json (persisted)
                                    ↓
                            In-memory cache (_last_scan)
                                    ↓
User ← Frontend ← GET /stats or GET /export ← FastAPI
```

### API Endpoints

- `POST /scan` - Run duplicate detection (params: `path`, `method`, `extensions`, `recursive`)
- `GET /stats` - Retrieve last scan summary
- `GET /export?format=json|csv` - Download results (files saved to `backend/exports/`)
- `GET /health` - Health check

### Extension Normalization

Both backend and library normalize file extensions automatically:
- Accepts `pdf` or `.pdf`
- Converts to lowercase `.pdf` format internally

### Environment Variables

- `DUPLY_LOG_DIR` - Override default log directory location
- `DUPLY_ENV` - Set environment tag in logs (`dev`/`staging`/`prod`, default: `dev`)

## Key Implementation Details

### File Hashing
- Chunked reading (default 8192 bytes) to handle large files efficiently
- Supports MD5 (default) and SHA256

### Hybrid Mode Optimization
- Phase 1: Group files by size (cheap)
- Phase 2: Hash only files with size collisions (expensive operation deferred)
- Reduces unnecessary hashing by ~90% in typical scenarios

### Quarantine Paths
- Source paths are sanitized when building quarantine destinations
- Windows drives, special characters, and path separators are normalized
- Default quarantine: `.quarantine/` in scan directory

### Error Handling
- Permission errors logged as WARNING, operation continues
- File read errors logged as ERROR with exception details
- API exceptions include proper HTTP status codes and are logged with correlation IDs

## Testing Workflow

No automated test suite currently exists. Manual testing:

1. Start backend server
2. Open frontend in browser
3. Point to a test directory with known duplicates
4. Verify results in UI and check `backend/data/last_scan.json`
5. Test export functionality
6. Verify logs in `logs/` directory match NDJSON specification
