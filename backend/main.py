"""FastAPI backend that wraps duplicate_detector utilities with NDJSON logging."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from duplicate_detector import DuplicateDetector  # noqa: E402

API_VERSION = "1.0.0"
API_ENV = os.getenv("DUPLY_ENV", "dev")
API_COMPONENT = "api"

app = FastAPI(
    title="Duplicate Detector API",
    description="REST API that exposes duplicate file detection functionality.",
    version=API_VERSION,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_detector = DuplicateDetector()
_api_logger = logging.getLogger("duplicate_detector")
_api_logger.setLevel(logging.INFO)

EXPORT_DIR = Path(__file__).resolve().parent / "exports"
EXPORT_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR = Path(__file__).resolve().parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
LAST_SCAN_PATH = DATA_DIR / "last_scan.json"


def _normalize_extensions(values: Optional[List[str]]) -> Optional[List[str]]:
    if not values:
        return None
    normalized: List[str] = []
    for item in values:
        if not item:
            continue
        cleaned = item.strip().lower()
        if not cleaned:
            continue
        if not cleaned.startswith('.'):
            cleaned = f'.{cleaned}'
        normalized.append(cleaned)
    return sorted(set(normalized)) or None


def _hash_payload(payload: Dict[str, Any]) -> str:
    try:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    except TypeError:
        encoded = repr(payload)
    return hashlib.md5(encoded.encode("utf-8")).hexdigest()[:12]


def _log_api_event(event: str, message: str, *, level: int = logging.INFO, **fields: Any) -> None:
    log_payload = {
        "event": event,
        "message": message,
        "component": API_COMPONENT,
        "version": API_VERSION,
        "env": API_ENV,
    }
    log_payload.update(fields)
    _api_logger.log(level, message, extra={"log_payload": log_payload})


class ScanRequest(BaseModel):
    path: str
    method: str = "hybrid"
    recursive: bool = True
    extensions: Optional[List[str]] = None


class ScanRecord(BaseModel):
    scan_id: str
    timestamp: str
    scan_path: str
    method: str
    recursive: bool
    extensions: Optional[List[str]]
    duplicates: Dict[Any, List[str]]
    stats: Dict[str, Any]


_last_scan: Optional[ScanRecord] = None


@app.get("/")
def root() -> FileResponse:
    frontend_path = ROOT_DIR / "frontend" / "index.html"
    if not frontend_path.exists():
        raise HTTPException(status_code=404, detail="Frontend not found")
    return FileResponse(frontend_path)


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/scan")
def scan_files(payload: ScanRequest, request: Request) -> Dict[str, Any]:
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    client_ip = request.client.host if request.client else "unknown"
    route = str(request.url.path)
    start = time.perf_counter()
    params_hash = _hash_payload(payload.model_dump())

    _log_api_event(
        "api_request",
        "Scan request received",
        request_id=request_id,
        route=route,
        method=request.method,
        client_ip=client_ip,
        params_hash=params_hash,
    )

    scan_path = Path(payload.path).expanduser()
    try:
        if not scan_path.exists():
            raise HTTPException(status_code=404, detail=f"Path not found: {scan_path}")
        if not scan_path.is_dir():
            raise HTTPException(status_code=400, detail="Path must be a directory")

        scan_path = scan_path.resolve()

        method = payload.method.lower()
        allowed_methods = {"hash", "name", "size", "hybrid"}
        if method not in allowed_methods:
            allowed = ", ".join(sorted(allowed_methods))
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported method '{payload.method}'. Allowed: {allowed}",
            )

        extensions = _normalize_extensions(payload.extensions)

        if method == "hash":
            duplicates = _detector.find_duplicates_by_hash(
                scan_path,
                file_extensions=extensions,
                recursive=payload.recursive,
            )
        elif method == "name":
            duplicates = _detector.find_duplicates_by_name(
                scan_path,
                case_sensitive=False,
                recursive=payload.recursive,
            )
        elif method == "size":
            duplicates = _detector.find_duplicates_by_size(
                scan_path,
                recursive=payload.recursive,
            )
        else:
            duplicates = _detector.find_duplicates_hybrid(
                scan_path,
                file_extensions=extensions,
                recursive=payload.recursive,
            )
    except HTTPException as exc:
        duration_ms = int((time.perf_counter() - start) * 1000)
        _log_api_event(
            "api_response",
            "Scan request failed",
            level=logging.ERROR,
            request_id=request_id,
            route=route,
            method=request.method,
            status_code=exc.status_code,
            duration_ms=duration_ms,
            exception_type=exc.__class__.__name__,
            exception_msg=str(exc.detail),
        )
        raise
    except Exception as exc:
        duration_ms = int((time.perf_counter() - start) * 1000)
        _log_api_event(
            "api_response",
            "Scan request failed",
            level=logging.ERROR,
            request_id=request_id,
            route=route,
            method=request.method,
            status_code=500,
            duration_ms=duration_ms,
            exception_type=exc.__class__.__name__,
            exception_msg=str(exc),
        )
        raise

    stats = _detector.get_duplicate_stats(duplicates)
    scan_context = getattr(_detector, "_last_scan_context", {}) or {}
    scan_id = str(scan_context.get("scan_id", uuid.uuid4()))
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

    global _last_scan
    _last_scan = ScanRecord(
        scan_id=scan_id,
        timestamp=timestamp,
        scan_path=str(scan_path),
        method=method,
        recursive=payload.recursive,
        extensions=extensions,
        duplicates=duplicates,
        stats=stats,
    )

    response_payload = {
        "scan_id": scan_id,
        "timestamp": timestamp,
        "scan_path": str(scan_path),
        "method": method,
        "recursive": payload.recursive,
        "extensions": extensions or [],
        "duplicates": duplicates,
        "stats": stats,
    }

    try:
        LAST_SCAN_PATH.write_text(
            json.dumps(response_payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError as exc:
        _detector.logger.warning(f"Failed to persist scan JSON: {exc}")

    duration_ms = int((time.perf_counter() - start) * 1000)
    _log_api_event(
        "api_response",
        "Scan request completed",
        request_id=request_id,
        route=route,
        method=request.method,
        status_code=200,
        duration_ms=duration_ms,
        scan_id=scan_id,
        duplicate_groups=stats["total_duplicate_groups"],
    )

    return response_payload


@app.get("/stats")
def get_stats(request: Request) -> Dict[str, Any]:
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    client_ip = request.client.host if request.client else "unknown"
    route = str(request.url.path)
    start = time.perf_counter()
    params_hash = _hash_payload({"query": dict(request.query_params)})

    _log_api_event(
        "api_request",
        "Stats request received",
        request_id=request_id,
        route=route,
        method=request.method,
        client_ip=client_ip,
        params_hash=params_hash,
    )

    if _last_scan is None:
        duration_ms = int((time.perf_counter() - start) * 1000)
        _log_api_event(
            "api_response",
            "Stats request failed",
            level=logging.ERROR,
            request_id=request_id,
            route=route,
            method=request.method,
            status_code=404,
            duration_ms=duration_ms,
            exception_type="HTTPException",
            exception_msg="No scan has been executed yet",
        )
        raise HTTPException(status_code=404, detail="No scan has been executed yet")

    duration_ms = int((time.perf_counter() - start) * 1000)
    payload = {
        "scan_id": _last_scan.scan_id,
        "timestamp": _last_scan.timestamp,
        "scan_path": _last_scan.scan_path,
        "method": _last_scan.method,
        "recursive": _last_scan.recursive,
        "extensions": _last_scan.extensions or [],
        "stats": _last_scan.stats,
        "duplicate_groups": len(_last_scan.duplicates),
    }

    _log_api_event(
        "api_response",
        "Stats request completed",
        request_id=request_id,
        route=route,
        method=request.method,
        status_code=200,
        duration_ms=duration_ms,
        scan_id=_last_scan.scan_id,
        duplicate_groups=payload["duplicate_groups"],
    )

    return payload


@app.get("/export")
def export_results(request: Request, format: str = Query(default="json", regex="^(json|csv)$")) -> FileResponse:
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    client_ip = request.client.host if request.client else "unknown"
    route = str(request.url.path)
    start = time.perf_counter()
    params_hash = _hash_payload({"format": format})

    _log_api_event(
        "api_request",
        "Export request received",
        request_id=request_id,
        route=route,
        method=request.method,
        client_ip=client_ip,
        params_hash=params_hash,
    )

    if _last_scan is None:
        duration_ms = int((time.perf_counter() - start) * 1000)
        _log_api_event(
            "api_response",
            "Export request failed",
            level=logging.ERROR,
            request_id=request_id,
            route=route,
            method=request.method,
            status_code=404,
            duration_ms=duration_ms,
            exception_type="HTTPException",
            exception_msg="No scan results available to export",
        )
        raise HTTPException(status_code=404, detail="No scan results available to export")

    file_stem = f"duplicates_{_last_scan.timestamp}"
    file_path = EXPORT_DIR / f"{file_stem}.{format}"

    try:
        _detector.export_results(
            _last_scan.duplicates,
            output_file=file_path,
            format=format,
            scan_context=getattr(_detector, "_last_scan_context", {}),
        )
    except Exception as exc:
        duration_ms = int((time.perf_counter() - start) * 1000)
        _log_api_event(
            "api_response",
            "Export request failed",
            level=logging.ERROR,
            request_id=request_id,
            route=route,
            method=request.method,
            status_code=500,
            duration_ms=duration_ms,
            scan_id=_last_scan.scan_id,
            exception_type=exc.__class__.__name__,
            exception_msg=str(exc),
        )
        raise

    duration_ms = int((time.perf_counter() - start) * 1000)
    _log_api_event(
        "api_response",
        "Export request completed",
        request_id=request_id,
        route=route,
        method=request.method,
        status_code=200,
        duration_ms=duration_ms,
        scan_id=_last_scan.scan_id,
        format=format,
    )

    media_type = "application/json" if format == "json" else "text/csv"
    return FileResponse(path=file_path, media_type=media_type, filename=file_path.name)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
