#!/usr/bin/env python3
"""Reusable duplicate detector with structured NDJSON logging."""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import os
import re
import shutil
from logging.handlers import RotatingFileHandler
import sys
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

MODULE_VERSION = "1.0.0"
DEFAULT_ENV = "dev"
PROGRESS_STEP = 500

LOG_DIR_ENV = "DUPLY_LOG_DIR"
DEFAULT_LOG_DIR = Path(__file__).resolve().parent / "logs"
GENERAL_LOG_FILENAME = "duplicate-detector.log"
API_LOG_FILENAME = "duplicate-detector.api.log"
LOG_MAX_BYTES = 5 * 1024 * 1024
GENERAL_TEXT_LOG_FILENAME = "duplicate-detector.txt"
API_TEXT_LOG_FILENAME = "duplicate-detector.api.txt"
LOG_BACKUP_COUNT = 5
DEFAULT_QUARANTINE_DIRNAME = ".quarantine"
PLAN_SURVIVOR_POLICIES = {"keep_first", "keep_oldest", "keep_newest"}
PLAN_ACTIONS = {"move_to_quarantine", "delete"}
PLAN_COLLISION_STRATEGIES = {"rename", "skip", "overwrite"}

API_LOG_BACKUP_COUNT = 3

def _iso_utc(timestamp: float) -> str:
    """Return ISO-8601 UTC timestamp with Z suffix."""
    dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

class NDJSONFormatter(logging.Formatter):
    """Render log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        payload = getattr(record, "log_payload", {}).copy()
        payload.setdefault("timestamp", _iso_utc(record.created))
        payload.setdefault("level", record.levelname)

        message = record.getMessage()
        if not payload.get("message"):
            payload["message"] = message

        payload.setdefault("event", getattr(record, "event", message))
        return json.dumps(payload, ensure_ascii=False)


class PlainTextFormatter(logging.Formatter):
    """Render log records as human-readable text."""

    def format(self, record: logging.LogRecord) -> str:
        payload = getattr(record, "log_payload", {}).copy()
        timestamp = _iso_utc(record.created)
        level = record.levelname
        message = record.getMessage()
        event = payload.get("event") or getattr(record, "event", message)
        human_message = payload.get("message") or message
        extras = {k: v for k, v in payload.items() if k not in {"event", "message"}}
        extra_str = " ".join(f"{key}={value}" for key, value in sorted(extras.items()))
        base = f"{timestamp} [{level}] {event}: {human_message}"
        return f"{base} | {extra_str}" if extra_str else base




class _ComponentFilter(logging.Filter):
    def __init__(self, *, component: str) -> None:
        super().__init__()
        self._component = component

    def filter(self, record: logging.LogRecord) -> bool:
        payload = getattr(record, "log_payload", {})
        return payload.get("component") == self._component


def _resolve_log_dir() -> Path:
    override = os.getenv(LOG_DIR_ENV)
    if override:
        candidate = Path(override).expanduser()
    else:
        candidate = DEFAULT_LOG_DIR
    try:
        candidate.mkdir(parents=True, exist_ok=True)
    except OSError:
        candidate = DEFAULT_LOG_DIR
        candidate.mkdir(parents=True, exist_ok=True)
    return candidate


class DuplicateDetector:
    """Detect duplicate files using different strategies."""

    def __init__(
        self,
        hash_method: str = "md5",
        chunk_size: int = 8192,
        *,
        environment: str = DEFAULT_ENV,
        version: str = MODULE_VERSION,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.hash_method = hash_method.lower()
        self.chunk_size = chunk_size
        self.env = environment.lower()
        self.version = version
        self.component = "library"
        self._last_scan_context: Optional[Dict[str, Any]] = None

        if self.hash_method not in {"md5", "sha256"}:
            raise ValueError("hash_method must be 'md5' or 'sha256'")

        self.logger = logger or self._setup_logger()

    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger("duplicate_detector")
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            log_dir = _resolve_log_dir()

            stream_handler = logging.StreamHandler()
            stream_handler.setFormatter(NDJSONFormatter())
            logger.addHandler(stream_handler)

            file_handler = RotatingFileHandler(
                log_dir / GENERAL_LOG_FILENAME,
                maxBytes=LOG_MAX_BYTES,
                backupCount=LOG_BACKUP_COUNT,
                encoding="utf-8",
                delay=True,
            )
            file_handler.setFormatter(NDJSONFormatter())
            logger.addHandler(file_handler)

            text_handler = RotatingFileHandler(
                log_dir / GENERAL_TEXT_LOG_FILENAME,
                maxBytes=LOG_MAX_BYTES,
                backupCount=LOG_BACKUP_COUNT,
                encoding="utf-8",
                delay=True,
            )
            text_handler.setFormatter(PlainTextFormatter())
            logger.addHandler(text_handler)

            api_file_handler = RotatingFileHandler(
                log_dir / API_LOG_FILENAME,
                maxBytes=LOG_MAX_BYTES,
                backupCount=API_LOG_BACKUP_COUNT,
                encoding="utf-8",
                delay=True,
            )
            api_file_handler.setFormatter(NDJSONFormatter())
            api_file_handler.addFilter(_ComponentFilter(component="api"))
            logger.addHandler(api_file_handler)

            api_text_handler = RotatingFileHandler(
                log_dir / API_TEXT_LOG_FILENAME,
                maxBytes=LOG_MAX_BYTES,
                backupCount=API_LOG_BACKUP_COUNT,
                encoding="utf-8",
                delay=True,
            )
            api_text_handler.setFormatter(PlainTextFormatter())
            api_text_handler.addFilter(_ComponentFilter(component="api"))
            logger.addHandler(api_text_handler)

        return logger

    @staticmethod
    def _collect_file_info(path_str: Union[str, Path], order: int) -> Dict[str, Any]:
        path = Path(path_str)
        exists = path.exists()
        error: Optional[str] = None
        size: Optional[int] = None
        modified: Optional[float] = None
        if exists:
            try:
                stat = path.stat()
                size = stat.st_size
                modified = stat.st_mtime
            except OSError as exc:
                exists = False
                error = str(exc)
        return {
            "order": order,
            "path": path,
            "path_str": str(path),
            "exists": exists,
            "size": size,
            "modified": modified,
            "error": error,
        }

    @staticmethod
    def _select_survivor_info(file_infos: List[Dict[str, Any]], policy: str) -> Dict[str, Any]:
        if not file_infos:
            raise ValueError("file_infos cannot be empty for survivor selection")

        existing = [info for info in file_infos if info["exists"]]
        if not existing:
            return file_infos[0]

        if policy == "keep_first":
            for info in file_infos:
                if info["exists"]:
                    return info
            return existing[0]

        if policy == "keep_oldest":
            return min(
                existing,
                key=lambda info: (
                    info["modified"] if info["modified"] is not None else float("inf"),
                    info["order"],
                ),
            )

        if policy == "keep_newest":
            return max(
                existing,
                key=lambda info: (
                    info["modified"] if info["modified"] is not None else float("-inf"),
                    -info["order"],
                ),
            )

        return existing[0]

    @staticmethod
    def _build_quarantine_destination(base_dir: Path, source_path: Path) -> Path:
        try:
            resolved = source_path.resolve()
        except Exception:
            resolved = source_path

        parts: List[str] = []

        if resolved.drive:
            drive_clean = re.sub(r"[^A-Za-z0-9._-]+", "_", resolved.drive.replace(":", "_"))
            if drive_clean:
                parts.append(drive_clean)
            remaining = list(resolved.parts)[1:]
        elif resolved.is_absolute():
            remaining = list(resolved.parts)[1:]
        else:
            remaining = list(resolved.parts)

        for part in remaining:
            if part in {"", ".", ".."}:
                cleaned = part.replace(".", "_")
            else:
                cleaned = part
            cleaned = re.sub(r"[\\/]+", "_", cleaned)
            cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", cleaned)
            if not cleaned:
                cleaned = "_"
            parts.append(cleaned)

        if not parts:
            fallback = source_path.name or "file"
            parts.append(re.sub(r"[^A-Za-z0-9._-]+", "_", fallback))

        return base_dir.joinpath(*parts)

    @staticmethod
    def _resolve_destination_collision(
        destination: Path,
        strategy: str,
        reserved: Set[Path],
    ) -> Tuple[Optional[Path], Optional[str]]:
        try:
            normalized = destination.expanduser().resolve(strict=False)
        except Exception:
            normalized = destination.expanduser()

        already_reserved = normalized in reserved
        try:
            exists = normalized.exists()
        except OSError:
            exists = False

        if not already_reserved and not exists:
            return normalized, None

        if strategy == "overwrite":
            return normalized, None

        if strategy == "skip":
            return None, "destination_exists"

        if strategy == "rename":
            counter = 1
            candidate = normalized
            stem = normalized.stem
            suffix = normalized.suffix
            while candidate in reserved or candidate.exists():
                candidate = normalized.with_name(f"{stem}__dup{counter}{suffix}")
                counter += 1
            return candidate, None

        return None, "invalid_strategy"

    @staticmethod
    def _ensure_json_serializable(plan: Dict[str, Any]) -> Dict[str, Any]:
        def _coerce(value: Any) -> Any:
            if isinstance(value, Path):
                return str(value)
            if isinstance(value, list):
                return [_coerce(item) for item in value]
            if isinstance(value, dict):
                return {key: _coerce(val) for key, val in value.items()}
            return value

        return _coerce(plan)

    @staticmethod
    def _load_plan_source(
        plan: Union[Dict[str, Any], str, Path],
    ) -> Tuple[Dict[str, Any], Optional[Path]]:
        if isinstance(plan, dict):
            return dict(plan), None
        if isinstance(plan, (str, Path)):
            plan_path = Path(plan)
            data = json.loads(plan_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("plan JSON must decode to a dictionary")
            return data, plan_path
        raise TypeError("plan must be a dict or a filesystem path")

    @staticmethod
    def _write_json_file(path: Path, payload: Dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def _ensure_extensions(self, extensions: Optional[List[str]]) -> Optional[List[str]]:
        if not extensions:
            return None
        cleaned: List[str] = []
        for item in extensions:
            if not item:
                continue
            value = item.strip().lower()
            if not value:
                continue
            if not value.startswith("."):
                value = f".{value}"
            cleaned.append(value)
        if not cleaned:
            return None
        return sorted(set(cleaned))

    def _build_log_context(
        self,
        scan_id: str,
        root_dir: Path,
        recursive: bool,
        extensions: Optional[List[str]],
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "scan_id": scan_id,
            "component": self.component,
            "version": self.version,
            "env": self.env,
            "root_dir": str(root_dir),
            "recursive": bool(recursive),
            "extensions": extensions,
            "hash_method": self.hash_method,
            "chunk_size": self.chunk_size,
        }
        if extra:
            payload.update(extra)
        return payload

    def _log_event(
        self,
        event: str,
        level: int,
        message: str,
        context: Optional[Dict[str, Any]] = None,
        **fields: Any,
    ) -> None:
        payload: Dict[str, Any] = {"event": event, "message": message}
        if context:
            payload.update(context)
        else:
            payload.setdefault("component", self.component)
            payload.setdefault("version", self.version)
            payload.setdefault("env", self.env)
            payload.setdefault("hash_method", self.hash_method)
            payload.setdefault("chunk_size", self.chunk_size)
        payload.update(fields)
        self.logger.log(level, message, extra={"log_payload": payload})

    def _resolve_context(self, context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if context:
            return dict(context)
        if self._last_scan_context:
            return dict(self._last_scan_context)
        return {
            "scan_id": "unknown-scan",
            "component": self.component,
            "version": self.version,
            "env": self.env,
            "root_dir": "",
            "recursive": False,
            "extensions": None,
            "hash_method": self.hash_method,
            "chunk_size": self.chunk_size,
        }

    @staticmethod
    def _duration_ms(start_time: float) -> int:
        return max(0, int((time.perf_counter() - start_time) * 1000))

    def _store_last_context(self, context: Dict[str, Any]) -> None:
        self._last_scan_context = dict(context)
    def calculate_file_hash(self, file_path: Union[str, Path]) -> str:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        if not path.is_file():
            raise ValueError(f"Path is not a regular file: {path}")

        hasher = hashlib.md5() if self.hash_method == "md5" else hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(self.chunk_size):
                hasher.update(chunk)
        return hasher.hexdigest()
    def find_duplicates_by_hash(
        self,
        directory: Union[str, Path],
        file_extensions: Optional[List[str]] = None,
        recursive: bool = True,
    ) -> Dict[str, List[str]]:
        dir_path = Path(directory)
        if not dir_path.exists():
            raise FileNotFoundError(f"Directory not found: {dir_path}")

        extensions = self._ensure_extensions(file_extensions)
        ext_filter = set(extensions) if extensions else None
        scan_id = str(uuid.uuid4())
        context = self._build_log_context(
            scan_id,
            dir_path.resolve(),
            recursive,
            extensions,
            extra={"scan_mode": "hash"},
        )

        self._store_last_context(context)
        start = time.perf_counter()
        files_processed = 0
        hash_map: Dict[str, List[str]] = defaultdict(list)
        pattern = "**/*" if recursive else "*"

        self._log_event("scan_started", logging.INFO, "Scan started", context)

        for entry in dir_path.glob(pattern):
            if not entry.is_file():
                self._log_event(
                    "file_skipped_not_file",
                    logging.WARNING,
                    "Skipped non regular file",
                    context,
                    file=str(entry),
                )
                continue

            if ext_filter and entry.suffix.lower() not in ext_filter:
                continue

            try:
                file_hash = self.calculate_file_hash(entry)
            except PermissionError as exc:
                self._log_event(
                    "file_skipped_permission",
                    logging.WARNING,
                    "Permission denied",
                    context,
                    file=str(entry),
                    exception_type=exc.__class__.__name__,
                )
                continue
            except Exception as exc:
                self._log_event(
                    "file_error_hash",
                    logging.ERROR,
                    "Failed to calculate hash",
                    context,
                    file=str(entry),
                    exception_type=exc.__class__.__name__,
                    exception_msg=str(exc),
                )
                continue

            hash_map[file_hash].append(str(entry))
            files_processed += 1

            if files_processed % PROGRESS_STEP == 0:
                self._log_event(
                    "directory_walk_progress",
                    logging.INFO,
                    "Directory walk progress",
                    context,
                    files_processed=files_processed,
                    duration_ms=self._duration_ms(start),
                )

            if self.logger.isEnabledFor(logging.DEBUG):
                try:
                    size = entry.stat().st_size
                except OSError:
                    size = None
                self._log_event(
                    "hash_computed",
                    logging.DEBUG,
                    "Hash computed",
                    context,
                    file=str(entry),
                    size=size,
                    hash_prefix=file_hash[:12],
                )

        duplicates = {
            hash_value: files for hash_value, files in hash_map.items() if len(files) > 1
        }

        stats = self.get_duplicate_stats(duplicates)
        self._log_event(
            "scan_finished",
            logging.INFO,
            "Scan finished",
            context,
            files_processed=files_processed,
            groups_found=stats["total_duplicate_groups"],
            total_duplicate_files=stats["total_duplicate_files"],
            wasted_size_bytes=stats["wasted_size_bytes"],
            duration_ms=self._duration_ms(start),
        )

        return duplicates

    def find_duplicates_by_name(
        self,
        directory: Union[str, Path],
        case_sensitive: bool = False,
        recursive: bool = True,
    ) -> Dict[str, List[str]]:
        dir_path = Path(directory)
        if not dir_path.exists():
            raise FileNotFoundError(f"Directory not found: {dir_path}")

        scan_id = str(uuid.uuid4())
        context = self._build_log_context(
            scan_id,
            dir_path.resolve(),
            recursive,
            extensions=None,
            extra={"scan_mode": "name", "case_sensitive": case_sensitive},
        )

        self._store_last_context(context)
        self._log_event("scan_started", logging.INFO, "Scan started", context)

        pattern = "**/*" if recursive else "*"
        files_processed = 0
        name_map: Dict[str, List[str]] = defaultdict(list)
        start = time.perf_counter()

        for entry in dir_path.glob(pattern):
            if not entry.is_file():
                self._log_event(
                    "file_skipped_not_file",
                    logging.WARNING,
                    "Skipped non regular file",
                    context,
                    file=str(entry),
                )
                continue

            name = entry.name if case_sensitive else entry.name.lower()
            name_map[name].append(str(entry))
            files_processed += 1

            if files_processed % PROGRESS_STEP == 0:
                self._log_event(
                    "directory_walk_progress",
                    logging.INFO,
                    "Directory walk progress",
                    context,
                    files_processed=files_processed,
                    duration_ms=self._duration_ms(start),
                )

        duplicates = {name: files for name, files in name_map.items() if len(files) > 1}
        stats = self.get_duplicate_stats(duplicates)

        self._log_event(
            "scan_finished",
            logging.INFO,
            "Scan finished",
            context,
            files_processed=files_processed,
            groups_found=stats["total_duplicate_groups"],
            total_duplicate_files=stats["total_duplicate_files"],
            wasted_size_bytes=stats["wasted_size_bytes"],
            duration_ms=self._duration_ms(start),
        )

        return duplicates

    def find_duplicates_by_size(
        self,
        directory: Union[str, Path],
        recursive: bool = True,
    ) -> Dict[int, List[str]]:
        dir_path = Path(directory)
        if not dir_path.exists():
            raise FileNotFoundError(f"Directory not found: {dir_path}")

        scan_id = str(uuid.uuid4())
        context = self._build_log_context(
            scan_id,
            dir_path.resolve(),
            recursive,
            extensions=None,
            extra={"scan_mode": "size"},
        )

        self._store_last_context(context)
        self._log_event("scan_started", logging.INFO, "Scan started", context)

        size_map: Dict[int, List[str]] = defaultdict(list)
        files_processed = 0
        pattern = "**/*" if recursive else "*"
        start = time.perf_counter()

        for entry in dir_path.glob(pattern):
            if not entry.is_file():
                self._log_event(
                    "file_skipped_not_file",
                    logging.WARNING,
                    "Skipped non regular file",
                    context,
                    file=str(entry),
                )
                continue
            try:
                file_size = entry.stat().st_size
            except PermissionError as exc:
                self._log_event(
                    "file_skipped_permission",
                    logging.WARNING,
                    "Permission denied",
                    context,
                    file=str(entry),
                    exception_type=exc.__class__.__name__,
                )
                continue
            except OSError as exc:
                self._log_event(
                    "file_stat_error",
                    logging.ERROR,
                    "Failed to read file size",
                    context,
                    file=str(entry),
                    exception_type=exc.__class__.__name__,
                    exception_msg=str(exc),
                )
                continue

            size_map[file_size].append(str(entry))
            files_processed += 1

            if files_processed % PROGRESS_STEP == 0:
                self._log_event(
                    "directory_walk_progress",
                    logging.INFO,
                    "Directory walk progress",
                    context,
                    files_processed=files_processed,
                    duration_ms=self._duration_ms(start),
                )

        duplicates = {size: files for size, files in size_map.items() if len(files) > 1}
        stats = self.get_duplicate_stats(duplicates)

        self._log_event(
            "scan_finished",
            logging.INFO,
            "Scan finished",
            context,
            files_processed=files_processed,
            groups_found=stats["total_duplicate_groups"],
            total_duplicate_files=stats["total_duplicate_files"],
            wasted_size_bytes=stats["wasted_size_bytes"],
            duration_ms=self._duration_ms(start),
        )

        return duplicates

    def find_duplicates_hybrid(
        self,
        directory: Union[str, Path],
        file_extensions: Optional[List[str]] = None,
        recursive: bool = True,
    ) -> Dict[str, List[str]]:
        dir_path = Path(directory)
        if not dir_path.exists():
            raise FileNotFoundError(f"Directory not found: {dir_path}")

        extensions = self._ensure_extensions(file_extensions)
        ext_filter = set(extensions) if extensions else None
        scan_id = str(uuid.uuid4())
        context = self._build_log_context(
            scan_id,
            dir_path.resolve(),
            recursive,
            extensions,
            extra={"scan_mode": "hybrid"},
        )

        self._store_last_context(context)
        self._log_event("scan_started", logging.INFO, "Scan started", context)

        pattern = "**/*" if recursive else "*"
        size_groups: Dict[int, List[Path]] = defaultdict(list)
        size_stage_processed = 0
        start = time.perf_counter()

        for entry in dir_path.glob(pattern):
            if not entry.is_file():
                self._log_event(
                    "file_skipped_not_file",
                    logging.WARNING,
                    "Skipped non regular file",
                    context,
                    file=str(entry),
                )
                continue

            if ext_filter and entry.suffix.lower() not in ext_filter:
                continue

            try:
                file_size = entry.stat().st_size
            except PermissionError as exc:
                self._log_event(
                    "file_skipped_permission",
                    logging.WARNING,
                    "Permission denied",
                    context,
                    file=str(entry),
                    exception_type=exc.__class__.__name__,
                )
                continue
            except OSError as exc:
                self._log_event(
                    "file_stat_error",
                    logging.ERROR,
                    "Failed to read file size",
                    context,
                    file=str(entry),
                    exception_type=exc.__class__.__name__,
                    exception_msg=str(exc),
                )
                continue

            size_groups[file_size].append(entry)
            size_stage_processed += 1

            if size_stage_processed % PROGRESS_STEP == 0:
                self._log_event(
                    "directory_walk_progress",
                    logging.INFO,
                    "Directory walk progress",
                    context,
                    files_processed=size_stage_processed,
                    duration_ms=self._duration_ms(start),
                )

        candidates = [files for files in size_groups.values() if len(files) > 1]

        if self.logger.isEnabledFor(logging.DEBUG):
            for files in candidates:
                bucket_size = 0
                try:
                    bucket_size = files[0].stat().st_size if files else 0
                except OSError:
                    bucket_size = 0
                self._log_event(
                    "size_bucket_detected",
                    logging.DEBUG,
                    "Candidate bucket detected",
                    context,
                    size=bucket_size,
                    files_processed=size_stage_processed,
                )

        hash_duplicates: Dict[str, List[str]] = {}
        files_hashed = 0

        for files in candidates:
            hash_group: Dict[str, List[str]] = defaultdict(list)
            for entry in files:
                try:
                    file_hash = self.calculate_file_hash(entry)
                except PermissionError as exc:
                    self._log_event(
                        "file_skipped_permission",
                        logging.WARNING,
                        "Permission denied",
                        context,
                        file=str(entry),
                        exception_type=exc.__class__.__name__,
                    )
                    continue
                except Exception as exc:
                    self._log_event(
                        "file_error_hash",
                        logging.ERROR,
                        "Failed to calculate hash",
                        context,
                        file=str(entry),
                        exception_type=exc.__class__.__name__,
                        exception_msg=str(exc),
                    )
                    continue

                hash_group[file_hash].append(str(entry))
                files_hashed += 1

                if files_hashed % PROGRESS_STEP == 0:
                    self._log_event(
                        "directory_walk_progress",
                        logging.INFO,
                        "Directory walk progress",
                        context,
                        files_processed=files_hashed,
                        duration_ms=self._duration_ms(start),
                    )

                if self.logger.isEnabledFor(logging.DEBUG):
                    try:
                        file_size = entry.stat().st_size
                    except OSError:
                        file_size = None
                    self._log_event(
                        "hash_computed",
                        logging.DEBUG,
                        "Hash computed",
                        context,
                        file=str(entry),
                        size=file_size,
                        hash_prefix=file_hash[:12],
                    )

            for hash_value, paths in hash_group.items():
                if len(paths) > 1:
                    hash_duplicates[hash_value] = paths

        stats = self.get_duplicate_stats(hash_duplicates)
        self._log_event(
            "scan_finished",
            logging.INFO,
            "Scan finished",
            context,
            files_processed=files_hashed or size_stage_processed,
            groups_found=stats["total_duplicate_groups"],
            total_duplicate_files=stats["total_duplicate_files"],
            wasted_size_bytes=stats["wasted_size_bytes"],
            duration_ms=self._duration_ms(start),
        )

        return hash_duplicates

    def compare_directories(
        self,
        dir1: Union[str, Path],
        dir2: Union[str, Path],
        method: str = "hash",
    ) -> Dict[str, Dict[str, Any]]:
        dir1_path = Path(dir1)
        dir2_path = Path(dir2)

        if not dir1_path.exists():
            raise FileNotFoundError(f"Directory not found: {dir1_path}")
        if not dir2_path.exists():
            raise FileNotFoundError(f"Directory not found: {dir2_path}")

        scan_id = str(uuid.uuid4())
        context = self._build_log_context(
            scan_id,
            dir1_path.resolve(),
            recursive=False,
            extensions=None,
            extra={
                "comparison_with": str(dir2_path.resolve()),
                "comparison_method": method,
            },
        )

        self._log_event(
            "dir_compare_started",
            logging.INFO,
            "Directory comparison started",
            context,
        )

        if method == "hash":
            files1 = self._get_files_with_hash(dir1_path)
            files2 = self._get_files_with_hash(dir2_path)
        elif method == "name":
            files1 = self._get_files_with_name(dir1_path)
            files2 = self._get_files_with_name(dir2_path)
        elif method == "size":
            files1 = self._get_files_with_size(dir1_path)
            files2 = self._get_files_with_size(dir2_path)
        else:
            raise ValueError("method must be 'hash', 'name', or 'size'")

        keys1 = set(files1.keys())
        keys2 = set(files2.keys())
        common_keys = keys1 & keys2

        duplicates: Dict[str, Dict[str, Any]] = {}
        for key in common_keys:
            duplicates[key] = {
                "dir1_files": files1[key],
                "dir2_files": files2[key],
                "comparison_method": method,
            }

        stats = {
            "total_dir1": len(files1),
            "total_dir2": len(files2),
            "common_items": len(common_keys),
            "unique_dir1": len(keys1 - keys2),
            "unique_dir2": len(keys2 - keys1),
        }

        self._log_event(
            "dir_compare_finished",
            logging.INFO,
            "Directory comparison finished",
            context,
            stats=stats,
        )

        return {"duplicates": duplicates, "stats": stats}

    def _get_files_with_hash(self, directory: Path) -> Dict[str, List[str]]:
        hash_map: Dict[str, List[str]] = defaultdict(list)
        for file_path in directory.rglob("*"):
            if not file_path.is_file():
                continue
            try:
                file_hash = self.calculate_file_hash(file_path)
            except Exception:
                continue
            hash_map[file_hash].append(str(file_path))
        return dict(hash_map)

    def _get_files_with_name(self, directory: Path) -> Dict[str, List[str]]:
        name_map: Dict[str, List[str]] = defaultdict(list)
        for file_path in directory.rglob("*"):
            if file_path.is_file():
                name_map[file_path.name].append(str(file_path))
        return dict(name_map)

    def _get_files_with_size(self, directory: Path) -> Dict[int, List[str]]:
        size_map: Dict[int, List[str]] = defaultdict(list)
        for file_path in directory.rglob("*"):
            if not file_path.is_file():
                continue
            try:
                file_size = file_path.stat().st_size
            except OSError:
                continue
            size_map[file_size].append(str(file_path))
        return dict(size_map)


    def generate_action_plan(
        self,
        duplicates: Dict[str, List[str]],
        *,
        policy: str = "keep_newest",
        action: str = "move_to_quarantine",
        collision_strategy: str = "rename",
        quarantine_dir: Optional[Union[str, Path]] = None,
        output_file: Optional[Union[str, Path]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a plan describing how to handle duplicate files."""
        if policy not in PLAN_SURVIVOR_POLICIES:
            raise ValueError(f"policy must be one of {sorted(PLAN_SURVIVOR_POLICIES)}")
        if action not in PLAN_ACTIONS:
            raise ValueError(f"action must be one of {sorted(PLAN_ACTIONS)}")
        if collision_strategy not in PLAN_COLLISION_STRATEGIES:
            raise ValueError(
                f"collision_strategy must be one of {sorted(PLAN_COLLISION_STRATEGIES)}"
            )

        plan_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        context = self._resolve_context(self._last_scan_context)

        if quarantine_dir is not None:
            base_quarantine = Path(quarantine_dir)
        else:
            root_dir = context.get("root_dir") or ""
            if root_dir:
                base_quarantine = Path(root_dir) / DEFAULT_QUARANTINE_DIRNAME
            else:
                base_quarantine = Path.cwd() / DEFAULT_QUARANTINE_DIRNAME

        try:
            base_quarantine = base_quarantine.expanduser().resolve(strict=False)
        except Exception:
            base_quarantine = base_quarantine.expanduser()

        plan_groups: List[Dict[str, Any]] = []
        reserved_targets: Set[Path] = set()
        files_to_act = 0
        files_skipped = 0
        files_missing = 0
        wasted_size_bytes = 0

        for idx, (group_key, files) in enumerate(duplicates.items(), start=1):
            if not files:
                continue

            file_infos = [
                self._collect_file_info(path_str, order)
                for order, path_str in enumerate(files)
            ]
            survivor_info = self._select_survivor_info(file_infos, policy)

            group_entry: Dict[str, Any] = {
                "group_index": idx,
                "group_id": str(group_key),
                "survivor": survivor_info["path_str"],
                "survivor_info": {
                    "size_bytes": survivor_info["size"],
                    "modified_at": _iso_utc(survivor_info["modified"])
                    if survivor_info["modified"] is not None
                    else None,
                },
                "duplicates": [],
            }

            for info in file_infos:
                if info["path"] == survivor_info["path"]:
                    continue

                duplicate_entry: Dict[str, Any] = {
                    "path": info["path_str"],
                }
                if info["size"] is not None:
                    duplicate_entry["size_bytes"] = info["size"]
                if info["modified"] is not None:
                    duplicate_entry["modified_at"] = _iso_utc(info["modified"])
                if info["error"]:
                    duplicate_entry["note"] = info["error"]

                if not info["exists"]:
                    duplicate_entry["proposed"] = {
                        "action": "skip",
                        "reason": "missing",
                    }
                    files_skipped += 1
                    files_missing += 1
                    group_entry["duplicates"].append(duplicate_entry)
                    continue

                if action == "move_to_quarantine":
                    destination = self._build_quarantine_destination(
                        base_quarantine, info["path"]
                    )
                    resolved_destination, reason = self._resolve_destination_collision(
                        destination, collision_strategy, reserved_targets
                    )
                    if resolved_destination is None:
                        duplicate_entry["proposed"] = {
                            "action": "skip",
                            "reason": reason or "collision",
                        }
                        files_skipped += 1
                    else:
                        reserved_targets.add(resolved_destination)
                        duplicate_entry["proposed"] = {
                            "action": "move",
                            "to": str(resolved_destination),
                        }
                        files_to_act += 1
                        if info["size"] is not None:
                            wasted_size_bytes += info["size"]
                else:
                    duplicate_entry["proposed"] = {"action": "delete"}
                    files_to_act += 1
                    if info["size"] is not None:
                        wasted_size_bytes += info["size"]

                group_entry["duplicates"].append(duplicate_entry)

            if group_entry["duplicates"]:
                plan_groups.append(group_entry)

        stats = {
            "groups": len(plan_groups),
            "files_to_act": files_to_act,
            "files_skipped": files_skipped,
            "files_missing": files_missing,
            "wasted_size_bytes": wasted_size_bytes,
            "wasted_size_mb": round(wasted_size_bytes / (1024 * 1024), 2)
            if wasted_size_bytes
            else 0.0,
        }

        plan: Dict[str, Any] = {
            "plan_id": plan_id,
            "created_at": created_at,
            "policy": policy,
            "action": action,
            "collision_strategy": collision_strategy,
            "quarantine_dir": str(base_quarantine),
            "groups": plan_groups,
            "stats": stats,
            "context": context,
        }
        if metadata:
            plan["metadata"] = metadata

        if output_file is not None:
            output_path = Path(output_file)
            self._write_json_file(
                output_path, self._ensure_json_serializable(plan)
            )
        else:
            output_path = None

        log_fields: Dict[str, Any] = {
            "plan_id": plan_id,
            "groups": len(plan_groups),
            "files_to_act": files_to_act,
            "files_skipped": files_skipped,
            "files_missing": files_missing,
            "action": action,
            "collision_strategy": collision_strategy,
        }
        if output_path is not None:
            log_fields["plan_file"] = str(output_path)

        self._log_event(
            "plan_generated",
            logging.INFO,
            "Plan generated",
            context,
            **{k: v for k, v in log_fields.items() if v is not None},
        )

        return plan

    def dry_run_plan(
        self,
        plan: Union[Dict[str, Any], str, Path],
    ) -> Dict[str, Any]:
        """Simulate the execution of a plan without touching the filesystem."""
        plan_data, plan_path = self._load_plan_source(plan)
        context = self._resolve_context(plan_data.get("context"))

        summary = {
            "plan_id": plan_data.get("plan_id"),
            "moved": 0,
            "deleted": 0,
            "skipped": 0,
            "errors": 0,
            "missing": 0,
        }

        for group in plan_data.get("groups", []):
            for entry in group.get("duplicates", []):
                proposed = entry.get("proposed") or {}
                action_type = proposed.get("action")
                path_str = entry.get("path")
                source_exists = False
                if path_str:
                    try:
                        source_exists = Path(path_str).exists()
                    except OSError:
                        source_exists = False

                if action_type == "move":
                    summary["moved"] += 1
                    if path_str and not source_exists:
                        summary["errors"] += 1
                        summary["missing"] += 1
                elif action_type == "delete":
                    summary["deleted"] += 1
                    if path_str and not source_exists:
                        summary["errors"] += 1
                        summary["missing"] += 1
                else:
                    summary["skipped"] += 1
                    if proposed.get("reason") == "missing":
                        summary["missing"] += 1

        summary["total"] = summary["moved"] + summary["deleted"] + summary["skipped"]

        log_fields = {
            "plan_id": summary["plan_id"],
            "moved": summary["moved"],
            "deleted": summary["deleted"],
            "skipped": summary["skipped"],
            "errors": summary["errors"],
            "missing": summary["missing"],
        }
        if plan_path is not None:
            log_fields["plan_file"] = str(plan_path)

        self._log_event(
            "plan_dry_run_completed",
            logging.INFO,
            "Plan dry run completed",
            context,
            **log_fields,
        )

        return summary

    def apply_plan(
        self,
        plan: Union[Dict[str, Any], str, Path],
        *,
        confirm_delete: bool = False,
        undo_path: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """Apply a plan, optionally producing an undo file."""
        plan_data, plan_path = self._load_plan_source(plan)
        context = self._resolve_context(plan_data.get("context"))

        plan_action = plan_data.get("action", "move_to_quarantine")
        collision_strategy = plan_data.get("collision_strategy", "rename")
        if collision_strategy not in PLAN_COLLISION_STRATEGIES:
            collision_strategy = "rename"
        if plan_action == "delete" and not confirm_delete:
            raise ValueError("confirm_delete must be True when applying delete plans")

        summary = {
            "plan_id": plan_data.get("plan_id"),
            "plan_file": str(plan_path) if plan_path else None,
            "moved": 0,
            "deleted": 0,
            "skipped": 0,
            "errors": 0,
            "missing": 0,
        }
        start = time.perf_counter()
        undo_actions: List[Dict[str, Any]] = []
        reserved_destinations: Set[Path] = set()

        quarantine_dir = plan_data.get("quarantine_dir") or str(
            Path.cwd() / DEFAULT_QUARANTINE_DIRNAME
        )
        base_quarantine = Path(quarantine_dir)
        if not base_quarantine.is_absolute():
            base_dir = plan_path.parent if plan_path is not None else Path.cwd()
            base_quarantine = (base_dir / base_quarantine).expanduser()
        try:
            base_quarantine = base_quarantine.resolve(strict=False)
        except Exception:
            base_quarantine = base_quarantine.expanduser()

        self._log_event(
            "plan_apply_started",
            logging.INFO,
            "Plan apply started",
            context,
            plan_id=summary["plan_id"],
            action=plan_action,
            plan_file=summary["plan_file"],
        )

        for group in plan_data.get("groups", []):
            for entry in group.get("duplicates", []):
                proposed = entry.get("proposed") or {}
                action_type = proposed.get("action")
                source_str = entry.get("path")
                source_path = Path(source_str) if source_str else None

                if action_type == "move":
                    if source_path is None:
                        summary["errors"] += 1
                        continue

                    dest_str = proposed.get("to")
                    if dest_str is None:
                        summary["errors"] += 1
                        continue

                    dest_path = Path(dest_str)
                    if not dest_path.is_absolute():
                        dest_path = base_quarantine / dest_path
                    try:
                        dest_path = dest_path.expanduser().resolve(strict=False)
                    except Exception:
                        dest_path = dest_path.expanduser()

                    try:
                        source_exists = source_path.exists()
                    except OSError:
                        source_exists = False

                    if not source_exists:
                        summary["skipped"] += 1
                        summary["missing"] += 1
                        self._log_event(
                            "plan_apply_file_missing",
                            logging.WARNING,
                            "File missing during plan apply",
                            context,
                            plan_id=summary["plan_id"],
                            file=source_str,
                        )
                        continue

                    needs_resolution = dest_path in reserved_destinations
                    try:
                        if dest_path.exists():
                            needs_resolution = True
                    except OSError:
                        pass

                    actual_destination = dest_path
                    if needs_resolution:
                        actual_destination, reason = self._resolve_destination_collision(
                            dest_path, collision_strategy, reserved_destinations
                        )
                        if actual_destination is None:
                            summary["skipped"] += 1
                            self._log_event(
                                "plan_apply_skipped",
                                logging.INFO,
                                "Skipped plan entry",
                                context,
                                plan_id=summary["plan_id"],
                                file=source_str,
                                reason=reason,
                            )
                            continue

                    try:
                        actual_destination.parent.mkdir(parents=True, exist_ok=True)
                        shutil.move(str(source_path), str(actual_destination))
                        reserved_destinations.add(actual_destination)
                        summary["moved"] += 1
                        undo_actions.append(
                            {
                                "action": "move",
                                "from": str(actual_destination),
                                "to": source_str,
                                "planned_to": str(dest_path),
                            }
                        )
                    except Exception as exc:
                        summary["errors"] += 1
                        self._log_event(
                            "plan_apply_error",
                            logging.ERROR,
                            "Failed to move file",
                            context,
                            plan_id=summary["plan_id"],
                            file=source_str,
                            destination=str(actual_destination),
                            exception_type=exc.__class__.__name__,
                            exception_msg=str(exc),
                        )
                        continue

                elif action_type == "delete":
                    if source_path is None:
                        summary["errors"] += 1
                        continue

                    try:
                        source_exists = source_path.exists()
                    except OSError:
                        source_exists = False

                    if not source_exists:
                        summary["skipped"] += 1
                        summary["missing"] += 1
                        self._log_event(
                            "plan_apply_file_missing",
                            logging.WARNING,
                            "File missing during plan apply",
                            context,
                            plan_id=summary["plan_id"],
                            file=source_str,
                        )
                        continue

                    try:
                        source_path.unlink()
                        summary["deleted"] += 1
                        undo_actions.append(
                            {
                                "action": "delete",
                                "path": source_str,
                            }
                        )
                    except Exception as exc:
                        summary["errors"] += 1
                        self._log_event(
                            "plan_apply_error",
                            logging.ERROR,
                            "Failed to delete file",
                            context,
                            plan_id=summary["plan_id"],
                            file=source_str,
                            exception_type=exc.__class__.__name__,
                            exception_msg=str(exc),
                        )
                else:
                    summary["skipped"] += 1
                    if proposed.get("reason") == "missing":
                        summary["missing"] += 1

        summary["total"] = summary["moved"] + summary["deleted"] + summary["skipped"]
        summary["duration_ms"] = self._duration_ms(start)

        if undo_actions:
            undo_payload = {
                "plan_id": summary["plan_id"],
                "undo_id": str(uuid.uuid4()),
                "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "actions": undo_actions,
            }
            if undo_path is not None:
                undo_path_obj = Path(undo_path)
            elif plan_path is not None:
                undo_path_obj = plan_path.with_name(f"undo_{plan_path.stem}.json")
            else:
                undo_path_obj = Path("undo.json")
            self._write_json_file(
                undo_path_obj, self._ensure_json_serializable(undo_payload)
            )
            summary["undo_file"] = str(undo_path_obj)

        log_fields = {
            "plan_id": summary["plan_id"],
            "moved": summary["moved"],
            "deleted": summary["deleted"],
            "skipped": summary["skipped"],
            "errors": summary["errors"],
            "missing": summary["missing"],
            "duration_ms": summary["duration_ms"],
            "plan_file": summary.get("plan_file"),
            "undo_file": summary.get("undo_file"),
        }

        self._log_event(
            "plan_apply_completed",
            logging.INFO,
            "Plan apply completed",
            context,
            **{k: v for k, v in log_fields.items() if v is not None},
        )

        return summary

    def export_results(
        self,
        duplicates: Dict,
        output_file: Union[str, Path],
        format: str = "json",
        *,
        scan_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        output_path = Path(output_file)
        format_lower = format.lower()
        start = time.perf_counter()
        context = self._resolve_context(scan_context)

        try:
            if format_lower == "json":
                export_data = {
                    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "hash_method": self.hash_method,
                    "total_duplicate_groups": len(duplicates),
                    "total_duplicate_files": sum(len(files) for files in duplicates.values()),
                    "duplicates": duplicates,
                }
                output_path.write_text(
                    json.dumps(export_data, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
            elif format_lower == "csv":
                with output_path.open("w", newline="", encoding="utf-8") as handle:
                    writer = csv.writer(handle)
                    writer.writerow(["Group", "Identifier", "File", "SizeBytes", "Timestamp"])
                    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                    for group_idx, (identifier, files) in enumerate(duplicates.items(), start=1):
                        for file_path in files:
                            try:
                                file_size = Path(file_path).stat().st_size
                            except OSError:
                                file_size = "N/A"
                            writer.writerow([group_idx, identifier, file_path, file_size, timestamp])
            else:
                raise ValueError("format must be 'json' or 'csv'")

            bytes_written = output_path.stat().st_size
        except Exception as exc:
            self._log_event(
                "export_failed",
                logging.ERROR,
                "Export failed",
                context,
                format=format_lower,
                output_file=str(output_path),
                exception_type=exc.__class__.__name__,
                exception_msg=str(exc),
            )
            raise

        self._log_event(
            "export_completed",
            logging.INFO,
            "Export completed",
            context,
            format=format_lower,
            output_file=str(output_path),
            bytes_written=bytes_written,
            duration_ms=self._duration_ms(start),
        )

    def get_duplicate_stats(self, duplicates: Dict) -> Dict[str, int]:
        total_files = sum(len(files) for files in duplicates.values())
        total_groups = len(duplicates)
        wasted_files = total_files - total_groups if total_groups > 0 else 0

        total_size = 0
        wasted_size = 0

        for files in duplicates.values():
            if not files:
                continue
            try:
                file_size = Path(files[0]).stat().st_size
            except OSError:
                continue
            total_size += file_size * len(files)
            wasted_size += file_size * (len(files) - 1)

        return {
            "total_duplicate_groups": total_groups,
            "total_duplicate_files": total_files,
            "wasted_files": wasted_files,
            "total_size_bytes": total_size,
            "wasted_size_bytes": wasted_size,
            "wasted_size_mb": round(wasted_size / (1024 * 1024), 2),
            "wasted_size_gb": round(wasted_size / (1024 * 1024 * 1024), 2),
        }

def quick_duplicate_scan(
    directory: Union[str, Path],
    method: str = "hybrid",
    file_extensions: Optional[List[str]] = None,
) -> Dict[str, Any]:
    detector = DuplicateDetector()

    if method == "hash":
        duplicates = detector.find_duplicates_by_hash(directory, file_extensions)
    elif method == "name":
        duplicates = detector.find_duplicates_by_name(directory)
    elif method == "size":
        duplicates = detector.find_duplicates_by_size(directory)
    elif method == "hybrid":
        duplicates = detector.find_duplicates_hybrid(directory, file_extensions)
    else:
        raise ValueError("method must be 'hash', 'name', 'size', or 'hybrid'")

    stats = detector.get_duplicate_stats(duplicates)
    return {"duplicates": duplicates, "stats": stats, "method_used": method}


def merge_classifications_detect_duplicates(
    dir1_files: List[str],
    dir2_files: List[str],
    method: str = "name",
) -> Set[str]:
    duplicates: Set[str] = set()

    if method == "name":
        names1 = {Path(f).name for f in dir1_files}
        names2 = {Path(f).name for f in dir2_files}
        common_names = names1 & names2

        for name in common_names:
            duplicates.update([f for f in dir2_files if Path(f).name == name])

    elif method == "hash":
        detector = DuplicateDetector()
        hash_map: Dict[str, str] = {}

        for file_path in dir1_files:
            try:
                file_hash = detector.calculate_file_hash(file_path)
            except Exception:
                continue
            hash_map[file_hash] = file_path

        for file_path in dir2_files:
            try:
                file_hash = detector.calculate_file_hash(file_path)
            except Exception:
                continue
            if file_hash in hash_map:
                duplicates.add(file_path)
    else:
        raise ValueError("method must be 'name' or 'hash'")

    return duplicates


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python duplicate_detector.py <directory> [method]")
        print("Methods: hash, name, size, hybrid")
        sys.exit(1)

    target_dir = sys.argv[1]
    scan_method = sys.argv[2] if len(sys.argv) > 2 else "hybrid"

    print(f"Scanning {target_dir} using method: {scan_method}")
    result = quick_duplicate_scan(target_dir, scan_method)

    print("\nSummary:")
    stats = result["stats"]
    print(f"Groups: {stats['total_duplicate_groups']}")
    print(f"Duplicate files: {stats['total_duplicate_files']}")
    print(f"Wasted space: {stats['wasted_size_mb']} MB")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_name = f"duplicates_{scan_method}_{timestamp}.json"

    detector = DuplicateDetector()
    detector.export_results(result['duplicates'], output_name)
    print(f"\nResults stored in: {output_name}")
