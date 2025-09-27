#!/usr/bin/env python3
"""Reusable duplicate detector with structured NDJSON logging."""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import os
from logging.handlers import RotatingFileHandler
import sys
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

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



