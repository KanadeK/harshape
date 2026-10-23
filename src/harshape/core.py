"""Rebuild HAR from validated performance fields; never copy arbitrary objects."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__

DEFAULT_INPUT_BYTES = 32 * 1024 * 1024
MAX_INPUT_BYTES = 256 * 1024 * 1024
MAX_ENTRIES = 10_000
MAX_URL_LENGTH = 8192
MAX_PATH_SEGMENTS = 128
MAX_TOTAL_SEGMENTS = 200_000
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
EPOCH = datetime(2000, 1, 1, tzinfo=UTC)
METHODS = {"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "CONNECT", "TRACE"}
VERSIONS = {"HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3"}
MIMES = {
    "application/json",
    "application/javascript",
    "application/octet-stream",
    "application/pdf",
    "application/xml",
    "application/wasm",
    "application/x-www-form-urlencoded",
    "text/plain",
    "text/html",
    "text/css",
    "text/javascript",
    "text/xml",
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/svg+xml",
    "image/avif",
    "font/woff",
    "font/woff2",
    "audio/mpeg",
    "video/mp4",
}
PHASES = ("blocked", "dns", "connect", "send", "wait", "receive", "ssl")


class ShapeError(ValueError):
    """Input cannot be safely projected. Messages never include original field values."""


def _object(value, field):
    if not isinstance(value, dict):
        raise ShapeError(f"{field} must be an object")
    return value


def _number(value, field, *, minimum=-1, maximum=1e12, integer=False):
    if type(value) not in (int, float) or (integer and type(value) is not int):
        raise ShapeError(f"{field} has an invalid numeric type")
    try:
        valid = minimum <= value <= maximum and math.isfinite(value)
    except OverflowError:
        valid = False
    if not valid:
        raise ShapeError(f"{field} is outside the finite supported range")
    return value


def _size(value, field):
    return _number(value, field, minimum=-1, maximum=2**53 - 1, integer=True)


def _timing(value, field):
    value = _number(value, field)
    if value < 0 and value != -1:
        raise ShapeError(f"{field} must be nonnegative or -1 for unknown")
    return value


def _date(value, field):
    if not isinstance(value, str) or len(value) > 128:
        raise ShapeError(f"{field} must be an ISO timestamp with a timezone")
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("timezone required")
        return parsed.astimezone(UTC)
    except (ValueError, OverflowError) as exc:
        raise ShapeError(f"{field} must be an ISO timestamp with a timezone") from exc


def _enum(value, allowed, fallback):
    return value if isinstance(value, str) and value in allowed else fallback


def _mime(value):
    if not isinstance(value, str):
        return "application/octet-stream"
    normalized = value.partition(";")[0].strip().lower()
    return normalized if normalized in MIMES else "application/octet-stream"


class _Urls:
    def __init__(self):
        self.key = secrets.token_bytes(32)
        self.total_segments = 0
        self.origins = set()
        self.endpoints = set()

    def token(self, domain, value):
        return hmac.new(
            self.key, (domain + "\0" + value).encode("utf-8"), hashlib.sha256
        ).hexdigest()[:32]

    def project(self, value, field):
        if not isinstance(value, str) or not value or len(value) > MAX_URL_LENGTH:
            raise ShapeError(f"{field} must be a URL with at most 8192 characters")
        if any(
            ord(char) <= 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in value
        ):
            raise ShapeError(f"{field} contains unsupported URL characters")
        try:
            parts = urlsplit(value)
            if not parts.scheme or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9+.-]*", parts.scheme):
                raise ValueError("absolute URL required")
            if parts.scheme in ("http", "https"):
                if not parts.hostname:
                    raise ValueError("hostname required")
                port = (
                    parts.port
                    if parts.port is not None
                    else (443 if parts.scheme == "https" else 80)
                )
                origin = f"{parts.scheme}://{parts.hostname.lower().rstrip('.')}:{port}"
                segments = parts.path.split("/")
                if len(segments) > MAX_PATH_SEGMENTS:
                    raise ShapeError(f"{field} exceeds 128 path segments")
                self.total_segments += len(segments)
                masked = [
                    "p-" + self.token("path", origin + "\0" + "/".join(segments[: i + 1]))
                    if segment
                    else ""
                    for i, segment in enumerate(segments)
                ]
                path = "/".join(masked)
                if not path.startswith("/"):
                    path = "/" + path
            else:
                # data:, blob:, file:, ws:, and other absolute schemes remain opaque.
                origin = "opaque:" + parts.scheme
                self.total_segments += 1
                path = "/p-" + self.token("opaque-url", value)
        except (ValueError, UnicodeError) as exc:
            if isinstance(exc, ShapeError):
                raise
            raise ShapeError(f"{field} is not a supported absolute URL") from exc
        if self.total_segments > MAX_TOTAL_SEGMENTS:
            raise ShapeError("Capture exceeds the aggregate 200,000 URL-segment budget")
        host = "h-" + self.token("origin", origin) + ".invalid"
        projected = "https://" + host + path
        self.origins.add(host)
        self.endpoints.add(projected)
        return projected


def project_har(document: dict) -> tuple[dict, dict]:
    log = _object(_object(document, "root").get("log"), "log")
    if log.get("version") != "1.2":
        raise ShapeError("Only HAR log.version 1.2 is supported")
    entries = log.get("entries")
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        raise ShapeError("log.entries must be an array with at most 10,000 entries")
    dates = [
        _date(
            _object(entry, f"entry {index}").get("startedDateTime"),
            f"entry {index}.startedDateTime",
        )
        for index, entry in enumerate(entries)
    ]
    start = min(dates, default=EPOCH)
    if dates and max(dates) - start > timedelta(days=366):
        raise ShapeError("Capture spans more than 366 days")
    urls = _Urls()
    output_entries = []
    statuses = {}
    for index, (entry, date) in enumerate(zip(entries, dates, strict=True)):
        field = f"entry {index}"
        request = _object(entry.get("request"), field + ".request")
        response = _object(entry.get("response"), field + ".response")
        content = _object(response.get("content"), field + ".response.content")
        timings = _object(entry.get("timings"), field + ".timings")
        status = _number(
            response.get("status"), field + ".response.status", minimum=0, maximum=599, integer=True
        )
        if status != 0 and status < 100:
            raise ShapeError(field + ".response.status must be 0 or 100–599")
        projected_content = {
            "size": _number(
                content.get("size"),
                field + ".response.content.size",
                minimum=0,
                maximum=2**53 - 1,
                integer=True,
            ),
            "mimeType": _mime(content.get("mimeType")),
        }
        if "compression" in content:
            projected_content["compression"] = _number(
                content["compression"],
                field + ".response.content.compression",
                minimum=-(2**53 - 1),
                maximum=2**53 - 1,
                integer=True,
            )
        result = {
            "startedDateTime": (EPOCH + (date - start))
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
            "time": _number(entry.get("time"), field + ".time", minimum=0),
            "request": {
                "method": _enum(request.get("method"), METHODS, "OTHER"),
                "url": urls.project(request.get("url"), field + ".request.url"),
                "httpVersion": _enum(request.get("httpVersion"), VERSIONS, "unknown"),
                "cookies": [],
                "headers": [],
                "queryString": [],
                "headersSize": _size(
                    request.get("headersSize", -1), field + ".request.headersSize"
                ),
                "bodySize": _size(request.get("bodySize", -1), field + ".request.bodySize"),
            },
            "response": {
                "status": status,
                "statusText": "",
                "httpVersion": _enum(response.get("httpVersion"), VERSIONS, "unknown"),
                "cookies": [],
                "headers": [],
                "content": projected_content,
                "redirectURL": "",
                "headersSize": _size(
                    response.get("headersSize", -1), field + ".response.headersSize"
                ),
                "bodySize": _size(response.get("bodySize", -1), field + ".response.bodySize"),
            },
            "cache": {},
            "timings": {
                phase: _timing(timings.get(phase, -1), field + ".timings." + phase)
                for phase in PHASES
            },
        }
        output_entries.append(result)
        statuses[str(status)] = statuses.get(str(status), 0) + 1
    output = {
        "log": {
            "version": "1.2",
            "creator": {"name": "HarShape", "version": __version__},
            "pages": [],
            "entries": output_entries,
        }
    }
    summary = {
        "entries": len(entries),
        "origin_groups": len(urls.origins),
        "endpoint_groups": len(urls.endpoints),
        "status_counts": statuses,
        "time_origin": EPOCH.isoformat().replace("+00:00", "Z"),
    }
    return output, summary


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ShapeError("Duplicate JSON object key")
        result[key] = value
    return result


def _constant(_value):
    raise ShapeError("Non-standard NaN/Infinity literal in JSON")


def _check_depth(text):
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > 128:
                raise ShapeError("JSON exceeds the 128-container nesting limit")
        elif char in "]}":
            depth -= 1


def project_file(source: Path, output: Path, *, max_input_bytes=DEFAULT_INPUT_BYTES) -> dict:
    if type(max_input_bytes) is not int or not 1 <= max_input_bytes <= MAX_INPUT_BYTES:
        raise ShapeError("Input byte cap must be between 1 and 268435456")
    if not stat.S_ISREG(source.stat().st_mode):
        raise ShapeError("Input must be a stable regular file")
    with source.open("rb") as file:
        initial = os.fstat(file.fileno())
        raw = file.read(max_input_bytes + 1)
        final = os.fstat(file.fileno())
    if len(raw) > max_input_bytes:
        raise ShapeError("Input exceeds configured byte cap")
    if (initial.st_size, initial.st_mtime_ns) != (final.st_size, final.st_mtime_ns):
        raise ShapeError("Input changed during reading")
    try:
        text = raw.decode("utf-8-sig")
        _check_depth(text)
        document = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, ShapeError):
            raise
        raise ShapeError("Input is not supported strict UTF-8 JSON") from exc
    projected, summary = project_har(document)
    data = (json.dumps(projected, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode(
        "ascii"
    )
    if len(data) > MAX_OUTPUT_BYTES:
        raise ShapeError("Projected output exceeds 64 MiB")
    descriptor = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    return {"created": True, "output_bytes": len(data), **summary}
