"""
Format Detector — auto-detects the structural format of a log line.
Covers: JSON, CEF, LEEF, Syslog (RFC 3164/5424), XML, and unknown.
"""
from __future__ import annotations

import json
import re


# Regex patterns for format detection
_JSON_RE = re.compile(r'^\s*\{')
_CEF_RE = re.compile(r'^\s*CEF:', re.IGNORECASE)
_LEEF_RE = re.compile(r'^\s*LEEF:', re.IGNORECASE)
_SYSLOG_RE = re.compile(r'^<\d{1,3}>')
_SYSLOG_5424_RE = re.compile(r'^<\d{1,3}>\d\s')
_XML_RE = re.compile(r'^\s*<\?xml|^\s*<[A-Za-z]')
_NGINX_RE = re.compile(r'^\S+\s+-\s+-\s+\[.*\]\s+".*"\s+\d+')


def detect_format(raw: str) -> str:
    """
    Detect the structural format of a log line.

    Returns one of:
        "json", "cef", "leef", "syslog", "xml", "text", "unknown"
    """
    if not raw or not raw.strip():
        return "unknown"

    # Order matters — most specific first
    if _JSON_RE.match(raw):
        try:
            json.loads(raw)
            return "json"
        except (json.JSONDecodeError, ValueError):
            # Starts with { but isn't valid JSON — could be a log that starts with {
            pass

    if _CEF_RE.match(raw):
        return "cef"

    if _LEEF_RE.match(raw):
        return "leef"

    if _SYSLOG_5424_RE.match(raw):
        return "syslog"

    if _SYSLOG_RE.match(raw):
        return "syslog"

    # Linux syslog without priority tag (e.g., "Sep 02 20:01:17 host ...")
    if re.match(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\w+', raw):
        return "syslog"

    if _XML_RE.match(raw):
        return "xml"

    # If it has key=value pairs everywhere, it's probably structured text
    if _looks_key_value(raw):
        return "text"

    # Nginx/Apache combined log format
    if _NGINX_RE.match(raw):
        return "text"

    return "unknown"


def _looks_key_value(raw: str) -> bool:
    """Heuristic: does the string look like key=value pairs?"""
    kv_count = 0
    words = 0
    for token in raw.split():
        if "=" in token:
            kv_count += 1
        if token.strip():
            words += 1
    if words == 0:
        return False
    return kv_count / words > 0.3


def detect_and_score(raw: str) -> dict[str, Any]:
    """
    Detect format and return a confidence score.

    Returns:
        {"format": str, "confidence": float}
    """
    fmt = detect_format(raw)

    confidence_map = {
        "json": 0.95,    # JSON try is definitive (validates with json.loads)
        "cef": 0.95,
        "leef": 0.95,
        "syslog": 0.85,
        "xml": 0.90,
        "text": 0.60,
        "unknown": 0.0,
    }

    return {
        "format": fmt,
        "confidence": confidence_map.get(fmt, 0.0),
    }
