"""
generic_syslog — Universal Syslog parser (RFC 3164/5424 fallback).
Handles any Syslog-formatted log, with key=value pair extraction from the payload.
"""
from __future__ import annotations

import re
from typing import Any

from modules.base import BaseParser


class GenericSyslogParser(BaseParser):
    name = "generic_syslog"
    source_type = "generic"
    supported_formats = ["syslog"]
    version = "1.0.0"

    # Regex for key=value pairs in the payload
    KV_PAIR_RE = re.compile(r'(\w+)=([^\s]*)')
    # Common key aliases → unified field names
    FIELD_ALIASES = {
        "src": "src_ip",
        "src_ip": "src_ip",
        "source": "src_ip",
        "sip": "src_ip",
        "dst": "dst_ip",
        "dst_ip": "dst_ip",
        "dest": "dst_ip",
        "dip": "dst_ip",
        "sport": "src_port",
        "src_port": "src_port",
        "dport": "dst_port",
        "dst_port": "dst_port",
        "proto": "protocol",
        "protocol": "protocol",
        "action": "event_action",
        "msg": "message",
        "message": "message",
        "level": "log_level",
        "severity": "log_level",
    }

    def __init__(self):
        super().__init__()
        self._header = self.config_get("parse", "header_pattern", default=None)

    def recognize(self, raw: str) -> tuple[float, str]:
        """Match if it starts with a Syslog priority."""
        if raw.strip().startswith("<") and re.match(r'^<\d{1,3}>', raw.strip()):
            return 0.85, "syslog"
        return 0.0, "unknown"

    def parse(self, raw: str, format: str) -> dict[str, Any]:
        """Strip Syslog header, extract key=value pairs from payload."""
        header_fields = self.extract_syslog_header(raw)
        payload = self.strip_syslog_header(raw)

        # Extract key=value pairs from payload
        kv_pairs = dict(self.KV_PAIR_RE.findall(payload))

        # If no key=value, store first 200 chars of payload as message
        if not kv_pairs:
            kv_pairs["message"] = payload.strip()[:500] if payload.strip() else ""

        # Add Syslog header fields
        if header_fields:
            kv_pairs["_syslog_priority"] = header_fields.get("priority", "")
            kv_pairs["_syslog_hostname"] = header_fields.get("hostname", "")
            kv_pairs["_syslog_app"] = header_fields.get("app_name", "")
            kv_pairs["_syslog_pid"] = header_fields.get("pid", "")
            kv_pairs["_syslog_timestamp"] = header_fields.get("timestamp", "")

        return kv_pairs

    def map_fields(self, extracted: dict[str, Any]) -> dict[str, Any]:
        """Apply field alias mapping."""
        mapped = {}
        for key, value in extracted.items():
            if key.startswith("_"):
                continue  # Skip internal Syslog header fields for now
            unified_key = self.FIELD_ALIASES.get(key.lower(), key)
            mapped[unified_key] = value
        return mapped
