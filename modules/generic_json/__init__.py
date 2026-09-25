"""
generic_json — Universal JSON log parser.
Parses any JSON log, flattens nested objects, and extracts common fields.
"""
from __future__ import annotations

import json
import re
from typing import Any

from modules.base import BaseParser


class GenericJSONParser(BaseParser):
    name = "generic_json"
    source_type = "generic"
    supported_formats = ["json"]
    version = "1.0.0"

    # Common field name patterns → unified field
    COMMON_FIELDS = {
        # Timestamp
        "timestamp": "timestamp",
        "time": "timestamp",
        "@timestamp": "timestamp",
        "date": "timestamp",
        "created_at": "timestamp",
        "event_time": "timestamp",
        "log_time": "timestamp",
        # Level
        "level": "log_level",
        "severity": "log_level",
        "log_level": "log_level",
        # Message
        "message": "raw_message_supplement",
        "msg": "raw_message_supplement",
        "error": "raw_message_supplement",
        "details": "raw_message_supplement",
        # Network
        "src_ip": "src_ip",
        "source_ip": "src_ip",
        "srcip": "src_ip",
        "client_ip": "src_ip",
        "remote_addr": "src_ip",
        "dst_ip": "dst_ip",
        "dest_ip": "dst_ip",
        "destination_ip": "dst_ip",
        "src_port": "src_port",
        "sport": "src_port",
        "source_port": "src_port",
        "dst_port": "dst_port",
        "dport": "dst_port",
        "dest_port": "dst_port",
        "destination_port": "dst_port",
        "protocol": "protocol",
        # User
        "user": "user_name",
        "username": "user_name",
        "user_name": "user_name",
        "uid": "user_id",
        "user_id": "user_id",
        # Process
        "process": "process_name",
        "process_name": "process_name",
        "pid": "process_pid",
        "process_id": "process_pid",
        # File
        "file": "file_path",
        "file_path": "file_path",
        "filename": "file_name",
        "file_name": "file_name",
        # Action/Outcome
        "action": "event_action",
        "event": "event_action",
        "event_type": "event_action",
        "result": "event_outcome",
        "outcome": "event_outcome",
        "status": "event_outcome",
        # Source
        "host": "source_host",
        "hostname": "source_host",
        "host_name": "source_host",
        "source_host": "source_host",
        # Vendor/product
        "vendor": "source_vendor",
        "product": "source_product",
        "service": "source_product",
    }

    def recognize(self, raw: str) -> tuple[float, str]:
        """Match if it starts with { and is valid JSON."""
        if raw.strip().startswith("{"):
            try:
                json.loads(raw)
                return 0.95, "json"
            except (json.JSONDecodeError, ValueError):
                pass
        return 0.0, "unknown"

    def parse(self, raw: str, format: str) -> dict[str, Any]:
        """Parse JSON and flatten nested objects."""
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return {"_raw_fallback": raw[:500]}

        return self._flatten(data)

    def _flatten(self, obj: Any, parent_key: str = "", sep: str = ".") -> dict[str, Any]:
        """Flatten nested dicts: {"a": {"b": "c"}} → {"a.b": "c"}."""
        items: list[tuple[str, Any]] = []

        if isinstance(obj, dict):
            for k, v in obj.items():
                new_key = f"{parent_key}{sep}{k}" if parent_key else k
                if isinstance(v, dict):
                    items.extend(self._flatten(v, new_key, sep).items())
                elif isinstance(v, list):
                    items.extend(self._flatten(v, new_key, sep).items())
                else:
                    items.append((new_key, v))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                new_key = f"{parent_key}[{i}]"
                if isinstance(v, dict):
                    items.extend(self._flatten(v, new_key, sep).items())
                else:
                    items.append((new_key, v))
        else:
            items.append((parent_key, obj))

        return dict(items)

    def map_fields(self, extracted: dict[str, Any]) -> dict[str, Any]:
        """Map common JSON field names to unified schema."""
        mapped = {}
        for key, value in extracted.items():
            # Check exact match first, then case-insensitive
            unified_key = self.COMMON_FIELDS.get(key)
            if not unified_key:
                unified_key = self.COMMON_FIELDS.get(key.lower())
            if unified_key:
                mapped[unified_key] = value
            else:
                mapped[key] = value
        return mapped
