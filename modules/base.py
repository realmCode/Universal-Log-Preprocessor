"""
Base parser class — shared helpers for all parser modules.
Handles config loading, Syslog header stripping, and common utilities.
"""
from __future__ import annotations

import re
import yaml
from pathlib import Path
from typing import Any

from modules.interface import ParserModule


class BaseParser(ParserModule):
    """
    Base class that provides:
    - YAML config loading from the module's own directory
    - Syslog header stripping (RFC 3164/5424)
    - Common regex helpers
    """

    # Syslog header regex (RFC 3164)
    SYSLOG_HEADER_RE = re.compile(
        r'^<(?P<priority>\d+)>'
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\s+\d{4})?)?'
        r'\s+(?P<hostname>\S+)'
        r'\s+(?P<app_name>[^\[:]+)'
        r'(?:\[(?P<pid>\d+)\])?'
        r':\s*'
    )

    # Also try RFC 5424 header
    SYSLOG_5424_RE = re.compile(
        r'^<(?P<priority>\d+)>'
        r'(?P<version>\d) '
        r'(?P<timestamp>\S+) '
        r'(?P<hostname>\S+) '
        r'(?P<app_name>\S+) '
        r'(?P<pid>\S+) '
        r'(?P<msgid>\S+) '
        r'(?P<structured_data>\S+) '
        r'(?P<message>.*)'
    )

    def __init__(self):
        self._config: dict[str, Any] | None = None
        self._load_config()

    # ── Config loading ─────────────────────────────────────────────

    def _load_config(self):
        """Load config.yaml from the module's own directory."""
        module_dir = Path(self._get_module_dir())
        config_path = module_dir / "config.yaml"
        if config_path.exists():
            with open(config_path, "r") as f:
                self._config = yaml.safe_load(f) or {}
        else:
            self._config = {}

    def _get_module_dir(self) -> str:
        """Get the directory of the concrete subclass."""
        return str(Path(type(self).__module__.replace(".", "/")).parent)

    @property
    def config(self) -> dict[str, Any]:
        """Return the loaded config."""
        return self._config or {}

    def config_get(self, *keys: str, default=None):
        """Safely get a nested config value: config_get('parse', 'pattern', default=...)."""
        d = self._config
        for key in keys:
            if isinstance(d, dict) and key in d:
                d = d[key]
            else:
                return default
        return d

    # ── Syslog helpers ─────────────────────────────────────────────

    def strip_syslog_header(self, raw: str) -> str:
        """
        Strip the Syslog header (RFC 3164 or 5424) and return the payload.
        If no header found, returns the raw string unchanged.
        """
        m = self.SYSLOG_HEADER_RE.match(raw)
        if m:
            return raw[m.end():]
        m = self.SYSLOG_5424_RE.match(raw)
        if m:
            payload = m.group("message")
            structured = m.group("structured_data")
            if structured and structured != "-":
                payload = structured + " " + payload
            return payload.strip()
        return raw

    def extract_syslog_header(self, raw: str) -> dict[str, str] | None:
        """Extract and return the Syslog header fields, or None."""
        m = self.SYSLOG_HEADER_RE.match(raw)
        if m:
            return {k: v for k, v in m.groupdict().items() if v is not None}
        return None

    # ── Recognition helper ─────────────────────────────────────────

    def _regex_recognize(self, raw: str, patterns: list[dict]) -> tuple[float, str]:
        """
        Try a list of regex patterns for recognition.
        Each pattern: {"match": "regex_str", "confidence": 0.9, "format": "syslog"}
        Returns the first match's (confidence, format) or (0.0, "unknown").
        """
        for p in patterns:
            try:
                if re.search(p["match"], raw, re.IGNORECASE):
                    return p["confidence"], p.get("format", "unknown")
            except re.error:
                continue
        return 0.0, "unknown"

    def reload_config(self):
        """Reload config from disk (for hot-reload support)."""
        self._load_config()
