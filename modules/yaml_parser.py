"""
YAML-only parser module — for simple sources that don't need Python code.
Loaded by the registry when a module has config.yaml but no __init__.py
with a ParserModule class.
"""
from __future__ import annotations

import re
from typing import Any

from modules.interface import ParserModule


class YamlParserModule(ParserModule):
    """
    A parser module defined entirely via YAML config.
    No Python code needed for simple parsing.
    """

    def __init__(self, config: dict[str, Any], module_name: str):
        self._config = config
        self.name = config.get("module", {}).get("name", module_name)
        self.source_type = config.get("module", {}).get("source_type", "generic")
        self.supported_formats = config.get("module", {}).get("formats", ["text"])
        self.version = config.get("module", {}).get("version", "1.0.0")

        # Compile recognize patterns
        self._recognize_patterns = config.get("recognize", {}).get("patterns", [])

        # Compile parse pattern
        parse_config = config.get("parse", {})
        self._parse_pattern = None
        if "pattern" in parse_config:
            self._parse_pattern = re.compile(parse_config["pattern"])

        # Load field mappings
        self._mappings = config.get("mapping", {})

    def recognize(self, raw: str) -> tuple[float, str]:
        """Try recognize patterns from config."""
        for p in self._recognize_patterns:
            try:
                if re.search(p["match"], raw, re.IGNORECASE):
                    return p["confidence"], p.get("format", "unknown")
            except re.error:
                continue
        return 0.0, "unknown"

    def parse(self, raw: str, format: str) -> dict[str, Any]:
        """Parse using the configured regex pattern."""
        if self._parse_pattern:
            m = self._parse_pattern.match(raw)
            if m:
                return m.groupdict()
        return {}

    def map_fields(self, extracted: dict[str, Any]) -> dict[str, Any]:
        """Apply field mappings from config."""
        result = {}
        for src_field, target in self._mappings.items():
            if isinstance(target, str):
                # Direct 1:1 mapping
                if src_field in extracted:
                    result[target] = extracted[src_field]
            elif isinstance(target, dict):
                # Mapping with transform
                if src_field in extracted:
                    value = extracted[src_field]
                    transform_map = target.get("transform", {})
                    result[target["map_to"]] = transform_map.get(
                        str(value), transform_map.get("default", value)
                    )
        return result
