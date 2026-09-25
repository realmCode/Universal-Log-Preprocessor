"""
Field Mapping Engine — maps source-specific fields to the unified schema.
Handles direct 1:1 mappings, transforms, and lossless catch-all for unmapped fields.
"""
from __future__ import annotations

from typing import Any


class FieldMapper:
    """
    Maps extracted source fields to UnifiedEvent field names.

    Mapping config is a dict:
    {
        "src_ip": "src_ip",                     # 1:1 direct mapping
        "status": "event_outcome",              # direct mapping
        "result_status": {                      # mapping with transform
            "map_to": "event_outcome",
            "transform": {
                "200": "success",
                "403": "failure",
                "404": "failure",
                "default": "unknown"
            }
        }
    }

    Any source field not in the mapping goes to source_fields (lossless).
    """

    def __init__(self, mapping: dict[str, Any] | None = None):
        self.mapping = mapping or {}

    def apply(self, extracted: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        """
        Apply mapping to extracted fields.

        Returns:
            (unified_fields, unmapped_fields)
            unified_fields: fields that map to the unified schema
            unmapped_fields: everything else → stored as source_fields
        """
        unified = {}
        unmapped = {}

        # Track which source fields we've mapped
        mapped_sources = set()

        for source_field, value in extracted.items():
            if source_field in self.mapping:
                target = self.mapping[source_field]
                mapped_sources.add(source_field)

                if isinstance(target, str):
                    # Direct 1:1 mapping
                    if value is not None:
                        unified[target] = value
                elif isinstance(target, dict):
                    # Mapping with transform
                    map_to = target.get("map_to", source_field)
                    transform = target.get("transform", {})
                    str_value = str(value)
                    if str_value in transform:
                        unified[map_to] = transform[str_value]
                    elif "default" in transform:
                        unified[map_to] = transform["default"]
                    else:
                        unified[map_to] = value
            else:
                # No mapping defined — preserve as source-specific field
                unmapped[source_field] = value

        return unified, unmapped

    def get_unified_fields(self, mapping: dict[str, Any] | None = None) -> dict[str, str]:
        """
        Return a flat view of all source_field → unified_field mappings.
        Used to generate field mapping documentation.
        """
        m = mapping if mapping is not None else self.mapping
        result = {}
        for source_field, target in m.items():
            if isinstance(target, str):
                result[source_field] = target
            elif isinstance(target, dict):
                result[source_field] = target.get("map_to", source_field)
        return result
