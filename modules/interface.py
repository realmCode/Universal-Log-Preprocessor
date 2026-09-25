"""
Parser Module Interface — the contract every parser module must implement.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ParserModule(ABC):
    """
    Abstract base class for all parser modules.

    Each module in the modules/ directory implements this interface.
    The framework discovers modules via the registry and calls these methods
    during the processing pipeline.
    """

    # ── Identity (set by subclass) ─────────────────────────────────
    name: str = ""                      # e.g., "cisco_asa", "nginx_access"
    source_type: str = "generic"        # network_device, os, application, iot, generic
    supported_formats: list[str] = []   # ["syslog"], ["json"], ["text"], ["syslog", "json"]
    version: str = "1.0.0"

    @abstractmethod
    def recognize(self, raw: str) -> tuple[float, str]:
        """
        Score how well this module matches the raw log.

        Args:
            raw: The raw log line as a string.

        Returns:
            (confidence, detected_format)
            confidence: 0.0 (no match) to 1.0 (definite match)
            detected_format: one of "syslog", "json", "cef", "xml", "text", "unknown"
        """
        ...

    @abstractmethod
    def parse(self, raw: str, format: str) -> dict[str, Any]:
        """
        Extract structured fields from the raw log.

        Args:
            raw: The raw log line.
            format: The detected format string.

        Returns:
            Dict of extracted fields (source-specific field names).
            Returns empty dict if parsing fails — never raises.
        """
        ...

    def map_fields(self, extracted: dict[str, Any]) -> dict[str, Any]:
        """
        Map source-specific field names → unified field names.

        Args:
            extracted: Dict returned by parse().

        Returns:
            Dict with unified field names as keys.
        """
        return extracted

    def validate(self, extracted: dict[str, Any]) -> bool:
        """
        Optional sanity check on extracted fields.
        Return False if the parsed data looks corrupt or incomplete.
        Default: always pass.
        """
        return True

    def get_metadata(self) -> dict[str, Any]:
        """Return module metadata for the registry."""
        return {
            "name": self.name,
            "source_type": self.source_type,
            "supported_formats": self.supported_formats,
            "version": self.version,
        }
