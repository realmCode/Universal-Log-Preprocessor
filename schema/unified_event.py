"""
Unified Event Schema — the canonical log format that all sources normalize into.
Every event, regardless of source, is represented as a UnifiedEvent.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field


class UnifiedEvent(BaseModel):
    # ── Identity & metadata ────────────────────────────────────────
    event_id: str = Field(
        description="Unique UUID for this event (traceability to raw data)"
    )
    timestamp: Optional[datetime] = Field(
        default=None, description="Event timestamp from the source"
    )
    source_type: str = Field(
        default="generic",
        description="Category: network_device, os, application, database, iot, generic"
    )
    source_vendor: Optional[str] = Field(
        default=None, description="Vendor name: cisco, microsoft, nginx, unknown"
    )
    source_product: Optional[str] = Field(
        default=None, description="Product name: asa, windows_server, nginx"
    )
    source_version: Optional[str] = None
    source_host: Optional[str] = Field(
        default=None, description="Hostname of the source device"
    )
    source_ip: Optional[str] = None
    log_format: str = Field(
        default="unknown",
        description="Raw format: json, syslog, cef, leef, xml, text, unknown"
    )
    log_level: Optional[str] = None

    # ── Normalized event fields ────────────────────────────────────
    event_action: Optional[str] = Field(
        default=None,
        description="What happened: login, firewall_deny, connection_open, http_request"
    )
    event_outcome: Optional[str] = Field(
        default=None,
        description="Result: success, failure, allowed, denied, unknown"
    )
    event_category: list[str] = Field(
        default_factory=list,
        description="Categories: authentication, network, file, process, application"
    )
    event_type: list[str] = Field(
        default_factory=list,
        description="Specific types within the category"
    )

    # ── Network fields ─────────────────────────────────────────────
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    src_hostname: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    dst_hostname: Optional[str] = None
    protocol: Optional[str] = None
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None

    # ── Identity fields ────────────────────────────────────────────
    user_id: Optional[str] = None
    user_name: Optional[str] = None
    user_domain: Optional[str] = None

    # ── Process fields ─────────────────────────────────────────────
    process_name: Optional[str] = None
    process_pid: Optional[int] = None
    process_executable: Optional[str] = None

    # ── File fields ────────────────────────────────────────────────
    file_path: Optional[str] = None
    file_name: Optional[str] = None
    file_hash_md5: Optional[str] = None
    file_hash_sha256: Optional[str] = None

    # ── Lossless preservation (always present) ─────────────────────
    raw_message: str = Field(
        description="Complete original log line — NEVER modified"
    )
    source_fields: dict[str, Any] = Field(
        default_factory=dict,
        description="All source-specific extracted fields not mapped to unified schema"
    )
    enrichment: dict[str, Any] = Field(
        default_factory=dict,
        description="GeoIP, ASN, threat intel, Drain3 parameters"
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict — handles datetime objects."""
        d = self.model_dump(mode="json")
        return d

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return self.model_dump_json()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> UnifiedEvent:
        """Deserialize from dict."""
        return cls.model_validate(d)

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "event_id": "550e8400-e29b-41d4-a716-446655440000",
                    "timestamp": "2025-10-11T22:14:15Z",
                    "source_type": "network_device",
                    "source_vendor": "cisco",
                    "source_product": "asa",
                    "log_format": "syslog",
                    "event_action": "firewall_deny",
                    "event_outcome": "denied",
                    "src_ip": "10.0.0.50",
                    "src_port": 45678,
                    "dst_ip": "8.8.8.8",
                    "dst_port": 443,
                    "protocol": "tcp",
                    "bytes_sent": 0,
                    "raw_message": "<134>Oct 11 22:14:15 asa01 %ASA-4-106023: ...",
                    "source_fields": {"interface": "outside", "tcp_flags": "SYN"},
                    "enrichment": {},
                }
            ]
        }
    }
