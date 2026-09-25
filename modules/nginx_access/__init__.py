"""
nginx_access — Nginx access log parser.
Handles Combined Log Format and Common Log Format.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from modules.base import BaseParser


class NginxAccessParser(BaseParser):
    name = "nginx_access"
    source_type = "application"
    supported_formats = ["text"]
    version = "1.0.0"

    # Nginx Combined Log Format:
    # $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
    COMBINED_RE = re.compile(
        r'^(?P<remote_addr>\S+)'
        r'\s+-\s+'
        r'(?P<remote_user>\S+)'
        r'\s+\['
        r'(?P<time_local>[^\]]+)'
        r'\]\s+"'
        r'(?P<request_method>\S+)\s+'
        r'(?P<request_uri>\S+)\s+'
        r'(?P<server_protocol>[^"]+)'
        r'"\s+'
        r'(?P<status>\d+)'
        r'\s+'
        r'(?P<body_bytes_sent>\d+)'
        r'(?:\s+"'
        r'(?P<http_referer>[^"]*)'
        r'")?'
        r'(?:\s+"'
        r'(?P<http_user_agent>[^"]*)'
        r'")?'
    )

    # Nginx Common Log Format (no referer, no user agent)
    COMMON_RE = re.compile(
        r'^(?P<remote_addr>\S+)'
        r'\s+-\s+'
        r'(?P<remote_user>\S+)'
        r'\s+\['
        r'(?P<time_local>[^\]]+)'
        r'\]\s+"'
        r'(?P<request_method>\S+)\s+'
        r'(?P<request_uri>\S+)\s+'
        r'(?P<server_protocol>[^"]+)'
        r'"\s+'
        r'(?P<status>\d+)'
        r'\s+'
        r'(?P<body_bytes_sent>\d+)'
    )

    # Nginx time format: 11/Oct/2025:13:55:36 +0000
    TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

    def recognize(self, raw: str) -> tuple[float, str]:
        """Match Nginx Combined or Common log format."""
        if self.COMBINED_RE.match(raw):
            return 0.95, "text"
        if self.COMMON_RE.match(raw):
            return 0.90, "text"
        return 0.0, "unknown"

    def parse(self, raw: str, format: str) -> dict[str, Any]:
        """Parse Nginx access log."""
        m = self.COMBINED_RE.match(raw)
        if not m:
            m = self.COMMON_RE.match(raw)
        if not m:
            return {}

        fields = m.groupdict()

        # Parse timestamp
        time_str = fields.get("time_local", "")
        if time_str:
            try:
                dt = datetime.strptime(time_str, self.TIME_FORMAT)
                fields["_parsed_timestamp"] = dt.isoformat()
            except ValueError:
                fields["_parsed_timestamp"] = time_str

        # Split request into method + uri
        request = fields.get("request_uri", "")
        method = fields.get("request_method", "")
        if request and method:
            fields["_http_method"] = method
            fields["_http_uri"] = request

        # Convert status to int
        try:
            fields["status"] = int(fields.get("status", 0))
        except (ValueError, TypeError):
            pass

        try:
            fields["body_bytes_sent"] = int(fields.get("body_bytes_sent", 0))
        except (ValueError, TypeError):
            pass

        return fields

    def map_fields(self, extracted: dict[str, Any]) -> dict[str, Any]:
        """Map Nginx fields → unified schema."""
        mapping = {
            "remote_addr": "src_ip",
            "time_local": "timestamp",
            "_parsed_timestamp": "timestamp",
            "_http_method": "event_action",
            "status": "event_outcome",
            "body_bytes_sent": "bytes_sent",
            "http_referer": "referrer",
            "http_user_agent": "user_agent",
        }
        result = {}
        for src, unified in mapping.items():
            if src in extracted:
                result[unified] = extracted[src]

        # Determine event outcome from status code
        if "status" in extracted:
            status = extracted["status"]
            if isinstance(status, int):
                if 200 <= status < 400:
                    result["event_outcome"] = "success"
                elif 400 <= status < 500:
                    result["event_outcome"] = "client_error"
                elif status >= 500:
                    result["event_outcome"] = "server_error"

        result["event_category"] = ["application", "http"]
        result["event_type"] = ["web_access"]

        return result
