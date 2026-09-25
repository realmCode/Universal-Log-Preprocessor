"""
cisco_asa — Cisco ASA firewall log parser.
Handles %ASA- message codes: connection teardown, built, deny, etc.
This is the flagship module — complex vendor-specific Syslog payload parsing.
"""
from __future__ import annotations

import re
from typing import Any

from modules.base import BaseParser


class CiscoASAParser(BaseParser):
    name = "cisco_asa"
    source_type = "network_device"
    supported_formats = ["syslog"]
    version = "1.0.0"

    # Cisco ASA Syslog message patterns
    PATTERNS = {
        "teardown_tcp": re.compile(
            r'%ASA-6-302013:'
            r'.*?host\s+(?P<src_ip>\S+):(?P<src_port>\d+)'
            r'.*?host\s+(?P<dst_ip>\S+):(?P<dst_port>\d+)'
            r'.*?duration\s+(?P<duration>\d+)s'
            r'.*?bytes\s+(?P<bytes>\d+)'
            r'(?:.*?reason\s+"?(?P<reason>[^"]+)"?)?'
        ),
        "built_tcp": re.compile(
            r'%ASA-6-302015:'
            r'.*?host\s+(?P<src_ip>\S+):(?P<src_port>\d+)'
            r'.*?host\s+(?P<dst_ip>\S+):(?P<dst_port>\d+)'
        ),
        "deny_tcp": re.compile(
            r'%ASA-4-106023:'
            r'.*?from\s+(?P<src_ip>\S+)/(?P<src_port>\d+)'
            r'.*?to\s+(?P<dst_ip>\S+)/(?P<dst_port>\d+)'
            r'(?:.*?on\s+interface\s+(?P<interface>\S+))?'
        ),
        "deny_udp": re.compile(
            r'%ASA-4-106023:'
            r'.*?from\s+(?P<src_ip>\S+)/(?P<src_port>\d+)'
            r'.*?to\s+(?P<dst_ip>\S+)/(?P<dst_port>\d+)'
        ),
        "icmp_deny": re.compile(
            r'%ASA-4-106023:.*?ICMP\s+'
            r'.*?from\s+(?P<src_ip>\S+)'
            r'.*?to\s+(?P<dst_ip>\S+)'
        ),
        "l3_deny": re.compile(
            r'%ASA-3-106010:.*?from\s+(?P<src_ip>\S+):(?P<src_port>\d+)'
            r'.*?to\s+(?P<dst_ip>\S+):(?P<dst_port>\d+)'
            r'.*?type\s+(?P<icmp_type>\d+)'
            r'.*?code\s+(?P<icmp_code>\d+)'
        ),
        "login_success": re.compile(
            r'%ASA-6-113005:'
            r'.*?User\s+(?P<user_name>\S+)'
            r'.*?from\s+(?P<src_ip>\S+)'
            r'.*?succeeded'
        ),
        "login_failed": re.compile(
            r'%ASA-6-113004:'
            r'.*?User\s+(?P<user_name>\S+)'
            r'.*?from\s+(?P<src_ip>\S+)'
            r'.*?failed'
        ),
    }

    # Message code → event mapping
    MSG_CODE_MAP = {
        "302013": {"event_action": "connection_teardown", "event_outcome": "success", "category": ["network"]},
        "302015": {"event_action": "connection_built", "event_outcome": "success", "category": ["network"]},
        "106023": {"event_action": "firewall_deny", "event_outcome": "denied", "category": ["network", "security"]},
        "106010": {"event_action": "firewall_deny", "event_outcome": "denied", "category": ["network", "security"]},
        "113005": {"event_action": "login", "event_outcome": "success", "category": ["authentication"]},
        "113004": {"event_action": "login", "event_outcome": "failure", "category": ["authentication"]},
    }

    def recognize(self, raw: str) -> tuple[float, str]:
        """Match if payload contains Cisco ASA message codes."""
        if "%ASA-" in raw or "%PIX-" in raw:
            return 0.95, "syslog"
        return 0.0, "unknown"

    def parse(self, raw: str, format: str) -> dict[str, Any]:
        """Parse Cisco ASA Syslog message.
        Work with the full raw string because Cisco embeds the message code
        (%ASA-6-302013) right after the Syslog header app_name, before the colon.
        """
        payload = raw

        # Extract message code
        msg_code_match = re.search(r'%ASA-(\d)-(\d{6})', payload)
        msg_code = msg_code_match.group(2) if msg_code_match else "unknown"
        full_code = msg_code_match.group(0).replace("%", "").replace("-", "_") if msg_code_match else "unknown"

        # Try each pattern
        for pattern_name, pattern in self.PATTERNS.items():
            m = pattern.search(payload)
            if m:
                fields = m.groupdict()
                fields["message_code"] = msg_code
                fields["message_code_full"] = full_code
                fields["_pattern"] = pattern_name
                return fields

        # No pattern matched — extract what we can
        return {"message_code": msg_code, "_pattern": "unknown", "_payload": payload[:200]}

    def map_fields(self, extracted: dict[str, Any]) -> dict[str, Any]:
        """Map Cisco ASA fields → unified schema."""
        result = {}

        # Network fields
        for src, unified in [
            ("src_ip", "src_ip"), ("src_port", "src_port"),
            ("dst_ip", "dst_ip"), ("dst_port", "dst_port"),
            ("bytes", "bytes_sent"), ("duration", "duration"),
        ]:
            if src in extracted:
                result[unified] = extracted[src]

        # Try to convert port to int
        for field in ["src_port", "dst_port"]:
            if field in result:
                try:
                    result[field] = int(result[field])
                except (ValueError, TypeError):
                    pass

        # Try to convert bytes to int
        if "bytes_sent" in result:
            try:
                result["bytes_sent"] = int(result["bytes_sent"])
            except (ValueError, TypeError):
                pass

        # Protocol — TCP for most ASA messages
        result["protocol"] = "tcp"

        # Event classification from message code
        msg_code = extracted.get("message_code", "")
        msg_info = self.MSG_CODE_MAP.get(msg_code, {})
        if msg_info:
            result["event_action"] = msg_info.get("event_action")
            result["event_outcome"] = msg_info.get("event_outcome")
            result["event_category"] = msg_info.get("category", ["network"])
            result["event_type"] = ["firewall"]

        # User info
        if "user_name" in extracted:
            result["user_name"] = extracted["user_name"]

        # Interface
        if "interface" in extracted:
            result["source_interface"] = extracted["interface"]

        # Reason
        if "reason" in extracted and extracted["reason"]:
            result["_deny_reason"] = extracted["reason"]

        return result
