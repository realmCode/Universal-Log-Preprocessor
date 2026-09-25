"""
linux_syslog — Linux OS syslog parser.
Handles sudo, SSH, UFW, CRON, and systemd messages.
"""
from __future__ import annotations

import re
from typing import Any

from modules.base import BaseParser


class LinuxSyslogParser(BaseParser):
    name = "linux_syslog"
    source_type = "os"
    supported_formats = ["syslog"]
    version = "1.0.0"

    SUDO_RE = re.compile(r'sudo:\s*.*?User\s*:\s*(?P<user_name>\S+).*?COMMAND=(?P<command>\S+)')
    SSH_ACCEPT_RE = re.compile(r'sshd\[\d+\]:\s*Accepted\s+\w+\s+for\s+(?P<user_name>\S+)\s+from\s+(?P<src_ip>\S+)')
    SSH_FAIL_RE = re.compile(r'sshd\[\d+\]:\s*Failed\s+\w+\s+for\s+(?P<user_name>\S+)\s+from\s+(?P<src_ip>\S+)')
    UFW_RE = re.compile(r'UFW\s+(?P<action>\w+)')
    CRON_RE = re.compile(r'CRON\[\d+\]:\s*\(\s*(?P<user_name>\S+)\s*\)\s*CMD\s*\(\s*(?P<command>\S+)\s*\)')
    SYSTEMD_RE = re.compile(r'systemd\[\d+\]:\s*Started\s+(?P<service>\S+)\.')
    KERNEL_RE = re.compile(r'kernel:\s*\[\s*(?P<message>.*)')

    def recognize(self, raw: str) -> tuple[float, str]:
        # Be specific — require actual syslog structure, not just keywords
        if re.match(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+', raw):
            if 'sudo:' in raw: return 0.95, "syslog"
            if 'sshd' in raw: return 0.95, "syslog"
            if 'UFW' in raw: return 0.90, "syslog"
            if 'systemd' in raw: return 0.85, "syslog"
            if 'CRON' in raw: return 0.85, "syslog"
            return 0.6, "syslog"  # generic syslog with hostname
        # Don't match device-style logs that lack syslog structure
        return 0.0, "unknown"

    def parse(self, raw: str, format: str) -> dict[str, Any]:
        payload = self.strip_syslog_header(raw)

        patterns = [
            ("sudo", self.SUDO_RE, {"event_subtype": "sudo_command"}),
            ("ssh_accept", self.SSH_ACCEPT_RE, {"event_subtype": "ssh_login"}),
            ("ssh_fail", self.SSH_FAIL_RE, {"event_subtype": "ssh_failed"}),
            ("ufw", self.UFW_RE, {"event_subtype": "firewall"}),
            ("cron", self.CRON_RE, {"event_subtype": "cron_job"}),
            ("systemd", self.SYSTEMD_RE, {"event_subtype": "service_start"}),
        ]

        for name, pattern, extra in patterns:
            m = pattern.search(raw)
            if m:
                result = m.groupdict()
                result.update(extra)
                return result

        # Fallback
        return {"message": payload[:200], "event_subtype": "unknown"}

    def map_fields(self, extracted: dict[str, Any]) -> dict[str, Any]:
        result = {}
        mapping = {
            "src_ip": "src_ip",
            "user_name": "user_name",
            "command": "process_executable",
            "service": "process_name",
            "action": "event_action",
        }
        for src, tgt in mapping.items():
            if src in extracted:
                result[tgt] = extracted[src]

        subtype = extracted.get("event_subtype", "")
        # Outcome
        if "failed" in subtype.lower():
            result["event_outcome"] = "failure"
        elif "accept" in subtype.lower() or "built" in subtype.lower():
            result["event_outcome"] = "success"
        else:
            result["event_outcome"] = "success"

        # Category
        if subtype in ("sudo_command", "ssh_login", "ssh_failed"):
            result["event_category"] = ["authentication"]
            result["event_action"] = subtype
        elif subtype == "firewall":
            result["event_category"] = ["network", "security"]
            result["event_action"] = extracted.get("action", "firewall_block")
        elif subtype == "cron_job":
            result["event_category"] = ["system"]
            result["event_action"] = "scheduled_task"
        elif subtype == "service_start":
            result["event_category"] = ["system"]
            result["event_action"] = "service_started"
        else:
            result["event_category"] = ["system"]
            result["event_action"] = subtype

        result["event_type"] = [subtype] if subtype else ["unknown"]
        return result
