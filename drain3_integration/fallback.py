"""
Drain3 integration — per-source template miners as universal fallback.
When no parser module matches, Drain3 discovers patterns and extracts parameters.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import drain3
from drain3.template_miner import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

from utils.id_gen import generate_event_id
from schema.unified_event import UnifiedEvent


class Drain3Fallback:
    """
    Manages per-source Drain3 template miners.
    Each unique source (by source_id) gets its own miner with persistent state.
    """

    def __init__(self, state_dir: str = "drain3_state"):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._miners: dict[str, TemplateMiner] = {}
        self._config = self._build_config()
        self._alerts: list[dict[str, Any]] = []

    def _build_config(self) -> TemplateMinerConfig:
        """Configure Drain3 for log parsing."""
        config = TemplateMinerConfig()
        config.drain_max_clusters = 5000          # Max templates per source
        config.drain_sim_th = 0.4                 # Similarity threshold
        config.drain_max_depth = 4                # Parse tree depth
        config.drain_max_children = 100           # Max children per node
        config.drain_auto_extract_parameters = True
        config.mask_prefix = "<"
        config.mask_suffix = ">"
        config.masking = [
            {"mask": r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "mask_with": "<:IP:>"},
            {"mask": r"[0-9a-fA-F]{32}", "mask_with": "<:MD5:>"},
            {"mask": r"[0-9a-fA-F]{64}", "mask_with": "<:SHA256:>"},
            {"mask": r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", "mask_with": "<:TIMESTAMP:>"},
        ]
        config.snapshot_interval_minutes = 5
        return config

    def _get_miner(self, source_id: str) -> TemplateMiner:
        """Get or create a miner for a source. LRU eviction if too many."""
        if source_id not in self._miners:
            # Evict if too many miners
            if len(self._miners) > 100:
                oldest = next(iter(self._miners))
                del self._miners[oldest]

            miner = TemplateMiner(config=self._config)
            self._miners[source_id] = miner
        return self._miners[source_id]

    def process(self, source_id: str, raw: str) -> dict[str, Any]:
        """
        Process a log line with Drain3.
        Matches existing template or mines a new one.
        """
        miner = self._get_miner(source_id)

        # Try to match existing template
        match_result = miner.match(raw)

        if match_result:
            # Template matched — extract parameters
            template_str = match_result.get_template()
            try:
                params = miner.extract_parameters(template_str, raw)
                param_dict = {p.mask_name: p.value for p in params}
            except Exception:
                param_dict = {}

            return {
                "status": "matched",
                "template": template_str,
                "parameters": param_dict,
                "cluster_id": match_result.cluster_id,
                "cluster_size": match_result.size,
            }
        else:
            # No match — learn new template
            result = miner.add_log_message(raw)
            template = result.get("template_mined", "")

            alert_msg = (
                f"New pattern from {source_id}: {template}"
            )
            self._alerts.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_id": source_id,
                "template": template,
                "cluster_id": result.get("cluster_id", -1),
                "message": alert_msg,
            })

            # Try to extract parameters from the new template
            try:
                params = miner.extract_parameters(template, raw)
                param_dict = {p.mask_name: p.value for p in params}
            except Exception:
                param_dict = {"raw": raw[:200]}

            return {
                "status": "new_template",
                "template": template,
                "parameters": param_dict,
                "cluster_id": result.get("cluster_id", -1),
                "cluster_size": 1,
                "alert": alert_msg,
            }

    def get_alerts(self) -> list[dict[str, Any]]:
        """Return alerts for newly discovered templates."""
        alerts = list(self._alerts)
        self._alerts.clear()
        return alerts

    def get_miner_stats(self) -> dict[str, Any]:
        """Return stats about all active miners."""
        stats = {}
        for source_id, miner in self._miners.items():
            try:
                state = miner.get_state()
                stats[source_id] = {
                    "clusters": len(state.get("clusters", {})),
                    "total_messages": sum(
                        c.get("size", 0) for c in state.get("clusters", {}).values()
                    ),
                }
            except Exception:
                stats[source_id] = {"clusters": 0, "total_messages": 0}
        return stats

    def generate_scaffold(self, source_id: str, template: str) -> str:
        """
        Generate a YAML config scaffold from a Drain3 template.
        This is the "teach me a new source" feature.
        """
        # Parse the template to extract variable positions
        import re
        params = re.findall(r'<:([^:]+):>', template)

        module_name = f"auto_{source_id.replace('.', '_').replace('-', '_')}"
        yaml_config = f"""# Auto-generated module from Drain3 template discovery
# Source: {source_id}
# Template: {template}

module:
  name: {module_name}
  source_type: generic
  formats: [text]
  version: "1.0.0"
  description: "Auto-discovered from {source_id}"

recognize:
  patterns:
    - match: '{template.replace("<:", "\\\\S+").replace(":>", "\\\\S*")}'
      confidence: 0.70
      format: text

parse:
  pattern: '{template}'
  extract_parameters: true

mapping:
  # TODO: Map extracted parameters to unified fields
  # Parameters found: {', '.join(params)}
"""
        return yaml_config
