"""
ULPF — Universal Log Pre-processing Framework
Main processing pipeline.

Usage:
    # File mode (no Kafka needed):
    python pathway_app.py --input data/sample_logs/raw.log --output output/normalized.jsonl

    # With demo logs:
    python pathway_app.py --demo

    # Kafka mode (requires Kafka running):
    python pathway_app.py --kafka-input raw_logs --kafka-output normalized_events
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from schema.unified_event import UnifiedEvent
from modules import get_registry, reset_registry
from normalizer.mapper import FieldMapper
from utils.format_detector import detect_format, detect_and_score
from utils.id_gen import generate_event_id


# ─────────────────────────────────────────────────────────────────────
# Processing Pipeline
# ─────────────────────────────────────────────────────────────────────

class LogProcessor:
    """
    Core processing engine.
    Takes raw log lines → produces UnifiedEvent objects.

    Pipeline stages:
        1. Format Detection   — determine if JSON/Syslog/CEF/etc
        2. Module Matching    — find the best parser module
        3. Parsing            — extract structured fields
        4. Normalization      — map fields to unified schema
        5. Enrichment         — add metadata, timestamps
        6. Output             — produce UnifiedEvent
    """

    def __init__(self, modules_dir: str = "modules", enable_drain3: bool = False):
        print("[ULPF] Initializing LogProcessor...")

        # Load modules
        reset_registry()
        self.registry = get_registry()
        self.registry.discover()
        print(f"[ULPF] Loaded {len(self.registry)} parser modules")

        # Field mapper (used as fallback if module doesn't provide map_fields)
        self.mapper = FieldMapper()

        # Drain3 (optional)
        self.drain3 = None
        if enable_drain3:
            try:
                from drain3_integration.fallback import Drain3Fallback
                self.drain3 = Drain3Fallback(state_dir="drain3_state")
                print("[ULPF] Drain3 fallback enabled")
            except ImportError:
                print("[ULPF] Drain3 not available, skipping")

        # Stats
        self.stats = {
            "total": 0,
            "parsed_by_module": {},
            "fallback_used": 0,
            "errors": 0,
            "start_time": time.time(),
        }

    def process_line(self, raw: str, source_hint: str = "") -> UnifiedEvent:
        """
        Process a single raw log line through the full pipeline.

        Args:
            raw: The raw log line.
            source_hint: Optional hint about the source (e.g., source IP).

        Returns:
            UnifiedEvent with normalized fields.
        """
        self.stats["total"] += 1
        timestamp = datetime.now(timezone.utc)

        # ── Stage 1: Format Detection ──────────────────────────────
        fmt_result = detect_and_score(raw)
        fmt = fmt_result["format"]
        fmt_confidence = fmt_result["confidence"]

        # ── Stage 2: Module Matching ───────────────────────────────
        # Try to match a module for this source
        module, matched_format, is_fallback = self.registry.match_or_fallback(raw)

        # ── Stage 3: Parsing ───────────────────────────────────────
        extracted: dict[str, Any] = {}
        source_fields: dict[str, Any] = {}
        module_name = "unknown"
        used_drain3 = False
        drain3_template = ""
        drain3_status = "unknown"

        if module and not is_fallback:
            # Specific module matched — try to parse
            try:
                extracted = module.parse(raw, matched_format or fmt)
                if extracted and module.validate(extracted):
                    module_name = module.name
                    self.stats["parsed_by_module"][module_name] = \
                        self.stats["parsed_by_module"].get(module_name, 0) + 1
                else:
                    # Module matched but returned empty → try Drain3
                    extracted = {}
            except Exception:
                extracted = {}

        # If no specific module parsed it, try Drain3 fallback
        if not extracted and self.drain3:
            try:
                drain3_result = self.drain3.process(source_hint or "default", raw)
                extracted = drain3_result.get("parameters", {})
                if extracted or drain3_result.get("status") == "new_template":
                    module_name = "drain3"
                    used_drain3 = True
                    self.stats["fallback_used"] += 1
                    drain3_template = drain3_result.get("template", "")
                    drain3_status = drain3_result.get("status", "unknown")
            except Exception:
                pass

        # If still nothing, use generic fallback module's parse
        if not extracted and is_fallback and not used_drain3:
            try:
                extracted = module.parse(raw, matched_format or fmt)
                module_name = module.name
                self.stats["parsed_by_module"][module_name] = \
                    self.stats["parsed_by_module"].get(module_name, 0) + 1
            except Exception:
                extracted = {}

        # ── Stage 4: Normalization ─────────────────────────────────
        unified_fields: dict[str, Any] = {}

        if module_name != "unknown" and module_name != "drain3":
            # Use module's built-in mapping
            try:
                mapped = module.map_fields(extracted)
                unified_fields.update(mapped)
            except Exception:
                pass

        # Unmapped fields → source_fields (lossless preservation)
        if module and module_name not in ("unknown", "drain3"):
            try:
                _, unmapped = self.mapper.apply(extracted)
                source_fields.update(unmapped)
            except Exception:
                source_fields.update(extracted)
        else:
            # For fallback/Drain3, preserve all extracted fields
            source_fields.update(extracted)

        # ── Stage 5: Enrichment ────────────────────────────────────
        enrichment: dict[str, Any] = {
            "format_detected": fmt,
            "format_confidence": fmt_confidence,
            "module": module_name,
            "module_confidence": fmt_confidence if not is_fallback else 0.0,
        }

        # Add Drain3-specific enrichment
        if used_drain3:
            enrichment["drain3_template"] = drain3_template
            enrichment["drain3_status"] = drain3_status

        # ── Stage 6: Build UnifiedEvent ────────────────────────────
        # Merge unified fields, letting module-extracted values take priority
        # For Drain3 events, use "drain3" as the product name
        effective_product = module_name if used_drain3 else (module.name if module else None)
        effective_source_type = module.source_type if module else "generic"
        effective_vendor = module.name.split("_")[0] if module and "_" in module.name else (module.name if module else None)

        if used_drain3:
            effective_product = "drain3"
            effective_source_type = "unknown"
            effective_vendor = "unknown"

        event_defaults: dict[str, Any] = {
            "event_id": generate_event_id(),
            "timestamp": timestamp,
            "source_type": effective_source_type,
            "source_vendor": effective_vendor,
            "source_product": effective_product,
            "log_format": fmt,
            "raw_message": raw,
            "source_fields": source_fields,
            "enrichment": enrichment,
        }

        # Module-extracted unified fields override defaults
        merged = {**event_defaults}
        for k, v in unified_fields.items():
            if v is not None:
                merged[k] = v

        try:
            event = UnifiedEvent(**merged)
            return event
        except Exception as e:
            self.stats["errors"] += 1
            # Create minimal event
            return UnifiedEvent(
                event_id=generate_event_id(),
                timestamp=timestamp,
                log_format=fmt,
                raw_message=raw,
                source_fields=source_fields,
                enrichment=enrichment,
            )

    def process_file(self, input_path: str, output_path: str = None,
                     limit: int = None, verbose: bool = True) -> list[UnifiedEvent]:
        """
        Process a log file and produce normalized output.

        Args:
            input_path: Path to the input log file.
            output_path: Path for normalized output (JSONL).
            limit: Max lines to process (None = all).
            verbose: Print progress.

        Returns:
            List of processed UnifiedEvents.
        """
        input_path = Path(input_path)
        if not input_path.exists():
            print(f"[ULPF] ERROR: Input file not found: {input_path}")
            return []

        print(f"[ULPF] Processing: {input_path}")
        events: list[UnifiedEvent] = []

        # Read input
        with open(input_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        total_lines = len(lines)
        if limit:
            lines = lines[:limit]

        print(f"[ULPF] {total_lines} lines loaded, processing {len(lines)}...")

        # Process each line
        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue

            try:
                event = self.process_line(line)
                events.append(event)
            except Exception as e:
                self.stats["errors"] += 1
                if verbose:
                    print(f"  [ERROR] Line {i+1}: {e}")

            if verbose and (i + 1) % 100 == 0:
                print(f"  ... {i+1}/{len(lines)} lines processed")

        # Write output
        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                for event in events:
                    f.write(event.to_json() + "\n")
            print(f"[ULPF] Output written to: {output_path}")

        # Print summary
        self.print_summary()

        return events

    def process_stream(self, input_stream: TextIO, output_stream: TextIO = None,
                       limit: int = None, verbose: bool = False) -> list[UnifiedEvent]:
        """Process lines from a stream (stdin, pipe, etc.)."""
        events = []
        count = 0

        for line in input_stream:
            line = line.strip()
            if not line:
                continue

            try:
                event = self.process_line(line)
                events.append(event)

                if output_stream:
                    output_stream.write(event.to_json() + "\n")

                count += 1
                if limit and count >= limit:
                    break
            except Exception:
                self.stats["errors"] += 1

        if verbose:
            self.print_summary()

        return events

    def print_summary(self):
        """Print processing statistics."""
        elapsed = time.time() - self.stats["start_time"]
        total = self.stats["total"]
        eps = total / elapsed if elapsed > 0 else 0

        print(f"\n{'='*60}")
        print(f"[ULPF] Processing Summary")
        print(f"{'='*60}")
        print(f"  Total events:    {total}")
        print(f"  Time elapsed:    {elapsed:.2f}s")
        print(f"  Events/sec:      {eps:.0f}")
        print(f"  Errors:          {self.stats['errors']}")
        print(f"  Drain3 fallback: {self.stats['fallback_used']}")
        print(f"\n  Modules used:")
        for mod, count in sorted(self.stats["parsed_by_module"].items(),
                                  key=lambda x: -x[1]):
            pct = count / total * 100 if total > 0 else 0
            print(f"    {mod:25s} {count:8d}  ({pct:.1f}%)")
        print(f"{'='*60}")

    def get_stats(self) -> dict[str, Any]:
        """Return processing statistics."""
        return dict(self.stats)


# ─────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="ULPF — Universal Log Pre-processing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process a log file:
  python pathway_app.py --input data/sample_logs/raw.log

  # Process with output:
  python pathway_app.py --input raw.log --output normalized.jsonl

  # Limit to 50 lines:
  python pathway_app.py --input raw.log --limit 50

  # Run demo:
  python pathway_app.py --demo
        """,
    )
    parser.add_argument("--input", "-i", help="Input log file path")
    parser.add_argument("--output", "-o", help="Output normalized JSONL file")
    parser.add_argument("--limit", "-n", type=int, help="Max lines to process")
    parser.add_argument("--demo", action="store_true", help="Run with demo logs")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--modules-dir", default="modules", help="Modules directory")
    parser.add_argument("--drain3", action="store_true", help="Enable Drain3 fallback")

    args = parser.parse_args()

    # Initialize processor
    processor = LogProcessor(
        modules_dir=args.modules_dir,
        enable_drain3=args.drain3,
    )

    if args.demo:
        # Generate demo logs and process them
        print("\n[ULPF] Running demo mode...\n")
        from scripts.generate_demo_logs import generate_demo_logs
        demo_file = "data/sample_logs/demo_mixed.log"
        generate_demo_logs(demo_file, count_per_source=20)
        args.input = demo_file
        if not args.output:
            args.output = "output/demo_output.jsonl"

    if args.input:
        # File mode
        output = args.output or "output/last_run.jsonl"
        events = processor.process_file(
            input_path=args.input,
            output_path=output,
            limit=args.limit,
            verbose=args.verbose,
        )

        # Print a few sample events
        if events and args.verbose:
            print(f"\n[ULPF] Sample events (first 3):")
            for event in events[:3]:
                print(json.dumps(event.to_dict(), indent=2, default=str))
    else:
        # Stdin mode
        print("[ULPF] Reading from stdin (Ctrl+D to stop)...")
        events = processor.process_stream(sys.stdin, sys.stdout, args.limit, args.verbose)


if __name__ == "__main__":
    main()
