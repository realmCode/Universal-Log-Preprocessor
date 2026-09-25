# Module Development Guide

## Creating a New Parser Module

### Quick Start

```bash
# 1. Create module directory
mkdir -p modules/my_source

# 2. Create config.yaml (YAML-only, no Python needed for simple cases)
# 3. Or create __init__.py (Python class for complex parsing)

# 4. Restart or hot-reload the framework
# Module is auto-discovered from modules/ directory
```

### Option A: YAML-Only Module (Recommended for Simple Sources)

For sources with straightforward log formats, a YAML config is sufficient.

**`modules/my_source/config.yaml`**:
```yaml
module:
  name: my_source
  source_type: application
  formats: [text]
  version: "1.0.0"
  description: "Description of this log source"

recognize:
  patterns:
    - match: '^MYAPP\['
      confidence: 0.90
      format: text

parse:
  pattern: '^MYAPP\[(?P<timestamp>[^\]]+)\] (?P<level>\w+) (?P<message>.*)'

mapping:
  timestamp: timestamp
  level: log_level
  message: raw_message_supplement
```

The framework auto-loads YAML configs via the `YamlParserModule` class.

### Option B: Python Module (For Complex Sources)

For sources needing complex parsing logic, multi-pattern matching, or custom field transforms.

**`modules/my_source/__init__.py`**:
```python
from modules.base import BaseParser
import re

class MySourceParser(BaseParser):
    name = "my_source"
    source_type = "application"
    supported_formats = ["text"]
    version = "1.0.0"

    # Patterns for different log types within this source
    PATTERNS = {
        "login": re.compile(r'...'),
        "error": re.compile(r'...'),
    }

    def recognize(self, raw: str) -> tuple[float, str]:
        if raw.startswith("MYAPP["):
            return 0.9, "text"
        return 0.0, "unknown"

    def parse(self, raw: str, format: str) -> dict[str, Any]:
        for name, pattern in self.PATTERNS.items():
            m = pattern.match(raw)
            if m:
                return {**m.groupdict(), "_pattern": name}
        return {}

    def map_fields(self, extracted: dict[str, Any]) -> dict[str, Any]:
        return {
            "event_action": extracted.get("action"),
            "src_ip": extracted.get("src_ip"),
            "event_category": ["application"],
        }
```

### Module Interface Reference

| Method | Required | Purpose |
|---|---|---|
| `name` | Yes | Unique module identifier |
| `source_type` | Yes | Category: `network_device`, `os`, `application`, `database`, `iot`, `generic` |
| `supported_formats` | Yes | Raw formats this module handles |
| `version` | Yes | Semantic version |
| `recognize(raw)` | Yes | Return (confidence 0.0-1.0, format). Framework calls this to pick the right module. |
| `parse(raw, format)` | Yes | Extract fields. Return dict or empty dict. Never raise. |
| `map_fields(extracted)` | No | Map source field names → unified field names |
| `validate(extracted)` | No | Return False if parsed data looks corrupt |

### Field Mapping Reference

Use these unified field names in `map_fields()`:

| Unified Field | Type | Description |
|---|---|---|
| `event_action` | str | What happened: `login`, `firewall_deny`, `http_request` |
| `event_outcome` | str | Result: `success`, `failure`, `allowed`, `denied` |
| `event_category` | list[str] | Categories: `authentication`, `network`, `file`, `process` |
| `event_type` | list[str] | Specific types within category |
| `src_ip` / `src_port` | str / int | Source IP and port |
| `dst_ip` / `dst_port` | str / int | Destination IP and port |
| `protocol` | str | `tcp`, `udp`, `icmp`, `http` |
| `bytes_sent` / `bytes_received` | int | Byte counts |
| `user_name` / `user_id` / `user_domain` | str | User identity |
| `process_name` / `process_pid` | str / int | Process info |
| `timestamp` | str (ISO8601) | Event timestamp |

### Testing Your Module

```bash
# Test module loading
python -c "from modules import get_registry; r = get_registry(); r.discover(); print([m.name for m in r.get_all()])"

# Test parsing a sample log
python -c "
from modules import get_registry
r = get_registry()
r.discover()
m = r.get('my_source')
result = m.parse('MYAPP[2025-10-11] INFO Hello world', 'text')
print(result)
mapped = m.map_fields(result)
print(mapped)
"

# Run full pipeline with your module
python pathway_app.py --input test_logs.txt --output test_output.jsonl
```
