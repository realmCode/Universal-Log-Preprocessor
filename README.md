# ULPF — Universal Log Pre-processing Framework

> Transform any log, from any source, into a unified, analytics-ready format.

ULPF ingests logs from any hardware or software system, parses them using a plug-and-play module system, normalizes fields into a unified schema, and outputs structured events to SIEM, data lakes, and ML pipelines. It handles billions of events per day, works in air-gapped networks, and automatically discovers unknown log patterns using Drain3 template mining.

## Key Features

- **Universal Parsing**: Handles JSON, Syslog (RFC 3164/5424), CEF, LEEF, Nginx/Apache access logs, Cisco ASA firewall logs, and any custom format
- **Plug-and-Play**: Add a new log source by dropping a module config into the `modules/` directory. No framework code changes. Auto-discovered at startup.
- **Unknown Source Discovery**: Drain3 automatically mines templates from unrecognized logs and generates YAML config scaffolds
- **Lossless Preservation**: Raw log messages preserved verbatim. Source-specific fields retained alongside normalized output
- **Scalable**: Stateless processing workers, Kafka-based streaming, horizontal scaling
- **Air-Gap Ready**: No runtime external API dependencies. Deploys with a single tarball
- **AI/ML Ready**: Unified schema with structured fields for threat analytics and anomaly detection

## Quick Start

### Prerequisites

- Python 3.11+
- pip

### Installation

```bash
git clone https://github.com/yourusername/ulpf.git
cd ulpf
pip install -r requirements.txt
```

### Run Demo

```bash
# Generate demo logs and run full demo
python scripts/run_demo.py all

# Or process your own log file
python pathway_app.py --input /path/to/logs.txt --output output/normalized.jsonl
```

### Output

Each log line produces a **UnifiedEvent** (JSON):

```json
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
  "dst_ip": "8.8.8.8",
  "src_port": 45678,
  "dst_port": 443,
  "protocol": "tcp",
  "raw_message": "<134>Oct 11 22:14:15 asa01 %ASA-4-106023: ...",
  "source_fields": {"interface": "outside", "tcp_flags": "SYN"},
  "enrichment": {"module": "cisco_asa", "format_detected": "syslog"}
}
```

## Architecture

```
  Log Sources          Network Boundary         Isolated Network
  (Firewalls,          ┌──────────┐            ┌──────────────┐
   Servers,   ────────▶│  Kafka   │───────────▶│  Pathway     │
   IoT, ...)            │ Broker   │            │  Workers     │
                        └──────────┘            │              │
                                               │  1. Format    │
                                               │     Detect    │
                                               │  2. Module    │
                                               │     Match     │
                                               │  3. Parse     │
                                               │  4. Normalize │
                                               │  5. Enrich    │
                                               │  6. Output    │
                                               └──┬──────┬─────┘
                                                   │      │
                                          ┌────────┘      │
                                          ▼               ▼
                                  ┌──────────────┐ ┌─────────────┐
                                  │  Kafka:      │ │  Elastic-   │
                                  │  normalized  │ │  search     │
                                  │  events      │ │  (SIEM)     │
                                  └──────────────┘ └─────────────┘
```

### Processing Pipeline

1. **Format Detection**: Auto-detect JSON, Syslog, CEF, LEEF, XML, or plain text
2. **Module Matching**: Find the best parser module using confidence scoring
3. **Parsing**: Extract structured fields using regex/Grok patterns
4. **Normalization**: Map source-specific fields to unified schema
5. **Enrichment**: Add metadata, GeoIP, threat intel
6. **Output**: Emit UnifiedEvent to Kafka, Elasticsearch, S3, or file

## Adding a New Log Source

### Option A: YAML Config (Simple Sources)

Create `modules/my_source/config.yaml`:

```yaml
module:
  name: my_source
  source_type: application
  formats: [text]

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
  src_ip: src_ip
```

Drop it in `modules/`. The framework auto-discovers it.

### Option B: Python Class (Complex Sources)

Create `modules/my_source/__init__.py`:

```python
from modules.base import BaseParser
import re

class MySourceParser(BaseParser):
    name = "my_source"
    source_type = "application"
    supported_formats = ["text"]

    PATTERN = re.compile(r'...')

    def recognize(self, raw):
        if raw.startswith("MYAPP["):
            return 0.9, "text"
        return 0.0, "unknown"

    def parse(self, raw, format):
        m = self.PATTERN.match(raw)
        return m.groupdict() if m else {}

    def map_fields(self, extracted):
        return {"event_action": extracted.get("action")}
```

## Docker Deployment

```bash
# Start full stack (Kafka + ULPF worker)
make docker-up

# Run demo with log generator
make docker-demo

# Stop
make docker-down
```

### Air-Gap Deployment

```bash
# On a machine with internet:
pip download -r requirements.txt -d python-wheels/ --platform manylinux2014_x86_64
docker save confluentinc/cp-zookeeper:7.5.0 confluentinc/cp-kafka:7.5.0 -o docker-images.tar

# Transfer everything to the air-gapped network:
tar czf ulpf-airgap.tar.gz python-wheels/ docker-images.tar.gz modules/ SIH26/

# On the isolated machine:
tar xzf ulpf-airgap.tar.gz
pip install python-wheels/*.whl
docker load < docker-images.tar.gz
docker compose up -d
```

## Module Reference

| Module | Source | Format | What It Parses |
|---|---|---|---|
| `generic_syslog` | Any | Syslog | RFC 3164/5424 header + key=value pairs |
| `generic_json` | Any | JSON | Any JSON, flattened with dot notation |
| `nginx_access` | Nginx | Text | Combined/Common log format |
| `cisco_asa` | Cisco ASA | Syslog | Firewall connection teardown, built, deny, login |
| `linux_syslog` | Linux | Syslog | SSH, sudo, UFW, CRON, systemd |

## Performance

- **Throughput**: 3,000+ events/sec on a single core (demo mode)
- **Scalability**: Add Pathway workers to scale horizontally via Kafka partitioning
- **Memory**: Drain3 LRU eviction prevents unbounded growth

## Tech Stack

- **Python 3.11** — Core language
- **Pathway** — Streaming pipeline engine (Kafka connectors built-in)
- **Drain3** — Log template mining for unknown sources
- **Pydantic v2** — Schema validation and serialization
- **Kafka** — Message broker for streaming
- **Docker Compose** — Deployment orchestration

## License

MIT
