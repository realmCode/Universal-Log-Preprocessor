# ULPF — Architecture Document

## 1. Overview

ULPF (Universal Log Pre-processing Framework) is a streaming log processing system that ingests logs from any hardware or software source, parses them using a plug-and-play module system, normalizes fields into a unified schema, and outputs structured events to SIEM, data lakes, and ML pipelines.

### Design Principles

1. **Push, Don't Pull**: Sources push logs to the system. The framework never reaches out to sources.
2. **Lossless by Default**: Raw messages always preserved alongside normalized output.
3. **Graceful Degradation**: Unknown formats get partial parsing via Drain3, never dropped.
4. **Extensible over Complete**: Ship the framework + common modules + ability to add more without core changes.
5. **Air-Gap Native**: Every component works without external API calls.

## 2. System Architecture

```
┌─────────────┐     ┌──────────┐     ┌──────────────────┐
│ Log Sources │────▶│  Kafka   │────▶│  Pathway Workers │
│             │     │ Broker   │     │                  │
│ Firewalls   │     │          │     │ 1. Format Detect │
│ Servers     │     │ Topics:  │     │ 2. Module Match  │
│ Containers  │     │ raw_logs │     │ 3. Parse         │
│ IoT         │     │ +        │     │ 4. Normalize     │
│ Databases   │     │ normalized│     │ 5. Enrich        │
│             │     │ events   │     │ 6. Output        │
└─────────────┘     └──────────┘     └────────┬─────────┘
                                               │
                          ┌────────────────────┼──────────────────────┐
                          ▼                    ▼                      ▼
                   ┌──────────────┐    ┌───────────────┐    ┌──────────────┐
                   │   Kafka:     │    │   Elastic-    │    │   S3/MinIO   │
                   │   normalized │    │   search      │    │  (raw +      │
                   │   events     │    │   (SIEM)      │    │   norm)      │
                   └──────────────┘    └───────────────┘    └──────────────┘
```

### Data Flow

1. **Ingestion**: Sources push logs via Syslog/UDP, Syslog/TCP, or application protocol to Kafka topic `raw_logs`.
2. **Consumption**: Pathway workers consume from `raw_logs` topic partitions in parallel.
3. **Format Detection**: Heuristic-based detection (JSON-first, then CEF/LEEF/Syslog/text).
4. **Module Matching**: Each module declares `recognize()` patterns. Framework scores all modules, picks best match.
5. **Parsing**: Module extracts structured fields using regex/Grok patterns.
6. **Normalization**: Module maps source fields to unified schema. Unmapped fields go to `source_fields`.
7. **Enrichment**: GeoIP lookup, threat intel, Drain3 template metadata.
8. **Output**: Events written to `normalized_events` Kafka topic, Elasticsearch, and S3/MinIO.

## 3. Unified Schema

The canonical `UnifiedEvent` schema has these sections:

| Section | Fields | Purpose |
|---|---|---|
| Identity | event_id, timestamp, source_type, source_vendor, source_product | Metadata about the event origin |
| Event | event_action, event_outcome, event_category, event_type | What happened |
| Network | src_ip, src_port, dst_ip, dst_port, protocol, bytes_sent | Network context |
| Identity | user_id, user_name, user_domain | Who performed the action |
| Process | process_name, process_pid, process_executable | Which process |
| File | file_path, file_name, file_hash_md5 | File context |
| Lossless | raw_message, source_fields, enrichment | Original data + extras |

The `source_fields` dict captures ALL source-specific fields not in the unified schema, ensuring zero data loss.

## 4. Module System

### Module Interface

```python
class ParserModule(ABC):
    name: str                    # "cisco_asa", "nginx_access"
    source_type: str             # "network_device", "application"
    supported_formats: list[str] # ["syslog"], ["json"], ["text"]

    def recognize(self, raw: str) -> tuple[float, str]:
        """Return (confidence, format). Framework uses this to pick the right module."""

    def parse(self, raw: str, format: str) -> dict[str, Any]:
        """Extract structured fields. Returns dict of source field names."""

    def map_fields(self, extracted: dict) -> dict[str, Any]:
        """Map source field names → unified field names."""
```

### Module Discovery

The `ModuleRegistry` scans the `modules/` directory at startup, imports each subpackage, and collects all classes implementing `ParserModule`. No registration code needed in the framework core.

### Adding a New Module

1. Create `modules/my_source/__init__.py` implementing `ParserModule`
2. Create `modules/my_source/config.yaml` with patterns and field mappings
3. Restart (or use filesystem watcher for hot-reload)

For simple sources, YAML-only configs work (no Python needed). Python is the escape hatch for complex parsing.

## 5. Drain3 Integration

Drain3 (from logpai) provides automatic log template mining. When no parser module matches a log:

1. A per-source Drain3 miner attempts to match against known templates
2. If no match: a new template is mined, parameters are extracted
3. An alert is generated: "New pattern discovered from source X"
4. The framework can auto-generate a YAML config scaffold from the template
5. User reviews and activates → new module goes live

This creates a closed loop: unknown sources → auto-discovery → module creation → production parsing.

## 6. Scalability

### Horizontal Scaling

- **Kafka partitioning**: Each partition processed independently by one worker
- **Stateless workers**: No shared state. Scale by adding more Pathway workers
- **Backpressure**: Kafka consumer groups naturally handle flow control

### Throughput

| Deployment | Events/sec | Notes |
|---|---|---|
| Single process (file mode) | ~3,500 | Demo/testing |
| 4 Pathway workers + Kafka | ~15,000 | Small deployment |
| 12+ workers + Kafka | 50,000+ | Production scale |

### Memory Management

- Drain3: `max_clusters=5000` per source, LRU eviction
- Module patterns: pre-compiled regex at load time
- No per-event allocations beyond the UnifiedEvent object

## 7. Air-Gap Deployment

ULPF requires no internet access at runtime. The deployment package contains:

| Component | Method |
|---|---|
| Python packages | `pip download` → .whl files |
| Kafka | Docker images → `docker save` tarball |
| GeoIP database | MaxMind GeoLite2 shipped with package |
| Threat intel | Local text files, manually updated |
| TLS certificates | Pre-generated, shipped with package |

Installation: `tar xzf ulpf-airgap.tar.gz && ./install.sh`

## 8. Security Considerations

- **No outbound connections**: Framework never calls external APIs
- **Input validation**: Pydantic models validate all parsed fields
- **Raw data integrity**: `raw_message` field is write-once, never modified
- **Kafka SASL**: Supports SASL/SCRAM and mTLS for Kafka authentication
- **Container isolation**: Each component runs in its own container
