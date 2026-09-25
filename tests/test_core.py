"""
Tests for ULPF framework.
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_registry_discovers_modules():
    from modules import get_registry, reset_registry
    reset_registry()
    registry = get_registry()
    registry.discover()
    names = [m.name for m in registry.get_all()]
    assert "cisco_asa" in names
    assert "nginx_access" in names
    assert "generic_syslog" in names
    assert "generic_json" in names
    assert "linux_syslog" in names


def test_format_detection():
    from utils.format_detector import detect_format
    assert detect_format('{"key": "val"}') == "json"
    assert detect_format('<134>Oct 11 22:14:15 host app: msg') == "syslog"
    assert detect_format('10.0.0.1 - - [01/Jan/2025:00:00:00 +0000] "GET / HTTP/1.1" 200 0') == "text"
    assert detect_format('CEF:0|Vendor|Product|1.0|100|Name|Low|') == "cef"


def test_cisco_asa_parsing():
    from modules import get_registry
    registry = get_registry()
    registry.discover()
    m = registry.get("cisco_asa")
    raw = '<134>Oct 11 22:14:15 asa01 %ASA-6-302013: Teardown TCP connection 1234 for host 10.0.0.1:80 to host 8.8.8.8:443, duration 5s, bytes 1500'
    extracted = m.parse(raw, "syslog")
    assert extracted["src_ip"] == "10.0.0.1"
    assert extracted["dst_ip"] == "8.8.8.8"
    assert extracted["message_code"] == "302013"
    mapped = m.map_fields(extracted)
    assert mapped["event_action"] == "connection_teardown"
    assert mapped["src_ip"] == "10.0.0.1"
    assert mapped["dst_ip"] == "8.8.8.8"


def test_nginx_parsing():
    from modules import get_registry
    registry = get_registry()
    registry.discover()
    m = registry.get("nginx_access")
    raw = '10.0.0.1 - - [11/Oct/2025:13:55:36 +0000] "GET /api HTTP/1.1" 200 1234'
    extracted = m.parse(raw, "text")
    assert extracted["remote_addr"] == "10.0.0.1"
    assert extracted["status"] == 200
    mapped = m.map_fields(extracted)
    assert mapped["src_ip"] == "10.0.0.1"
    assert mapped["event_outcome"] == "success"


def test_unified_event_creation():
    from schema.unified_event import UnifiedEvent
    from utils.id_gen import generate_event_id
    event = UnifiedEvent(
        event_id=generate_event_id(),
        source_type="network_device",
        source_vendor="cisco",
        event_action="firewall_deny",
        src_ip="10.0.0.1",
        raw_message="test log",
        source_fields={"interface": "outside"},
    )
    assert event.src_ip == "10.0.0.1"
    assert event.source_fields["interface"] == "outside"
    assert event.event_action == "firewall_deny"


def test_field_mapper():
    from normalizer.mapper import FieldMapper
    mapper = FieldMapper({
        "src_ip": "src_ip",
        "status": "event_outcome",
        "action": {"map_to": "event_action", "transform": {"deny": "firewall_deny", "allow": "firewall_allow"}},
    })
    unified, unmapped = mapper.apply({"src_ip": "10.0.0.1", "status": "403", "action": "deny", "extra": "value"})
    assert unified["src_ip"] == "10.0.0.1"
    assert unified["event_outcome"] == "403"
    assert unified["event_action"] == "firewall_deny"
    assert unmapped["extra"] == "value"


def test_pipeline_end_to_end():
    from pathway_app import LogProcessor
    processor = LogProcessor(enable_drain3=False)
    
    event = processor.process_line('{"level": "info", "src_ip": "10.0.0.1"}')
    assert event.src_ip == "10.0.0.1"
    assert event.enrichment["module"] == "generic_json"
    
    event = processor.process_line('<134>Oct 11 22:14:15 host sudo: user=admin action=login')
    assert event.enrichment["module"] == "generic_syslog"
    
    event = processor.process_line('<134>Oct 11 22:14:15 asa01 %ASA-6-302013: Teardown TCP connection 1234 for host 10.0.0.1:80 to host 8.8.8.8:443, duration 5s, bytes 1500')
    assert event.enrichment["module"] == "cisco_asa"
    assert event.event_action == "connection_teardown"
    assert event.src_ip == "10.0.0.1"


def test_drain3_fallback():
    from pathway_app import LogProcessor
    processor = LogProcessor(enable_drain3=True)

    event = processor.process_line('DEVICE:sensor-001 motion=detected zone=6 confidence=91%')
    assert event.enrichment["module"] == "drain3"
    assert event.enrichment.get("drain3_status") in ("new_template", "matched")


if __name__ == "__main__":
    test_registry_discovers_modules()
    print("PASS: test_registry_discovers_modules")

    test_format_detection()
    print("PASS: test_format_detection")

    test_cisco_asa_parsing()
    print("PASS: test_cisco_asa_parsing")

    test_nginx_parsing()
    print("PASS: test_nginx_parsing")

    test_unified_event_creation()
    print("PASS: test_unified_event_creation")

    test_field_mapper()
    print("PASS: test_field_mapper")

    test_pipeline_end_to_end()
    print("PASS: test_pipeline_end_to_end")

    test_drain3_fallback()
    print("PASS: test_drain3_fallback")

    print("\nAll tests passed!")
