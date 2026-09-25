"""
Demo Log Generator — produces realistic mixed-source log files for the demo video.
Generates logs from: Cisco ASA, Nginx, Linux Syslog, and an Unknown IoT device.
All interleaved to simulate a real production environment.
"""
from __future__ import annotations

import random
import string
import time
from datetime import datetime, timezone
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────
# Cisco ASA Templates
# ─────────────────────────────────────────────────────────────────────

ASA_TEMPLATES = [
    # Connection teardown
    ('<{pri}>Oct {day} {hour}:{min}:{sec} {host} %ASA-6-302013: Teardown TCP connection {conn_id} for host {src_ip}:{src_port} to host {dst_ip}:{dst_port}, duration {dur}s, bytes {bytes}, reason "{reason}"'),
    # Connection built
    ('<{pri}>Oct {day} {hour}:{min}:{sec} {host} %ASA-6-302015: Built inbound TCP connection {conn_id} for host {src_ip}:{src_port} to host {dst_ip}:{dst_port}'),
    # TCP deny
    ('<{pri}>Oct {day} {hour}:{min}:{sec} {host} %ASA-4-106023: Deny TCP (no connection) from {src_ip}/{src_port} to {dst_ip}/{dst_port} flags {tcp_flags} on interface {iface}'),
    # UDP deny
    ('<{pri}>Oct {day} {hour}:{min}:{sec} {host} %ASA-4-106023: Deny UDP (no connection) from {src_ip}/{src_port} to {dst_ip}/{dst_port} on interface {iface}'),
    # Login success
    ('<{pri}>Oct {day} {hour}:{min}:{sec} {host} %ASA-6-113005: User \'{user}\' from {src_ip} succeeded'),
    # Login failed
    ('<{pri}>Oct {day} {hour}:{min}:{sec} {host} %ASA-6-113004: User \'{user}\' from {src_ip} failed'),
]

ASA_INTERFACES = ["outside", "inside", "dmz", "management"]
ASA_REASONS = ["Reset by peer", "Timeout", "FIN", "RST"]
ASA_TCP_FLAGS = ["SYN", "ACK", "FIN", "RST", "SYN-ACK"]
ASA_USERS = ["admin", "jsmith", "mgarcia", "devops", "netops", "svc_account"]


# ─────────────────────────────────────────────────────────────────────
# Nginx Templates
# ─────────────────────────────────────────────────────────────────────

NGINX_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]
NGINX_PATHS = ["/api/v1/users", "/api/v1/auth/login", "/api/v1/data/export",
               "/static/js/main.js", "/api/v1/health", "/favicon.ico",
               "/api/v1/upload", "/dashboard", "/ws/events"]
NGINX_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "curl/7.68.0",
    "python-requests/2.28.0",
    "kube-probe/1.25",
]
NGINX_REFERERS = ["-", "https://google.com", "https://internal.corp", "https://dashboard.corp", "-"]


# ─────────────────────────────────────────────────────────────────────
# Linux Syslog Templates
# ─────────────────────────────────────────────────────────────────────

LINUX_TEMPLATES = [
    '{host} sudo:   {user} : TTY=pts/{tty} ; PWD={pwd} ; USER={target_user} ; COMMAND={cmd}',
    '{host} sshd[{pid}]: Accepted publickey for {user} from {src_ip} port {src_port} ssh2',
    '{host} sshd[{pid}]: Failed password for {user} from {src_ip} port {src_port} ssh2',
    '{host} systemd[1]: Started {service}.',
    '{host} kernel: [UFW {action}] IN={iface} SRC={src_ip} DST={dst_ip} LEN={len}',
    '{host} CRON[{pid}]: ({user}) CMD ({cmd})',
]

LINUX_HOSTS = ["web01", "web02", "api01", "db01", "monitoring", "bastion"]
LINUX_USERS = ["deploy", "admin", "ubuntu", "root", "appuser", "svc_scanner"]
LINUX_TTYS = ["0", "1", "2", "3"]
LINUX_SERVICES = ["nginx.service", "docker.service", "sshd.service", "prometheus.service"]
LINUX_CMDS = ["/usr/bin/systemctl restart nginx", "kubectl get pods -A",
              "df -h /data", "tail -f /var/log/app.log", "/opt/scripts/backup.sh"]
LINUX_UFW_ACTIONS = ["ALLOW", "BLOCK", "LIMIT"]


# ─────────────────────────────────────────────────────────────────────
# Unknown IoT Templates
# ─────────────────────────────────────────────────────────────────────

IOT_TEMPLATES = [
    'DEVICE:{device_id} motion=detected zone={zone} confidence={conf}% ts={ts}',
    'DEVICE:{device_id} temp={temp}C humidity={hum}% battery={batt}%',
    'DEVICE:{device_id} connection=established protocol={proto} uptime={uptime}s',
    'DEVICE:{device_id} alert=threshold_exceeded metric={metric} value={val}',
    'DEVICE:{device_id} heartbeat sent=OK seq={seq}',
]

IOT_DEVICES = ["sensor-001", "sensor-002", "camera-03", "thermostat-01", "gateway-01"]


# ─────────────────────────────────────────────────────────────────────
# Generation helpers
# ─────────────────────────────────────────────────────────────────────

def _rand_ip():
    return f"{random.randint(10,192)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def _rand_port():
    return random.randint(1, 65535)

def _rand_int(min_val, max_val):
    return random.randint(min_val, max_val)

def _rand_choice(lst):
    return random.choice(lst)


def generate_cisco_asa(count=30, base_time=None) -> list[str]:
    """Generate Cisco ASA firewall log lines."""
    lines = []
    base = base_time or datetime.now(timezone.utc)

    for i in range(count):
        t = base.replace(microsecond=0)
        pri = _rand_choice([134, 135, 188])
        day = t.strftime("%d")
        hour = t.strftime("%H")
        min_s = t.strftime("%M")
        sec = t.strftime("%S")

        template = _rand_choice(ASA_TEMPLATES)
        line = template.format(
            pri=pri, day=day, hour=hour, min=min_s, sec=sec,
            host=_rand_choice(["fw01", "fw02", "asa-edge", "fw-dmz"]),
            conn_id=_rand_int(1000, 999999),
            src_ip=_rand_ip(), src_port=_rand_port(),
            dst_ip=_rand_ip(), dst_port=_rand_port(),
            dur=_rand_int(1, 3600), bytes=_rand_int(64, 150000),
            reason=_rand_choice(ASA_REASONS),
            iface=_rand_choice(ASA_INTERFACES),
            tcp_flags=_rand_choice(ASA_TCP_FLAGS),
            user=_rand_choice(ASA_USERS),
        )
        lines.append(line)

    return lines


def generate_nginx(count=30, base_time=None) -> list[str]:
    """Generate Nginx access log lines."""
    lines = []
    base = base_time or datetime.now(timezone.utc)

    for i in range(count):
        src_ip = _rand_ip()
        user = "-"
        t = base.replace(microsecond=0)
        time_str = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        method = _rand_choice(NGINX_METHODS)
        path = _rand_choice(NGINX_PATHS)
        proto = "HTTP/1.1"
        status = _rand_choice([200, 200, 200, 301, 304, 400, 401, 403, 404, 500, 502])
        bytes_sent = _rand_int(50, 50000)
        referer = _rand_choice(NGINX_REFERERS)
        agent = _rand_choice(NGINX_AGENTS)

        line = f'{src_ip} - {user} [{time_str}] "{method} {path} {proto}" {status} {bytes_sent} "{referer}" "{agent}"'
        lines.append(line)

    return lines


def generate_linux_syslog(count=20, base_time=None) -> list[str]:
    """Generate Linux syslog lines."""
    lines = []
    base = base_time or datetime.now(timezone.utc)

    for i in range(count):
        t = base.replace(microsecond=0)
        ts = t.strftime("%b %d %H:%M:%S")
        template = _rand_choice(LINUX_TEMPLATES)
        line = template.format(
            host=_rand_choice(LINUX_HOSTS),
            user=_rand_choice(LINUX_USERS),
            tty=_rand_choice(LINUX_TTYS),
            pwd="/home/" + _rand_choice(LINUX_USERS),
            target_user=_rand_choice(["root", "postgres", "www-data"]),
            cmd=_rand_choice(LINUX_CMDS),
            pid=_rand_int(100, 99999),
            src_ip=_rand_ip(), src_port=_rand_port(),
            dst_ip=_rand_ip(),
            iface=_rand_choice(["eth0", "eth1"]),
            len=_rand_int(40, 1500),
            service=_rand_choice(LINUX_SERVICES),
            action=_rand_choice(LINUX_UFW_ACTIONS),
        )
        lines.append(f"{ts} {line}")

    return lines


def generate_iot_logs(count=15, base_time=None) -> list[str]:
    """Generate unknown-format IoT device log lines (no module will match)."""
    lines = []
    base = base_time or datetime.now(timezone.utc)

    for i in range(count):
        device = _rand_choice(IOT_DEVICES)
        template = _rand_choice(IOT_TEMPLATES)
        ts = int(base.timestamp()) + i

        line = template.format(
            device_id=device,
            zone=_rand_int(1, 12),
            conf=_rand_int(70, 99),
            ts=ts,
            temp=_rand_int(18, 35),
            hum=_rand_int(30, 80),
            batt=_rand_int(10, 100),
            proto=_rand_choice(["MQTT", "CoAP", "HTTP"]),
            uptime=_rand_int(100, 99999),
            metric=_rand_choice(["cpu", "memory", "disk", "network"]),
            val=_rand_int(1, 1000),
            seq=_rand_int(1, 99999),
        )
        lines.append(line)

    return lines


def generate_demo_logs(output_path: str = "data/sample_logs/demo_mixed.log",
                       count_per_source: int = 20):
    """
    Generate a mixed log file with interleaved entries from multiple sources.
    This simulates a real production environment where logs from different
    sources arrive interleaved.
    """
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    print(f"[Generator] Generating demo logs...")

    # Generate from each source
    cisco_logs = generate_cisco_asa(count_per_source)
    nginx_logs = generate_nginx(count_per_source)
    linux_logs = generate_linux_syslog(count_per_source)
    iot_logs = generate_iot_logs(count_per_source)

    # Interleave all sources (shuffle)
    all_logs = []
    all_logs.extend([("cisco_asa", line) for line in cisco_logs])
    all_logs.extend([("nginx_access", line) for line in nginx_logs])
    all_logs.extend([("linux_syslog", line) for line in linux_logs])
    all_logs.extend([("iot_unknown", line) for line in iot_logs])

    random.seed(42)  # Reproducible for demo
    random.shuffle(all_logs)

    # Write to file with source annotations (for demo visibility)
    with open(output, "w", encoding="utf-8") as f:
        for source, line in all_logs:
            f.write(f"{line}\n")

    print(f"[Generator] Wrote {len(all_logs)} log lines to {output}")
    print(f"  Cisco ASA:   {len(cisco_logs)}")
    print(f"  Nginx:       {len(nginx_logs)}")
    print(f"  Linux Syslog:{len(linux_logs)}")
    print(f"  IoT Unknown: {len(iot_logs)}")

    return output


def print_sample_logs():
    """Print sample logs from each source for demo purposes."""
    print("\n" + "="*70)
    print("SAMPLE LOGS BY SOURCE")
    print("="*70)

    print("\n─── Cisco ASA (Firewall) ───")
    for line in generate_cisco_asa(3)[:3]:
        print(f"  {line[:120]}")

    print("\n─── Nginx Access Log ───")
    for line in generate_nginx(3)[:3]:
        print(f"  {line[:120]}")

    print("\n─── Linux Syslog ───")
    for line in generate_linux_syslog(3)[:3]:
        print(f"  {line[:120]}")

    print("\n─── Unknown IoT Device ───")
    for line in generate_iot_logs(3)[:3]:
        print(f"  {line[:120]}")

    print("\n" + "="*70 + "\n")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        output = sys.argv[1]
    else:
        output = "data/sample_logs/demo_mixed.log"

    generate_demo_logs(output, count_per_source=20)
    print_sample_logs()
