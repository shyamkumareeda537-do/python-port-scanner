# utils.py
"""Utility functions for the Python TCP Port Scanner.
Provides input validation, logging setup, progress display, service name
lookup, hostname resolution, and report generation/saving.
"""
import os
import re
import socket
import logging
from datetime import datetime
from typing import List, Dict

# ------------------------------------------------------------
# Logger
# ------------------------------------------------------------
LOGGER = None

def setup_logger() -> None:
    """Initialise a global logger that writes to ``logs/scanner.log``.
    Creates the ``logs`` directory if it does not exist.
    """
    global LOGGER
    if LOGGER is not None:
        return
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    log_dir = os.path.join(base_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "scanner.log")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.FileHandler(log_path, encoding="utf-8"), logging.StreamHandler()],
    )
    LOGGER = logging.getLogger("port_scanner")
    LOGGER.info("Logger initialised – output to %s", log_path)

# expose a module‑level logger for imports
logger = logging.getLogger("port_scanner")

# ------------------------------------------------------------
# Validation helpers
# ------------------------------------------------------------
def validate_ip_or_hostname(value: str) -> bool:
    """Return ``True`` if *value* looks like a valid IPv4 address or hostname.
    Does **not** perform DNS resolution – that is handled separately.
    """
    # IPv4 pattern
    ipv4_pat = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if re.fullmatch(ipv4_pat, value):
        parts = value.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    # Hostname pattern (RFC 1123 compliance, simple version)
    hostname_pat = r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
    return re.fullmatch(hostname_pat, value) is not None

def validate_port(port: int) -> bool:
    return 1 <= port <= 65535

def validate_timeout(value: float) -> bool:
    return value > 0

def validate_thread_count(value: int) -> bool:
    return value > 0

# ------------------------------------------------------------
# Service name lookup
# ------------------------------------------------------------
COMMON_SERVICE_MAP = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    3306: "mysql",
    3389: "rdp",
    8080: "http-proxy",
    8443: "https-alt",
}

def get_service_name(port: int) -> str:
    """Return a human readable service name for *port*.
    If the port is unknown, returns ``"unknown"``.
    """
    return COMMON_SERVICE_MAP.get(port, "unknown")

# ------------------------------------------------------------
# Host resolution
# ------------------------------------------------------------
def resolve_target(target: str) -> str:
    """Resolve *target* (hostname or IP string) to an IPv4 address.
    Raises ``socket.gaierror`` on failure.
    """
    return socket.gethostbyname(target)

# ------------------------------------------------------------
# Progress display
# ------------------------------------------------------------
def display_progress(scanned: int, total: int) -> None:
    """Print a simple progress line that overwrites itself.
    ``scanned`` – ports already processed.
    ``total``   – total ports to scan.
    """
    percent = (scanned / total) * 100 if total else 0.0
    print(f"Scanning ports: {scanned}/{total} ({percent:.1f}%)", end="\r", flush=True)
    if scanned == total:
        print()  # newline after final update

# ------------------------------------------------------------
# Report generation & saving
# ------------------------------------------------------------
def generate_report(data: Dict) -> str:
    """Create a formatted multiline report from *data*.
    Expected keys: ``date_time``, ``target``, ``resolved_ip``, ``scan_type``,
    ``port_range``, ``timeout``, ``threads``, ``open_ports`` (list of (port,svc)),
    ``ports_scanned``, ``duration``.
    """
    lines: List[str] = []
    lines.append("=" * 60)
    lines.append("PYTHON TCP PORT SCANNER REPORT")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"Date/Time       : {data.get('date_time', '')}")
    lines.append(f"Target          : {data.get('target', '')}")
    lines.append(f"Resolved IP     : {data.get('resolved_ip', '')}")
    lines.append(f"Scan Type       : {data.get('scan_type', '')}")
    lines.append(f"Port Range      : {data.get('port_range', '')}")
    lines.append(f"Timeout         : {data.get('timeout', '')} seconds")
    lines.append(f"Threads         : {data.get('threads', '')}")
    lines.append("")
    lines.append("Open Ports:")
    for port, svc in sorted(data.get('open_ports', [])):
        lines.append(f"{port}/tcp    OPEN    {svc}")
    lines.append("")
    lines.append(f"Ports Scanned   : {data.get('ports_scanned', 0)}")
    lines.append(f"Open Ports      : {len(data.get('open_ports', []))}")
    lines.append(f"Scan Duration   : {data.get('duration', '')}")
    lines.append("=" * 60)
    return "\n".join(lines)

def save_report(report: str, filename: str) -> None:
    """Write *report* to ``output/<filename>`` creating the directory as needed.
    """
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    out_dir = os.path.join(base_dir, "output")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(report + "\n")
    logger.info("Report saved to %s", path)
