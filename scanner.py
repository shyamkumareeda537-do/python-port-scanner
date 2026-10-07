# scanner.py
"""Core scanning logic for the Python TCP Port Scanner.
Provides `scan_target` which performs a TCP connect scan on a list of ports
using a thread pool. Results are reported via a callback supplied by the
caller.
"""
import socket
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List


def _worker(host: str, port: int, timeout: float, service_lookup: Callable[[int], str]):
    """Attempt a TCP connection to *host*: *port*.
    Returns a tuple (port, is_open, service_name).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        is_open = (result == 0)
        service = service_lookup(port) if is_open else ""
        return port, is_open, service
    finally:
        sock.close()


def scan_target(host: str, ports: List[int], timeout: float, max_workers: int,
                progress_callback: Callable[[int, bool, str], None] = lambda p, o, s: None) -> None:
    """Scan *host* for the given *ports* using a thread pool.
    Calls *progress_callback* for each probed port.
    """
    logger = logging.getLogger("port_scanner")
    logger.info(f"Scanning {host} – {len(ports)} ports, timeout={timeout}s, workers={max_workers}")
    start = time.perf_counter()

    def service_lookup(p: int) -> str:
        try:
            import utils
            return utils.get_service_name(p)
        except Exception:
            return "unknown"

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(_worker, host, port, timeout, service_lookup): port for port in ports}
        for future in as_completed(future_to_port):
            port, is_open, service = future.result()
            progress_callback(port, is_open, service)

    duration = time.perf_counter() - start
    logger.info(f"Scan completed in {duration:.2f} seconds")
