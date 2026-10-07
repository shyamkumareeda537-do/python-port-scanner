# main.py
"""Entry point for the Python TCP Port Scanner.
Provides a clean CLI, menu handling, user input validation, and orchestrates
scanning using :mod:`scanner`.
"""
import sys
import time
import signal
from datetime import datetime

import scanner
import utils
import config

# ---------------------------------------------------------------------------
# Banner & Disclaimer
# ---------------------------------------------------------------------------
BANNER = """
============================================================
                 PYTHON TCP PORT SCANNER
============================================================

Use this tool only on systems you own or
have explicit permission to test.

WARNING:
Use this port scanner only against systems you own
or systems for which you have explicit authorization.

Unauthorized scanning may violate laws, policies,
or network security rules.
------------------------------------------------------------
"""

def signal_handler(sig, frame):
    print("\n[INFO] Scan interrupted by user. Exiting gracefully.")
    utils.logger.info("User interrupted execution via KeyboardInterrupt.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def prompt_default(prompt_text: str, default: str) -> str:
    """Prompt the user showing a default value.
    Returns the entered value or the default if the input is empty.
    """
    response = input(f"{prompt_text} [{default}]: ").strip()
    return response or default

def get_target() -> str:
    while True:
        target = input("Enter target IP address or hostname: ").strip()
        if not target:
            print("[ERROR] Target cannot be empty.")
            continue
        if utils.validate_ip_or_hostname(target):
            return target
        else:
            print("[ERROR] Invalid IP address or hostname. Please try again.")

def get_port_range() -> tuple[int, int]:
    start = prompt_default("Enter start port", str(config.PORT_RANGE_MIN))
    end = prompt_default("Enter end port", str(config.DEFAULT_END_PORT))
    try:
        start_i = int(start)
        end_i = int(end)
    except ValueError:
        print("[ERROR] Ports must be numeric.")
        return get_port_range()
    if not utils.validate_port(start_i) or not utils.validate_port(end_i):
        print("[ERROR] Ports must be in the range 1‑65535.")
        return get_port_range()
    if start_i > end_i:
        print("[ERROR] Start port cannot be greater than end port.")
        return get_port_range()
    return start_i, end_i

def get_timeout() -> float:
    while True:
        val = prompt_default("Enter timeout in seconds", str(config.DEFAULT_TIMEOUT))
        try:
            t = float(val)
            if t <= 0:
                raise ValueError
            return t
        except ValueError:
            print("[ERROR] Timeout must be a positive number.")

def get_thread_count() -> int:
    while True:
        val = prompt_default("Enter number of threads", str(config.DEFAULT_THREADS))
        try:
            n = int(val)
            if n <= 0:
                raise ValueError
            return n
        except ValueError:
            print("[ERROR] Thread count must be a positive integer.")

def select_scan_mode() -> str:
    menu = """
============================================================
Select Scan Mode
============================================================

1. Quick Scan
2. Custom Port Range
3. Single Port
4. Exit

Choose an option: """
    while True:
        choice = input(menu).strip()
        if choice == "1":
            return "quick"
        elif choice == "2":
            return "custom"
        elif choice == "3":
            return "single"
        elif choice == "4":
            sys.exit(0)
        else:
            print("[ERROR] Invalid selection. Please choose 1‑4.")

def main() -> None:
    utils.setup_logger()
    print(BANNER)
    mode = select_scan_mode()
    target = get_target()

    if mode == "quick":
        ports = config.COMMON_PORTS
    elif mode == "custom":
        start, end = get_port_range()
        ports = list(range(start, end + 1))
    else:  # single
        while True:
            single = input("Enter port: ").strip()
            try:
                p = int(single)
                if utils.validate_port(p):
                    ports = [p]
                    break
                else:
                    print("[ERROR] Port must be between 1‑65535.")
            except ValueError:
                print("[ERROR] Please enter a numeric port.")

    timeout = get_timeout()
    threads = get_thread_count()

    # Resolve hostname
    try:
        resolved_ip = utils.resolve_target(target)
    except Exception as e:
        print(f"[ERROR] Unable to resolve hostname: {e}")
        utils.logger.error(f"Hostname resolution failed for {target}: {e}")
        sys.exit(1)

    print("\n============================================================")
    print(f"Target       : {target}")
    print(f"Resolved IP  : {resolved_ip}")
    if mode == "quick":
        print("Port Range   : quick scan (common ports)")
    else:
        print(f"Port Range   : {ports[0]}‑{ports[-1]}")
    print(f"Timeout      : {timeout} seconds")
    print(f"Threads      : {threads}\n")
    print("------------------------------------------------------------")
    print("Starting TCP scan...")
    print("------------------------------------------------------------\n")

    start_time = time.perf_counter()
    open_ports = []
    total = len(ports)
    scanned = 0

    def progress_callback(port, is_open, service):
        nonlocal scanned, open_ports
        scanned += 1
        if is_open:
            open_ports.append((port, service))
        utils.display_progress(scanned, total)

    try:
        scanner.scan_target(resolved_ip, ports, timeout, threads, progress_callback)
    except KeyboardInterrupt:
        print("\n[INFO] Scan cancelled by user.")
        utils.logger.info("Scan cancelled by user via KeyboardInterrupt.")
        sys.exit(0)
    except Exception as e:
        print(f"[ERROR] Unexpected error during scanning: {e}")
        utils.logger.exception("Unexpected error during scanning")
        sys.exit(1)

    duration = time.perf_counter() - start_time
    print("\n------------------------------------------------------------")
    print("SCAN SUMMARY")
    print("------------------------------------------------------------\n")
    print(f"Target          : {target}")
    print(f"Resolved IP     : {resolved_ip}")
    print(f"Ports Scanned   : {total}")
    print(f"Open Ports      : {len(open_ports)}")
    print(f"Scan Duration   : {duration:.2f} seconds\n")
    if open_ports:
        print("Open Ports:")
        for p, svc in sorted(open_ports):
            print(f"{p}/tcp    OPEN    {svc}")
    else:
        print("No open ports were found.")
    print("\nScan completed successfully.")
    print("============================================================")

    # Ask to save report
    while True:
        save = input("Do you want to save the results? (y/n): ").strip().lower()
        if save in ("y", "n"):
            break
        print("Please answer with 'y' or 'n'.")
    if save == "y":
        default_name = "results.txt"
        filename = prompt_default("Enter filename", default_name)
        report = utils.generate_report({
            "date_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "target": target,
            "resolved_ip": resolved_ip,
            "scan_type": mode,
            "port_range": f"{ports[0]}-{ports[-1]}",
            "timeout": timeout,
            "threads": threads,
            "open_ports": open_ports,
            "ports_scanned": total,
            "duration": f"{duration:.2f} seconds",
        })
        utils.save_report(report, filename)
        print(f"Report saved to output/{filename}")

if __name__ == "__main__":
    main()
