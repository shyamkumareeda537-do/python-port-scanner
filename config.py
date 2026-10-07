# config.py
"""Configuration constants for the Python TCP Port Scanner.
These defaults can be overridden by user input at runtime.
"""
# Default socket timeout (seconds)
DEFAULT_TIMEOUT = 1.0

# Default number of threads for the thread pool
DEFAULT_THREADS = 50

# Common ports used in the Quick Scan mode
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 3306, 3389, 8080, 8443,
]

# Port range limits
PORT_RANGE_MIN = 1
PORT_RANGE_MAX = 65535

# Default end port when prompting for a custom range (used only for defaults)
DEFAULT_END_PORT = 1024
