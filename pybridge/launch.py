#!/usr/bin/env python3
"""
Launch helper for the RedShark Python bridge server.
Finds an available port, starts the Flask server, and prints the
chosen port to stdout so the Go parent can discover it.
"""

import os
import socket
import subprocess
import sys

VENV_PYTHON = os.path.join(os.path.dirname(__file__), ".venv", "bin", "python")
SERVER_SCRIPT = os.path.join(os.path.dirname(__file__), "server.py")


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    port = find_free_port()
    env = os.environ.copy()
    env["REDSHARK_PYBRIDGE_PORT"] = str(port)
    env["REDSHARK_PYBRIDGE_HOST"] = "127.0.0.1"

    # Print the port so the Go parent can read it
    print(f"REDSHARK_PYBRIDGE_PORT={port}", flush=True)

    python = VENV_PYTHON if os.path.exists(VENV_PYTHON) else sys.executable
    proc = subprocess.Popen(
        [python, SERVER_SCRIPT],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # Block until the process exits
    proc.wait()


if __name__ == "__main__":
    main()
