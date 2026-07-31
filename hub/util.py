"""Shared subprocess / network helpers."""
from __future__ import annotations

import socket
import subprocess


def sh(cmd, timeout=10, shell=False):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=shell)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -1, "", "not found"


def port_open(port, host="localhost", timeout=0.6):
    if not port:
        return None
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False
