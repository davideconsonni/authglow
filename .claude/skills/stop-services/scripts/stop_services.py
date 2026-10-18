#!/usr/bin/env python3
"""Stop services running on specified ports. Cross-platform: Linux, macOS, Windows."""

import sys
import subprocess
import json
import argparse
import re
from pathlib import Path


def find_pids_on_ports(ports):
    """Find PIDs listening on given ports."""
    pids = {}
    
    if sys.platform == "win32":
        # Windows: use netstat
        result = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            if "LISTENING" in line:
                parts = line.split()
                if len(parts) >= 5:
                    local_addr = parts[1]
                    pid = parts[-1]
                    for port in ports:
                        if local_addr.endswith(f":{port}"):
                            pids.setdefault(port, []).append(int(pid))
    else:
        # Linux/macOS: use ss (preferred) or lsof
        # Try ss first (standard on modern Linux)
        result = subprocess.run(
            ["ss", "-ltnp"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "LISTEN" in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        local_addr = parts[3]
                        pid_part = parts[-1]
                        for port in ports:
                            if local_addr.endswith(f":{port}"):
                                m = re.search(r"pid=(\d+)", pid_part)
                                if m:
                                    pids.setdefault(port, []).append(int(m.group(1)))
        else:
            # Fallback to lsof
            try:
                for port in ports:
                    result = subprocess.run(
                        ["lsof", "-ti", f"tcp:{port}"],
                        capture_output=True, text=True
                    )
                    for line in result.stdout.strip().splitlines():
                        if line:
                            pids.setdefault(port, []).append(int(line))
            except FileNotFoundError:
                pass
    
    return pids


def kill_pids(pids, force=False):
    """Kill the given PIDs."""
    killed = []
    for port, pid_list in pids.items():
        for pid in pid_list:
            try:
                if sys.platform == "win32":
                    cmd = ["taskkill", "/PID", str(pid)]
                    if force:
                        cmd.append("/F")
                    subprocess.run(cmd, capture_output=True)
                else:
                    cmd = ["kill"]
                    if force:
                        cmd.append("-9")
                    cmd.append(str(pid))
                    subprocess.run(cmd, capture_output=True)
                killed.append((port, pid))
            except Exception as e:
                print(f"Failed to kill PID {pid} on port {port}: {e}")
    return killed


def main():
    parser = argparse.ArgumentParser(description="Stop services on specified ports")
    parser.add_argument("ports", nargs="*", type=int, help="Ports to stop services on")
    parser.add_argument("--config", "-c", help="JSON config file with ports array")
    parser.add_argument("--force", "-f", action="store_true", help="Force kill (SIGKILL / taskkill /F)")
    args = parser.parse_args()
    
    ports = args.ports
    if args.config:
        with open(args.config) as f:
            config = json.load(f)
            ports = config.get("ports", [])
    
    if not ports:
        print("No ports specified")
        return 1
    
    print(f"Scanning ports: {ports}")
    pids = find_pids_on_ports(ports)
    
    if not pids:
        print("No services found on specified ports")
        return 0
    
    for port, pid_list in pids.items():
        for pid in pid_list:
            print(f"Found PID {pid} on port {port}")
    
    killed = kill_pids(pids, force=args.force)
    
    if killed:
        for port, pid in killed:
            print(f"Stopped PID {pid} on port {port}")
    else:
        print("No processes were stopped")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())