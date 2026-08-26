# Stop Services Skill

Stop services running on specified ports. Works on Linux, macOS, and Windows.

## Usage

```bash
# Stop services on ports 8001 and 5173
/stop-services 8001 5173

# Or with a config file
/stop-services --config ports.json
```

## Implementation

```python
import sys
import subprocess
import json
import argparse
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
        # Linux/macOS: use lsof or ss
        try:
            result = subprocess.run(
                ["lsof", "-ti"] + [f"tcp:{p}" for p in ports],
                capture_output=True, text=True
            )
            for line in result.stdout.strip().splitlines():
                if line:
                    pid = int(line)
                    # Need to map PID to port - lsof -ti doesn't show port
                    # Fallback: use ss
                    pass
        except FileNotFoundError:
            pass
        
        # Use ss as primary on Linux
        result = subprocess.run(
            ["ss", "-ltnp"],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            if "LISTEN" in line:
                parts = line.split()
                if len(parts) >= 5:
                    local_addr = parts[3]
                    pid_part = parts[-1]
                    for port in ports:
                        if local_addr.endswith(f":{port}"):
                            # Extract PID from pid=1234,comm=name
                            import re
                            m = re.search(r"pid=(\d+)", pid_part)
                            if m:
                                pids.setdefault(port, []).append(int(m.group(1)))
    
    return pids

def kill_pids(pids, force=False):
    """Kill the given PIDs."""
    killed = []
    for port, pid_list in pids.items():
        for pid in pid_list:
            try:
                if sys.platform == "win32":
                    subprocess.run(["taskkill", "/PID", str(pid)] + (["/F"] if force else []), 
                                 capture_output=True)
                else:
                    subprocess.run(["kill"] + (["-9"] if force else []) + [str(pid)], 
                                 capture_output=True)
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
```

## Installation

Place this skill in `.agents/skills/stop-services/` and it will be available as `/stop-services`.