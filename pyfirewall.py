#!/usr/bin/env python3
"""
pyfirewall.py
Firewall local simple :
- Surveille les connexions sortantes (psutil)
- Bloque les IP au niveau OS (iptables sous Linux, netsh sous Windows)
- Tue les processus suspects
- Log normal et alertes CRITIQUES en rouge

Utilisation :
    python pyfirewall.py   (Windows admin / Linux root)
"""

import os
import sys
import time
import json
import platform
import subprocess
import socket
import psutil
from datetime import datetime

CONFIG_FILE = "fw_rules.json"
LOGFILE = "pyfirewall.log"
CHECK_INTERVAL = 2  # secondes

# Codes couleurs ANSI
RED = "\033[91m"
RESET = "\033[0m"


def log(msg, critical=False):
    ts = datetime.utcnow().isoformat() + "Z"
    if critical:
        line_console = f"{RED}[{ts}] CRITICAL: {msg}{RESET}"
        line_file = f"[{ts}] CRITICAL: {msg}"
    else:
        line_console = f"[{ts}] {msg}"
        line_file = line_console

    print(line_console)
    with open(LOGFILE, "a", encoding="utf-8") as f:
        f.write(line_file + "\n")


def load_config():
    if not os.path.exists(CONFIG_FILE):
        log(f"Config file {CONFIG_FILE} not found. Creating default.")
        default = {
            "blacklist_ips": [],
            "blacklist_domains": [],
            "blacklist_ports": [],
            "auto_block_on_connect": True,
            "block_processes_by_name": []
        }
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(default, f, indent=2)
        return default
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def is_windows():
    return platform.system().lower().startswith("win")


def block_ip_os(remote_ip):
    """Ajoute une règle OS pour bloquer une IP."""
    if is_windows():
        rule_name = f"PyFirewallBlock_{remote_ip}"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=out",
            "action=block",
            f"remoteip={remote_ip}"
        ]
    else:
        cmd = ["iptables", "-I", "OUTPUT", "-d", remote_ip, "-j", "DROP"]
    try:
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log(f"OS-level block applied for {remote_ip}", critical=True)
        return True
    except Exception as e:
        log(f"Failed to apply OS block for {remote_ip}: {e}", critical=True)
        return False


def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def monitor_loop(cfg):
    seen_connections = set()
    blocked_ips = set()

    for d in cfg.get("blacklist_domains", []):
        ip = resolve_domain(d)
        if ip:
            cfg.setdefault("blacklist_ips", []).append(ip)
            log(f"Resolved domain {d} -> {ip} and added to blacklist_ips")

    while True:
        try:
            connections = psutil.net_connections(kind='inet')
        except Exception as e:
            log(f"Error getting connections: {e}", critical=True)
            connections = []

        for c in connections:
            raddr = c.raddr
            if not raddr:
                continue
            remote_ip = raddr.ip if hasattr(raddr, "ip") else raddr[0]
            remote_port = raddr.port if hasattr(raddr, "port") else raddr[1]

            try:
                remote_ip = str(remote_ip)
            except Exception:
                continue

            key = (c.pid, remote_ip, remote_port)
            if key in seen_connections:
                continue
            seen_connections.add(key)

            try:
                proc = psutil.Process(c.pid) if c.pid else None
                proc_name = proc.name() if proc else "unknown"
                proc_info = f"pid={c.pid}, name={proc_name}"
            except Exception:
                proc_info = f"pid={c.pid}, name=unknown"

            log(f"New connection -> {remote_ip}:{remote_port} ({proc_info})")

            # Vérifie port interdit
            if remote_port in cfg.get("blacklist_ports", []):
                log(f"Remote port {remote_port} is blacklisted.", critical=True)
                if cfg.get("auto_block_on_connect", True):
                    block_ip_os(remote_ip)

            # Vérifie IP interdite
            if remote_ip in cfg.get("blacklist_ips", []):
                log(f"Remote IP {remote_ip} is blacklisted.", critical=True)
                if cfg.get("auto_block_on_connect", True):
                    block_ip_os(remote_ip)

            # Vérifie processus interdit
            proc_name_lower = ""
            try:
                proc_name_lower = proc.name().lower() if proc else ""
            except Exception:
                pass
            for bad_name in cfg.get("block_processes_by_name", []):
                if bad_name.lower() in proc_name_lower:
                    log(f"Process {proc_name_lower} is blacklisted. Killing...", critical=True)
                    try:
                        proc.terminate()
                        proc.wait(timeout=3)
                        log(f"Terminated process {proc_name_lower} (pid {c.pid})", critical=True)
                    except Exception as e:
                        log(f"Failed to terminate {c.pid}: {e}", critical=True)

        if len(seen_connections) > 10000:
            seen_connections.clear()

        time.sleep(CHECK_INTERVAL)


def main():
    if not (is_windows() or platform.system().lower() == "linux"):
        log("Unsupported OS. Only Windows and Linux supported.", critical=True)
        return

    if not is_windows():
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            log("Not root. Run with sudo/root for full firewall features.", critical=True)
    else:
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False
        if not is_admin:
            log("Not Administrator. Run as Admin for firewall rules.", critical=True)

    cfg = load_config()
    log("Starting pyfirewall (monitor + OS blocks).")
    try:
        monitor_loop(cfg)
    except KeyboardInterrupt:
        log("Interrupted by user. Exiting.")
        sys.exit(0)
    except Exception as e:
        log(f"Fatal error: {e}", critical=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
