#!/usr/bin/env python3
"""
diagnostics.py
Linux System Diagnostics Toolkit
- Run as root (or with sudo) for full data.
- Produces a text report (default: report.txt) and prints a colorized summary to terminal.
"""

import os
import sys
import shutil
import subprocess
import argparse
from datetime import datetime

# ---- Config ----
KEYWORDS = ["error", "fail", "failed", "panic", "traceback", "segfault", "timeout", "corrupt", "critical"]
LOG_FILES = ["/var/log/messages", "/var/log/syslog"]  # CentOS uses /var/log/messages; syslog if exists
REPORT_DEFAULT = "report.txt"

# ---- Helpers ----
def run(cmd):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True, timeout=20)
    except subprocess.CalledProcessError as e:
        out = f"[ERROR] Command failed: {e}\nOutput:\n{e.output}"
    except Exception as e:
        out = f"[ERROR] {e}"
    return out

def short(title):
    return f"\n=== {title} ===\n"

def find_first_existing(paths):
    for p in paths:
        if os.path.exists(p):
            return p
    return None

def keyword_scan(text, keywords=KEYWORDS):
    found = {}
    lowered = text.lower()
    for kw in keywords:
        count = lowered.count(kw.lower())
        if count:
            found[kw] = count
    return found

# ---- Sections ----
def system_overview():
    parts = []
    parts.append(short("System Overview"))
    parts.append(f"Generated: {datetime.utcnow().isoformat()} UTC\n")
    parts.append(run("uname -a"))
    parts.append(run("cat /etc/os-release"))
    parts.append(run("hostnamectl"))
    return "\n".join(parts)

def resource_usage():
    parts = []
    parts.append(short("Resource Usage (snapshot)"))
    parts.append("uptime & load:\n" + run("uptime"))
    parts.append("\nmemory:\n" + run("free -h"))
    parts.append("\ndisk usage:\n" + run("df -hT"))
    parts.append("\nblock devices:\n" + run("lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINT,ROTA"))
    parts.append("\nIO stats (iostat - requires sysstat):\n" + run("iostat -xz 1 1"))
    parts.append("\nTop CPU processes (ps):\n" + run("ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 15"))
    return "\n".join(parts)

def network_info():
    parts = []
    parts.append(short("Network Info"))
    parts.append("Interfaces:\n" + run("ip -br a"))
    parts.append("\nRouting table:\n" + run("ip route"))
    parts.append("\nNetwork connections (ss -tunlp):\n" + run("ss -tunlp"))
    parts.append("\nDNS (resolv.conf):\n" + run("cat /etc/resolv.conf"))
    parts.append("\nFirewall status (firewall-cmd --state or iptables -L):\n" + run("which firewall-cmd >/dev/null && firewall-cmd --state || echo 'firewalld not installed'") )
    parts.append(run("sudo iptables -L -n || true"))
    parts.append("\nNetworkManager status:\n" + run("systemctl is-active NetworkManager || true"))
    parts.append("\nActive connections (nmcli):\n" + run("nmcli -t -f NAME,DEVICE,STATE connection show --active || true"))
    return "\n".join(parts)

def services_and_journal():
    parts = []
    parts.append(short("Systemd Services (failed/disabled)"))
    parts.append(run("systemctl --failed --no-pager --no-legend | sed -n '1,50p' || true"))
    parts.append("\nTop services by memory/cpu:\n" + run("ps -eo pid,unit,%mem,%cpu,cmd --sort=-%mem | head -n 20"))
    parts.append("\nRecent journal (last 500 lines):\n" + run("journalctl -n 500 --no-pager"))
    return "\n".join(parts)

def package_and_updates():
    parts = []
    parts.append(short("Package & Updates"))
    parts.append("rpm kernel packages:\n" + run("rpm -qa | grep kernel | sort -r | head -n 10"))
    parts.append("\nlast yum updates (if yum history exists):\n" + run("yum history list | head -n 20"))
    parts.append("\nInstalled packages count:\n" + run("rpm -qa | wc -l"))
    return "\n".join(parts)

def logs_and_keyword_scan():
    parts = []
    parts.append(short("Log Keyword Scan"))
    logpath = find_first_existing(LOG_FILES) or "/var/log/messages"
    parts.append(f"Scanning log: {logpath}\n")
    try:
        with open(logpath, "r", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        content = f"[ERROR] Could not read {logpath}: {e}"
    parts.append("Last 500 lines:\n")
    parts.append("\n".join(content.splitlines()[-500:]))
    parts.append("\n\nKeyword summary:\n")
    found = keyword_scan(content)
    if found:
        for k,v in found.items():
            parts.append(f"{k}: {v}")
    else:
        parts.append("No keywords found in log (by configured keywords).")
    return "\n".join(parts)

def open_files_and_ports():
    parts = []
    parts.append(short("Open Files & Listening Ports"))
    parts.append("Open files (lsof) top 30:\n" + run("lsof -nP | head -n 40"))
    parts.append("\nListening ports:\n" + run("ss -ltnp || netstat -ltnp || true"))
    return "\n".join(parts)

def generate_report(outpath):
    with open(outpath, "w") as r:
        r.write(system_overview())
        r.write(resource_usage())
        r.write(network_info())
        r.write(services_and_journal())
        r.write(package_and_updates())
        r.write(logs_and_keyword_scan())
        r.write(open_files_and_ports())
    return True

def terminal_summary(outpath):
    print("\n==== Quick Summary ====\n")
    print("Report written to:", outpath)
    # show uptime, top cpu, mem, disk, any failed services
    print("\nUptime & load:")
    print(run("uptime"))
    print("\nTop memory processes:")
    print(run("ps -eo pid,cmd,%mem --sort=-%mem | head -n 5"))
    print("\nDisk usage (top mounts):")
    print(run("df -hT | sort -k6 -r | head -n 8"))
    print("\nFailed services (if any):")
    svc = run("systemctl --failed --no-legend --no-pager || true")
    print(svc or "None")
    # quick log keyword hits:
    logpath = find_first_existing(LOG_FILES) or "/var/log/messages"
    try:
        with open(logpath, "r", errors="ignore") as f:
            content = f.read()
        found = keyword_scan(content)
        if found:
            print("\nLog keyword hits:", found)
        else:
            print("\nNo keyword hits found in logs.")
    except:
        print("\nCannot read log for quick scan.")

# ---- Main ----
def main():
    parser = argparse.ArgumentParser(description="Linux System Diagnostics Toolkit")
    parser.add_argument("--output", "-o", default=REPORT_DEFAULT, help="Report output file")
    args = parser.parse_args()
    out = args.output

    # check root for some commands
    if os.geteuid() != 0:
        print("[WARN] Not running as root. Some sections may show limited info. Run with sudo for full data.\n")

    print("Collecting system diagnostics... this may take ~20s - 2m depending on system.")
    try:
        generate_report(out)
        print("Report generation complete.")
        terminal_summary(out)
    except Exception as e:
        print("Fatal error during report generation:", e)
        sys.exit(2)

if __name__ == "__main__":
    main()

