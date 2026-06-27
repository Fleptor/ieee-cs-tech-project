#roles/detection/files/dos_monitor.py

#!/usr/bin/env python3
"""
SOHO Router DoS/DDoS Detection Daemon
Monitors traffic per IP and triggers blocks via nftables
"""

import subprocess
import time
import logging
import smtplib
import os
from collections import defaultdict
from email.mime.text import MIMEText
from datetime import datetime

# --- Config (overridden by environment variables set by Ansible) ---
INTERFACE        = os.getenv("MONITOR_IFACE", "eth0")
ICMP_THRESHOLD   = int(os.getenv("ICMP_THRESHOLD", "50"))
SYN_THRESHOLD    = int(os.getenv("SYN_THRESHOLD", "100"))
UDP_THRESHOLD    = int(os.getenv("UDP_THRESHOLD", "200"))
CONN_THRESHOLD   = int(os.getenv("CONN_THRESHOLD", "300"))
BAN_DURATION     = int(os.getenv("BAN_DURATION", "3600"))
CHECK_INTERVAL   = int(os.getenv("CHECK_INTERVAL", "5"))   # seconds
ALERT_EMAIL      = os.getenv("ALERT_EMAIL", "admin@example.com")
SMTP_HOST        = os.getenv("SMTP_HOST", "localhost")
WHITELIST        = os.getenv("WHITELIST", "127.0.0.1,192.168.1.1").split(",")
LOG_FILE         = "/var/log/dos_monitor.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# Counters per IP per interval
counters = defaultdict(lambda: {"icmp": 0, "syn": 0, "udp": 0, "conn": 0})
blocked  = set()


def get_conntrack_counts():
    """Count active connections per source IP using conntrack."""
    counts = defaultdict(int)
    try:
        out = subprocess.check_output(
            ["conntrack", "-L"], stderr=subprocess.DEVNULL, text=True
        )
        for line in out.splitlines():
            if "src=" in line:
                src = line.split("src=")[1].split()[0]
                counts[src] += 1
    except Exception as e:
        logging.warning(f"conntrack error: {e}")
    return counts


def parse_tcpdump(duration=5):
    """Capture packets briefly and count per IP per protocol."""
    counts = defaultdict(lambda: {"icmp": 0, "syn": 0, "udp": 0})
    try:
        cmd = [
            "tcpdump", "-i", INTERFACE, "-nn", "-c", "5000",
            "--immediate-mode", "-q",
            f"icmp or (tcp[tcpflags] & tcp-syn != 0) or udp"
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True)
        time.sleep(duration)
        proc.terminate()
        for line in proc.stdout:
            parts = line.strip().split()
            if len(parts) < 3:
                continue
            src_ip = parts[2].rsplit(".", 1)[0]  # strip port
            if "ICMP" in line or "icmp" in line:
                counts[src_ip]["icmp"] += 1
            elif "Flags [S]" in line or "S " in line:
                counts[src_ip]["syn"] += 1
            elif "UDP" in line or "udp" in line:
                counts[src_ip]["udp"] += 1
    except Exception as e:
        logging.warning(f"tcpdump error: {e}")
    return counts


def block_ip(ip, reason):
    """Add IP to nftables blocked_ips set."""
    if ip in blocked or ip in WHITELIST:
        return
    try:
        subprocess.run([
            "nft", "add", "element", "inet", "filter",
            "blocked_ips", f"{{ {ip} timeout {BAN_DURATION}s }}"
        ], check=True)
        blocked.add(ip)
        msg = f"BLOCKED {ip} | Reason: {reason} | Duration: {BAN_DURATION}s"
        logging.warning(msg)
        send_alert(ip, reason)
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to block {ip}: {e}")


def unblock_ip(ip):
    """Remove IP from blocked set (nftables handles timeout automatically)."""
    blocked.discard(ip)


def send_alert(ip, reason):
    """Send email alert via msmtp."""
    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        body = f"""
SOHO Router DoS/DDoS Alert
===========================
Time     : {now}
Blocked IP: {ip}
Reason   : {reason}
Duration : {BAN_DURATION} seconds
Interface: {INTERFACE}

This IP has been automatically blocked by the DoS monitor.
        """
        msg = MIMEText(body)
        msg["Subject"] = f"[ROUTER ALERT] DoS Attack Detected - {ip}"
        msg["From"]    = ALERT_EMAIL
        msg["To"]      = ALERT_EMAIL

        with smtplib.SMTP(SMTP_HOST, 25) as server:
            server.sendmail(ALERT_EMAIL, [ALERT_EMAIL], msg.as_string())
        logging.info(f"Alert sent for {ip}")
    except Exception as e:
        logging.warning(f"Email alert failed: {e}")


def check_thresholds(pkt_counts, conn_counts):
    """Compare counts against thresholds and block if exceeded."""
    for ip, counts in pkt_counts.items():
        if ip in WHITELIST:
            continue

        reasons = []
        if counts["icmp"] > ICMP_THRESHOLD:
            reasons.append(f"ICMP flood ({counts['icmp']}/interval > {ICMP_THRESHOLD})")
        if counts["syn"] > SYN_THRESHOLD:
            reasons.append(f"SYN flood ({counts['syn']}/interval > {SYN_THRESHOLD})")
        if counts["udp"] > UDP_THRESHOLD:
            reasons.append(f"UDP flood ({counts['udp']}/interval > {UDP_THRESHOLD})")

        if reasons:
            block_ip(ip, " | ".join(reasons))

    for ip, count in conn_counts.items():
        if ip in WHITELIST:
            continue
        if count > CONN_THRESHOLD:
            block_ip(ip, f"Connection flood ({count} conns > {CONN_THRESHOLD})")


def main():
    logging.info("DoS Monitor started")
    logging.info(f"Interface: {INTERFACE} | Thresholds: ICMP={ICMP_THRESHOLD} "
                 f"SYN={SYN_THRESHOLD} UDP={UDP_THRESHOLD} CONN={CONN_THRESHOLD}")

    while True:
        try:
            pkt_counts  = parse_tcpdump(duration=CHECK_INTERVAL)
            conn_counts = get_conntrack_counts()
            check_thresholds(pkt_counts, conn_counts)
        except Exception as e:
            logging.error(f"Main loop error: {e}")
        time.sleep(1)


if __name__ == "__main__":
    main()