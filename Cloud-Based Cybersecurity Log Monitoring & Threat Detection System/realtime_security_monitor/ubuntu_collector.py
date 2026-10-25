"""
Ubuntu authentication-log collector.
Run this INSIDE your Ubuntu VM, not on Windows/PyCharm.
It tails /var/log/auth.log and sends parsed SSH login events to the Flask app.
For a first local lab, the Flask app must be reachable from Ubuntu and the ingest token must match.
"""
import os
import re
import time
import json
import urllib.request
import urllib.error
from datetime import datetime, timezone

LOG_PATH = os.environ.get("AUTH_LOG_PATH", "/var/log/auth.log")
INGEST_URL = os.environ.get("INGEST_URL", "http://127.0.0.1:5000/api/ingest")
INGEST_TOKEN = os.environ.get("INGEST_TOKEN", "change-this-ingest-token")
POLL_SECONDS = float(os.environ.get("POLL_SECONDS", "1.0"))

IP_RE = re.compile(r"\bfrom\s+((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)")
USER_RE = re.compile(r"(?:for (?:invalid user )?)([A-Za-z0-9_.@-]+)")
FAIL_MARKERS = ("Failed password", "Invalid user", "authentication failure", "Failed publickey")
SUCCESS_MARKERS = ("Accepted password", "Accepted publickey", "session opened for user")

def parse_line(line):
    if "sshd" not in line:
        return None
    event_type = None
    if any(marker in line for marker in FAIL_MARKERS):
        event_type = "ssh_failed_login"
    elif any(marker in line for marker in SUCCESS_MARKERS):
        event_type = "ssh_successful_login"
    if not event_type:
        return None
    ip_match = IP_RE.search(line)
    user_match = USER_RE.search(line)
    return {
        "source": "ubuntu",
        "event_type": event_type,
        "username": user_match.group(1) if user_match else "",
        "source_ip": ip_match.group(1) if ip_match else "",
        "message": line.strip()[:1000],
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

def send_event(event):
    body = json.dumps(event).encode("utf-8")
    req = urllib.request.Request(
        INGEST_URL, data=body, method="POST",
        headers={"Content-Type": "application/json", "X-Ingest-Token": INGEST_TOKEN}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status in (200, 201)
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"[WARN] Could not send event: {exc}")
        return False

def main():
    if not os.path.exists(LOG_PATH):
        print(f"Log file not found: {LOG_PATH}")
        print("Check whether your Ubuntu uses /var/log/auth.log or systemd journal.")
        raise SystemExit(1)
    print(f"Monitoring {LOG_PATH}")
    print(f"Sending events to {INGEST_URL}")
    print("Press Ctrl+C to stop.")
    with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as log:
        log.seek(0, os.SEEK_END)  # Only process new lines after startup.
        while True:
            line = log.readline()
            if not line:
                time.sleep(POLL_SECONDS)
                continue
            event = parse_line(line)
            if event:
                if send_event(event):
                    print(f"[SENT] {event['event_type']} user={event['username']} ip={event['source_ip']}")
                else:
                    print("[WARN] Event was not sent; check URL/token/network.")
if __name__ == "__main__":
    main()
