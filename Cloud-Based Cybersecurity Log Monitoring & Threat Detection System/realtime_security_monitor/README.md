# Real-Time Security Monitoring & Threat Detection (College Project)

This is a local MVP for PyCharm + Flask. It demonstrates:
- Administrator login to the monitoring dashboard
- A separate demo website login (`/demo-login`) whose successful/failed attempts are recorded
- Persistent event and alert records in SQLite
- Rule-based alert when 5 failed logins from the same source IP occur within 2 minutes
- Live dashboard refresh by polling the backend every 3 seconds
- Optional Ubuntu SSH authentication log collector (`ubuntu_collector.py`) that sends events to `/api/ingest`

## Important scope and safety notes
- This is an educational prototype, not a production SIEM.
- It detects patterns, not confirmed attackers.
- The collector reads logs on a machine you own or are authorized to monitor.
- The Flask server binds to `127.0.0.1` by default. Do not expose it directly to the public internet.
- Change default credentials and secret tokens before using this on any network.
- SQLite is used for the first local version so it runs immediately. MongoDB Atlas/AWS deployment can be added after the local workflow works.

## Run in PyCharm on Windows

1. Extract the ZIP.
2. Open the `realtime_security_monitor` folder in PyCharm.
3. Create/select a Python 3.10+ interpreter.
4. Open the PyCharm terminal and run:

   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   ```

5. Set environment variables in the terminal before starting (recommended):

   ```powershell
   $env:ADMIN_USERNAME="admin"
   $env:ADMIN_PASSWORD="UseYourOwnStrongPassword"
   $env:FLASK_SECRET_KEY="make-a-long-random-secret"
   $env:INGEST_TOKEN="make-a-long-random-ingest-token"
   python app.py
   ```

   If you do not set them, demo defaults are:
   - Dashboard admin: `admin` / `ChangeMe123!`
   - Demo website login: `demo` / `DemoPass123!`
   - Collector token: `change-this-ingest-token`

6. Open `http://127.0.0.1:5000`.
7. Sign in with the dashboard admin credentials.
8. Use **Demo Website Login** in the dashboard to test application-level login monitoring.
9. Open **Events** and **Threat Alerts** to review recorded data.

The database file `security_monitor.db` is created automatically on first start.

## How to test threat detection

1. Start the app and open `http://127.0.0.1:5000/demo-login`.
2. Enter a wrong password for the demo login five times from the same browser/IP within two minutes.
3. Return to the dashboard or Threat Alerts page.
4. The repeated-failed-login alert should appear. The pages refresh automatically every 3 seconds.

For testing the dashboard admin login rule, log out and submit an incorrect dashboard password five times. Note: if you lock yourself out of the dashboard, use the correct credentials again; this prototype does not implement account lockout.

## Optional: Ubuntu VirtualBox collector

### A. Make the Flask server reachable from the Ubuntu VM
The app currently binds to `127.0.0.1`, which is only reachable from the same machine. If Flask is running on the Windows host and Ubuntu is in VirtualBox, you must configure a private host-only network and a firewall rule, then run Flask bound to the host-only adapter address (or `0.0.0.0` only on a trusted isolated lab network). Do not expose the endpoint publicly.

For a simple lab, change this line at the bottom of `app.py`:

```python
app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
```

to bind to the Windows host-only adapter IP, for example:

```python
app.run(host="192.168.56.1", port=int(os.environ.get("PORT", "5000")), debug=False)
```

Use the actual host-only adapter IP from your machine, not necessarily the example address. Allow port 5000 only on the private lab network in Windows Firewall.

### B. Install and run collector inside Ubuntu

```bash
sudo apt update
sudo apt install python3
```

Check whether the log exists:

```bash
ls -l /var/log/auth.log
```

If it exists, run the collector with permission to read it:

```bash
sudo env INGEST_URL="http://HOST_ONLY_IP:5000/api/ingest" INGEST_TOKEN="your-same-ingest-token" python3 ubuntu_collector.py
```

Copy `ubuntu_collector.py` into Ubuntu first. Replace `HOST_ONLY_IP` with the Windows host-only adapter IP and set the same token used by Flask.

If `/var/log/auth.log` does not exist, this collector needs adaptation to read `journalctl` on that Ubuntu installation. Do not assume every Ubuntu image uses the same logging configuration.

### C. Generate authorized test events
Only test against your own VM/account. SSH failed-login events will be collected when they are written to the monitored authentication log. The collector starts at the end of the file and processes new lines only.

## Project structure

```text
realtime_security_monitor/
├── app.py
├── ubuntu_collector.py
├── requirements.txt
├── .env.example
├── README.md
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── dashboard.html
│   ├── events.html
│   ├── alerts.html
│   └── demo_login.html
└── static/
    └── style.css
```

## Known limitations and next improvements
- Local SQLite database; cloud database is a planned extension.
- Polling every 3 seconds, not push-based streaming.
- Simple threshold-based detection; false positives are possible.
- The collector currently parses common SSH messages from `/var/log/auth.log`.
- No production-grade rate limiting, audit integrity protection, multi-user roles, or TLS configuration.

## Upgraded project features

This edition adds security analytics, source-IP activity overview, transparent risk scoring, safe synthetic-event generation, an application-level simulated IP blocklist, incident records, audit history, PDF reporting, optional SMTP email notifications, and admin/analyst login roles.

### Run on Windows / PyCharm

1. Extract the ZIP and open the `realtime_security_monitor` folder in PyCharm.
2. Open the terminal in that folder.
3. Run `python -m pip install -r requirements.txt`.
4. Run `python app.py`.
5. Open `http://127.0.0.1:5000`.

Demo credentials:
- Admin: `admin` / `ChangeMe123!`
- Analyst (read-only for incident creation, simulation and blocklist changes): `analyst` / `AnalystPass123!`
- Monitored demo login: `demo` / `DemoPass123!`

### Where to test

- `/analytics` — event-type counts and daily totals.
- `/attack-map` — source-IP activity overview. It deliberately does not invent geographic locations; configure a GeoIP service before presenting actual geographic mapping.
- `/simulate` — generate synthetic failed-login events safely within this application.
- `/blocklist` — application-level blocklist simulation only; no OS firewall rules are changed.
- `/incidents` — create/update incidents and inspect the audit history.
- `/report.pdf` — download a PDF report (requires ReportLab, installed from requirements).
- `/api/risk-scores` — inspect transparent rule-based event risk scores.

### Important scope and safety notes

- Risk scores use explainable rules; this is not a trained machine-learning model.
- The attack-source page groups IP addresses but does not perform GeoIP geolocation.
- Email notifications are optional and remain disabled until SMTP environment variables are configured. Use an app password or a dedicated SMTP credential; do not commit secrets.
- IP blocking is simulated in the application only. It does not change Windows/Ubuntu firewalls or block packets.
- The safe simulation generates local database records only; it does not perform real attacks.
- This is an educational local demo. Change default credentials, `FLASK_SECRET_KEY`, and `INGEST_TOKEN` before any shared/network use. Do not expose the Flask development server to the public internet.
