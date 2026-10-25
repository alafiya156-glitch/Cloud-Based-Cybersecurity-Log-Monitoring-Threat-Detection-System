import os
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, g, make_response

APP_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.environ.get("SECURITY_DB_PATH", os.path.join(APP_DIR, "security_monitor.db"))
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
# Change this before using beyond a local demo. Set ADMIN_PASSWORD as an environment variable.
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "ChangeMe123!")
INGEST_TOKEN = os.environ.get("INGEST_TOKEN", "change-this-ingest-token")
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "dev-only-change-this-secret-key")

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        source TEXT NOT NULL,
        event_type TEXT NOT NULL,
        username TEXT,
        source_ip TEXT,
        message TEXT,
        suspicious INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        source TEXT NOT NULL,
        alert_type TEXT NOT NULL,
        source_ip TEXT,
        username TEXT,
        severity TEXT NOT NULL,
        details TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Open'
    );
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, severity TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Open', notes TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, actor TEXT NOT NULL,
        action TEXT NOT NULL, details TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS blocked_ips (
        ip TEXT PRIMARY KEY, reason TEXT NOT NULL, created_at TEXT NOT NULL, simulated INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS web_users (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL
    );
    """)
    # Create a demo monitored account once. Change the password via the environment before real use.
    row = db.execute("SELECT username FROM web_users WHERE username = ?", ("demo",)).fetchone()
    if not row:
        db.execute("INSERT INTO web_users(username, password_hash) VALUES (?, ?)",
                   ("demo", hashlib.sha256("DemoPass123!".encode()).hexdigest()))
    db.commit()
    db.close()

def record_event(source, event_type, username="", source_ip="", message="", timestamp=None):
    db = get_db()
    timestamp = timestamp or utc_now()
    db.execute("""INSERT INTO events(timestamp, source, event_type, username, source_ip, message, suspicious)
                  VALUES (?, ?, ?, ?, ?, ?, 0)""",
               (timestamp, source, event_type, username or "", source_ip or "", message or ""))
    db.commit()
    return db.execute("SELECT last_insert_rowid()").fetchone()[0]

def maybe_create_failed_login_alert(source, source_ip, username):
    if not source_ip:
        return
    db = get_db()
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat(timespec="seconds")
    count = db.execute("""SELECT COUNT(*) FROM events
                          WHERE source = ? AND event_type = 'failed_login'
                          AND source_ip = ? AND timestamp >= ?""",
                       (source, source_ip, cutoff)).fetchone()[0]
    if count >= 5:
        # Avoid creating an identical open alert repeatedly for the same source/IP.
        existing = db.execute("""SELECT id FROM alerts
                                 WHERE source = ? AND source_ip = ?
                                 AND alert_type = 'Repeated failed logins'
                                 AND status != 'Resolved' AND timestamp >= ?""",
                              (source, source_ip, cutoff)).fetchone()
        if not existing:
            db.execute("""INSERT INTO alerts(timestamp, source, alert_type, source_ip, username,
                          severity, details, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'Open')""",
                       (utc_now(), source, "Repeated failed logins", source_ip, username or "",
                        "High", f"{count} failed login attempts from {source_ip} within 2 minutes. Review this activity."))
            db.execute("""UPDATE events SET suspicious = 1 WHERE source = ? AND source_ip = ?
                          AND event_type = 'failed_login' AND timestamp >= ?""",
                       (source, source_ip, cutoff))
            db.commit()
            try:
                send_email_alert("Security threat detected", f"{count} failed login attempts from {source_ip} within two minutes.")
            except Exception as exc:
                app.logger.warning("Email notification failed: %s", exc)

def audit(action, details=""):
    db = get_db()
    db.execute("INSERT INTO audit_log(timestamp, actor, action, details) VALUES (?, ?, ?, ?)",
               (utc_now(), session.get("admin_username", "system"), action, details[:500]))
    db.commit()

def risk_score(event):
    score = 10
    kind = event["event_type"] if isinstance(event, sqlite3.Row) else event.get("event_type", "")
    if "failed_login" in kind: score += 35
    if event["suspicious"] if isinstance(event, sqlite3.Row) else event.get("suspicious", 0): score += 35
    ip = event["source_ip"] if isinstance(event, sqlite3.Row) else event.get("source_ip", "")
    if ip and ip in {r[0] for r in get_db().execute("SELECT ip FROM blocked_ips")}: score += 20
    return min(score, 100)

def send_email_alert(subject, body):
    """Optional SMTP notification; disabled unless SMTP_HOST and SMTP_TO are configured."""
    host = os.environ.get("SMTP_HOST")
    to_addr = os.environ.get("SMTP_TO")
    if not host or not to_addr: return False
    import smtplib
    from email.message import EmailMessage
    msg = EmailMessage(); msg["Subject"] = subject
    msg["From"] = os.environ.get("SMTP_FROM", to_addr); msg["To"] = to_addr; msg.set_content(body)
    with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", "587")), timeout=8) as smtp:
        smtp.starttls()
        user = os.environ.get("SMTP_USER"); password = os.environ.get("SMTP_PASSWORD")
        if user and password: smtp.login(user, password)
        smtp.send_message(msg)
    return True

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

@app.route("/")
def index():
    if session.get("admin_logged_in"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        client_ip = request.remote_addr or "unknown"
        analyst_user = os.environ.get("ANALYST_USERNAME", "analyst")
        analyst_password = os.environ.get("ANALYST_PASSWORD", "AnalystPass123!")
        is_admin = secrets.compare_digest(username, ADMIN_USERNAME) and secrets.compare_digest(password, ADMIN_PASSWORD)
        is_analyst = secrets.compare_digest(username, analyst_user) and secrets.compare_digest(password, analyst_password)
        if is_admin or is_analyst:
            session.clear()
            session["admin_logged_in"] = True
            session["admin_username"] = username
            session["role"] = "admin" if is_admin else "analyst"
            audit("login", f"{username} signed in as {session['role']}")
            record_event("website", "successful_login", username, client_ip, "Administrator signed in to monitoring dashboard")
            return redirect(url_for("dashboard"))
        record_event("website", "failed_login", username, client_ip, "Failed administrator dashboard login")
        maybe_create_failed_login_alert("website", client_ip, username)
        flash("Invalid username or password.", "error")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    username = session.get("admin_username", "admin")
    record_event("website", "logout", username, request.remote_addr or "", "Administrator signed out")
    audit("logout", f"{username} signed out")
    session.clear()
    return redirect(url_for("login"))

@app.route("/demo-login", methods=["GET", "POST"])
def demo_login():
    """A small monitored demo website login to demonstrate application-level login monitoring."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        client_ip = request.remote_addr or "unknown"
        db = get_db()
        row = db.execute("SELECT password_hash FROM web_users WHERE username = ?", (username,)).fetchone()
        # Demo account: demo / DemoPass123!
        valid = bool(row) and secrets.compare_digest(
            row["password_hash"], hashlib.sha256(password.encode()).hexdigest()
        )
        if valid:
            record_event("website_demo", "successful_login", username, client_ip, "Demo website login successful")
            return render_template("demo_login.html", result="Login successful for demo account.", success=True)
        record_event("website_demo", "failed_login", username, client_ip, "Failed login to demo website")
        maybe_create_failed_login_alert("website_demo", client_ip, username)
        return render_template("demo_login.html", result="Login failed. Event recorded.", success=False)
    return render_template("demo_login.html", result=None, success=False)

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=session.get("admin_username", "admin"))

@app.route("/events")
@login_required
def events_page():
    return render_template("events.html")

@app.route("/alerts")
@login_required
def alerts_page():
    return render_template("alerts.html")

@app.route("/api/summary")
@login_required
def api_summary():
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    failed = db.execute("SELECT COUNT(*) FROM events WHERE event_type = 'failed_login'").fetchone()[0]
    successful = db.execute("SELECT COUNT(*) FROM events WHERE event_type = 'successful_login'").fetchone()[0]
    open_alerts = db.execute("SELECT COUNT(*) FROM alerts WHERE status != 'Resolved'").fetchone()[0]
    latest = db.execute("SELECT timestamp FROM events ORDER BY id DESC LIMIT 1").fetchone()
    # Status is only healthy if the application has received an event recently.
    latest_dt = None
    if latest:
        try:
            latest_dt = datetime.fromisoformat(latest["timestamp"].replace("Z", "+00:00"))
            if latest_dt.tzinfo is None:
                latest_dt = latest_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    active = bool(latest_dt and (datetime.now(timezone.utc) - latest_dt).total_seconds() <= 120)
    recent_alert = db.execute("SELECT id, timestamp, severity, alert_type, source_ip, details FROM alerts WHERE status != 'Resolved' ORDER BY id DESC LIMIT 1").fetchone()
    return jsonify({
        "total_events": total, "failed_logins": failed, "successful_logins": successful,
        "open_alerts": open_alerts, "monitoring_active": active,
        "status": "THREAT DETECTED" if open_alerts else ("MONITORING ACTIVE" if active else "NO RECENT EVENTS"),
        "latest_alert": dict(recent_alert) if recent_alert else None,
    })

@app.route("/api/events")
@login_required
def api_events():
    limit = min(max(request.args.get("limit", default=50, type=int), 1), 200)
    rows = get_db().execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return jsonify([dict(dict(r), risk_score=risk_score(r)) for r in rows])

@app.route("/api/alerts")
@login_required
def api_alerts():
    rows = get_db().execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 200").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/alerts/<int:alert_id>/status", methods=["POST"])
@login_required
def update_alert_status(alert_id):
    status = request.json.get("status", "") if request.is_json else request.form.get("status", "")
    if status not in ("Open", "Investigating", "Resolved"):
        return jsonify({"error": "Invalid status"}), 400
    db = get_db()
    cur = db.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
    db.commit()
    if cur.rowcount == 0:
        return jsonify({"error": "Alert not found"}), 404
    return jsonify({"ok": True})

@app.route("/api/ingest", methods=["POST"])
def ingest_event():
    # Collector endpoint: protect it with a shared token and keep it off the public internet where possible.
    token = request.headers.get("X-Ingest-Token", "")
    if not secrets.compare_digest(token, INGEST_TOKEN):
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    allowed_types = {"failed_login", "successful_login", "ssh_failed_login", "ssh_successful_login", "system_event"}
    event_type = str(data.get("event_type", "system_event"))[:60]
    if event_type not in allowed_types:
        return jsonify({"error": "Unsupported event_type"}), 400
    source = str(data.get("source", "ubuntu"))[:60]
    username = str(data.get("username", ""))[:120]
    source_ip = str(data.get("source_ip", ""))[:80]
    message = str(data.get("message", ""))[:1000]
    timestamp = str(data.get("timestamp", utc_now()))[:80]
    record_event(source, event_type, username, source_ip, message, timestamp)
    if event_type in ("failed_login", "ssh_failed_login"):
        # Normalize collector SSH event type to failed_login for rule counting.
        if event_type == "ssh_failed_login":
            db = get_db()
            db.execute("UPDATE events SET event_type = 'failed_login' WHERE id = last_insert_rowid()")
            db.commit()
        maybe_create_failed_login_alert(source, source_ip, username)
    return jsonify({"ok": True}), 201

@app.route("/analytics")
@login_required
def analytics_page():
    db=get_db()
    daily=db.execute("SELECT substr(timestamp,1,10) day, COUNT(*) total FROM events GROUP BY day ORDER BY day DESC LIMIT 7").fetchall()
    types=db.execute("SELECT event_type, COUNT(*) total FROM events GROUP BY event_type ORDER BY total DESC").fetchall()
    return render_template("analytics.html", daily=list(reversed(daily)), types=types)

@app.route("/attack-map")
@login_required
def attack_map_page():
    rows=get_db().execute("SELECT source_ip, COUNT(*) attempts, MAX(timestamp) last_seen FROM events WHERE event_type LIKE '%failed_login%' AND source_ip != '' GROUP BY source_ip ORDER BY attempts DESC LIMIT 100").fetchall()
    # No external GeoIP lookup is performed: locations are intentionally not guessed.
    return render_template("attack_map.html", rows=rows)

@app.route("/incidents", methods=["GET", "POST"])
@login_required
def incidents_page():
    db=get_db()
    if request.method == "POST":
        if session.get("role") != "admin": return "Admin role required to create incidents", 403
        title=request.form.get("title", "").strip()[:160]
        if title:
            now=utc_now(); severity=request.form.get("severity", "Medium")
            if severity not in ("Low", "Medium", "High", "Critical"): severity="Medium"
            db.execute("INSERT INTO incidents(title,severity,status,notes,created_at,updated_at) VALUES(?,?, 'Open', ?, ?, ?)", (title,severity,request.form.get("notes","")[:1000],now,now)); db.commit()
            audit("incident_created", title); flash("Incident created.", "success")
        return redirect(url_for("incidents_page"))
    rows=db.execute("SELECT * FROM incidents ORDER BY id DESC").fetchall()
    logs=db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 50").fetchall()
    return render_template("incidents.html", incidents=rows, logs=logs)

@app.route("/incidents/<int:incident_id>/update", methods=["POST"])
@login_required
def update_incident(incident_id):
    if session.get("role") != "admin": return "Admin role required", 403
    status=request.form.get("status", "Open")
    if status not in ("Open", "Investigating", "Resolved"): return "Invalid status", 400
    db=get_db(); cur=db.execute("UPDATE incidents SET status=?, updated_at=? WHERE id=?", (status,utc_now(),incident_id)); db.commit()
    if cur.rowcount: audit("incident_updated", f"Incident #{incident_id} status -> {status}")
    return redirect(url_for("incidents_page"))

@app.route("/simulate", methods=["GET", "POST"])
@login_required
def simulate_page():
    if request.method == "POST":
        if session.get("role") != "admin": return "Admin role required", 403
        count=min(max(request.form.get("count", 5, type=int),1),20)
        ip=request.form.get("source_ip", "198.51.100.23").strip()[:80] or "198.51.100.23"
        for i in range(count):
            record_event("safe_simulation", "failed_login", "test_user", ip, "Synthetic test event; not a real attack")
        maybe_create_failed_login_alert("safe_simulation", ip, "test_user")
        audit("simulation", f"Generated {count} synthetic failed-login events for {ip}")
        flash(f"Generated {count} synthetic events. No attack was performed.", "success")
        return redirect(url_for("simulate_page"))
    return render_template("simulate.html")

@app.route("/blocklist", methods=["GET", "POST"])
@login_required
def blocklist_page():
    db=get_db()
    if request.method == "POST":
        if session.get("role") != "admin": return "Admin role required", 403
        ip=request.form.get("ip", "").strip()[:80]
        reason=request.form.get("reason", "Manual simulation")[:300]
        if ip:
            db.execute("INSERT OR REPLACE INTO blocked_ips(ip,reason,created_at,simulated) VALUES(?,?,?,1)",(ip,reason,utc_now())); db.commit(); audit("ip_block_simulated", ip)
            flash(f"{ip} added to the application-level block simulation. Your OS firewall was not changed.", "success")
        return redirect(url_for("blocklist_page"))
    rows=db.execute("SELECT * FROM blocked_ips ORDER BY created_at DESC").fetchall()
    return render_template("blocklist.html", rows=rows)

@app.route("/blocklist/<path:ip>/remove", methods=["POST"])
@login_required
def unblock_ip(ip):
    if session.get("role") != "admin": return "Admin role required", 403
    get_db().execute("DELETE FROM blocked_ips WHERE ip=?",(ip,)); get_db().commit(); audit("ip_unblocked_simulated",ip)
    return redirect(url_for("blocklist_page"))

@app.route("/report.pdf")
@login_required
def report_pdf():
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        import io
        db=get_db(); events=db.execute("SELECT timestamp,source,event_type,username,source_ip,message,suspicious FROM events ORDER BY id DESC LIMIT 100").fetchall()
        alerts=db.execute("SELECT timestamp,severity,alert_type,source_ip,status,details FROM alerts ORDER BY id DESC LIMIT 50").fetchall()
        buf=io.BytesIO(); pdf=canvas.Canvas(buf,pagesize=letter); width,height=letter; y=height-48
        pdf.setTitle("Security Incident Report")
        pdf.setFont("Helvetica-Bold",16); pdf.drawString(40,y,"Security Monitoring - Incident Report"); y-=25
        pdf.setFont("Helvetica",9); pdf.drawString(40,y,"Generated: "+utc_now()); y-=24
        pdf.setFont("Helvetica-Bold",12); pdf.drawString(40,y,"Recent alerts"); y-=16; pdf.setFont("Helvetica",8)
        for a in alerts:
            line=f"{a['timestamp']} | {a['severity']} | {a['alert_type']} | IP {a['source_ip']} | {a['status']}"
            pdf.drawString(40,y,line[:115]); y-=12
            if y<65: pdf.showPage(); y=height-45; pdf.setFont("Helvetica",8)
        y-=10; pdf.setFont("Helvetica-Bold",12); pdf.drawString(40,y,"Recent events"); y-=16; pdf.setFont("Helvetica",7)
        for e in events:
            line=f"{e['timestamp']} | {e['event_type']} | {e['source']} | {e['username']} | {e['source_ip']} | risk {risk_score(e)}"
            pdf.drawString(40,y,line[:150]); y-=10
            if y<45: pdf.showPage(); y=height-45; pdf.setFont("Helvetica",7)
        pdf.save(); response=make_response(buf.getvalue()); response.headers["Content-Type"]="application/pdf"; response.headers["Content-Disposition"]="attachment; filename=security_incident_report.pdf"; audit("report_downloaded","PDF report generated"); return response
    except ImportError:
        return "PDF dependency missing. Run: python -m pip install -r requirements.txt", 500

@app.route("/api/risk-scores")
@login_required
def api_risk_scores():
    rows=get_db().execute("SELECT * FROM events ORDER BY id DESC LIMIT 100").fetchall()
    return jsonify([dict(dict(r), risk_score=risk_score(r)) for r in rows])

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    init_db()
    print("Security Monitor starting on http://127.0.0.1:5000")
    print(f"Dashboard admin username: {ADMIN_USERNAME}")
    print("Change the default credentials and secret values before any network deployment.")
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
