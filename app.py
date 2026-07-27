from __future__ import annotations

import json
import random
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

import os

from flask import Flask, jsonify, render_template, request, Response, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = os.environ.get("CYBERSHIELD_SECRET_KEY", "cybershield-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///cybershield.db")
db = SQLAlchemy(app)


class URLScan(db.Model):
    __tablename__ = "url_scans"
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    checks = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "url": self.url,
            "status": self.status,
            "score": self.score,
            "checks": json.loads(self.checks),
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        }


class SecurityLog(db.Model):
    __tablename__ = "security_logs"
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    event_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "event_type": self.event_type,
            "severity": self.severity,
            "status": self.status,
        }


with app.app_context():
    db.create_all()



def login_required(view_func):
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login_page"))
        return view_func(*args, **kwargs)

    wrapped.__name__ = view_func.__name__
    return wrapped


def normalize_url(raw_url: str) -> str:
    url = raw_url.strip()
    if not url:
        raise ValueError("Please enter a URL to scan.")
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        return url
    if " " in url:
        raise ValueError("URL contains invalid characters.")
    if parsed.scheme:
        return f"https://{url.split('://', 1)[1]}"
    return f"https://{url}"


def generate_scan_result(target_url: str) -> dict[str, Any]:
    statuses = ["Safe", "Suspicious", "Malicious"]
    status = random.choice(statuses)

    if status == "Safe":
        score = random.randint(0, 30)
    elif status == "Suspicious":
        score = random.randint(31, 70)
    else:
        score = random.randint(71, 100)

    checks = [
        ("SSL Certificate", score >= 10),
        ("Domain Reputation", score >= 20),
        ("Malware Check", status != "Safe"),
        ("Phishing Check", status != "Safe"),
        ("Firewall Check", status != "Malicious"),
    ]

    return {
        "url": target_url,
        "status": status,
        "score": score,
        "checks": [
            {"name": name, "passed": passed}
            for name, passed in checks
        ],
    }


def get_dashboard_stats():
    total_scans = URLScan.query.count()
    malicious_count = URLScan.query.filter_by(status="Malicious").count()
    suspicious_count = URLScan.query.filter_by(status="Suspicious").count()
    critical_logs = SecurityLog.query.filter_by(severity="Critical").count()

    total_threats = malicious_count + suspicious_count
    active_threats = critical_logs

    return {
        "threats": total_threats,
        "active": active_threats,
        "status": "Secure" if active_threats == 0 else "Warning",
        "last_scan": (
            URLScan.query.order_by(URLScan.timestamp.desc()).first().timestamp.strftime("%b %d, %Y %H:%M:%S")
            if total_scans > 0
            else datetime.now().strftime("%b %d, %Y %H:%M:%S")
        ),
    }



@app.get("/")
def landing_page() -> str:
    return render_template("index.html")


@app.get("/login")
def login_page():
    return render_template("login.html", error=None)


@app.post("/login")
def handle_login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    if username == "admin" and password == "cybershield2025":
        session["logged_in"] = True
        session["username"] = username
        return redirect(url_for("dashboard"))

    return render_template("login.html", error="Invalid username or password."), 401


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing_page"))


@app.get("/dashboard")
@login_required
def dashboard() -> str:
    metrics = get_dashboard_stats()
    logs = [log.to_dict() for log in SecurityLog.query.order_by(SecurityLog.timestamp.desc()).limit(5).all()]
    scan_history = [scan.to_dict() for scan in URLScan.query.order_by(URLScan.timestamp.desc()).limit(3).all()]
    return render_template(
        "dashboard.html",
        page="dashboard",
        metrics=metrics,
        logs=logs,
        scan_history=scan_history,
    )


@app.get("/logs")
@login_required
def logs_page() -> str:
    metrics = get_dashboard_stats()
    logs = [log.to_dict() for log in SecurityLog.query.order_by(SecurityLog.timestamp.desc()).all()]
    scan_history = [scan.to_dict() for scan in URLScan.query.order_by(URLScan.timestamp.desc()).limit(3).all()]
    return render_template(
        "dashboard.html",
        page="logs",
        logs=logs,
        metrics=metrics,
        scan_history=scan_history,
    )


@app.post("/scan")
@login_required
def scan_url():
    data = request.get_json(silent=True) or {}
    target_url = data.get("url", "")

    try:
        normalized_url = normalize_url(target_url)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    result = generate_scan_result(normalized_url)
    
    scan = URLScan(
        url=result["url"],
        status=result["status"],
        score=result["score"],
        checks=json.dumps(result["checks"]),
    )
    db.session.add(scan)
    db.session.commit()
    
    return jsonify({"ok": True, "result": result})


@app.post("/add-log")
@login_required
def add_log():
    data = request.get_json(silent=True) or {}
    event_type = data.get("event_type", "").strip()
    severity = data.get("severity", "").strip()
    status = data.get("status", "").strip()

    if not event_type or not severity or not status:
        return jsonify({"ok": False, "error": "Missing required fields"}), 400

    log = SecurityLog(event_type=event_type, severity=severity, status=status)
    db.session.add(log)
    db.session.commit()

    return jsonify({"ok": True, "log": log.to_dict()})


@app.get("/report")
@login_required
def generate_report() -> Response:
    metrics = get_dashboard_stats()
    scans = URLScan.query.order_by(URLScan.timestamp.desc()).all()
    logs = SecurityLog.query.order_by(SecurityLog.timestamp.desc()).limit(5).all()

    report_lines = [
        "CyberShield Security Report",
        "==========================",
        "Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "",
        "Threat Summary",
        "--------------",
        f"Total Threats Detected: {metrics['threats']}",
        f"Active Threats: {metrics['active']}",
        f"System Status: {metrics['status']}",
        "",
        "Recent Security Logs",
        "--------------------",
    ]

    for log in logs:
        report_lines.append(
            f"- {log.timestamp.strftime('%Y-%m-%d %H:%M:%S')} | {log.event_type} | {log.severity} | {log.status}"
        )

    report_lines.extend(["", "Scan History", "-----------"])
    for scan in scans[:5]:
        report_lines.append(
            f"- {scan.url} | {scan.status} | Score: {scan.score}"
        )

    report_content = "\n".join(report_lines) + "\n"
    return Response(
        report_content,
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment; filename=cybershield_report.txt"},
    )


@app.get("/api/status")
def api_status():
    metrics = get_dashboard_stats()
    return jsonify(
        {
            "status": metrics["status"],
            "total_threats": metrics["threats"],
            "active_threats": metrics["active"],
            "last_scan": metrics["last_scan"],
        }
    )



if __name__ == "__main__":
    app.run(debug=True)
