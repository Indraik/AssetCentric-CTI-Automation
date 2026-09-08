from datetime import datetime
import json
import os
from flask import Blueprint, render_template, request, redirect, url_for, session, current_app

from app.core.config import Config
from app.core.state import get_pipeline_state
from app.services.asset_service import load_user_settings, save_user_settings
from app.services.stats_service import (
    build_platform_stats,
    format_trend,
    make_event,
)
from app.services.log_upload_service import validate_required_uploads, save_uploaded_logs
from app.services.correlation_service import load_correlation_results

views_bp = Blueprint("views", __name__)


@views_bp.route("/")
def index():
    session.clear()
    return render_template("index.html")


@views_bp.route("/start", methods=["POST"])
def start():
    session["started"] = True
    return redirect(url_for("views.config"))


@views_bp.route("/config", methods=["GET", "POST"])
def config():
    if "started" not in session:
        return redirect(url_for("views.index"))

    if request.method == "POST":
        session["asset_type"] = request.form.get("asset_type")
        session["port"] = request.form.get("critical_port")
        session["subnet"] = request.form.get("asset_subnet")
        session["host"] = request.form.get("asset_host")

        session["firewall"] = request.form.get("control_firewall")
        session["edr"] = request.form.get("control_edr")
        session["siem"] = request.form.get("control_siem")

        save_user_settings({
            "asset_type": session["asset_type"],
            "port": session["port"],
            "subnet": session["subnet"],
            "host": session["host"],
            "firewall": session["firewall"],
            "edr": session["edr"],
            "siem": session["siem"],
        })

        session["config_done"] = True
        return redirect(url_for("views.upload"))

    return render_template("config.html")


@views_bp.route("/upload", methods=["GET", "POST"])
def upload():
    if "config_done" not in session:
        return redirect(url_for("views.config"))

    upload_error = None
    upload_success = None

    if request.method == "GET" and request.args.get("status") == "uploaded":
        upload_success = "Logs uploaded successfully. Click 'Analyze Threat Intelligence' to start analysis."

    if request.method == "POST":
        enabled_controls = {
            "firewall": bool(session.get("firewall")),
            "edr": bool(session.get("edr")),
            "siem": bool(session.get("siem")),
        }

        upload_error = validate_required_uploads(request.files, enabled_controls)
        if not upload_error:
            save_uploaded_logs(request.files)

            session["logs_uploaded"] = True
            session["analysis_done"] = False

            timeline = session.get("timeline", [])
            timeline.append(make_event("Logs uploaded and validated"))
            session["timeline"] = timeline[-10:]

            return redirect(url_for("views.upload", status="uploaded"))

    return render_template(
        "upload.html",
        upload_error=upload_error,
        upload_success=upload_success,
        logs_uploaded=bool(session.get("logs_uploaded")),
    )


@views_bp.route("/dashboard")
def dashboard():
    if "analysis_done" not in session:
        return redirect(url_for("views.upload"))

    indicators = []
    norm_path = Config.NORMALIZED_FEED_PATH
    if not os.path.exists(norm_path) and os.path.exists(os.path.join(Config.LEGACY_DATA_DIR, "normalized_threat_feed.json")):
        norm_path = os.path.join(Config.LEGACY_DATA_DIR, "normalized_threat_feed.json")

    if os.path.exists(norm_path):
        try:
            with open(norm_path, "r", encoding="utf-8") as f:
                indicators = json.load(f)
        except Exception as e:
            print(f"Failed to load normalized threat feed: {e}")

    severity_score = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    top_indicators = sorted(
        indicators,
        key=lambda i: (
            severity_score.get(i.get("severity", "low"), 0),
            i.get("reliability_score", 0),
        ),
        reverse=True,
    )[:20]

    total_indicators = len(indicators)
    high_confidence = sum(1 for i in indicators if i.get("confidence") == "high")
    suspicious_ips = sum(1 for i in indicators if i.get("type") == "ip")
    domains = sum(1 for i in indicators if i.get("type") == "domain")
    sources = sorted({
        src
        for entry in indicators
        for src in entry.get("sources", [])
    })

    upload_folder = current_app.config.get("UPLOAD_FOLDER", Config.UPLOAD_DIR)
    total_logs = len(os.listdir(upload_folder)) if os.path.exists(upload_folder) else 0

    metrics = {
        "total_logs": total_logs,
        "indicators": total_indicators,
        "high_confidence": high_confidence,
        "suspicious_ips": suspicious_ips,
        "domains": domains,
        "risk": "HIGH" if high_confidence > 0 else "LOW",
    }

    threat_score = min(100, int(total_indicators * 1.5 + high_confidence * 4 + suspicious_ips * 1.2))

    prev_metrics = session.get("last_metrics", {})
    trends = {
        "indicators": format_trend(metrics["indicators"], prev_metrics.get("indicators")),
        "high_confidence": format_trend(metrics["high_confidence"], prev_metrics.get("high_confidence")),
        "suspicious_ips": format_trend(metrics["suspicious_ips"], prev_metrics.get("suspicious_ips")),
    }
    session["last_metrics"] = metrics

    timeline = session.get("timeline", [])
    if not timeline:
        timeline = [
            make_event("Session started"),
            make_event("Configuration loaded"),
        ]

    p_state = get_pipeline_state()
    pipeline_running = p_state["running"]
    pipeline_message = p_state.get("message")
    pipeline_last_run = p_state.get("last_run")

    correlation_payload = load_correlation_results()
    correlation_results = correlation_payload.get("results", []) if isinstance(correlation_payload, dict) else []
    local_attacks = sum(1 for r in correlation_results if r.get("status") == "MATCH")
    correlation_active = bool(correlation_results)
    correlation_status = "RUNNING" if pipeline_running else ("SUCCESS" if correlation_active else "IDLE")

    risk_meta = {
        "LOW": {"icon": "🟢", "label": "No active exploitation detected", "color": "green"},
        "HIGH": {"icon": "🔴", "label": "Active threat indicators detected", "color": "red"},
    }

    context = {
        "metrics": metrics,
        "trends": trends,
        "threat_score": threat_score,
        "risk_meta": risk_meta.get(metrics["risk"], risk_meta["LOW"]),
        "indicators": top_indicators,
        "sources": sources,
        "timeline": timeline[-8:],
        "pipeline_last_run": pipeline_last_run or session.get("pipeline_last_run"),
        "pipeline_running": pipeline_running,
        "pipeline_message": pipeline_message,
        "threat_feed_status": "ACTIVE" if sources else "INACTIVE",
        "correlation_status": correlation_status,
        "local_attacks": local_attacks,
    }

    return render_template("dashboard.html", **context)
