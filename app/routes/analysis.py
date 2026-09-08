from datetime import datetime
import os
import threading
from flask import Blueprint, render_template, request, redirect, url_for, session

from app.core.config import Config
from app.core.state import get_pipeline_state, set_pipeline_state
from app.services.asset_service import load_user_settings
from app.services.stats_service import make_event
from app.services.threat_pipeline_service import run_pipeline
from app.services.correlation_service import run_correlation

analysis_bp = Blueprint("analysis", __name__)


def _pipeline_worker():
    set_pipeline_state(running=True, message="Running analysis...")
    try:
        run_pipeline()
        try:
            config = load_user_settings()
            run_correlation(user_config=config)
        except Exception as e:
            print(f"Correlation run failed: {e}")

        now = datetime.utcnow().isoformat()
        set_pipeline_state(running=False, message="Completed successfully", last_run=now)
    except Exception as e:
        set_pipeline_state(running=False, message=f"Failed: {e}")


@analysis_bp.route("/analyze-threat", methods=["POST"])
def analyze_threat():
    if "config_done" not in session:
        return redirect(url_for("views.config"))

    if not session.get("logs_uploaded"):
        return render_template(
            "upload.html",
            upload_error="Please upload logs first, then click Analyze Threat Intelligence.",
            logs_uploaded=False,
        )

    try:
        run_pipeline()
        session["pipeline_last_run"] = datetime.utcnow().isoformat()

        user_config = {
            "asset_type": session.get("asset_type"),
            "port": session.get("port"),
            "subnet": session.get("subnet"),
            "host": session.get("host"),
            "firewall": bool(session.get("firewall")),
            "edr": bool(session.get("edr")),
            "siem": bool(session.get("siem")),
        }

        run_correlation(user_config=user_config)

    except Exception as e:
        print(f"Pipeline/analyze failed: {e}")
        return render_template(
            "upload.html",
            upload_error=f"Threat analysis failed: {e}",
            logs_uploaded=bool(session.get("logs_uploaded")),
        )

    session["analysis_done"] = True

    timeline = session.get("timeline", [])
    timeline.append(make_event("Threat intelligence analysis started"))
    timeline.append(make_event("Correlation and rule generation completed"))
    session["timeline"] = timeline[-10:]

    return redirect(url_for("views.dashboard"))


@analysis_bp.route("/run-pipeline", methods=["POST"])
def run_pipeline_route():
    if "config_done" not in session:
        return redirect(url_for("views.config"))

    p_state = get_pipeline_state()
    if p_state["running"]:
        return redirect(url_for("views.dashboard"))

    set_pipeline_state(running=False, message="Queued...")

    timeline = session.get("timeline", [])
    timeline.append(make_event("Pipeline execution requested"))
    session["timeline"] = timeline[-10:]

    thread = threading.Thread(target=_pipeline_worker, daemon=True)
    thread.start()

    session["analysis_done"] = True
    return redirect(url_for("views.dashboard"))
