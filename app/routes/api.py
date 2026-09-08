from flask import Blueprint, jsonify, session

from app.core.state import get_pipeline_state
from app.services.stats_service import build_platform_stats, build_dashboard_live_stats

api_bp = Blueprint("api", __name__)


@api_bp.route("/live-stats")
def live_stats():
    payload = {
        "platform_stats": build_platform_stats(),
        "dashboard": build_dashboard_live_stats(),
        "logs_uploaded": bool(session.get("logs_uploaded")),
    }
    return jsonify(payload)


@api_bp.route("/pipeline-status")
def pipeline_status():
    return jsonify(get_pipeline_state())
