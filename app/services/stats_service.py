import csv
from datetime import datetime
import json
import os
from typing import Any, Dict, List

from app.core.config import Config
from app.core.state import get_pipeline_state


def _safe_load_json(path: str, default: Any) -> Any:
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _safe_load_csv(path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", newline="", encoding="utf-8-sig") as f:
            return list(csv.DictReader(f))
    except Exception:
        return []


def format_trend(current: int, previous: Any) -> Dict[str, Any]:
    """Return trend information for dashboard display."""
    if previous is None:
        return {"delta": 0, "direction": "flat", "label": ""}
    delta = current - previous
    if delta > 0:
        return {"delta": delta, "direction": "up", "label": f"↑ +{delta}"}
    if delta < 0:
        return {"delta": delta, "direction": "down", "label": f"↓ {delta}"}
    return {"delta": 0, "direction": "flat", "label": "—"}


def make_event(message: str) -> Dict[str, str]:
    """Create a timeline event item."""
    return {
        "ts": datetime.utcnow().strftime("%H:%M"),
        "message": message,
    }


def build_platform_stats() -> Dict[str, Any]:
    """Calculate platform statistics for the upload & overview pages."""
    norm_path = Config.NORMALIZED_FEED_PATH
    corr_path = os.path.join(Config.OUTPUT_DIR, "correlation_results.json")

    normalized = _safe_load_json(norm_path, [])
    correlation = _safe_load_json(corr_path, {})

    correlation_results = correlation.get("results", []) if isinstance(correlation, dict) else []
    matches = [r for r in correlation_results if r.get("status") == "MATCH"]
    matched_ip_values = {
        r.get("indicator")
        for r in matches
        if r.get("type") == "ip" and r.get("indicator")
    }

    source_set = {
        src
        for item in normalized
        for src in item.get("sources", [])
    }

    uploads_expected = ["firewall.log", "firewall_logs.csv", "dns_logs.csv", "endpoint_logs.csv", "web.log"]
    uploaded_files = [
        name for name in uploads_expected
        if os.path.exists(os.path.join(Config.UPLOAD_DIR, name))
    ]

    firewall_rows = _safe_load_csv(os.path.join(Config.UPLOAD_DIR, "firewall.log"))
    if not firewall_rows:
        firewall_rows = _safe_load_csv(os.path.join(Config.UPLOAD_DIR, "firewall_logs.csv"))

    preview_rows = []
    for row in firewall_rows[-3:]:
        threat_match = str(row.get("threat_match", "")).strip().upper()
        action = str(row.get("action", "")).strip().upper()

        if threat_match == "MATCHED_THREAT_FEED":
            status = "Matched"
            status_class = "danger"
        elif action == "BLOCK":
            status = "Blocked"
            status_class = "warn"
        else:
            status = "Observed"
            status_class = "ok"

        preview_rows.append({
            "timestamp": row.get("timestamp", "N/A"),
            "source": "Firewall",
            "status": status,
            "status_class": status_class,
        })

    top_indicators = sorted(
        normalized,
        key=lambda i: (i.get("reliability_score", 0), i.get("severity", "")),
        reverse=True,
    )[:3]

    blocklist_exists = os.path.exists(os.path.join(Config.OUTPUT_DIR, "firewall_blocklist.csv"))
    yara_exists = os.path.exists(os.path.join(Config.OUTPUT_DIR, "yara_rules.yar"))

    return {
        "uploads": {
            "files_uploaded": len(uploaded_files),
            "preview_rows": preview_rows,
        },
        "feed": {
            "indicators": len(normalized),
            "suspicious_ips": sum(1 for i in normalized if i.get("type") == "ip"),
            "active_sources": len(source_set),
            "top_indicators": top_indicators,
        },
        "correlation": {
            "matches": len(matches),
            "unique_ip_matches": len(matched_ip_values),
        },
        "outputs": {
            "blocklist_exists": blocklist_exists,
            "yara_exists": yara_exists,
        },
    }


def build_dashboard_live_stats() -> Dict[str, Any]:
    """Calculate live status metrics for the dashboard."""
    norm_path = Config.NORMALIZED_FEED_PATH
    corr_path = os.path.join(Config.OUTPUT_DIR, "correlation_results.json")

    indicators = _safe_load_json(norm_path, [])
    correlation_payload = _safe_load_json(corr_path, {})
    correlation_results = correlation_payload.get("results", []) if isinstance(correlation_payload, dict) else []

    high_confidence = sum(1 for i in indicators if i.get("confidence") == "high")
    suspicious_ips = sum(1 for i in indicators if i.get("type") == "ip")
    risk = "HIGH" if high_confidence > 0 else "LOW"
    threat_score = min(100, int(len(indicators) * 1.5 + high_confidence * 4 + suspicious_ips * 1.2))

    p_state = get_pipeline_state()
    running = p_state["running"]
    message = p_state.get("message")
    last_run = p_state.get("last_run")

    sources = sorted({
        src
        for entry in indicators
        for src in entry.get("sources", [])
    })

    top_indicators = sorted(
        indicators,
        key=lambda i: (i.get("reliability_score", 0), i.get("severity", "")),
        reverse=True,
    )[:5]

    local_attacks = sum(1 for r in correlation_results if r.get("status") == "MATCH")
    correlation_status = "RUNNING" if running else ("SUCCESS" if correlation_results else "IDLE")

    return {
        "metrics": {
            "indicators": len(indicators),
            "high_confidence": high_confidence,
            "suspicious_ips": suspicious_ips,
            "risk": risk,
        },
        "threat_score": threat_score,
        "local_attacks": local_attacks,
        "pipeline": {
            "running": running,
            "message": message,
            "last_run": last_run,
            "threat_feed_status": "ACTIVE" if sources else "INACTIVE",
            "correlation_status": correlation_status,
        },
        "top_indicators": top_indicators,
    }
