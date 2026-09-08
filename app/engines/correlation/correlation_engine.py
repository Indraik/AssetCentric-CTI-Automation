import ipaddress
import json
import os
from typing import Any, Dict, List

from app.core.config import Config


def _norm(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except Exception:
        return False


def _pick_ip_for_hint(log: Dict[str, Any]):
    src_ip = _norm(log.get("src_ip"))
    dst_ip = _norm(log.get("dst_ip"))
    if _is_public_ip(src_ip):
        return src_ip, "src_ip"
    if _is_public_ip(dst_ip):
        return dst_ip, "dst_ip"
    return src_ip or dst_ip, "src_ip" if src_ip else "dst_ip"


def load_threat_feed(feed_path: str = None) -> List[Dict[str, Any]]:
    """Load normalized threat feed from storage (or fallback to legacy path)."""
    target_path = feed_path or Config.NORMALIZED_FEED_PATH
    if not os.path.exists(target_path):
        fallback = os.path.join(Config.LEGACY_DATA_DIR, "normalized_threat_feed.json")
        if os.path.exists(fallback):
            target_path = fallback
        else:
            return []

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def correlate(
    threat_feed: List[Dict[str, Any]],
    firewall_logs: List[Dict[str, Any]],
    dns_logs: List[Dict[str, Any]],
    endpoint_logs: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Correlate normalized threat indicators against internal security logs."""
    results = []
    matched_logs = set()

    for indicator in threat_feed:
        value = indicator.get("indicator")
        ttype = indicator.get("type")
        if not value:
            continue

        # --- IP Correlation ---
        if ttype == "ip":
            for log in firewall_logs:
                src_ip = _norm(log.get("src_ip"))
                dst_ip = _norm(log.get("dst_ip"))

                if _norm(value) in {src_ip, dst_ip}:
                    matched_field = "src_ip" if _norm(value) == src_ip else "dst_ip"
                    results.append({
                        "indicator": value,
                        "type": "ip",
                        "severity": indicator.get("severity", "medium"),
                        "confidence": indicator.get("confidence", "medium"),
                        "reliability_score": indicator.get("reliability_score", 0),
                        "source": indicator.get("sources", []),
                        "matched_field": matched_field,
                        "status": "MATCH",
                        "log_record": log,
                    })
                    matched_logs.add(id(log))

        # --- Domain Correlation ---
        elif ttype == "domain":
            for log in dns_logs:
                if _norm(log.get("domain")) == _norm(value):
                    results.append({
                        "indicator": value,
                        "type": "domain",
                        "severity": indicator.get("severity", "medium"),
                        "confidence": indicator.get("confidence", "medium"),
                        "reliability_score": indicator.get("reliability_score", 0),
                        "source": indicator.get("sources", []),
                        "matched_field": "domain",
                        "status": "MATCH",
                        "log_record": log,
                    })
                    matched_logs.add(id(log))

        # --- Hash Correlation ---
        elif ttype == "hash":
            for log in endpoint_logs:
                if _norm(log.get("file_hash")) == _norm(value):
                    results.append({
                        "indicator": value,
                        "type": "hash",
                        "severity": indicator.get("severity", "medium"),
                        "confidence": indicator.get("confidence", "medium"),
                        "reliability_score": indicator.get("reliability_score", 0),
                        "source": indicator.get("sources", []),
                        "matched_field": "file_hash",
                        "status": "MATCH",
                        "log_record": log,
                    })
                    matched_logs.add(id(log))

    # Add matched logs from sample data labeled with threat_match
    for log in firewall_logs:
        if id(log) in matched_logs:
            continue

        threat_match = _norm(log.get("threat_match"))
        if threat_match == "matched_threat_feed":
            indicator_ip, matched_field = _pick_ip_for_hint(log)
            if indicator_ip:
                results.append({
                    "indicator": indicator_ip,
                    "type": "ip",
                    "severity": "high",
                    "confidence": "medium",
                    "reliability_score": 65,
                    "source": ["log_hint"],
                    "matched_field": matched_field,
                    "status": "MATCH",
                    "log_record": log,
                })
                matched_logs.add(id(log))

    # Add unmatched logs for full auditability
    for log in firewall_logs + dns_logs + endpoint_logs:
        if id(log) not in matched_logs:
            results.append({
                "status": "NO_MATCH",
                "log_record": log,
            })

    return results
