import json
import os
from typing import Any, Dict, List, Optional

from correlation.threat_correlation_engine import (
    correlate,
    load_threat_feed,
)
from correlation.security_log_parser import (
    load_dns_logs,
    load_endpoint_logs,
    load_firewall_logs,
)

from security_automation.firewall_blocklist_generator import generate_firewall_blocklist
from security_automation.iptables_rule_generator import generate_firewall_rules
from security_automation.risk_engine import calculate_risk
from security_automation.unmatched_report_generator import generate_unmatched_records
from security_automation.yara_generator import generate_yara_rules

from config.settings import BASE_DIR


UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")
CORRELATION_OUTPUT_PATH = os.path.join(OUTPUT_DIR, "correlation_results.json")


def _safe_load_logs(load_fn, path: str) -> List[Dict[str, Any]]:
    """Load logs if the file exists; return empty list otherwise."""

    if not os.path.exists(path):
        return []

    try:
        return load_fn(path)
    except Exception:
        # Best-effort; return empty list on parse errors.
        return []


def run_correlation(user_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Run correlation between normalized threat feed and uploaded logs.

    The output is persisted to `outputs/correlation_results.json`.
    """

    firewall_path = os.path.join(UPLOAD_DIR, "firewall_logs.csv")
    dns_path = os.path.join(UPLOAD_DIR, "dns_logs.csv")
    endpoint_path = os.path.join(UPLOAD_DIR, "endpoint_logs.csv")

    threat_feed = []
    try:
        threat_feed = load_threat_feed()
    except Exception:
        # If the normalized feed is missing or malformed, correlation cannot proceed.
        threat_feed = []

    firewall_logs = _safe_load_logs(load_firewall_logs, firewall_path)
    dns_logs = _safe_load_logs(load_dns_logs, dns_path)
    endpoint_logs = _safe_load_logs(load_endpoint_logs, endpoint_path)

    results = correlate(threat_feed, firewall_logs, dns_logs, endpoint_logs)

    # Add metadata so downstream rules engines can make use of user configuration
    payload = {
        "metadata": {
            "user_config": user_config or {},
            "logs": {
                "firewall_file": os.path.basename(firewall_path) if os.path.exists(firewall_path) else None,
                "dns_file": os.path.basename(dns_path) if os.path.exists(dns_path) else None,
                "endpoint_file": os.path.basename(endpoint_path) if os.path.exists(endpoint_path) else None,
            },
        },
        "results": results,
    }

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(CORRELATION_OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    # Generate enforcement artifacts (blocklists, YARA rules, etc.)
    results = payload.get("results", [])

    try:
        generate_firewall_blocklist(results, output_dir=OUTPUT_DIR)
        generate_firewall_rules(
            blocklist_path=os.path.join(OUTPUT_DIR, "firewall_blocklist.csv"),
            output_dir=OUTPUT_DIR,
        )
        generate_yara_rules(results, output_dir=OUTPUT_DIR)
        generate_unmatched_records(results, output_dir=OUTPUT_DIR)

        local_matches = sum(1 for r in results if r.get("status") == "MATCH")
        score, level = calculate_risk(results, local_matches=local_matches)
        payload["risk"] = {"score": score, "level": level}
        payload["stats"] = {
            "matches": local_matches,
            "total_records": len(results),
        }
    except Exception as e:
        # Fail gracefully if rule generation fails.
        print(f"Rule generation failed: {e}")

    return payload


def load_correlation_results() -> Dict[str, Any]:
    """Load previously generated correlation results."""

    if not os.path.exists(CORRELATION_OUTPUT_PATH):
        return {}

    with open(CORRELATION_OUTPUT_PATH, "r", encoding="utf-8") as f:
        return json.load(f)
