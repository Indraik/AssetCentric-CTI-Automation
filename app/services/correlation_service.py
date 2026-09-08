import json
import os
from typing import Any, Dict, List, Optional

from app.core.config import Config
from app.engines.correlation import (
    correlate,
    load_threat_feed,
    load_firewall_logs,
    load_dns_logs,
    load_endpoint_logs,
)
from app.engines.generators import (
    generate_firewall_blocklist,
    generate_firewall_rules,
    generate_yara_rules,
    generate_unmatched_records,
    calculate_risk,
)


def _safe_load_logs(load_fn, path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        return []
    try:
        return load_fn(path)
    except Exception:
        return []


def _resolve_log_path(filename: str) -> str:
    return os.path.join(Config.UPLOAD_DIR, filename)


def run_correlation(user_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Run correlation between normalized threat feed and uploaded logs."""
    firewall_path = _resolve_log_path("firewall_logs.csv")
    dns_path = _resolve_log_path("dns_logs.csv")
    endpoint_path = _resolve_log_path("endpoint_logs.csv")

    threat_feed = load_threat_feed()
    firewall_logs = _safe_load_logs(load_firewall_logs, firewall_path)
    dns_logs = _safe_load_logs(load_dns_logs, dns_path)
    endpoint_logs = _safe_load_logs(load_endpoint_logs, endpoint_path)

    results = correlate(threat_feed, firewall_logs, dns_logs, endpoint_logs)

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

    Config.init_directories()
    try:
        os.makedirs(Config.OUTPUT_DIR, exist_ok=True)
        with open(os.path.join(Config.OUTPUT_DIR, "correlation_results.json"), "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
    except Exception:
        pass

    # Generate enforcement artifacts
    try:
        generate_firewall_blocklist(results, output_dir=Config.OUTPUT_DIR)
        generate_firewall_rules(
            blocklist_path=os.path.join(Config.OUTPUT_DIR, "firewall_blocklist.csv"),
            output_dir=Config.OUTPUT_DIR,
        )
        generate_yara_rules(results, output_dir=Config.OUTPUT_DIR)
        generate_unmatched_records(results, output_dir=Config.OUTPUT_DIR)

        local_matches = sum(1 for r in results if r.get("status") == "MATCH")
        score, level = calculate_risk(results, local_matches=local_matches)
        payload["risk"] = {"score": score, "level": level}
        payload["stats"] = {
            "matches": local_matches,
            "total_records": len(results),
        }
    except Exception as e:
        print(f"Rule generation warning: {e}")

    return payload


def load_correlation_results() -> Dict[str, Any]:
    """Load correlation results from storage."""
    path = os.path.join(Config.OUTPUT_DIR, "correlation_results.json")
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}
