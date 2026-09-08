import json
import ipaddress

from config.settings import NORMALIZED_FEED_PATH


def _norm(value):
    if value is None:
        return ""
    return str(value).strip().lower()


def _is_public_ip(value):
    try:
        return ipaddress.ip_address(value).is_global
    except Exception:
        return False


def _pick_ip_for_hint(log):
    src_ip = _norm(log.get("src_ip"))
    dst_ip = _norm(log.get("dst_ip"))
    if _is_public_ip(src_ip):
        return src_ip, "src_ip"
    if _is_public_ip(dst_ip):
        return dst_ip, "dst_ip"
    return src_ip or dst_ip, "src_ip" if src_ip else "dst_ip"


# Load normalized CTI feed
def load_threat_feed():

    with open(NORMALIZED_FEED_PATH, "r", encoding="utf-8") as f:
        threat_feed = json.load(f)

    return threat_feed


# Correlation logic
def correlate(threat_feed, firewall_logs, dns_logs, endpoint_logs):

    results = []
    matched_logs = set()

    for indicator in threat_feed:

        value = indicator["indicator"]
        ttype = indicator["type"]

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
                        "severity": indicator["severity"],
                        "confidence": indicator["confidence"],
                        "reliability_score": indicator.get("reliability_score", 0),
                        "source": indicator["sources"],
                        "matched_field": matched_field,
                        "status": "MATCH",
                        "log_record": log
                    })

                    matched_logs.add(id(log))

        # --- Domain Correlation ---
        elif ttype == "domain":

            for log in dns_logs:

                if _norm(log.get("domain")) == _norm(value):

                    results.append({
                        "indicator": value,
                        "type": "domain",
                        "severity": indicator["severity"],
                        "confidence": indicator["confidence"],
                        "reliability_score": indicator.get("reliability_score", 0),
                        "source": indicator["sources"],
                        "matched_field": "domain",
                        "status": "MATCH",
                        "log_record": log
                    })

                    matched_logs.add(id(log))

        # --- Hash Correlation ---
        elif ttype == "hash":

            for log in endpoint_logs:

                if _norm(log.get("file_hash")) == _norm(value):

                    results.append({
                        "indicator": value,
                        "type": "hash",
                        "severity": indicator["severity"],
                        "confidence": indicator["confidence"],
                        "reliability_score": indicator.get("reliability_score", 0),
                        "source": indicator["sources"],
                        "matched_field": "file_hash",
                        "status": "MATCH",
                        "log_record": log
                    })

                    matched_logs.add(id(log))


    # Add SAFE logs (no match)
    for log in firewall_logs:
        if id(log) in matched_logs:
            continue

        # Optional fallback for sample logs that already carry threat match labels.
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

    for log in firewall_logs + dns_logs + endpoint_logs:

        if id(log) not in matched_logs:

            results.append({
                "status": "NO_MATCH",
                "log_record": log
            })

    return results

def save_results(results, output_file="correlation_results.json"):

    with open(output_file, "w") as f:

        json.dump(results, f, indent=4)

    print(f"Results saved to {output_file}")