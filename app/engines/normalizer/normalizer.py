from datetime import datetime
import json
import os
from typing import Any, Dict, List

from app.core.config import Config
from app.core.logger import setup_logger
from app.engines.normalizer.ip_enricher import enrich_ip

logger = setup_logger("FeedNormalizer")

SOURCE_RELIABILITY = {
    "abuseipdb": 70,
    "urlhaus": 65,
    "threatfox": 90,
}


def calculate_severity(score: int) -> str:
    """Convert reliability score to severity level."""
    if score >= 90:
        return "critical"
    elif score >= 70:
        return "high"
    elif score >= 50:
        return "medium"
    else:
        return "low"


def normalize_feed(raw_feed_path: str = None, output_path: str = None) -> List[Dict[str, Any]]:
    """Normalize raw threat indicators, calculate severity and enrich IPs."""
    raw_path = raw_feed_path or Config.RAW_FEED_PATH
    norm_path = output_path or Config.NORMALIZED_FEED_PATH

    logger.info("Normalizer | Starting normalization")

    if not os.path.exists(raw_path):
        logger.error(f"Normalizer | Raw feed not found at {raw_path}")
        return []

    try:
        with open(raw_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
    except Exception as e:
        logger.error(f"Normalizer | Failed to load raw feed | {str(e)}")
        return []

    grouped = {}
    for entry in raw_data:
        indicator = entry.get("indicator")
        source = entry.get("source")
        ind_type = entry.get("type")
        if not indicator:
            continue

        if indicator not in grouped:
            grouped[indicator] = {
                "indicator": indicator,
                "type": ind_type,
                "sources": set(),
            }
        grouped[indicator]["sources"].add(source)

    normalized = []
    for indicator_data in grouped.values():
        sources = list(indicator_data["sources"])
        reliability_scores = [SOURCE_RELIABILITY.get(src, 50) for src in sources]
        reliability_score = int(sum(reliability_scores) / len(reliability_scores))
        confidence = "high" if len(sources) > 1 else "medium"
        severity = calculate_severity(reliability_score)

        enrichment_data = {}
        if indicator_data["type"] == "ip":
            enrichment_data = enrich_ip(indicator_data["indicator"])

        normalized.append({
            "indicator": indicator_data["indicator"],
            "type": indicator_data["type"],
            "sources": sources,
            "confidence": confidence,
            "reliability_score": reliability_score,
            "severity": severity,
            "country": enrichment_data.get("country"),
            "asn": enrichment_data.get("asn"),
            "isp": enrichment_data.get("isp"),
            "tags": ["external_feed", "threat_intel"],
            "timestamp": datetime.utcnow().isoformat(),
        })

    os.makedirs(os.path.dirname(norm_path), exist_ok=True)
    try:
        with open(norm_path, "w", encoding="utf-8") as f:
            json.dump(normalized, f, indent=4)
        logger.info(f"Normalizer | Indicators normalized: {len(normalized)}")
    except Exception as e:
        logger.error(f"Normalizer | Failed to save normalized feed | {str(e)}")

    return normalized
