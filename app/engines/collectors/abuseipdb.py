from typing import Any, Dict, List
import requests

from app.core.config import Config
from app.core.logger import setup_logger

logger = setup_logger("AbuseIPDBCollector")


def collect_abuseipdb() -> List[Dict[str, Any]]:
    """Collect malicious IP addresses from AbuseIPDB API."""
    logger.info("AbuseIPDB Collector | Starting collection")

    if not Config.is_abuseipdb_configured():
        logger.warning("AbuseIPDB Collector | ABUSEIPDB_API_KEY is not configured; skipping feed")
        return []

    headers = {
        "Key": Config.ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "confidenceMinimum": 75
    }

    indicators = []

    try:
        response = requests.get(
            Config.ABUSEIPDB_API_URL,
            headers=headers,
            params=params,
            timeout=10
        )
        response.raise_for_status()
        data = response.json()

        for entry in data.get("data", [])[:Config.MAX_INDICATORS_PER_FEED]:
            indicators.append({
                "indicator": entry["ipAddress"],
                "type": "ip",
                "source": "abuseipdb"
            })

        logger.info(f"AbuseIPDB Collector | Indicators collected: {len(indicators)}")

    except Exception as e:
        logger.error(f"AbuseIPDB Collector | Error: {str(e)}")

    return indicators
