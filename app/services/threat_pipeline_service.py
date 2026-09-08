import json
import os
import threading
from typing import Any, Dict, List

from app.core.config import Config
from app.core.logger import setup_logger
from app.core.state import set_pipeline_state
from app.engines.collectors import collect_abuseipdb, collect_urlhaus, collect_threatfox
from app.engines.normalizer import normalize_feed

logger = setup_logger("ThreatPipelineService")


def run_pipeline() -> List[Dict[str, Any]]:
    """Execute concurrent threat intelligence collection and normalization."""
    logger.info("Threat Pipeline | Starting threat intelligence collection")

    results = {
        "abuseipdb": [],
        "urlhaus": [],
        "threatfox": []
    }

    def abuseipdb_task():
        try:
            results["abuseipdb"] = collect_abuseipdb()
        except Exception as e:
            logger.error(f"AbuseIPDB Collector Failed | {str(e)}")

    def urlhaus_task():
        try:
            results["urlhaus"] = collect_urlhaus()
        except Exception as e:
            logger.error(f"URLHaus Collector Failed | {str(e)}")

    def threatfox_task():
        try:
            results["threatfox"] = collect_threatfox()
        except Exception as e:
            logger.error(f"ThreatFox Collector Failed | {str(e)}")

    threads = [
        threading.Thread(target=abuseipdb_task),
        threading.Thread(target=urlhaus_task),
        threading.Thread(target=threatfox_task)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    all_indicators = results["abuseipdb"] + results["urlhaus"] + results["threatfox"]
    logger.info(f"Threat Pipeline | Total raw indicators collected: {len(all_indicators)}")

    Config.init_directories()
    raw_paths = [Config.RAW_FEED_PATH, os.path.join(Config.LEGACY_DATA_DIR, "raw_threat_feed.json")]
    for rpath in raw_paths:
        try:
            os.makedirs(os.path.dirname(rpath), exist_ok=True)
            with open(rpath, "w", encoding="utf-8") as f:
                json.dump(all_indicators, f, indent=4)
        except Exception as e:
            logger.error(f"Threat Pipeline | Failed to save raw feed to {rpath} | {str(e)}")

    # Run normalization
    normalized = normalize_feed()
    logger.info("Threat Pipeline | Completed successfully")
    return normalized
