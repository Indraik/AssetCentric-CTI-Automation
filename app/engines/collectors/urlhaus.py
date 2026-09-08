import csv
from io import StringIO
import re
from typing import Any, Dict, List
from urllib.parse import urlparse
import requests

from app.core.config import Config
from app.core.logger import setup_logger

logger = setup_logger("URLHausCollector")


def collect_urlhaus() -> List[Dict[str, Any]]:
    """Collect malware URLs and hostnames from URLHaus CSV feed."""
    logger.info("URLHaus Collector | Starting collection")

    indicators = []

    try:
        response = requests.get(Config.URLHAUS_FEED_URL, timeout=10)
        response.raise_for_status()

        csv_data = StringIO(response.text)
        reader = csv.reader(csv_data)
        count = 0
        ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

        for row in reader:
            if row and not row[0].startswith("#"):
                if count >= Config.MAX_INDICATORS_PER_FEED:
                    break

                url = row[2]
                parsed = urlparse(url)
                host = parsed.netloc.split(":")[0]

                if not host:
                    continue

                if re.match(ip_pattern, host):
                    indicators.append({
                        "indicator": host,
                        "type": "ip",
                        "source": "urlhaus"
                    })
                else:
                    indicators.append({
                        "indicator": host,
                        "type": "domain",
                        "source": "urlhaus"
                    })

                count += 1

        logger.info(f"URLHaus Collector | Indicators collected: {len(indicators)}")

    except Exception as e:
        logger.error(f"URLHaus Collector | Error: {str(e)}")

    return indicators
