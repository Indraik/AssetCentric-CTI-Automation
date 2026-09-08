from typing import Any, Dict
import requests


def enrich_ip(ip: str) -> Dict[str, Any]:
    """Enrich an IP address using ip-api.com.

    Returns country, ASN, and ISP information.
    """
    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=5)

        if response.status_code != 200:
            return {"country": None, "asn": None, "isp": None}

        data = response.json()
        return {
            "country": data.get("country"),
            "asn": data.get("as"),
            "isp": data.get("isp")
        }
    except Exception:
        return {"country": None, "asn": None, "isp": None}
