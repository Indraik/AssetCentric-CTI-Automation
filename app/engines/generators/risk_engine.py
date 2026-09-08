from typing import Any, Dict, List, Tuple


def calculate_risk(indicators: List[Dict[str, Any]], local_matches: int = 0) -> Tuple[int, str]:
    """Calculate risk score and categorical level."""
    high = sum(1 for i in indicators if i.get("confidence") == "high")
    medium = sum(1 for i in indicators if i.get("confidence") == "medium")

    score = (high * 10) + (medium * 5) + (local_matches * 3)

    if score > 40:
        level = "HIGH"
    elif score > 20:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level
