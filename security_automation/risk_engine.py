def calculate_risk(indicators, local_matches=0):

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
