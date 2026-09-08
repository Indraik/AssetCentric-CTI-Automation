import json
import os
from typing import Optional

from security_automation.firewall_blocklist_generator import generate_firewall_blocklist
from security_automation.iptables_rule_generator import generate_firewall_rules
from security_automation.risk_engine import calculate_risk
from security_automation.unmatched_report_generator import generate_unmatched_records
from security_automation.yara_generator import generate_yara_rules


def run_rule_automation(
    indicators_path: str,
    output_dir: Optional[str] = None,
    local_matches: int = 0,
):
    """Generate all output artifacts from correlation indicators."""

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(indicators_path, "r", encoding="utf-8") as f:
        indicators = json.load(f)

    generate_firewall_blocklist(indicators, output_dir=output_dir)
    generate_firewall_rules(
        blocklist_path=os.path.join(output_dir or "", "firewall_blocklist.csv"),
        output_dir=output_dir,
    )
    generate_yara_rules(indicators, output_dir=output_dir)
    generate_unmatched_records(indicators, output_dir=output_dir)

    score, level = calculate_risk(indicators, local_matches=local_matches)
    return score, level


if __name__ == "__main__":
    out_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
    out_dir = os.path.abspath(out_dir)
    indicators_path = os.path.join(os.path.dirname(__file__), "threat_indicators.json")

    score, level = run_rule_automation(indicators_path, output_dir=out_dir, local_matches=2)
    print("Risk Score:", score)
    print("Risk Level:", level)
