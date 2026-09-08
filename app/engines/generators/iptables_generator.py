import csv
import os
from typing import Optional

from app.core.config import Config


def generate_firewall_rules(
    blocklist_path: Optional[str] = None,
    output_dir: Optional[str] = None,
    filename: str = "firewall_rules.log",
) -> str:
    """Generate firewall rules based on the firewall blocklist CSV."""
    target_blocklist = blocklist_path or os.path.join(Config.OUTPUT_DIR, "firewall_blocklist.csv")
    if not os.path.exists(target_blocklist):
        # Fallback to legacy blocklist
        fallback = os.path.join(Config.LEGACY_OUTPUT_DIR, "firewall_blocklist.csv")
        if os.path.exists(fallback):
            target_blocklist = fallback
        else:
            target_blocklist = None

    target_dir = output_dir or Config.OUTPUT_DIR
    os.makedirs(target_dir, exist_ok=True)
    output_path = os.path.join(target_dir, filename)

    rules = []
    if target_blocklist and os.path.exists(target_blocklist):
        with open(target_blocklist, "r", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            for row in reader:
                ip = row.get("IP")
                if not ip:
                    continue
                rules.append(f"iptables -A INPUT -s {ip} -j DROP\n")

    with open(output_path, "w", encoding="utf-8") as log_file:
        log_file.writelines(rules)

    # Legacy copy for compatibility
    if target_dir != Config.LEGACY_OUTPUT_DIR:
        try:
            os.makedirs(Config.LEGACY_OUTPUT_DIR, exist_ok=True)
            with open(os.path.join(Config.LEGACY_OUTPUT_DIR, filename), "w", encoding="utf-8") as f:
                f.writelines(rules)
        except Exception:
            pass

    return output_path
