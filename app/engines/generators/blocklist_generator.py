import csv
import os
from typing import Iterable, Mapping, Optional

from app.core.config import Config


def generate_firewall_blocklist(
    data: Iterable[Mapping[str, object]],
    output_dir: Optional[str] = None,
    filename: str = "firewall_blocklist.csv",
) -> str:
    """Generate a firewall blocklist CSV from correlation results."""
    target_dir = output_dir or Config.OUTPUT_DIR
    os.makedirs(target_dir, exist_ok=True)
    output_path = os.path.join(target_dir, filename)

    firewall_ips = set()
    for record in data:
        if record.get("status") == "MATCH" and record.get("type") == "ip":
            severity = record.get("severity")
            indicator = record.get("indicator")
            if severity in ["critical", "high", "medium"] and indicator:
                firewall_ips.add(indicator)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Action"])
        for ip in sorted(firewall_ips):
            writer.writerow([ip, "Block"])

    # Duplicate to legacy outputs if different for backward compatibility
    if target_dir != Config.LEGACY_OUTPUT_DIR:
        try:
            os.makedirs(Config.LEGACY_OUTPUT_DIR, exist_ok=True)
            legacy_path = os.path.join(Config.LEGACY_OUTPUT_DIR, filename)
            with open(legacy_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["IP", "Action"])
                for ip in sorted(firewall_ips):
                    writer.writerow([ip, "Block"])
        except Exception:
            pass

    return output_path
