import csv
import os
from typing import Iterable, Mapping, Optional


def generate_firewall_blocklist(
    data: Iterable[Mapping[str, object]],
    output_dir: Optional[str] = None,
    filename: str = "firewall_blocklist.csv",
):
    """Generate a firewall blocklist CSV from correlation results.

    Args:
        data: A sequence of correlation result dictionaries.
        output_dir: Optional directory to write the file into (defaults to current dir).
        filename: Output filename.
    """

    firewall_ips = set()

    for record in data:
        if record.get("status") == "MATCH" and record.get("type") == "ip":
            severity = record.get("severity")
            indicator = record.get("indicator")
            if severity in ["critical", "high", "medium"] and indicator:
                firewall_ips.add(indicator)

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, filename)
    else:
        output_path = filename

    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Action"])
        for ip in sorted(firewall_ips):
            writer.writerow([ip, "Block"])

    print(f"[+] Firewall blocklist generated: {output_path}")
