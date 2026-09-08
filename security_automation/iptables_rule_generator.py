import csv
import os
from typing import Optional


def generate_firewall_rules(
    blocklist_path: str = "firewall_blocklist.csv",
    output_dir: Optional[str] = None,
    filename: str = "firewall_rules.log",
):
    """Generate firewall rules based on the firewall blocklist CSV."""

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, filename)
    else:
        output_path = filename

    with open(blocklist_path) as file:
        reader = csv.DictReader(file)

        with open(output_path, "w") as log_file:
            for row in reader:
                ip = row.get("IP")
                if not ip:
                    continue
                rule = f"iptables -A INPUT -s {ip} -j DROP"
                log_file.write(rule + "\n")

    return output_path


if __name__ == "__main__":
    generate_firewall_rules()
