import csv
import os
from typing import Any, Dict, List


def load_csv_logs(file_path: str) -> List[Dict[str, Any]]:
    """Generic CSV log reader."""
    if not os.path.exists(file_path):
        return []

    logs = []
    try:
        with open(file_path, "r", newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                logs.append(row)
    except Exception:
        return []
    return logs


def load_firewall_logs(file_path: str) -> List[Dict[str, Any]]:
    return load_csv_logs(file_path)


def load_dns_logs(file_path: str) -> List[Dict[str, Any]]:
    return load_csv_logs(file_path)


def load_endpoint_logs(file_path: str) -> List[Dict[str, Any]]:
    return load_csv_logs(file_path)
