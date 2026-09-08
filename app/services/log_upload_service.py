import os
import shutil
from typing import Any, Dict, Optional

from app.core.config import Config


def validate_required_uploads(files: Dict[str, Any], enabled_controls: Dict[str, bool]) -> Optional[str]:
    """Validate that required logs are present based on enabled controls."""
    required = []
    if enabled_controls.get("firewall"):
        required.append(("firewall_log", "Firewall log"))
    if enabled_controls.get("siem"):
        required.append(("siem_log", "SIEM log"))

    missing = []
    for field, label in required:
        fileobj = files.get(field)
        if not fileobj or not getattr(fileobj, "filename", None):
            missing.append(label)

    if missing:
        return (
            "Missing required uploads: " + ", ".join(missing) + ". "
            "Please provide the required log files before continuing."
        )
    return None


def save_uploaded_logs(files: Dict[str, Any]) -> None:
    """Save and stage uploaded log files into storage directory."""
    Config.init_directories()

    firewall_log = files.get("firewall_log")
    edr_log = files.get("edr_log")
    siem_log = files.get("siem_log")
    endpoint_log = files.get("endpoint_log")
    web_log = files.get("web_log")

    if firewall_log and getattr(firewall_log, "filename", None):
        primary_csv = os.path.join(Config.UPLOAD_DIR, "firewall_logs.csv")
        primary_log = os.path.join(Config.UPLOAD_DIR, "firewall.log")
        firewall_log.save(primary_csv)
        shutil.copyfile(primary_csv, primary_log)

    if edr_log and getattr(edr_log, "filename", None):
        endpoint_csv = os.path.join(Config.UPLOAD_DIR, "endpoint_logs.csv")
        edr_path = os.path.join(Config.UPLOAD_DIR, "edr.edf")
        edr_log.save(endpoint_csv)
        shutil.copyfile(endpoint_csv, edr_path)

    if siem_log and getattr(siem_log, "filename", None):
        dns_csv = os.path.join(Config.UPLOAD_DIR, "dns_logs.csv")
        siem_path = os.path.join(Config.UPLOAD_DIR, "siem.log")
        siem_log.save(dns_csv)
        shutil.copyfile(dns_csv, siem_path)

    if endpoint_log and getattr(endpoint_log, "filename", None):
        endpoint_csv = os.path.join(Config.UPLOAD_DIR, "endpoint_logs.csv")
        endpoint_path = os.path.join(Config.UPLOAD_DIR, "endpoint.log")
        endpoint_log.save(endpoint_csv)
        shutil.copyfile(endpoint_csv, endpoint_path)

    if web_log and getattr(web_log, "filename", None):
        web_path = os.path.join(Config.UPLOAD_DIR, "web.log")
        web_log.save(web_path)
