import os
from flask import Blueprint, send_from_directory

from app.core.config import Config

downloads_bp = Blueprint("downloads", __name__)


def _send_file(directory: str, filename: str):
    if os.path.exists(os.path.join(directory, filename)):
        return send_from_directory(directory, filename, as_attachment=True)
    return None


@downloads_bp.route("/download/firewall")
def download_firewall():
    res = _send_file(Config.UPLOAD_DIR, "firewall.log")
    return res or ("Firewall log not found", 404)


@downloads_bp.route("/download/endpoint")
def download_endpoint():
    res = _send_file(Config.UPLOAD_DIR, "endpoint.log")
    return res or ("Endpoint log not found", 404)


@downloads_bp.route("/download/web")
def download_web():
    res = _send_file(Config.UPLOAD_DIR, "web.log")
    return res or ("Web server log not found", 404)


@downloads_bp.route("/download/report")
def download_report():
    res = _send_file(Config.UPLOAD_DIR, "threat_report.pdf")
    return res or ("Threat report not found", 404)


@downloads_bp.route("/download/threat-feed")
def download_threat_feed():
    res = _send_file(Config.DATA_DIR, "normalized_threat_feed.json")
    return res or ("Normalized threat feed not found", 404)


@downloads_bp.route("/download/raw-feed")
def download_raw_feed():
    res = _send_file(Config.DATA_DIR, "raw_threat_feed.json")
    return res or ("Raw threat feed not found", 404)


@downloads_bp.route("/download/blocklist")
def download_blocklist():
    res = _send_file(Config.OUTPUT_DIR, "firewall_blocklist.csv")
    return res or ("Blocklist not found", 404)


@downloads_bp.route("/download/yara")
def download_yara():
    res = _send_file(Config.OUTPUT_DIR, "yara_rules.yar")
    return res or ("YARA rules not found", 404)


@downloads_bp.route("/download/correlation")
def download_correlation():
    res = _send_file(Config.OUTPUT_DIR, "correlation_results.json")
    return res or ("Correlation results not found", 404)
