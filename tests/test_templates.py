import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from wsgi import app

BASE_CONTEXT = {
    "asset_type": "postgresql",
    "port": "5432",
    "subnet": "192.168.1.0/24",
    "host": "db.internal.corp",
    "firewall_enabled": True,
    "edr_enabled": False,
    "siem_enabled": False,
    "enabled_controls": ["Firewall"],
    "logs_uploaded": False,
    "platform_stats": {
        "uploads": {"files_uploaded": 0, "preview_rows": []},
        "feed": {"indicators": 0, "suspicious_ips": 0, "active_sources": 0, "top_indicators": []},
        "correlation": {"matches": 0, "unique_ip_matches": 0},
        "outputs": {"blocklist_exists": False, "yara_exists": False},
    },
}

DASHBOARD_CONTEXT = {
    "metrics": {"indicators": 0, "high_confidence": 0, "suspicious_ips": 0, "domains": 0, "risk": "LOW", "total_logs": 0},
    "trends": {"indicators": "stable", "high_confidence": "stable", "suspicious_ips": "stable"},
    "threat_score": 0,
    "risk_meta": {"icon": "🟢", "label": "No active exploitation detected", "color": "green"},
    "indicators": [],
    "sources": [],
    "distribution": {"ip": 0, "domain": 0, "hash": 0, "url": 0},
    "timeline": [],
    "pipeline_last_run": None,
}


def test_template_rendering():
    with app.test_request_context("/"):
        for tmpl in ["index.html", "config.html", "upload.html", "dashboard.html"]:
            context = dict(BASE_CONTEXT)
            if tmpl == "dashboard.html":
                context.update(DASHBOARD_CONTEXT)
            rendered = app.jinja_env.get_template(tmpl).render(**context)
            assert len(rendered) > 0, f"Template {tmpl} rendered empty"
            print(f"[+] Template render validated: {tmpl}")


if __name__ == "__main__":
    test_template_rendering()
    print("All templates rendered successfully!")
