from web_app import app

# This script validates that our templates are renderable.
# Some templates rely on context variables that are only available at runtime.
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

with app.test_request_context('/'):
    for tmpl in ['index.html', 'config.html', 'upload.html', 'dashboard.html']:
        try:
            context = dict(BASE_CONTEXT)
            if tmpl == 'dashboard.html':
                context.update(DASHBOARD_CONTEXT)
            app.jinja_env.get_template(tmpl).render(**context)
            print('OK', tmpl)
        except Exception as e:
            print('ERROR', tmpl, e)
            raise
