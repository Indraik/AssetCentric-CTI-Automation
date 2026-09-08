import os
from typing import Type
from flask import Flask, session
from werkzeug.routing import BuildError
from flask import url_for as flask_url_for

from app.core.config import Config
from app.services.asset_service import load_user_settings
from app.services.stats_service import build_platform_stats


def create_app(config_class: Type[Config] = Config) -> Flask:
    """Application factory for AssetCentric CTI Automation."""
    app_dir = os.path.dirname(os.path.abspath(__file__))
    templates_dir = os.path.join(app_dir, "templates")
    static_dir = os.path.join(app_dir, "static")

    app = Flask(
        __name__,
        template_folder=templates_dir,
        static_folder=static_dir,
    )
    app.config.from_object(config_class)

    # Initialize runtime storage directories
    config_class.init_directories()

    # Register Blueprints
    from app.routes.views import views_bp
    from app.routes.analysis import analysis_bp
    from app.routes.api import api_bp
    from app.routes.downloads import downloads_bp

    app.register_blueprint(views_bp)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(downloads_bp)

    # Register root endpoint aliases for backward compatibility with templates/scripts
    # This allows both url_for('config') and url_for('views.config') to work identically.
    registered_endpoints = set()
    for rule in list(app.url_map.iter_rules()):
        if "." in rule.endpoint:
            short_name = rule.endpoint.split(".", 1)[1]
            if short_name not in app.view_functions and short_name not in registered_endpoints:
                try:
                    app.add_url_rule(
                        rule.rule,
                        endpoint=short_name,
                        view_func=app.view_functions[rule.endpoint],
                        methods=rule.methods,
                    )
                    registered_endpoints.add(short_name)
                except Exception:
                    pass

    # Expose session variables and platform stats globally to templates
    @app.context_processor
    def inject_session_vars():
        settings = load_user_settings()

        def _get(name, default=None):
            if name in session:
                return session.get(name)
            return settings.get(name, default)

        asset_type = _get("asset_type", "postgresql")
        port = _get("port", "5432")
        subnet = _get("subnet", "192.168.1.0/24")
        host = _get("host", "db.internal.corp")

        firewall_enabled = bool(_get("firewall"))
        edr_enabled = bool(_get("edr"))
        siem_enabled = bool(_get("siem"))
        enabled_controls = []
        if firewall_enabled:
            enabled_controls.append("Firewall")
        if edr_enabled:
            enabled_controls.append("EDR")
        if siem_enabled:
            enabled_controls.append("SIEM")

        platform_stats = build_platform_stats()

        session["asset_type"] = asset_type
        session["port"] = port
        session["subnet"] = subnet
        session["host"] = host

        if firewall_enabled:
            session["firewall"] = "on"
        if edr_enabled:
            session["edr"] = "on"
        if siem_enabled:
            session["siem"] = "on"

        return {
            "asset_type": asset_type,
            "port": port,
            "subnet": subnet,
            "host": host,
            "firewall_enabled": firewall_enabled,
            "edr_enabled": edr_enabled,
            "siem_enabled": siem_enabled,
            "enabled_controls": enabled_controls,
            "platform_stats": platform_stats,
        }

    # Jinja url_for fallback helper
    @app.context_processor
    def utility_processor():
        def smart_url_for(endpoint, **values):
            try:
                return flask_url_for(endpoint, **values)
            except BuildError:
                for prefix in ["views.", "analysis.", "api.", "downloads."]:
                    try:
                        return flask_url_for(prefix + endpoint, **values)
                    except BuildError:
                        continue
                raise
        return {"url_for": smart_url_for}

    return app
