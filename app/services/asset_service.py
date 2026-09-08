import json
import os
from typing import Any, Dict

from app.core.config import Config


def load_user_settings() -> Dict[str, Any]:
    """Load persisted user asset settings from storage."""
    target_path = Config.USER_SETTINGS_PATH
    if not os.path.exists(target_path):
        legacy = os.path.join(Config.LEGACY_DATA_DIR, "user_settings.json")
        if os.path.exists(legacy):
            target_path = legacy
        else:
            return {}

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def save_user_settings(settings: Dict[str, Any]) -> bool:
    """Persist user asset settings to storage."""
    Config.init_directories()
    try:
        with open(Config.USER_SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)

        # Legacy copy for compatibility
        os.makedirs(Config.LEGACY_DATA_DIR, exist_ok=True)
        with open(os.path.join(Config.LEGACY_DATA_DIR, "user_settings.json"), "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)
        return True
    except Exception:
        return False
