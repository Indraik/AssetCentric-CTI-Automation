import json
import os

from config.settings import USER_SETTINGS_PATH


def load_user_settings():
    """Load persisted user settings.

    Returns a dict. If the settings file is missing or malformed, returns an empty dict.
    """

    if not os.path.exists(USER_SETTINGS_PATH):
        return {}

    try:
        with open(USER_SETTINGS_PATH, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        # If the file is corrupted or unreadable, ignore and start fresh.
        return {}


def save_user_settings(settings: dict):
    """Persist user settings to disk."""

    os.makedirs(os.path.dirname(USER_SETTINGS_PATH), exist_ok=True)
    try:
        with open(USER_SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)
    except Exception:
        # Best-effort persistence; ignore write failures.
        pass
