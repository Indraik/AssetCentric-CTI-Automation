import os


class Config:
    """Centralized configuration for AssetCentric CTI Automation."""

    # Base Paths
    # Root of the repository (parent of app/)
    ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    # Isolated Storage Directories
    STORAGE_DIR = os.path.join(ROOT_DIR, "storage")
    DATA_DIR = os.path.join(STORAGE_DIR, "data")
    UPLOAD_DIR = os.path.join(STORAGE_DIR, "uploads")
    OUTPUT_DIR = os.path.join(STORAGE_DIR, "outputs")
    LOG_DIR = os.path.join(STORAGE_DIR, "logs")

    # Fallback/Legacy Paths (for backward compatibility)
    LEGACY_DATA_DIR = os.path.join(ROOT_DIR, "data")
    LEGACY_UPLOAD_DIR = os.path.join(ROOT_DIR, "uploads")
    LEGACY_OUTPUT_DIR = os.path.join(ROOT_DIR, "outputs")
    LEGACY_LOG_DIR = os.path.join(ROOT_DIR, "logs")

    # Data File Paths
    RAW_FEED_PATH = os.path.join(DATA_DIR, "raw_threat_feed.json")
    NORMALIZED_FEED_PATH = os.path.join(DATA_DIR, "normalized_threat_feed.json")
    USER_SETTINGS_PATH = os.path.join(DATA_DIR, "user_settings.json")
    LOG_FILE_PATH = os.path.join(LOG_DIR, "threat_pipeline.log")

    # Flask Settings
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")
    UPLOAD_FOLDER = UPLOAD_DIR
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload

    # Threat Intelligence Settings
    MAX_INDICATORS_PER_FEED = int(os.getenv("MAX_INDICATORS_PER_FEED", "100"))
    ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/blacklist"
    URLHAUS_FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    THREATFOX_FEED_URL = "https://threatfox.abuse.ch/export/json/recent/"

    ABUSEIPDB_API_KEY_PLACEHOLDER = "ABUSEIPDB_API_KEY_PLACEHOLDER"
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", ABUSEIPDB_API_KEY_PLACEHOLDER).strip()

    @classmethod
    def is_abuseipdb_configured(cls) -> bool:
        return bool(cls.ABUSEIPDB_API_KEY) and cls.ABUSEIPDB_API_KEY != cls.ABUSEIPDB_API_KEY_PLACEHOLDER

    @classmethod
    def init_directories(cls):
        """Ensure all required runtime storage directories exist."""
        for path in [cls.DATA_DIR, cls.UPLOAD_DIR, cls.OUTPUT_DIR, cls.LOG_DIR]:
            os.makedirs(path, exist_ok=True)
