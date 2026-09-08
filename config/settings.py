import os


# ==============================
# Threat Intelligence Settings
# ==============================

MAX_INDICATORS_PER_FEED = 100


# ==============================
# Threat Feed URLs
# ==============================

ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/blacklist"

URLHAUS_FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

THREATFOX_FEED_URL = "https://threatfox.abuse.ch/export/json/recent/"


# ==============================
# File Paths
# ==============================

# Resolve paths relative to this config file to avoid issues when the module is used from another working directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_DIR = os.path.join(BASE_DIR, "data")
LOG_DIR = os.path.join(BASE_DIR, "logs")

RAW_FEED_PATH = os.path.join(DATA_DIR, "raw_threat_feed.json")

NORMALIZED_FEED_PATH = os.path.join(DATA_DIR, "normalized_threat_feed.json")

# User settings persistence (asset/config defaults)
USER_SETTINGS_PATH = os.path.join(DATA_DIR, "user_settings.json")


# ==============================
# Logging
# ==============================

LOG_FILE_PATH = os.path.join(LOG_DIR, "threat_pipeline.log")