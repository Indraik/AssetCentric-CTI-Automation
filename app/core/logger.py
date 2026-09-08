import logging
import os
from app.core.config import Config


def setup_logger(name: str = "ThreatIntelPipeline") -> logging.Logger:
    """Setup and configure a structured logger."""
    Config.init_directories()

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    if not logger.handlers:
        file_handler = logging.FileHandler(Config.LOG_FILE_PATH, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    return logger
