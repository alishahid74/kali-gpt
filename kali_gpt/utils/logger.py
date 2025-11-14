"""Logging utilities"""

import logging
import sys
from pathlib import Path
from datetime import datetime

def setup_logger(name: str = "kali-gpt", log_dir: str = "~/.kali-gpt") -> logging.Logger:
    """Setup logger with file and console handlers"""

    log_path = Path(log_dir).expanduser()
    log_path.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # Remove existing handlers
    logger.handlers = []

    # File handler
    log_file = log_path / f"kali-gpt-{datetime.now().strftime('%Y-%m-%d')}.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)

    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
