import logging
import os

def setup_logger():
    """Set up application logging."""
    log_directory = "logs"
    os.makedirs(log_directory, exist_ok=True)

    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # Console handler (Logs to terminal)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(log_formatter)

    # File handler (Logs to file)
    log_file = os.path.join(log_directory, "scan_logs.log")
    file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(log_formatter)

    # Get logger and prevent duplicate handlers
    logger = logging.getLogger("vuln_scanner")
    if not logger.hasHandlers():
        logger.setLevel(logging.INFO)
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)

    return logger

# Initialize logger
logger = setup_logger()
logger.info("Logging system initialized.")