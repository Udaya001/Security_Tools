import logging
import os

# Ensure logs directory exists
os.makedirs("logs", exist_ok=True)

# Create log formatter
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Console handler (Logs to terminal)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(log_formatter)

# File handler (Logs to file)
file_handler = logging.FileHandler("logs/scan_logs.log", mode='a', encoding='utf-8')  # Append mode
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(log_formatter)

# Get logger and prevent duplicate handlers
logger = logging.getLogger("vuln_scanner")  # Use a unique name for the logger
if not logger.hasHandlers():  # Avoid duplicate handlers
    logger.setLevel(logging.INFO)
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

# Function to force log flushing
def force_flush_logs():
    for handler in logger.handlers:
        if hasattr(handler, "flush"):
            handler.flush()

# Log initialization message
logger.info("✅ Logging system initialized.")

# Force flushing logs after initialization
force_flush_logs()

# To ensure the log file is updated properly, you can call `force_flush_logs` after any log statement:
# Example usage:
logger.info("This is an info log.")
force_flush_logs()  # Ensure it is written to the file immediately.
