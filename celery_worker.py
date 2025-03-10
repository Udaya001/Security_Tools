from celery import Celery
import os
from logs.logger_config import logger
from redis import Redis

# Redis Configuration
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")  # Default to 'localhost'
REDIS_PORT = os.getenv("REDIS_PORT", "6379")  # Default to '6379' (string)
REDIS_DB = os.getenv("REDIS_DB", "1")  # Default to '1' (string)

# Convert Redis Port and DB to Integer
REDIS_PORT = int(REDIS_PORT)
REDIS_DB = int(REDIS_DB)

# Log Redis Connection Info
logger.debug(f"Connecting to Redis at {REDIS_HOST}:{REDIS_PORT}, DB: {REDIS_DB}")

# Celery Configuration
celery_app = Celery(
    "tasks",
    broker=f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}",
    backend=f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}",
    include=["tasks"]
)

# Add Celery Configurations
celery_app.conf.update(
    task_routes={
        "tasks.run_scan": {"queue": "scanning"}
    },
    task_serializer="json",
    accept_content=["json"],
    result_expires=3600,
)

# Test Redis Connection
try:
    redis_client = Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)
    redis_client.ping()
    logger.info("Successfully connected to Redis.")
except Exception as e:
    logger.error(f"Error connecting to Redis: {e}")
    raise Exception("Unable to connect to Redis. Please check your configuration.")
