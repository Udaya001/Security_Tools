from celery import Celery
from services.redis_service import redis_service
import os

# Fetch Redis connection details from RedisService
redis_config = redis_service.get_connection_details()
REDIS_HOST = redis_config["host"]
REDIS_PORT = redis_config["port"]
REDIS_DB = redis_config["db"]

# Define the Redis URL for Celery
REDIS_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"

# Initialize Celery
celery_app = Celery(
    "tasks",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["tasks"]
)

celery_app.conf.update(
    task_routes={
        "tasks.run_scan": {"queue": "scanning"}
    },
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    result_expires=3600,
)
