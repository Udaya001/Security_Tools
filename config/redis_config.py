import os
import redis
from config.logger_config import logger

# Redis Configuration (loaded from environment variables)
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "1"))

def get_redis_connection():
    """Initialize and return a Redis connection."""
    try:
        client = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            decode_responses=True
        )
        client.ping()  # Ensure the Redis server is reachable
        logger.info(f"Connected to Redis at {REDIS_HOST}:{REDIS_PORT}, DB: {REDIS_DB}")
        return client
    except redis.ConnectionError as e:
        logger.error(f"Failed to connect to Redis: {e}")
        raise Exception("Redis connection failed. Check your Redis server.")

# Create a Redis client instance for direct imports
redis_client = get_redis_connection()
