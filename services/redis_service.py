import redis
from config.config import Config
from config.logger_config import logger


class RedisService:
    """Handles Redis-related services."""

    def __init__(self):
        # Get Redis connection details from the centralized Config class
        self.host = Config.REDIS_HOST
        self.port = Config.REDIS_PORT
        self.db = Config.REDIS_DB
        self.password = Config.REDIS_PASSWORD

        self.client = self.connect_to_redis()

    def connect_to_redis(self):
        """Initialize and return a Redis connection."""
        try:
            client = redis.Redis(
                host=self.host,
                port=self.port,
                db=self.db,
                password=self.password,
                decode_responses=True
            )
            client.ping()  # Ensure Redis is reachable
            logger.info(f"Connected to Redis at {self.host}:{self.port}, DB: {self.db}")
            return client
        except redis.ConnectionError as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise Exception("Redis connection failed. Check your Redis server.")

    def get_connection_details(self):
        """Return Redis connection details."""
        return {
            "host": self.host,
            "port": self.port,
            "db": self.db,
            "password": "******" if self.password else None  # Mask password for security
        }

    def set(self, key, value):
        """Set a key in Redis."""
        return self.client.set(key, value)

    def setex(self, key, time, value):
        """Set a key with an expiration time in Redis."""
        return self.client.setex(key, time, value)

    def get(self, key):
        """Get a value from Redis."""
        return self.client.get(key)

    def delete(self, key):
        """Delete a key from Redis."""
        return self.client.delete(key)
    
    def ttl(self, key):
        """Get the remaining time-to-live (TTL) of a key in Redis."""
        return self.client.ttl(key)


# Create an instance for direct import
redis_service = RedisService()