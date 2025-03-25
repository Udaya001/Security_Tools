import os

class Config:
    """Centralized configuration for the application."""

    # General settings
    DEBUG = os.getenv("DEBUG", "True").lower() == "true"  # Convert string to boolean
    SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")

    # Redis Configuration
    REDIS_HOST = os.getenv("REDIS_HOST", "redis")  # Default to 'redis' for Docker
    REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))  # Default Redis port
    REDIS_DB = int(os.getenv("REDIS_DB", 1))  # Default Redis DB index
    REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)  # Optional Redis password

    # Other application-specific configurations can go here