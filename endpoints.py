import redis
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from tasks import run_scan
import json
import os
from logs.logger_config import logger
from urllib.parse import urlparse

router = APIRouter()

# Use environment variables to get Redis host (for Docker compatibility)
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")  # Default to localhost for non-Docker environments
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "1"))  # Ensure this matches your Celery config

# Initialize Redis client
redis_client = None

def get_redis_client():
    """Create and return a Redis client."""
    global redis_client
    
    if redis_client is None:
        
        try:
            redis_client = redis.StrictRedis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                db=REDIS_DB,
                decode_responses=True
            )
            redis_client.ping()  # Ensure the Redis server is reachable
            
            logger.info(f"Connected to Redis at {REDIS_HOST}:{REDIS_PORT}, DB: {REDIS_DB}")
        except Exception as e:
            
            logger.error(f"Failed to connect to Redis: {e}")
            raise HTTPException(status_code=500, detail="Failed to connect to Redis")
    
    
    
    return redis_client

# Request Schema
class ScanRequest(BaseModel):
    target_url: str
    mode: Optional[str] = "both"

# Start a Scan (Runs in Celery)
@router.post("/scan/url")
async def start_scan(scan_request: ScanRequest):
    """Starts a scan and returns task_id."""
    try:
        # Validate the mode parameter
        if scan_request.mode not in [ "security"]:
            raise HTTPException(status_code=400, detail="Invalid mode parameter. Use 'security'")

        
        # Initialize Redis client
        redis_client = get_redis_client()
        

        # Run the scan task in Celery
        task = run_scan.apply_async(args=[scan_request.target_url, scan_request.mode])

        # Store the initial task status in Redis (clear existing data for the task)
        redis_client.setex(task.id, 3600, json.dumps({"status": "processing"}))  # Expires in 1 hour

        # Log the scan start
        logger.info(f"Scan started for {scan_request.target_url}, Task ID: {task.id}")

        return {
            "task_id": task.id,
            "message": f"Scan started. Use /api/scan/result/{task.id} to check status."
        }
    except HTTPException as he:
        logger.error(f"HTTPException starting scan: {he.detail}")
        raise he
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to start the scan")

# Check Scan Result
@router.get("/scan/result/{task_id}")
async def get_scan_result(task_id: str):
    """Fetches scan results using task_id."""
    try:
        # Initialize Redis client
        redis_client = get_redis_client()

        # Fetch the scan data from Redis
        scan_id = redis_client.get(task_id)

        scan_data = redis_client.get(scan_id)

        # If no data is found, the scan may still be processing
        if scan_data is None:
            logger.info(f"Scan for Task ID {task_id} is still processing.")
            return {"status": "processing", "message": "Scan is still in progress. Please check again later."}

        # Attempt to parse the stored JSON data
        try:
            scan_result = json.loads(scan_data)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode JSON from Redis for Task ID {task_id}: {e}")
            raise HTTPException(status_code=400, detail="Invalid scan result format")

        logger.info("Successfully loaded scan result data")

        # Optionally check for TTL (time-to-live) in Redis to see if the scan has expired
        ttl = redis_client.ttl(task_id)
        if ttl == -2:
            logger.warning(f"Scan for Task ID {task_id} does not exist in Redis.")
            raise HTTPException(status_code=404, detail="Scan result expired or does not exist")

        # Return the scan result as a response
        return scan_result

    except redis.RedisError as e:
        logger.error(f"Redis error occurred while fetching scan result for Task ID {task_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch scan result from Redis")
    except Exception as e:
        logger.error(f"Error fetching scan result for Task ID {task_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch scan result")