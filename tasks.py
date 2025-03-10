import uuid
import redis
import json
import asyncio
import os
from celery_worker import celery_app
from vuln_scanner.ssl_scanner import check_ssl
from vuln_scanner.url_scanner import scan_url
from vuln_scanner.sqli_scanner import run_sqlmap_alt
from vuln_scanner.xss_scanner import run_xss_scan
from vuln_scanner.server_misconfig_scanner import scan_server_misconfig
from vuln_scanner.network_scanner import run_network_scans
from vuln_scanner.dir_trav_scanner import run_dtscan
from vuln_scanner.cmd_inj_scanner import run_cmdscan
from vuln_scanner.csrf_scanner import scan_csrf
from logs.logger_config import logger

# Redis Configuration
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "1"))

# Redis Connection (with error handling)
def get_redis_connection():
    try:
        redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)
        redis_client.ping()  # Ensure the Redis server is reachable
        logger.info(f"Connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
        return redis_client
    except redis.ConnectionError as e:
        logger.error(f"Failed to connect to Redis: {e}")
        raise Exception("Redis connection failed. Check your Redis server.")

redis_client = get_redis_connection()

@celery_app.task(bind=True)
def run_scan(self, target_url: str, mode: str):
    """Executes the scan asynchronously and stores results in Redis"""
    scan_id = str(uuid.uuid4())
    task_id = self.request.id

    logger.info(f"Received scan request: Task ID {task_id}, Scan ID {scan_id}, URL {target_url}, Mode {mode}")

    try:
        if mode not in ["security"]:
            raise ValueError(f"Invalid mode '{mode}'. Use only 'security'.")

        # Store initial status in Redis
        redis_client.set(task_id, scan_id)
        redis_client.set(scan_id, json.dumps({"status": "processing"}))

        domain = target_url.split("//")[-1].split("/")[0]  # Extract domain from URL

        logger.info("Starting scans")

        # Run all scans asynchronously
        result = asyncio.run(execute_scan(domain, target_url, mode))  # FIXED: Use asyncio.run()

        # Store completed result in Redis
        redis_client.set(scan_id, json.dumps({"status": "completed", "result": result}))
        redis_client.set(task_id, scan_id)  # Make sure task_id and scan_id are both linked

        logger.info(f"Scan completed successfully: Scan ID {scan_id}")

    except Exception as e:
        error_msg = str(e)
        redis_client.set(scan_id, json.dumps({"status": "error", "result": error_msg}))
        redis_client.set(task_id, scan_id)  # Store error state
        logger.error(f"Scan failed: Scan ID {scan_id}, Error: {error_msg}")

    return scan_id

async def execute_scan(domain: str, target_url: str, mode: str) -> dict:
    """Executes all security and malware scans asynchronously"""
    scan_tasks = {}

    if mode in ["security"]:
        # Create async tasks for each security scan
        scan_tasks["ssl_scan"] = asyncio.create_task(check_ssl(target_url))
        scan_tasks["url_scan"] = asyncio.create_task(scan_url(target_url))
        scan_tasks["sql_scan"] = asyncio.create_task(run_sqlmap_alt(target_url))
        scan_tasks["xss_scan"] = asyncio.create_task(run_xss_scan(target_url))
        scan_tasks["misconfig_scan"] = asyncio.create_task(scan_server_misconfig(target_url))
        scan_tasks["network_scan"] = asyncio.create_task(run_network_scans(target_url))
        
        # Directory Traversal (with parameter)
        scan_tasks["dir_traversal"] = asyncio.create_task(
            run_dtscan(target_url, "file")  # Use parameter from scan_config if needed
        )
        
        # Command Injection (with parameter)
        scan_tasks["command_injection"] = asyncio.create_task(
            run_cmdscan(target_url, "cmd")  # Use parameter from scan_config if needed
        )
        
        # CSRF Scan (new addition)
        scan_tasks["csrf_scan"] = asyncio.create_task(
            scan_csrf(target_url, "action")  # Use parameter from scan_config if needed
        )

    # if mode in ["both", "malware"]:
    #     scan_tasks["malware_scan"] = asyncio.create_task(scan_urls([target_url]))

    try:
        # Run all tasks concurrently
        results = await asyncio.gather(*scan_tasks.values(), return_exceptions=True)

        # Process results and handle exceptions
        scan_results = {}
        for task_name, result in zip(scan_tasks.keys(), results):
            if isinstance(result, Exception):
                logger.error(f"{task_name} failed with error: {result}")
                scan_results[task_name] = {"status": "error", "message": str(result)}
            else:
                scan_results[task_name] = result

        logger.info(f"Scan completed for {target_url}. Results: {scan_results}")
        return {"target_url": target_url, **scan_results}
    
    except Exception as e:
        logger.error(f"Unexpected error during scan execution: {e}")
        return {"status": "error", "message": str(e)}