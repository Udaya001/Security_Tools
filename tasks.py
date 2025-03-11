import uuid
import json
import asyncio
from celery_worker import celery_app
from vuln_scanner.ssl_scanner import check_ssl
from vuln_scanner.url_scanner import scan_url
from vuln_scanner.sqli_scanner import run_sql_alt
from vuln_scanner.xss_scanner import run_xss_scan
from vuln_scanner.server_misconfig_scanner import scan_server_misconfig
from vuln_scanner.network_scanner import run_network_scans
from vuln_scanner.dir_trav_scanner import run_dtscan
from vuln_scanner.cmd_inj_scanner import run_cmdscan
from vuln_scanner.csrf_scanner import scan_csrf
from config.config import logger  
from services.redis_service import redis_service  

@celery_app.task(bind=True)
def run_scan(self, target_url: str, mode: str):
    """Executes the scan asynchronously and stores results in Redis"""
    scan_id = str(uuid.uuid4())
    task_id = self.request.id

    logger.info(f"Received scan request: Task ID {task_id}, Scan ID {scan_id}, URL {target_url}, Mode {mode}")

    try:
        if mode.lower() not in ["security"]:
            raise ValueError(f"Invalid mode '{mode}'. Use only 'security'.")

        # Store initial status in Redis
        redis_service.set(task_id, scan_id)
        redis_service.set(scan_id, json.dumps({"status": "processing"}))  

        domain = target_url.split("//")[-1].split("/")[0]  # Extract domain from URL
        logger.info("Starting scans")

        # Run all scans asynchronously
        result = asyncio.run(execute_scan(domain, target_url, mode))

        # Ensure Redis is updated when scan completes
        if "status" in result and result["status"] == "error":
            redis_service.set(scan_id, json.dumps({"status": "error", "result": result}))
        else:
            redis_service.set(scan_id, json.dumps({"status": "completed", "result": result}))

        redis_service.set(task_id, scan_id)  # Ensure task_id and scan_id linkage
        logger.info(f"Scan completed successfully: Scan ID {scan_id}")

    except Exception as e:
        error_msg = str(e)
        redis_service.set(scan_id, json.dumps({"status": "error", "result": error_msg}))
        redis_service.set(task_id, scan_id)  # Store error state
        logger.error(f"Scan failed: Scan ID {scan_id}, Error: {error_msg}")

    return scan_id

async def execute_scan(domain: str, target_url: str, mode: str) -> dict:
    """Executes all security scans asynchronously"""
    scan_tasks = {}

    if mode == "security":
        scan_tasks["ssl_scan"] = asyncio.create_task(check_ssl(target_url))
        scan_tasks["url_scan"] = asyncio.create_task(scan_url(target_url))
        scan_tasks["sql_scan"] = asyncio.create_task(run_sql_alt(target_url))
        scan_tasks["xss_scan"] = asyncio.create_task(run_xss_scan(target_url))
        scan_tasks["misconfig_scan"] = asyncio.create_task(scan_server_misconfig(target_url))
        scan_tasks["network_scan"] = asyncio.create_task(run_network_scans(target_url))
        scan_tasks["dir_traversal"] = asyncio.create_task(run_dtscan(target_url, "file"))
        scan_tasks["command_injection"] = asyncio.create_task(run_cmdscan(target_url, "cmd"))
        scan_tasks["csrf_scan"] = asyncio.create_task(scan_csrf(target_url, "action"))

    try:
        results = await asyncio.gather(*scan_tasks.values(), return_exceptions=True)

        scan_results = {}
        scan_failed = False

        for task_name, result in zip(scan_tasks.keys(), results):
            if isinstance(result, Exception):
                logger.error(f"{task_name} failed with error: {result}")
                scan_results[task_name] = {"status": "error", "message": str(result)}
                scan_failed = True
            else:
                scan_results[task_name] = result

        logger.info(f"Scan completed for {target_url}. Results: {scan_results}")

        if scan_failed:
            return {"status": "error", "message": "One or more scans failed", "details": scan_results}
        
        return {"target_url": target_url, "status": "completed", **scan_results}

    except Exception as e:
        logger.error(f"Unexpected error during scan execution: {e}")
        return {"status": "error", "message": str(e)}
