import asyncio
import aiohttp
from config.logger_config import logger
from utils.constants import CMD_PAYLOADS
from timing_decorator import measure_time

async def check_command_injection(target_url: str, param: str, payload: str, session: aiohttp.ClientSession) -> dict:
    """Check individual payload and return formatted result"""
    test_url = f"{target_url}?{param}={payload}"
    result = {
        "url": test_url,
        "payload": payload,
        "vulnerable": False
    }
    
    try:
        async with session.get(target_url, params={param: payload}, timeout=0.3) as response:
            content = await response.text()
            
            # Check for vulnerability indicators
            if any(keyword in content for keyword in ["uid=", "root", "vulnerable", "groups=0"]):
                result["vulnerable"] = True
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass  # Suppress errors to speed up execution
    
    return result

async def scan_command_injection(target_url: str, param: str) -> dict:
    """Main scanning function using async requests"""
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=50, ttl_dns_cache=300)) as session:
        tasks = [check_command_injection(target_url, param, payload, session) for payload in CMD_PAYLOADS]
        
        vulnerable_entries = []
        tested_urls = []
        
        for future in asyncio.as_completed(tasks):
            res = await future
            tested_urls.append(res["url"])
            if res.get("vulnerable", False):
                vulnerable_entries.append({
                    "url": res["url"],
                    "payload": res["payload"]
                })
    
    return {
        "status": "success" if vulnerable_entries else "no_vulnerabilities",
        "vulnerable_entries": vulnerable_entries,
        "total_payloads": len(CMD_PAYLOADS),
        "tested_urls": tested_urls
    }

@measure_time
async def run_cmdscan(target_url: str, param: str) -> dict:
    """Entry point for the scan (async)"""
    logger.info(f"Starting command injection scan for {target_url}")
    scan_result = await scan_command_injection(target_url, param)
    logger.info(f"Scan completed.")
    return scan_result

def run_cmdscan_sync(target_url: str, param: str) -> dict:
    """Synchronous wrapper for the scan"""
    return asyncio.run(run_cmdscan(target_url, param))
