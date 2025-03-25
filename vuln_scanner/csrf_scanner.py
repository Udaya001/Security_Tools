import asyncio
import aiohttp
from config.logger_config import logger
from utils.constants import CSRF_PAYLOADS
from timing_decorator import measure_time

async def check_csrf(target_url: str, param: str, payload: str, session: aiohttp.ClientSession) -> dict:
    """Check individual CSRF payload asynchronously"""
    test_url = f"{target_url}?{param}={payload}"
    result = {
        "url": test_url,
        "payload": payload,
        "vulnerable": False
    }

    try:
        # Simulate a POST request (common in CSRF attacks)
        async with session.post(
            target_url,
            data={param: payload},
            headers={"X-Requested-With": "XMLHttpRequest"},  # Common in AJAX requests
            timeout=0.3  # Reduced timeout for faster execution
        ) as response:
            content = await response.text()
            
            # Check for success indicators (customize based on target behavior)
            if (
                "Transaction successful" in content 
                or "Account deleted" in content 
                or response.status in [200, 201]
            ):
                result["vulnerable"] = True
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass  # Suppress errors to speed up execution
    
    return result

@measure_time
async def scan_csrf(target_url: str, param: str) -> dict:
    """Main CSRF scanning function using async requests"""
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=50, ttl_dns_cache=300)) as session:
        tasks = [check_csrf(target_url, param, payload, session) for payload in CSRF_PAYLOADS]
        
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
        "total_payloads": len(CSRF_PAYLOADS),
        "tested_urls": tested_urls
    }
