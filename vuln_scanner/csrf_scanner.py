import asyncio
import aiohttp
from config.config import logger
from utils.constants import CSRF_PAYLOADS

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
            timeout=5
        ) as response:
            content = await response.text()
            
            # Check for success indicators (customize based on target behavior)
            if (
                "Transaction successful" in content 
                or "Account deleted" in content 
                or response.status in [200, 201]
            ):
                result["vulnerable"] = True
                logger.warning(f"VULNERABLE: {test_url} with payload '{payload}'")
            else:
                logger.info(f"Clean: {test_url} with payload '{payload}'")
                
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logger.error(f"Request failed for {test_url}: {str(e)}")
        result["error"] = str(e)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        result["error"] = str(e)
    
    return result

async def scan_csrf(target_url: str, param: str) -> dict:
    """Main CSRF scanning function using async requests"""
    async with aiohttp.ClientSession() as session:
        tasks = []
        vulnerable_entries = []
        
        for payload in CSRF_PAYLOADS:
            task = asyncio.create_task(check_csrf(target_url, param, payload, session))
            tasks.append(task)
        
        # Gather all results
        results = await asyncio.gather(*tasks)
        
        # Extract vulnerable entries
        for res in results:
            if res.get("vulnerable", False):
                vulnerable_entries.append({
                    "url": res["url"],
                    "payload": res["payload"]
                })
    
    return {
        "status": "success" if vulnerable_entries else "no_vulnerabilities",
        "vulnerable_entries": vulnerable_entries,
        "total_payloads": len(CSRF_PAYLOADS),
        "tested_urls": [res["url"] for res in results]
    }
