import asyncio
import aiohttp
from config.logger_config import logger
from utils.constants import DIR_PAYLOADS
from timing_decorator import measure_time

MAX_CONCURRENT_REQUESTS = 10  # Limit concurrency to avoid overloading

async def check_directory_traversal(target_url: str, param: str, payload: str, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore) -> dict:
    """Check individual payload and return formatted result"""
    async with semaphore:
        test_url = f"{target_url}?{param}={payload}"
        result = {
            "url": test_url,
            "vulnerable": False
        }
        
        try:
            async with session.get(test_url, timeout=3) as response:
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
    connector = aiohttp.TCPConnector(limit_per_host=MAX_CONCURRENT_REQUESTS)
    async with aiohttp.ClientSession(connector=connector) as session:
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        tasks = [check_directory_traversal(target_url, param, payload, session, semaphore) for payload in DIR_PAYLOADS]
        
        results = await asyncio.gather(*tasks)
        
        # Extract vulnerable URLs
        vulnerable_urls = [res["url"] for res in results if res.get("vulnerable", False)]
    
    return {
        "status": "success" if vulnerable_urls else "no_vulnerabilities",
        "vulnerable_urls": vulnerable_urls,
        "total_payloads": len(DIR_PAYLOADS),
        "tested_urls": [res["url"] for res in results]
    }

@measure_time
async def run_dtscan(target_url: str, param: str) -> dict:
    """Entry point for the scan (async)"""
    logger.info(f"Starting directory traversal scan for {target_url}")
    scan_result = await scan_directory_traversal(target_url, param)
    logger.info(f"Scan completed. Results: {scan_result}")
    return scan_result

def run_dtscan_sync(target_url: str, param: str) -> dict:
    """Synchronous wrapper for the scan"""
    return asyncio.run(run_dtscan(target_url, param))
