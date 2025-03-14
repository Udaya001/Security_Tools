import aiohttp
import asyncio
from config.logger_config import logger
from utils.constants import SECURITY_HEADERS, SENSITIVE_FILES
from timing_decorator import measure_time

async def check_sensitive_files(target_url, session):
    """Check if sensitive files are accessible concurrently."""
    exposed_files = []

    async def check_file(file):
        file_url = f"{target_url.rstrip('/')}/{file}"
        try:
            async with session.get(file_url, timeout=1) as response:
                if response.status == 200:
                    exposed_files.append(file_url)
        except Exception as e:
            logger.debug(f"Error checking {file_url}: {str(e)}")

    await asyncio.gather(*(check_file(file) for file in SENSITIVE_FILES))
    return {"exposed_files": exposed_files} if exposed_files else {"message": "No sensitive files exposed"}

async def check_security_headers(target_url, session):
    """Check for missing security headers."""
    try:
        async with session.get(target_url, timeout=1) as response:
            headers = response.headers
            missing_headers = [header for header in SECURITY_HEADERS if header not in headers]

            return {"missing_headers": missing_headers} if missing_headers else {"message": "All security headers are present"}
    except Exception as e:
        return {"error": f"Failed to check security headers: {str(e)}"}

@measure_time
async def scan_server_misconfig(target_url):
    """Run all server misconfiguration checks in parallel with shared session."""
    timeout = aiohttp.ClientTimeout(total=1)  # Reduce timeout
    connector = aiohttp.TCPConnector(limit_per_host=5)  # Limit connections per host

    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        sensitive_files_task = check_sensitive_files(target_url, session)
        security_headers_task = check_security_headers(target_url, session)
        
        sensitive_files, security_headers = await asyncio.gather(
            sensitive_files_task, security_headers_task
        )

    return {
        "sensitive_files_check": sensitive_files,
        "security_headers_check": security_headers
    }
