import aiohttp
import asyncio
from config.logger_config import logger
from utils.constants import SECURITY_HEADERS,SENSITIVE_FILES

async def check_sensitive_files(target_url):
    """Check if sensitive files are accessible"""
    async with aiohttp.ClientSession() as session:
        exposed_files = []

        for file in SENSITIVE_FILES:
            file_url = f"{target_url.rstrip('/')}/{file}"
            try:
                async with session.get(file_url, timeout=5) as response:
                    if response.status == 200:
                        exposed_files.append(file_url)
            except Exception as e:
                logger.error(f"Error checking {file_url}: {str(e)}")

        return {"exposed_files": exposed_files} if exposed_files else {"message": "No sensitive files exposed"}

async def check_security_headers(target_url):
    """Check for missing security headers"""
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(target_url, timeout=5) as response:
                headers = response.headers
                missing_headers = [header for header in SECURITY_HEADERS if header not in headers]

                return {"missing_headers": missing_headers} if missing_headers else {"message": "All security headers are present"}

        except Exception as e:
            return {"error": f"Failed to check security headers: {str(e)}"}

async def scan_server_misconfig(target_url):
    """Run all server misconfiguration checks"""
    sensitive_files = await check_sensitive_files(target_url)
    security_headers = await check_security_headers(target_url)

    return {
        "target_url": target_url,
        "sensitive_files_check": sensitive_files,
        "security_headers_check": security_headers
    }
