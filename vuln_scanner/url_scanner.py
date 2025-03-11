import aiohttp
import asyncio
from utils.constants import SUSPICIOUS_PATTERNS

async def scan_url(target_url: str):
    """Scan URL for security risks with expanded pattern coverage."""
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(target_url, timeout=10) as response:
                if not str(response.status).startswith('2'):
                    return {
                        "status": "error",
                        "message": f"HTTP {response.status}: Request failed",
                        "target_url": target_url
                    }

                content_type = response.headers.get("Content-Type", "").lower()
                if not content_type.startswith("text/html"):
                    return {
                        "status": "error",
                        "message": "Non-HTML content type received",
                        "target_url": target_url
                    }

                html_content = await response.text(errors="ignore")
                
                risks_found = []
                for pattern in SUSPICIOUS_PATTERNS:
                    if pattern.search(html_content):
                        risks_found.append(pattern.pattern)

                return {
                    "status": "success",
                    "message": "Scan completed successfully",
                    "target_url": target_url,
                    "risks_detected": risks_found if risks_found else "No major risks found"
                }

        except aiohttp.ClientConnectionError as e:
            return {
                "status": "error",
                "message": f"Connection error: {str(e)}",
                "target_url": target_url
            }
        except asyncio.TimeoutError:
            return {
                "status": "error",
                "message": "Request timed out",
                "target_url": target_url
            }
        except (aiohttp.InvalidURL, ValueError) as e:
            return {
                "status": "error",
                "message": f"Invalid URL format: {str(e)}",
                "target_url": target_url
            }
        except Exception as e:
            return {
                "status": "error",
                "message": f"Unexpected error: {str(e)}",
                "target_url": target_url
            }