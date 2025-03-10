import aiohttp
import re
import asyncio

# Pre-compiled regex patterns for efficiency and case-insensitivity
SUSPICIOUS_PATTERNS = [
    # Existing patterns
    re.compile(r"<iframe.*?>", re.IGNORECASE),
    re.compile(r"eval\([^)]*\)", re.IGNORECASE),
    re.compile(r"document\.write\([^)]*\)", re.IGNORECASE),
    re.compile(r"unescape\([^)]*\)", re.IGNORECASE),

    # New patterns
    # Malicious scripts and event handlers
    re.compile(r"<script.*?onerror\s*=\s*['\"][^'\"]*['\"].*?>", re.IGNORECASE),
    re.compile(r"<img.*?onerror\s*=\s*['\"][^'\"]*['\"].*?>", re.IGNORECASE),
    re.compile(r"on(mouse|click|load|error)\s*=\s*['\"][^'\"]*['\"]", re.IGNORECASE),

    # Obfuscation and encoding
    re.compile(r"data:text/javascript;base64", re.IGNORECASE),
    re.compile(r"atob\([^)]*\)|btoa\([^)]*\)", re.IGNORECASE),

    # Redirection and navigation
    re.compile(r"<meta\s+http-equiv\s*=\s*['\"]refresh['\"]\s+content\s*=\s*\d+;\s*url=", re.IGNORECASE),
    re.compile(r"window\.location\s*[=+]", re.IGNORECASE),

    # Client-side execution
    re.compile(r"alert\([^)]*\)|prompt\([^)]*\)|confirm\([^)]*\)", re.IGNORECASE),
    re.compile(r"expression\([^)]*\)", re.IGNORECASE),
    re.compile(r"window\.open\([^)]*\)", re.IGNORECASE),

    # Malicious elements
    re.compile(r"<a.*?href\s*=\s*['\"]javascript:[^'\"]*['\"].*?>", re.IGNORECASE),
    re.compile(r"javascript:[^ ]*", re.IGNORECASE),
    re.compile(r"innerHTML\s*[=+]", re.IGNORECASE)
]

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