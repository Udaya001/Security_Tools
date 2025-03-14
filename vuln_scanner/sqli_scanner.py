import asyncio
import aiohttp
import time
from urllib.parse import urlparse, parse_qs, urlencode
from utils.constants import SQLI_PAYLOADS, SQLI_ERROR_KEYWORDS
from timing_decorator import measure_time

@measure_time
async def run_sql_alt(target_url: str):
    parsed_url = urlparse(target_url)
    query_params = parse_qs(parsed_url.query)

    if not query_params:
        return {"status": "success", "message": "No parameters found"}

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=50, ttl_dns_cache=300)) as session:
        try:
            async with session.get(target_url, timeout=1) as original_resp:
                original_response = await original_resp.text()
        except:
            return {"status": "error", "message": "Connection failed"}

        async def test_parameter(param, session, original_response):
            original_value = query_params[param][0]

            async def send_request(payload):
                modified_params = {k: v for k, v in query_params.items()}
                modified_params[param] = [payload]
                modified_url = parsed_url._replace(query=urlencode(modified_params, doseq=True)).geturl()
                
                try:
                    start_time = time.time()
                    async with session.get(modified_url, timeout=0.5) as resp:
                        response_text = await resp.text()
                        duration = time.time() - start_time
                        return response_text, duration, modified_url
                except:
                    return None, None, None

            for payload in SQLI_PAYLOADS:
                response_text, duration, modified_url = await send_request(payload)
                if not response_text:
                    continue
                
                if any(kw in response_text for kw in SQLI_ERROR_KEYWORDS):
                    return {"vulnerable": True, "type": "error-based", "payload": payload, "url": modified_url}
                if len(response_text) != len(original_response):
                    return {"vulnerable": True, "type": "boolean-based", "payload": payload, "url": modified_url}
                if duration > 0.4 and "SLEEP" in payload:
                    return {"vulnerable": True, "type": "time-based", "payload": payload, "url": modified_url}

            return {"vulnerable": False}

        tasks = [test_parameter(param, session, original_response) for param in query_params]
        results = await asyncio.gather(*tasks)
        
        scan_results = {param: result for param, result in zip(query_params.keys(), results) if result.get("vulnerable")}

    return {"status": "success", "message": "Scan completed", "scan_results": scan_results}