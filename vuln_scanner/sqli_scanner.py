import asyncio
import aiohttp
import time
from urllib.parse import urlparse, parse_qs, urlencode
from utils.constants import SQLI_PAYLOADS, SQLI_ERROR_KEYWORDS
from timing_decorator import measure_time
import logging

# Setting up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@measure_time
async def run_sql_alt(target_url: str):
    parsed_url = urlparse(target_url)
    query_params = parse_qs(parsed_url.query)

    if not query_params:
        logger.info("No parameters found")
        return {"status": "success", "message": "No parameters found"}

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=50, ttl_dns_cache=300)) as session:
        try:
            async with session.get(target_url, timeout=5) as original_resp:
                original_response = await original_resp.text()
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.error(f"Connection failed: {e}")
            return {"status": "error", "message": f"Connection failed: {e}"}

        async def test_parameter(param, session, original_response):
            original_value = query_params[param][0]

            async def send_request(payload):
                modified_params = {k: v for k, v in query_params.items()}
                modified_params[param] = [payload]
                modified_url = parsed_url._replace(query=urlencode(modified_params, doseq=True)).geturl()

                try:
                    start_time = time.time()
                    async with session.get(modified_url, timeout=2) as resp:
                        response_text = await resp.text()
                        duration = time.time() - start_time
                        return response_text, duration, modified_url
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    logger.error(f"Request failed for {modified_url}: {e}")
                    return None, None, None

            for payload in SQLI_PAYLOADS:
                response_text, duration, modified_url = await send_request(payload)
                if not response_text:
                    continue

                if any(kw in response_text for kw in SQLI_ERROR_KEYWORDS):
                    logger.info(f"Vulnerable to error-based SQL injection via {param} with payload: {payload}")
                    return {"vulnerable": True, "type": "error-based", "payload": payload, "url": modified_url}
                if len(response_text) != len(original_response):
                    logger.info(f"Vulnerable to boolean-based SQL injection via {param} with payload: {payload}")
                    return {"vulnerable": True, "type": "boolean-based", "payload": payload, "url": modified_url}
                if duration > 0.4 and "SLEEP" in payload:
                    logger.info(f"Vulnerable to time-based SQL injection via {param} with payload: {payload}")
                    return {"vulnerable": True, "type": "time-based", "payload": payload, "url": modified_url}

            logger.info(f"No vulnerability found for parameter: {param}")
            return {"vulnerable": False}

        tasks = [test_parameter(param, session, original_response) for param in query_params]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collecting results
        final_results = {}
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Task failed with exception: {result}")
            elif result["vulnerable"]:
                final_results[result["url"]] = result

        if final_results:
            logger.info(f"Found vulnerabilities: {final_results}")
            return {"status": "success", "vulnerabilities": final_results}
        else:
            logger.info("No vulnerabilities found")
            return {"status": "success", "message": "No vulnerabilities found"}

