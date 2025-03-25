import asyncio
import aiohttp
from urllib.parse import urlparse, parse_qs, urlencode
from itertools import product
from utils.constants import TAGS, EVENTS, ATTRIBUTES, ENCODINGS, PAYLOAD_TEMPLATES
from timing_decorator import measure_time
import logging

# Setting up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Semaphore to control concurrency
CONCURRENT_REQUESTS = 50  # Reduced concurrency to avoid overwhelming the server

def generate_payloads():
    """Generate all possible XSS payloads."""
    payloads = set()

    # Generate base payloads with all tag, event, attr combinations
    for tag, event, attr in product(TAGS, EVENTS, ATTRIBUTES):
        for template in PAYLOAD_TEMPLATES:
            payloads.add(template.format(tag=tag, event=event, attr=attr))

    # Encode variations
    encoded_payloads = set()
    for payload in payloads:
        for encoding_name, encoder in ENCODINGS.items():
            encoded_payloads.add(encoder(payload))

    return list(encoded_payloads)

async def test_request(session, url, semaphore):
    """Perform a GET request with a timeout and concurrency control."""
    async with semaphore:
        try:
            async with session.get(url, timeout=0.5) as response:
                response_text = await response.text()
                logger.debug(f"Response from {url}: {response_text[:200]}")
                return response_text
        except (asyncio.TimeoutError, aiohttp.ClientError) as e:
            logger.debug(f"Request failed for {url}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error for {url}: {e}")
            return None

@measure_time
async def run_xss_scan(target_url: str):
    """Run XSS scan by injecting payloads into query parameters."""
    parsed_url = urlparse(target_url)
    query_params = parse_qs(parsed_url.query)

    if not query_params:
        logger.info("No parameters found in URL")
        return {
            "status": "success",
            "message": "No parameters found in URL",
            "scan_results": []
        }

    payloads = generate_payloads()
    scan_results = []
    semaphore = asyncio.Semaphore(CONCURRENT_REQUESTS)

    async with aiohttp.ClientSession() as session:
        tasks = []
        for param in query_params:
            for payload in payloads:
                # Modify URL with injected payload
                modified_params = query_params.copy()
                modified_params[param] = [payload]
                modified_url = parsed_url._replace(query=urlencode(modified_params, doseq=True)).geturl()

                # Create async request task
                tasks.append(test_request(session, modified_url, semaphore))

        # Process tasks in batches for efficiency
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter responses for successful payload injection
        for i, response_text in enumerate(results):
            if isinstance(response_text, Exception):
                logger.error(f"Task failed with exception: {response_text}")
                continue
            if response_text and any(payload in response_text for payload in payloads):
                scan_results.append({
                    "parameter": list(query_params.keys())[i // len(payloads)],
                    "payload": payloads[i % len(payloads)],
                    "url": modified_url,
                    "evidence": response_text[:200]  # Capture first 200 chars of response
                })

    return {
        "status": "success",
        "message": "XSS scan completed",
        "scan_results": scan_results
    }

