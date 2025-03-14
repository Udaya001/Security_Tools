import asyncio
import aiohttp
from urllib.parse import urlparse, parse_qs, urlencode
from itertools import product
from utils.constants import TAGS, EVENTS, ATTRIBUTES, ENCODINGS, PAYLOAD_TEMPLATES
from timing_decorator import measure_time

# Semaphore to control concurrency
CONCURRENT_REQUESTS = 100

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
            async with session.get(url, timeout=0.3) as response:
                return await response.text()
        except Exception:
            return None

@measure_time
async def run_xss_scan(target_url: str):
    """Run XSS scan by injecting payloads into query parameters."""
    parsed_url = urlparse(target_url)
    query_params = parse_qs(parsed_url.query)

    if not query_params:
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
        results = await asyncio.gather(*tasks)

        # Filter responses for successful payload injection
        for i, response_text in enumerate(results):
            if response_text and payloads[i % len(payloads)] in response_text:
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
