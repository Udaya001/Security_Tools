import asyncio
import aiohttp
import socket
from config.logger_config import logger
from typing import List
from urllib.parse import urlparse
from utils.constants import OPTIMIZED_SERVICE_MAP,COMMON_PORTS
from timing_decorator import measure_time

async def scan_port(target_ip: str, port: int, timeout: float = 0.15) -> bool:
    """Ultra-fast port check with aggressive timeout"""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(target_ip, port),
            timeout=timeout
        )
        writer.close()
        return True
    except:
        return False

async def mass_port_scan(target_ip: str) -> dict:
    """Massively parallel port scanning with optimized parameters"""
    semaphore = asyncio.Semaphore(1000)  # High concurrency
    
    async def probe(port):
        async with semaphore:
            return port if await scan_port(target_ip, port) else None

    # Split into batches for better timeout handling
    batch_size = 50
    open_ports = []
    
    for i in range(0, len(COMMON_PORTS), batch_size):
        batch = COMMON_PORTS[i:i+batch_size]
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*[probe(p) for p in batch]),
                timeout=0.3
            )
            open_ports += [p for p in results if p]
        except asyncio.TimeoutError:
            continue

    return {"open_ports": sorted(open_ports)}

async def quick_header_check(target_url: str) -> dict:
    """Fast security header check with aggressive timeouts"""
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=1),
            connector=aiohttp.TCPConnector(ssl=False)
        ) as session:
            async with session.head(target_url, allow_redirects=False) as resp:
                return {
                    "headers": {
                        h: resp.headers.get(h) 
                        for h in ["Content-Security-Policy", "X-Frame-Options"]
                    },
                    "final_url": str(resp.url)
                }
    except:
        return {"headers": {}, "final_url": target_url}

@measure_time
async def run_network_scans(target_url: str) -> dict:
    """Optimized scanner with strict timeout enforcement"""
    try:
        # Fast DNS resolution with timeout
        domain = urlparse(target_url).hostname or target_url
        target_ip = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(
                None, 
                lambda: socket.gethostbyname(domain)
            ),
            timeout=0.2
        )

        # Parallel execution with overall timeout
        port_results, header_results = await asyncio.wait_for(
            asyncio.gather(
                mass_port_scan(target_ip),
                quick_header_check(target_url)
            ),
            timeout=0.45
        )

        return {
            "status": "completed",
            "target": target_url,
            "network_scan": port_results,
            "security_headers": header_results,
            "services": {p: OPTIMIZED_SERVICE_MAP.get(p, "Unknown") 
                        for p in port_results["open_ports"]}
        }
    except asyncio.TimeoutError:
        return {"status": "timeout", "warning": "Scan exceeded time limit"}
    except Exception as e:
        return {"status": "error", "message": str(e)}