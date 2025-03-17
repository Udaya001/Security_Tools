import asyncio
import aiohttp
import socket
from config.logger_config import logger
from typing import List
from urllib.parse import urlparse
from utils.constants import OPTIMIZED_SERVICE_MAP, COMMON_PORTS
from timing_decorator import measure_time

async def scan_port(target_ip: str, port: int, timeout: float = 0.1) -> bool:
    """Ultra-fast port check with aggressive timeout"""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(target_ip, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
        logger.debug(f"Port {port} on {target_ip} is closed or timed out: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error scanning port {port} on {target_ip}: {e}")
        return False

async def mass_port_scan(target_ip: str) -> dict:
    """Massively parallel port scanning with optimized parameters"""
    semaphore = asyncio.Semaphore(100)  # Reduced concurrency to avoid resource exhaustion
    
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
                timeout=1  # Increased batch timeout
            )
            open_ports += [p for p in results if p]
        except asyncio.TimeoutError:
            logger.warning(f"Batch {i//batch_size + 1} timed out")
            continue

    return {"open_ports": sorted(open_ports)}

async def quick_header_check(target_url: str) -> dict:
    """Fast security header check with aggressive timeouts"""
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=2),  # Increased timeout
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
    except asyncio.TimeoutError:
        logger.warning(f"Header check for {target_url} timed out")
        return {"headers": {}, "final_url": target_url}
    except aiohttp.ClientError as e:
        logger.error(f"Client error during header check for {target_url}: {e}")
        return {"headers": {}, "final_url": target_url}
    except Exception as e:
        logger.error(f"Unexpected error during header check for {target_url}: {e}")
        return {"headers": {}, "final_url": target_url}

@measure_time
async def run_network_scans(target_url: str) -> dict:
    """Optimized scanner with strict timeout enforcement"""
    try:
        # Fast DNS resolution with timeout
        domain = urlparse(target_url).hostname or target_url
        try:
            target_ip = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None, 
                    lambda: socket.gethostbyname(domain)
                ),
                timeout=0.5  # Increased timeout
            )
        except socket.gaierror as e:
            logger.error(f"DNS resolution failed for {domain}: {e}")
            return {"status": "error", "message": f"DNS resolution failed for {domain}: {e}"}
        except asyncio.TimeoutError:
            logger.error(f"DNS resolution timed out for {domain}")
            return {"status": "error", "message": f"DNS resolution timed out for {domain}"}
        except Exception as e:
            logger.error(f"Unexpected error during DNS resolution for {domain}: {e}")
            return {"status": "error", "message": f"Unexpected error during DNS resolution for {domain}: {e}"}

        # Parallel execution with overall timeout
        port_results, header_results = await asyncio.wait_for(
            asyncio.gather(
                mass_port_scan(target_ip),
                quick_header_check(target_url)
            ),
            timeout=2  # Increased overall timeout
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
        logger.error(f"Overall scan for {target_url} exceeded time limit")
        return {"status": "timeout", "warning": "Scan exceeded time limit"}
    except Exception as e:
        logger.error(f"Unexpected error during overall scan for {target_url}: {e}")
        return {"status": "error", "message": str(e)}

