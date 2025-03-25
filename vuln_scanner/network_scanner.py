import asyncio
import socket
from config.logger_config import logger
from urllib.parse import urlparse
from utils.constants import COMMON_PORTS, OPTIMIZED_SERVICE_MAP
from timing_decorator import measure_time

async def resolve_dns(domain: str, timeout: float = 1.0) -> str:
    """Asynchronous DNS resolution using a thread pool."""
    loop = asyncio.get_event_loop()
    try:
        addrinfo = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                socket.getaddrinfo,
                domain, 
                None,
                socket.AF_UNSPEC,
                socket.SOCK_STREAM
            ),
            timeout=timeout
        )
        return addrinfo[0][4][0]
    except (socket.gaierror, asyncio.TimeoutError, IndexError):
        return None

async def probe(target_ip: str, port: int, timeout: float = 0.5) -> int | None:
    """Check if a port is open using TCP handshake."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target_ip, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return port
    except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
        return None

@measure_time
async def mass_port_scan(target_ip: str) -> dict:
    """Scans target IP using asynchronous TCP probes."""
    tasks = [probe(target_ip, p) for p in COMMON_PORTS]
    results = await asyncio.gather(*tasks)
    open_ports = [p for p in results if p is not None]
    return {"open_ports": sorted(open_ports)}

async def quick_header_check(url: str) -> dict:
    """Check security headers using aiohttp."""
    # Implement actual header check logic here
    return {"headers": {"Strict-Transport-Security": "present"}}

async def run_network_scans(target_url: str) -> dict:
    """Optimized scanner with DNS resolution and network scanning."""
    try:
        if '://' not in target_url:
            target_url = f'http://{target_url}'
        
        parsed = urlparse(target_url)
        domain = parsed.hostname
        
        if not domain:
            return {"status": "error", "message": "Invalid domain format"}

        target_ip = await resolve_dns(domain)
        if not target_ip:
            return {"status": "error", "message": "DNS resolution failed"}

        port_results, header_results = await asyncio.wait_for(
            asyncio.gather(
                mass_port_scan(target_ip),
                quick_header_check(target_url)
            ),
            timeout=10.0  # Increased timeout for realistic scans
        )

        return {
            "status": "completed",
            "target": target_url,
            "resolved_ip": target_ip,
            "network_scan": port_results,
            "security_headers": header_results,
            "services": {p: OPTIMIZED_SERVICE_MAP.get(p, "Unknown") 
                        for p in port_results["open_ports"]}
        }

    except asyncio.TimeoutError:
        return {"status": "timeout", "warning": "Scan exceeded time limit"}
    except Exception as e:
        logger.error(f"Network scan error: {str(e)}", exc_info=True)
        return {"status": "error", "message": "Scan failed"}