import asyncio
import aiohttp
import socket
from config.config import logger
from typing import List
from urllib.parse import urlparse



# Common ports to scan (top 100 + critical services)
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445, 
    465, 514, 587, 636, 993, 995, 1080, 1433, 1434, 1521, 1701, 
    1723, 1883, 1900, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 
    2375, 2376, 3000, 3128, 3306, 3389, 4000, 4040, 4080, 4500, 
    4567, 4848, 4900, 4993, 5000, 5432, 5601, 5672, 5900, 5938, 
    5984, 6379, 6666, 6881, 6969, 7000, 7077, 7547, 7680, 7687, 
    7777, 7890, 8000, 8008, 8042, 8069, 8080, 8081, 8088, 8090, 
    8091, 8181, 8200, 8222, 8243, 8280, 8333, 8443, 8500, 8530, 
    8531, 8880, 8888, 8983, 9000, 9042, 9090, 9091, 9100, 9200, 
    9443, 9500, 9800, 9981, 10000, 10250, 10255, 10443, 11211, 
    12000, 12345, 15672, 16010, 16080, 16992, 16993, 18091, 18092, 
    27017, 27018, 28015, 32400
]

async def scan_port(target_ip: str, port: int, timeout: float = 0.5) -> bool:
    """Scan individual port with timeout and connection cleanup."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target_ip, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False
    except Exception as e:
        logger.debug(f"Error scanning {target_ip}:{port}: {str(e)}")
        return False

async def scan_ports(target_ip: str, ports: List[int] = COMMON_PORTS, concurrency: int = 200) -> dict:
    """Optimized port scanning with concurrency control."""
    logger.info(f"Starting port scan for {target_ip}")
    semaphore = asyncio.Semaphore(concurrency)

    async def scan_with_semaphore(port):
        async with semaphore:
            is_open = await scan_port(target_ip, port)
            return port if is_open else None

    scan_tasks = [scan_with_semaphore(port) for port in ports]
    results = await asyncio.gather(*scan_tasks)
    
    open_ports = [port for port in results if port is not None]
    logger.info(f"Port scan completed for {target_ip}. Found {len(open_ports)} open ports")
    return {"status": "success", "open_ports": sorted(open_ports)}

async def detect_service(target_ip: str, port: int) -> str:
    """Enhanced service detection with basic banner grabbing."""
    logger.info(f"Detecting service on {target_ip}:{port}")
    service_map = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 
            80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 
            139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 
            993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL", 
            3389: "RDP", 5900: "VNC", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
        }

    # Try to get service from known ports first
    if port in service_map:
        return service_map[port]

    # Attempt banner grabbing for unknown ports
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target_ip, port),
            timeout=1
        )
        writer.write(b"GET / HTTP/1.1\r\n\r\n")
        await writer.drain()
        banner = await asyncio.wait_for(reader.read(1024), timeout=1)
        writer.close()
        await writer.wait_closed()
        return f"Unknown ({banner[:50].decode(errors='ignore').strip()})"
    except Exception:
        return "Unknown Service"

async def check_security_headers(target_url: str) -> dict:
    """Optimized security header check with connection reuse."""
    logger.info(f"Checking security headers for {target_url}")
    security_headers = {
        "Content-Security-Policy": None,
        "X-Frame-Options": None,
        "X-Content-Type-Options": None,
        "Strict-Transport-Security": None,
        "Permissions-Policy": None,
        "Referrer-Policy": None
    }

    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=5),
            connector=aiohttp.TCPConnector(limit=10)
        ) as session:
            async with session.head(target_url, allow_redirects=True) as response:
                for header in security_headers:
                    security_headers[header] = response.headers.get(header)
                
                return {
                    "status": "success",
                    "headers": security_headers,
                    "final_url": str(response.url)
                }
    except Exception as e:
        logger.error(f"Header check failed for {target_url}: {str(e)}")
        return {"status": "failed", "error": str(e)}

async def run_network_scans(target_url: str) -> dict:
    """Optimized unified scanner with parallel execution."""
    logger.info(f"Starting comprehensive scan for {target_url}")
    
    try:
        # Extract domain and resolve IP
        domain = urlparse(target_url).hostname
        target_ip = await asyncio.get_event_loop().run_in_executor(
            None, socket.gethostbyname, domain
        )
    except (socket.gaierror, ValueError) as e:
        return {"status": "failed", "error": f"DNS resolution failed: {str(e)}"}

    try:
        # Run parallel scans
        port_scan, header_scan = await asyncio.gather(
            scan_ports(target_ip),
            check_security_headers(target_url)
        )

        # Service detection only if ports found
        services = {}
        if port_scan["status"] == "success" and port_scan["open_ports"]:
            detected_services = await asyncio.gather(
                *(detect_service(target_ip, port) for port in port_scan["open_ports"])
            )
            services = dict(zip(port_scan["open_ports"], detected_services))

        return {
            "status": "completed",
            "target": target_url,
            "network_scan": port_scan,
            "security_headers": header_scan,
            "services": services
        }
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        return {"status": "failed", "error": str(e)}