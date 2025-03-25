import ssl
import socket
import asyncio
from datetime import datetime
from urllib.parse import urlparse
from cryptography import x509
from timing_decorator import measure_time

async def resolve_dns(domain: str):
    """Resolve DNS asynchronously using socket.getaddinfo in a thread."""
    try:
        loop = asyncio.get_event_loop()
        # Use executor to run blocking call
        await loop.run_in_executor(
            None,  # Use default executor
            socket.getaddrinfo,  # Function to execute
            domain,  # Domain argument
            443,  # Port argument
            socket.AF_UNSPEC,  # Allow IPv4/IPv6
            socket.SOCK_STREAM  # TCP socket
        )
        return True
    except socket.gaierror:
        return False
    except Exception as e:
        print(f"Unexpected error in DNS resolution: {e}")
        return False

@measure_time
async def check_ssl(domain: str):
    """Check SSL certificate details for a domain asynchronously."""
    # Extract domain from URL if necessary
    parsed = urlparse(domain)
    if parsed.scheme:
        domain = parsed.netloc or parsed.path.split('/')[0]
    else:
        domain = domain.split('/')[0]

    context = ssl.create_default_context()
    
    # Verify DNS resolution
    if not await resolve_dns(domain):
        return {
            "status": "error",
            "message": "DNS resolution failed",
            "domain": domain
        }
    
    try:
        # Connect with timeout
        connect_coro = asyncio.open_connection(
            domain, 443, ssl=context, server_hostname=domain
        )
        reader, writer = await asyncio.wait_for(connect_coro, timeout=5)
        
        # Get SSL certificate
        ssl_obj = writer.get_extra_info('ssl_object')
        cert_bin = ssl_obj.getpeercert(binary_form=True)
        writer.close()
        await writer.wait_closed()
        
        # Load certificate with cryptography
        
        cert = x509.load_der_x509_certificate(cert_bin)
        
        expiry = cert.not_valid_after.strftime("%Y-%m-%d %H:%M:%S")
        issuer = cert.issuer.rfc4514_string()
        expired = datetime.utcnow() > cert.not_valid_after
        
        return {
            "status": "success",
            "domain": domain,
            "issuer": issuer,
            "expiry_date": expiry,
            "expired": expired
        }
    except asyncio.TimeoutError:
        return {"status": "error", "message": "Timeout", "domain": domain}
    except ssl.SSLError as e:
        return {"status": "error", "message": f"SSL Error: {e}", "domain": domain}
    except Exception as e:
        return {"status": "error", "message": f"Error: {e}", "domain": domain}