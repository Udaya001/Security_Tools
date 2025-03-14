import ssl
import socket
import asyncio
from timing_decorator import measure_time


@measure_time
async def check_ssl(domain: str):
    """Check SSL certificate details for a domain asynchronously."""
    context = ssl.create_default_context()
    try:
        # Set up the connection with a 5-second timeout
        connect_coro = asyncio.open_connection(
            domain, 443, ssl=context, server_hostname=domain
        )
        reader, writer = await asyncio.wait_for(connect_coro, timeout=5)
        
        # Extract SSL information from the socket
        sock = writer.get_extra_info('socket')
        cert = sock.getpeercert()
        
        # Close the connection
        writer.close()
        await writer.wait_closed()

        # Extract certificate details
        expiry_date = cert.get("notAfter")
        # Extract issuer (assumes the first element is the relevant issuer component)
        issuer = cert.get("issuer", [])[0][1] if cert.get("issuer") else "Unknown"
        
        return {
            "status": "success",
            "message": "SSL certificate retrieved",
            "domain": domain,
            "issuer": issuer,
            "expiry_date": expiry_date
        }
    except asyncio.TimeoutError:
        return {
            "status": "error",
            "message": "SSL check timed out",
            "domain": domain
        }
    except ssl.SSLError as e:
        return {
            "status": "error",
            "message": f"SSL error: {str(e)}",
            "domain": domain
        }
    except socket.gaierror:
        return {
            "status": "error",
            "message": "DNS resolution failed",
            "domain": domain
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"General error: {str(e)}",
            "domain": domain
        }