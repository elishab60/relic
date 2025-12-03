import asyncio
import socket
from typing import List, Dict, Optional, Callable, Awaitable, Literal
from pydantic import BaseModel
from ..config import settings

HTTP_PORTS = {80, 8080, 443, 8443}

class PortScanResult(BaseModel):
    port: int
    state: Literal["open", "closed", "filtered"]
    service_guess: Optional[str] = None
    banner: Optional[str] = None
    risk_level: Optional[Literal["info", "low", "medium", "high"]] = None
    risk_reason: Optional[str] = None
    owasp_refs: List[str] = []

def guess_service(port: int) -> str:
    services = {
        21: "ftp",
        22: "ssh",
        25: "smtp",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        3306: "mysql",
        5432: "postgresql",
        6379: "redis",
        8080: "http-alt",
        8443: "https-alt"
    }
    return services.get(port, "unknown")

def assess_risk(port: int, service: str, banner: Optional[str]) -> tuple[Optional[str], Optional[str], List[str]]:
    """
    Returns (risk_level, risk_reason, owasp_refs)
    """
    # Default safe ports
    if port in [80, 443, 8080, 8443]:
        return "info", "Standard web port", []

    # Sensitive services
    if port in [21, 22, 23, 25, 3389, 3306, 5432, 6379, 27017]:
        refs = ["A05:2021-Security Misconfiguration"]
        if port in [21, 23]: # FTP, Telnet
            return "medium", f"Insecure protocol ({service}) exposed", refs + ["A02:2021-Cryptographic Failures"]
        if port in [3306, 5432, 6379, 27017]: # Databases
            return "medium", f"Database service ({service}) exposed to public internet", refs + ["A01:2021-Broken Access Control"]
        if port == 22: # SSH
            return "low", "SSH exposed (ensure strong auth/keys)", refs
        if port == 3389: # RDP
            return "medium", "RDP exposed", refs
            
    return "info", f"Open port {port} ({service})", []

async def grab_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int) -> Optional[str]:
    banner = None
    try:
        # For HTTP ports, send a request first
        if port in HTTP_PORTS:
            # Minimal HTTP GET
            request = b"GET / HTTP/1.0\r\n\r\n"
            writer.write(request)
            await writer.drain()
        
        # Try to read up to 200 bytes
        # We use a short timeout for reading the banner
        data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
        if data:
            # Decode and truncate
            text = data.decode('utf-8', errors='replace').strip()
            # Take first line or first 200 chars
            lines = text.split('\n')
            if lines:
                banner = lines[0].strip()
            
            if banner and len(banner) > 200:
                banner = banner[:197] + "..."
                
    except Exception:
        # Ignore errors during banner grab (timeout, connection reset, etc.)
        pass
        
    return banner

async def scan_single_port(ip: str, port: int, log_callback: Optional[Callable[[str, str], Awaitable[None]]]) -> PortScanResult:
    state = "closed"
    banner = None
    service_guess = guess_service(port)
    
    try:
        # Attempt connection
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=settings.PORT_SCAN_TIMEOUT)
        
        # If we get here, it's open
        state = "open"
        if log_callback:
            await log_callback("INFO", f"Port {port} ({service_guess}) is OPEN")
            
        # Grab banner
        banner = await grab_banner(reader, writer, port)
        if banner and log_callback:
             await log_callback("DEBUG", f"Banner on port {port}: {banner}")
        
        # Close connection
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except Exception:
            pass
            
    except asyncio.TimeoutError:
        state = "filtered"
        if log_callback:
             await log_callback("DEBUG", f"Port {port} filtered (timeout)")
    except (ConnectionRefusedError, OSError):
        state = "closed"
    except Exception as e:
        # Fallback for other errors
        state = "closed"
        if log_callback:
             await log_callback("DEBUG", f"Port {port} check error: {e}")

    risk_level, risk_reason, owasp_refs = (None, None, [])
    if state == "open":
        risk_level, risk_reason, owasp_refs = assess_risk(port, service_guess, banner)

    return PortScanResult(
        port=port,
        state=state,
        service_guess=service_guess if state == "open" else None,
        banner=banner,
        risk_level=risk_level,
        risk_reason=risk_reason,
        owasp_refs=owasp_refs
    )

async def scan_ports(ip_address: str, log_callback: Optional[Callable[[str, str], Awaitable[None]]] = None) -> List[PortScanResult]:
    if log_callback:
        await log_callback("INFO", f"Starting TCP port scan on {ip_address}...")
        
    tasks = []
    for port in settings.SCAN_PORTS:
        tasks.append(scan_single_port(ip_address, port, log_callback))
        
    results = await asyncio.gather(*tasks)
    
    # Sort by port number for cleaner output
    results.sort(key=lambda x: x.port)
    
    if log_callback:
        open_count = sum(1 for r in results if r.state == "open")
        await log_callback("INFO", f"Port scan completed. Found {open_count} open ports.")
        
    return results
