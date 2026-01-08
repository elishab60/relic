"""
Port Scanner V2 - Reliable Aggressive Scanning
===============================================
Solves false positives from CDN/WAF catch-all TCP proxies (Vercel, Cloudflare, etc.)

Key improvements:
1. Service validation layer - don't trust TCP connect alone
2. CDN detection and attribution
3. Classification: open_confirmed vs open_suspected
4. Protocol-specific probes for validation
"""

import asyncio
import socket
import ssl
import subprocess
import shutil
from enum import Enum
from typing import Optional, List, Dict, Tuple, Callable, Awaitable, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone
import xml.etree.ElementTree as ET
import struct
import logging

logger = logging.getLogger(__name__)


# =============================================================================
# TYPES & ENUMS
# =============================================================================

class PortScanProfile(Enum):
    """Port scanning intensity profiles."""
    LIGHT = "light"
    MID = "mid"
    HIGH = "high"


class PortState(Enum):
    """Port state classification with reliability indicator."""
    OPEN_CONFIRMED = "open_confirmed"      # Service responded with valid protocol
    OPEN_SUSPECTED = "open_suspected"      # TCP open but no service validation
    FILTERED = "filtered"                  # No response / timeout
    CLOSED = "closed"                      # RST received
    CDN_CATCHALL = "cdn_catchall"          # CDN accepts all TCP but no service


@dataclass
class ServiceProbe:
    """Result of a service validation probe."""
    success: bool
    protocol: str
    banner: Optional[str] = None
    version: Optional[str] = None
    tls_info: Optional[Dict] = None
    error: Optional[str] = None


@dataclass
class PortResult:
    """Enhanced port scan result with validation."""
    port: int
    tcp_state: str                         # raw: open/closed/filtered
    final_state: PortState                 # validated state
    service_guess: Optional[str] = None    # nmap table guess
    service_confirmed: Optional[str] = None # validated service
    banner: Optional[str] = None
    version: Optional[str] = None
    validation_method: Optional[str] = None # how we validated
    risk_level: str = "info"
    risk_reason: Optional[str] = None
    owasp_refs: List[str] = field(default_factory=list)
    latency_ms: Optional[int] = None


@dataclass
class ScanSummary:
    """Scan summary with proper classification."""
    profile: str
    target: str
    resolved_ips: List[str]
    scan_mode: str                         # hostname or ip
    sni_used: bool
    cdn_detected: bool
    cdn_provider: Optional[str] = None
    asn: Optional[str] = None
    org: Optional[str] = None
    
    ports_scanned: int = 0
    open_confirmed_count: int = 0
    open_suspected_count: int = 0
    cdn_catchall_count: int = 0
    filtered_count: int = 0
    closed_count: int = 0
    
    duration_ms: int = 0
    scan_method: str = "tcp_connect_validated"
    nmap_available: bool = False


# =============================================================================
# PORT LISTS
# =============================================================================

PORTS_LIGHT = [21, 22, 23, 25, 80, 110, 143, 443, 3306, 5432, 6379, 8080]

PORTS_MID = [
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 514, 515, 548, 554, 587, 636, 993, 995, 1080, 1433, 1434, 1521, 1723,
    1883, 2049, 2181, 2375, 2376, 3000, 3128, 3306, 3389, 4369, 5000, 5432,
    5672, 5900, 5984, 6379, 6443, 6666, 8000, 8008, 8080, 8081, 8443, 8888,
    9000, 9042, 9090, 9092, 9200, 9300, 10000, 11211, 15672, 27017, 27018,
    28017, 50000, 50030, 50070
] + list(range(8001, 8010))

PORTS_HIGH = sorted(set(
    PORTS_MID + 
    list(range(1, 100)) +
    list(range(100, 1025)) +
    [1025, 1026, 1027, 1028, 1029, 1030, 1099, 1194, 1433, 1521, 1723, 1812,
     1813, 2000, 2022, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2222, 2375,
     2376, 2379, 2380, 3000, 3001, 3128, 3306, 3389, 4000, 4040, 4443, 4444,
     4567, 4848, 5000, 5001, 5432, 5555, 5601, 5672, 5800, 5900, 5984, 6000,
     6001, 6379, 6443, 6666, 6667, 7000, 7001, 7002, 7070, 7077, 7443, 7474,
     7687, 8000, 8008, 8009, 8010, 8020, 8025, 8042, 8080, 8081, 8082, 8083,
     8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8161, 8200, 8300, 8443,
     8500, 8761, 8880, 8888, 8983, 9000, 9001, 9042, 9043, 9060, 9080, 9090,
     9091, 9092, 9100, 9200, 9300, 9418, 9443, 9999, 10000, 10250, 10255,
     11211, 11311, 15672, 16379, 18080, 20000, 27017, 27018, 28015, 28017,
     29015, 32768, 32769, 32770, 33060, 44818, 49152, 49153, 49154, 50000,
     50030, 50070, 50075, 61616]
))


def get_ports_for_profile(profile: PortScanProfile) -> List[int]:
    """Get port list for a given profile."""
    if profile == PortScanProfile.LIGHT:
        return PORTS_LIGHT
    elif profile == PortScanProfile.MID:
        return PORTS_MID
    else:
        return PORTS_HIGH


# =============================================================================
# CDN / ASN DETECTION
# =============================================================================

CDN_SIGNATURES = {
    "cloudflare": ["cloudflare", "cf-ray"],
    "vercel": ["vercel", "x-vercel"],
    "fastly": ["fastly", "x-served-by"],
    "akamai": ["akamai", "x-akamai"],
    "aws_cloudfront": ["cloudfront", "x-amz-cf"],
    "azure_cdn": ["azure", "x-azure"],
    "google_cdn": ["google", "x-goog"],
}

CDN_ASNS = {
    "AS13335": "Cloudflare",
    "AS209242": "Cloudflare",
    "AS14618": "AWS",
    "AS16509": "AWS",
    "AS15169": "Google",
    "AS8075": "Microsoft",
    "AS54113": "Fastly",
    "AS395973": "Vercel",   # Vercel, Inc
    "AS60068": "Vercel",
}


async def detect_cdn(hostname: str, ip: str) -> Tuple[bool, Optional[str]]:
    """Detect if target is behind a CDN."""
    # Method 1: Check HTTP headers
    try:
        import httpx
        async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
            try:
                resp = await client.head(f"https://{hostname}/", follow_redirects=True)
                headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
                
                for cdn, signatures in CDN_SIGNATURES.items():
                    for sig in signatures:
                        if any(sig in str(v) for v in headers_lower.values()) or \
                           any(sig in k for k in headers_lower.keys()):
                            return True, cdn
            except:
                pass
    except ImportError:
        pass
    
    # Method 2: ASN lookup (simplified - would use whois in prod)
    # For now, check known Vercel IPs
    vercel_ranges = ["64.29.17.", "216.198.79.", "76.76.21."]
    for prefix in vercel_ranges:
        if ip.startswith(prefix):
            return True, "vercel"
    
    return False, None


# =============================================================================
# SERVICE VALIDATION PROBES
# =============================================================================

# Protocol-specific probes for validation
SERVICE_PROBES = {
    # (port, label): (probe_bytes, expected_response_pattern, is_tls)
    21: ("ftp", b"", b"220", False),          # FTP banner starts with 220
    22: ("ssh", b"", b"SSH-", False),          # SSH banner
    23: ("telnet", b"\xff\xfb\x01", None, False), # Telnet negotiation
    25: ("smtp", b"", b"220", False),          # SMTP banner
    80: ("http", b"HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n", b"HTTP/", False),
    110: ("pop3", b"", b"+OK", False),
    143: ("imap", b"", b"* OK", False),
    443: ("https", None, None, True),           # TLS handshake
    3306: ("mysql", b"", b"\x00\x00", False),   # MySQL greeting packet
    5432: ("postgresql", b"\x00\x00\x00\x08\x04\xd2\x16\x2f", b"R", False),  # PG SSL req
    6379: ("redis", b"PING\r\n", b"+PONG", False),
    8080: ("http", b"HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n", b"HTTP/", False),
    8443: ("https", None, None, True),
    9090: ("http", b"HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n", b"HTTP/", False),
    27017: ("mongodb", b"", b"\x00\x00\x00", False),  # MongoDB wire protocol
}


async def validate_service(
    host: str,
    port: int, 
    timeout: float = 5.0
) -> ServiceProbe:
    """
    Validate that a real service is running on the port.
    Returns ServiceProbe with success=True only if we got a valid response.
    """
    # Check if we have a specific probe for this port
    probe_info = SERVICE_PROBES.get(port)
    
    if probe_info:
        label, probe_bytes, expected, is_tls = probe_info
        if probe_bytes and b"{host}" in probe_bytes:
            probe_bytes = probe_bytes.replace(b"{host}", host.encode())
    else:
        # Generic probe for unknown ports
        label = "generic"
        probe_bytes = b"\r\n"
        expected = None
        is_tls = False
    
    try:
        if is_tls:
            return await validate_tls_service(host, port, timeout)
        else:
            return await validate_tcp_service(host, port, probe_bytes, expected, label, timeout)
    except Exception as e:
        return ServiceProbe(success=False, protocol=label, error=str(e))


async def validate_tcp_service(
    host: str,
    port: int,
    probe: bytes,
    expected: Optional[bytes],
    label: str,
    timeout: float
) -> ServiceProbe:
    """Validate a TCP service by sending probe and checking response."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        
        try:
            # Try to read banner first (services like SSH send banner on connect)
            banner_data = b""
            try:
                banner_data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            except asyncio.TimeoutError:
                pass
            
            # If we got data and it matches expected, we're good
            if banner_data:
                if expected and expected in banner_data:
                    return ServiceProbe(
                        success=True,
                        protocol=label,
                        banner=banner_data[:200].decode('utf-8', errors='replace')
                    )
                elif banner_data.strip():  # Got something
                    return ServiceProbe(
                        success=True,
                        protocol=label,
                        banner=banner_data[:200].decode('utf-8', errors='replace')
                    )
            
            # Send probe if we have one
            if probe:
                writer.write(probe)
                await writer.drain()
                
                try:
                    response = await asyncio.wait_for(reader.read(1024), timeout=3.0)
                    if response:
                        if expected and expected in response:
                            return ServiceProbe(
                                success=True,
                                protocol=label,
                                banner=response[:200].decode('utf-8', errors='replace')
                            )
                        elif response.strip():
                            return ServiceProbe(
                                success=True,
                                protocol=label,
                                banner=response[:200].decode('utf-8', errors='replace')
                            )
                except asyncio.TimeoutError:
                    pass
            
            # TCP connected but no valid response - suspected CDN catchall
            return ServiceProbe(success=False, protocol=label, error="no_response")
            
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
                
    except asyncio.TimeoutError:
        return ServiceProbe(success=False, protocol=label, error="timeout")
    except ConnectionRefusedError:
        return ServiceProbe(success=False, protocol=label, error="connection_refused")
    except Exception as e:
        return ServiceProbe(success=False, protocol=label, error=str(e))


async def validate_tls_service(
    host: str,
    port: int,
    timeout: float
) -> ServiceProbe:
    """Validate TLS service by attempting handshake."""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context),
            timeout=timeout
        )
        
        try:
            # Get TLS info
            ssl_object = writer.get_extra_info('ssl_object')
            if ssl_object:
                tls_info = {
                    "version": ssl_object.version(),
                    "cipher": ssl_object.cipher()[0] if ssl_object.cipher() else None,
                }
                
                # Try HTTP over TLS
                writer.write(f"HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
                await writer.drain()
                
                try:
                    response = await asyncio.wait_for(reader.read(1024), timeout=3.0)
                    if b"HTTP/" in response:
                        return ServiceProbe(
                            success=True,
                            protocol="https",
                            tls_info=tls_info,
                            banner=response[:200].decode('utf-8', errors='replace')
                        )
                except asyncio.TimeoutError:
                    pass
                
                # TLS handshake succeeded
                return ServiceProbe(success=True, protocol="tls", tls_info=tls_info)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
            
    except ssl.SSLError as e:
        return ServiceProbe(success=False, protocol="tls", error=f"ssl_error: {e}")
    except asyncio.TimeoutError:
        return ServiceProbe(success=False, protocol="tls", error="timeout")
    except Exception as e:
        return ServiceProbe(success=False, protocol="tls", error=str(e))


# =============================================================================
# RISK ASSESSMENT
# =============================================================================

def assess_risk(port: int, service: Optional[str], state: PortState) -> Tuple[str, str, List[str]]:
    """
    Assess risk level for a port.
    Only penalize OPEN_CONFIRMED ports, not suspected ones.
    """
    if state not in (PortState.OPEN_CONFIRMED, PortState.OPEN_SUSPECTED):
        return "info", "Port not open", []
    
    # If only suspected, reduced risk
    if state == PortState.OPEN_SUSPECTED:
        return "low", "Port accepts TCP but no service validated (possible CDN catch-all)", []
    
    # Confirmed open - full risk assessment
    HIGH_RISK_PORTS = {
        21: ("ftp", "FTP - insecure plaintext protocol", ["A02:2021"]),
        23: ("telnet", "Telnet - insecure remote access", ["A02:2021", "A07:2021"]),
        512: ("rexec", "Remote execution service exposed", ["A07:2021"]),
        513: ("rlogin", "Remote login exposed", ["A07:2021"]),
        514: ("rsh", "Remote shell exposed", ["A07:2021"]),
    }
    
    MEDIUM_RISK_PORTS = {
        3306: ("mysql", "MySQL database exposed", ["A05:2021"]),
        5432: ("postgresql", "PostgreSQL database exposed", ["A05:2021"]),
        6379: ("redis", "Redis exposed (often no auth)", ["A05:2021", "A01:2021"]),
        27017: ("mongodb", "MongoDB exposed", ["A05:2021"]),
        9200: ("elasticsearch", "Elasticsearch exposed", ["A05:2021"]),
        11211: ("memcached", "Memcached exposed", ["A05:2021"]),
        2375: ("docker", "Docker API exposed (critical!)", ["A05:2021", "A01:2021"]),
    }
    
    LOW_RISK_PORTS = {
        22: ("ssh", "SSH exposed - ensure strong auth", []),
        3389: ("rdp", "RDP exposed - ensure strong auth", []),
        5900: ("vnc", "VNC exposed", []),
    }
    
    if port in HIGH_RISK_PORTS:
        _, reason, refs = HIGH_RISK_PORTS[port]
        return "high", reason, refs
    
    if port in MEDIUM_RISK_PORTS:
        _, reason, refs = MEDIUM_RISK_PORTS[port]
        return "medium", reason, refs
    
    if port in LOW_RISK_PORTS:
        _, reason, refs = LOW_RISK_PORTS[port]
        return "low", reason, refs
    
    # Web ports are generally OK
    if port in (80, 443, 8080, 8443):
        return "info", "Standard web port", []
    
    return "info", f"Port {port} open", []


# =============================================================================
# MAIN SCANNER
# =============================================================================

async def scan_port_with_validation(
    host: str,
    ip: str,
    port: int,
    is_cdn: bool,
    timeout: float = 5.0
) -> PortResult:
    """
    Scan a single port with service validation.
    This is the core function that eliminates false positives.
    """
    start = asyncio.get_event_loop().time()
    
    # Step 1: TCP connect
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except:
            pass
        tcp_state = "open"
    except asyncio.TimeoutError:
        return PortResult(
            port=port,
            tcp_state="filtered",
            final_state=PortState.FILTERED,
            latency_ms=int((asyncio.get_event_loop().time() - start) * 1000)
        )
    except ConnectionRefusedError:
        return PortResult(
            port=port,
            tcp_state="closed", 
            final_state=PortState.CLOSED,
            latency_ms=int((asyncio.get_event_loop().time() - start) * 1000)
        )
    except Exception:
        return PortResult(
            port=port,
            tcp_state="filtered",
            final_state=PortState.FILTERED,
            latency_ms=int((asyncio.get_event_loop().time() - start) * 1000)
        )
    
    # Step 2: Service validation (critical for CDN targets)
    probe_result = await validate_service(host, port, timeout=timeout)
    
    latency = int((asyncio.get_event_loop().time() - start) * 1000)
    
    if probe_result.success:
        # Validated service!
        final_state = PortState.OPEN_CONFIRMED
        risk_level, risk_reason, owasp = assess_risk(port, probe_result.protocol, final_state)
        
        return PortResult(
            port=port,
            tcp_state=tcp_state,
            final_state=final_state,
            service_guess=probe_result.protocol,
            service_confirmed=probe_result.protocol,
            banner=probe_result.banner,
            version=probe_result.version,
            validation_method="protocol_probe",
            risk_level=risk_level,
            risk_reason=risk_reason,
            owasp_refs=owasp,
            latency_ms=latency
        )
    else:
        # TCP open but no service response
        if is_cdn:
            # Known CDN - mark as catchall
            final_state = PortState.CDN_CATCHALL
            risk_level = "info"
            risk_reason = "CDN accepts all TCP connections - no real service"
        else:
            # Not a known CDN - still suspicious
            final_state = PortState.OPEN_SUSPECTED
            risk_level, risk_reason, _ = assess_risk(port, None, final_state)
        
        return PortResult(
            port=port,
            tcp_state=tcp_state,
            final_state=final_state,
            validation_method="no_response",
            risk_level=risk_level,
            risk_reason=risk_reason or probe_result.error,
            latency_ms=latency
        )


async def scan_ports_v2(
    target: str,
    log_callback: Optional[Callable[[str, str], Awaitable[None]]] = None,
    profile: PortScanProfile = PortScanProfile.LIGHT,
    timeout: float = 5.0,
    concurrency: int = 50
) -> Tuple[List[PortResult], ScanSummary]:
    """
    Enhanced port scanner with CDN detection and service validation.
    
    Key features:
    1. Detects CDN and adjusts expectations
    2. Validates services before marking as open
    3. Classifies ports into confirmed/suspected/catchall
    4. Aggressive but accurate
    5. Real-time progress logging
    """
    start_time = datetime.now(timezone.utc)
    
    async def log(level: str, msg: str):
        if log_callback:
            await log_callback(level, msg)
        logger.info(f"[{level}] {msg}")
    
    await log("info", f"[PORT-V2] Starting validated port scan on {target}")
    await log("info", f"[PORT-V2] Profile: {profile.value}")
    
    # Resolve hostname
    try:
        ip_info = socket.getaddrinfo(target, None, socket.AF_INET)
        resolved_ips = list(set([info[4][0] for info in ip_info]))
        primary_ip = resolved_ips[0]
    except socket.gaierror as e:
        await log("error", f"[PORT-V2] DNS resolution failed: {e}")
        return [], ScanSummary(
            profile=profile.value,
            target=target,
            resolved_ips=[],
            scan_mode="hostname",
            sni_used=True,
            cdn_detected=False
        )
    
    await log("info", f"[PORT-V2] Resolved to: {', '.join(resolved_ips)}")
    
    # Detect CDN
    is_cdn, cdn_provider = await detect_cdn(target, primary_ip)
    if is_cdn:
        await log("warning", f"[PORT-V2] CDN detected: {cdn_provider} - will validate services")
    
    # Get ports to scan
    ports = get_ports_for_profile(profile)
    total_ports = len(ports)
    await log("info", f"[PORT-V2] Scanning {total_ports} ports with validation layer")
    
    # Progress tracking
    scanned_count = 0
    last_progress_log = 0
    confirmed_ports = []
    
    # Scan with concurrency limit and progress tracking
    semaphore = asyncio.Semaphore(concurrency)
    results: List[PortResult] = []
    
    async def scan_with_sem(port: int) -> PortResult:
        nonlocal scanned_count, last_progress_log
        async with semaphore:
            result = await scan_port_with_validation(
                host=target,
                ip=primary_ip,
                port=port,
                is_cdn=is_cdn,
                timeout=timeout
            )
            
            # Update progress
            scanned_count += 1
            progress_pct = (scanned_count * 100) // total_ports
            
            # Log progress every 10% for large scans, or every 20 ports for small scans
            progress_interval = 10 if total_ports > 100 else 25
            if progress_pct >= last_progress_log + progress_interval:
                last_progress_log = (progress_pct // progress_interval) * progress_interval
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                await log("info", f"[PORT-V2] Progress: {scanned_count}/{total_ports} ports ({progress_pct}%) - {elapsed:.1f}s elapsed")
            
            # Log confirmed open ports immediately
            if result.final_state == PortState.OPEN_CONFIRMED:
                confirmed_ports.append(result)
                service = result.service_confirmed or result.service_guess or "unknown"
                await log("info", f"[PORT-V2] ✓ Port {port}/{service} CONFIRMED OPEN (banner: {(result.banner or '')[:50]}...)")
            
            return result
    
    # Run scans with batched progress updates
    tasks = [scan_with_sem(port) for port in ports]
    results = await asyncio.gather(*tasks)
    
    # Sort by port
    results = sorted(results, key=lambda r: r.port)
    
    # Calculate summary
    duration_ms = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
    
    summary = ScanSummary(
        profile=profile.value,
        target=target,
        resolved_ips=resolved_ips,
        scan_mode="hostname",
        sni_used=True,
        cdn_detected=is_cdn,
        cdn_provider=cdn_provider,
        ports_scanned=len(ports),
        open_confirmed_count=sum(1 for r in results if r.final_state == PortState.OPEN_CONFIRMED),
        open_suspected_count=sum(1 for r in results if r.final_state == PortState.OPEN_SUSPECTED),
        cdn_catchall_count=sum(1 for r in results if r.final_state == PortState.CDN_CATCHALL),
        filtered_count=sum(1 for r in results if r.final_state == PortState.FILTERED),
        closed_count=sum(1 for r in results if r.final_state == PortState.CLOSED),
        duration_ms=duration_ms,
        scan_method="tcp_connect_validated",
        nmap_available=shutil.which("nmap") is not None
    )
    
    # Log final results
    confirmed = [r for r in results if r.final_state == PortState.OPEN_CONFIRMED]
    suspected = [r for r in results if r.final_state == PortState.OPEN_SUSPECTED]
    catchall = [r for r in results if r.final_state == PortState.CDN_CATCHALL]
    
    await log("info", f"[PORT-V2] Scan completed in {duration_ms}ms")
    await log("info", f"[PORT-V2] Results: {summary.open_confirmed_count} confirmed, "
                      f"{summary.open_suspected_count} suspected, "
                      f"{summary.cdn_catchall_count} CDN catchall")
    
    if confirmed:
        ports_str = ", ".join([f"{r.port}/{r.service_confirmed}" for r in confirmed])
        await log("info", f"[PORT-V2] CONFIRMED OPEN: {ports_str}")
    
    if catchall and is_cdn:
        await log("info", f"[PORT-V2] CDN catchall detected on {len(catchall)} ports (ignored for scoring)")
    
    return results, summary


# =============================================================================
# SCORING (only count confirmed)
# =============================================================================

def calculate_network_score(results: List[PortResult], summary: ScanSummary) -> Dict[str, Any]:
    """
    Calculate a realistic network exposure score.
    Only CONFIRMED open ports affect the score.
    """
    confirmed = [r for r in results if r.final_state == PortState.OPEN_CONFIRMED]
    
    # Start at 100, deduct for confirmed issues
    score = 100
    findings = []
    
    for port_result in confirmed:
        if port_result.risk_level == "high":
            score -= 25
            findings.append({
                "port": port_result.port,
                "severity": "high",
                "service": port_result.service_confirmed,
                "reason": port_result.risk_reason
            })
        elif port_result.risk_level == "medium":
            score -= 10
            findings.append({
                "port": port_result.port,
                "severity": "medium",
                "service": port_result.service_confirmed,
                "reason": port_result.risk_reason
            })
        elif port_result.risk_level == "low":
            score -= 3
    
    score = max(0, score)
    
    # Grade calculation
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"
    
    return {
        "network_score": score,
        "network_grade": grade,
        "confirmed_open_ports": summary.open_confirmed_count,
        "suspected_ports": summary.open_suspected_count,
        "cdn_catchall_ports": summary.cdn_catchall_count,
        "high_risk_findings": len([f for f in findings if f["severity"] == "high"]),
        "medium_risk_findings": len([f for f in findings if f["severity"] == "medium"]),
        "findings": findings,
        "notes": [
            f"CDN detected: {summary.cdn_provider}" if summary.cdn_detected else None,
            f"{summary.cdn_catchall_count} ports ignored (CDN catch-all)" if summary.cdn_catchall_count > 0 else None
        ]
    }


# =============================================================================
# NMAP PROFILE RECOMMENDATIONS
# =============================================================================

NMAP_PROFILES = {
    "aggressive_reliable": {
        "description": "Fast scan with service validation",
        "command": "-sT -Pn -T4 --min-rate 500 --max-retries 2 -sV --version-intensity 2 --reason",
        "notes": [
            "-sT: TCP connect (reliable, no root needed)",
            "-Pn: Skip host discovery (target may block ping)",
            "-T4: Aggressive timing",
            "--min-rate 500: Maintain speed",
            "-sV: Version detection to validate services",
            "--version-intensity 2: Quick but effective probes",
            "--reason: Show why port is in each state"
        ]
    },
    "baseline_validation": {
        "description": "Thorough validation scan",
        "command": "-sT -Pn -T3 -sV --version-intensity 5 --script=banner --reason",
        "notes": [
            "-T3: Normal timing for accuracy",
            "--version-intensity 5: More probes for better service ID",
            "--script=banner: Grab banners",
            "Slower but catches edge cases"
        ]
    },
    "cdn_aware": {
        "description": "CDN-aware scan that ignores catch-all",
        "command": "-sT -Pn -T4 -sV --reason --script=http-headers,ssl-cert",
        "notes": [
            "Use with post-processing to filter CDN catch-all ports",
            "http-headers: Detect CDN via headers",
            "ssl-cert: Check certificate for CDN indicators",
            "Must validate that service actually responds"
        ]
    }
}


def get_recommended_nmap_command(target: str, profile: str = "aggressive_reliable", ports: Optional[List[int]] = None) -> str:
    """Generate recommended nmap command."""
    config = NMAP_PROFILES.get(profile, NMAP_PROFILES["aggressive_reliable"])
    
    port_arg = ""
    if ports:
        port_arg = f"-p {','.join(map(str, ports[:100]))}"  # Limit for command length
    else:
        port_arg = "-p-"  # All ports
    
    return f"nmap {config['command']} {port_arg} {target}"


# =============================================================================
# JSON OUTPUT
# =============================================================================

def results_to_json(results: List[PortResult], summary: ScanSummary) -> Dict[str, Any]:
    """Convert results to structured JSON output."""
    scoring = calculate_network_score(results, summary)
    
    return {
        "target": summary.target,
        "scan_metadata": {
            "profile": summary.profile,
            "resolved_ips": summary.resolved_ips,
            "scan_mode": summary.scan_mode,
            "sni_used": summary.sni_used,
            "cdn_detected": summary.cdn_detected,
            "cdn_provider": summary.cdn_provider,
            "duration_ms": summary.duration_ms,
            "scan_method": summary.scan_method,
            "timestamp": datetime.now(timezone.utc).isoformat()
        },
        "summary": {
            "ports_scanned": summary.ports_scanned,
            "open_confirmed": summary.open_confirmed_count,
            "open_suspected": summary.open_suspected_count,
            "cdn_catchall": summary.cdn_catchall_count,
            "filtered": summary.filtered_count,
            "closed": summary.closed_count
        },
        "scoring": scoring,
        "ports": {
            "confirmed_open": [
                {
                    "port": r.port,
                    "service": r.service_confirmed,
                    "banner": r.banner,
                    "risk_level": r.risk_level,
                    "risk_reason": r.risk_reason,
                    "owasp_refs": r.owasp_refs,
                    "latency_ms": r.latency_ms
                }
                for r in results if r.final_state == PortState.OPEN_CONFIRMED
            ],
            "suspected_open": [
                {
                    "port": r.port,
                    "reason": r.risk_reason,
                    "note": "TCP accepts connection but no service response"
                }
                for r in results if r.final_state == PortState.OPEN_SUSPECTED
            ],
            "cdn_catchall": [
                r.port for r in results if r.final_state == PortState.CDN_CATCHALL
            ]
        }
    }
