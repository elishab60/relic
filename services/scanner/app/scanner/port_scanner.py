"""
Port Scanner Module
===================
Async TCP port scanning with profiles (LIGHT/MID/HIGH) and optional nmap integration.

Profiles:
- LIGHT: ~12 common ports (current behavior, very fast)
- MID: Top 100 ports (balanced, ~30s)  
- HIGH: Top 1000 ports (comprehensive, ~2-5min)

Features:
- Pure Python async TCP connect scan (always available)
- Optional nmap subprocess for service detection
- Banner grabbing on open ports
- Risk assessment with OWASP references
"""

import asyncio
import socket
import subprocess
import shutil
import xml.etree.ElementTree as ET
from datetime import datetime
from enum import Enum
from typing import List, Dict, Optional, Callable, Awaitable, Literal, Tuple, Set
from pydantic import BaseModel
from ..config import settings

HTTP_PORTS = {80, 8080, 443, 8443}


# =============================================================================
# PORT SCAN PROFILES
# =============================================================================

class PortScanProfile(Enum):
    """
    Port scanning intensity profiles.
    
    - LIGHT: ~12 common service ports (very fast, <5s)
    - MID: Top 100 most common ports (balanced, ~30s)
    - HIGH: Top 1000 ports (comprehensive, ~2-5min)
    """
    LIGHT = "light"
    MID = "mid"
    HIGH = "high"


# Common service ports (LIGHT profile) - matches original behavior
PORTS_LIGHT: List[int] = [
    21,    # FTP
    22,    # SSH
    25,    # SMTP
    80,    # HTTP
    110,   # POP3
    143,   # IMAP
    443,   # HTTPS
    3306,  # MySQL
    5432,  # PostgreSQL
    6379,  # Redis
    8080,  # HTTP-Alt
    8443,  # HTTPS-Alt
]

# Top 100 ports (MID profile) - nmap's --top-ports 100 equivalent
PORTS_MID: List[int] = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 
    88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 
    179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 
    993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 
    1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 
    3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 
    5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 
    6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 
    8443, 8888, 9100, 9999, 10000, 27017, 32768, 49152, 
    49153, 49154, 49155, 49156, 49157
]

# Top 1000 ports (HIGH profile) - nmap's default scan range
# This is a curated list based on nmap-services most common ports
PORTS_HIGH: List[int] = sorted(set(PORTS_MID + [
    # Additional common ports for comprehensive scan
    1, 2, 3, 5, 11, 15, 17, 18, 19, 20, 24, 30, 32, 33, 34, 35, 38, 
    39, 41, 42, 43, 49, 50, 57, 59, 66, 69, 70, 77, 78, 83, 84, 85, 
    89, 90, 99, 100, 102, 104, 105, 107, 108, 109, 114, 115, 117, 
    118, 120, 121, 122, 123, 124, 125, 126, 129, 130, 131, 132, 133, 
    137, 138, 140, 142, 146, 158, 161, 162, 163, 175, 180, 191, 192,
    194, 197, 198, 201, 202, 204, 206, 209, 210, 211, 212, 213, 256, 
    259, 264, 280, 301, 306, 311, 340, 366, 388, 406, 407, 416, 417,
    425, 458, 464, 481, 497, 500, 512, 516, 517, 518, 519, 520, 524, 
    541, 545, 555, 556, 563, 565, 593, 616, 617, 625, 666, 667, 668, 
    683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 
    783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 
    903, 911, 912, 981, 987, 992, 997, 999, 1000, 1001, 1002, 1007, 
    1009, 1010, 1011, 1021, 1022, 1023, 1024, 1030, 1031, 1032, 1033, 
    1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 
    1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 
    1056, 1057, 1058, 1059, 1060, 1070, 1080, 1081, 1082, 1083, 1084, 
    1085, 1086, 1087, 1088, 1089, 1090, 1091, 1100, 1102, 1104, 1105, 
    1107, 1108, 1111, 1112, 1113, 1119, 1121, 1122, 1126, 1130, 1131, 
    1132, 1137, 1138, 1141, 1145, 1147, 1148, 1149, 1151, 1152, 1154, 
    1163, 1164, 1165, 1166, 1169, 1174, 1183, 1185, 1186, 1192, 1198, 
    1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236, 1244, 1247, 
    1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 
    1311, 1322, 1328, 1334, 1352, 1417, 1434, 1443, 1455, 1461, 1494, 
    1500, 1501, 1503, 1521, 1524, 1533, 1556, 1580, 1583, 1594, 1600, 
    1641, 1658, 1666, 1687, 1688, 1700, 1717, 1718, 1719, 1721, 1725, 
    1761, 1782, 1783, 1801, 1805, 1812, 1839, 1840, 1862, 1863, 1864, 
    1875, 1914, 1935, 1947, 1971, 1972, 1974, 1984, 1998, 1999, 2002, 
    2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2013, 2020, 2021, 
    2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 
    2046, 2047, 2048, 2050, 2063, 2068, 2099, 2100, 2101, 2103, 2105, 
    2106, 2107, 2111, 2119, 2126, 2135, 2144, 2160, 2161, 2170, 2179, 
    2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366, 
    2381, 2382, 2383, 2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 
    2557, 2601, 2602, 2604, 2605, 2607, 2608, 2638, 2701, 2702, 2710, 
    2718, 2725, 2809, 2811, 2869, 2875, 2909, 2910, 2920, 2967, 2968, 
    3003, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031, 3052, 3071, 
    3077, 3128, 3168, 3211, 3221, 3260, 3261, 3268, 3269, 3283, 3300, 
    3301, 3323, 3325, 3333, 3351, 3367, 3369, 3370, 3371, 3372, 3390, 
    3404, 3476, 3493, 3517, 3527, 3546, 3551, 3580, 3659, 3689, 3690, 
    3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827, 3828, 
    3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 
    3971, 3991, 3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 
    4111, 4125, 4126, 4129, 4224, 4242, 4279, 4321, 4343, 4443, 4444, 
    4445, 4446, 4449, 4550, 4567, 4662, 4848, 4900, 4998, 5001, 5002, 
    5003, 5004, 5005, 5006, 5007, 5008, 5010, 5011, 5012, 5013, 5015, 
    5020, 5050, 5052, 5054, 5059, 5061, 5080, 5087, 5100, 5102, 5120, 
    5200, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5353, 5355, 
    5400, 5405, 5414, 5431, 5433, 5440, 5500, 5510, 5544, 5550, 5555, 
    5560, 5566, 5600, 5633, 5678, 5679, 5718, 5730, 5801, 5802, 5810, 
    5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5901, 5902, 5903, 
    5904, 5906, 5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959, 
    5960, 5961, 5962, 5963, 5987, 5988, 5989, 5998, 5999, 6003, 6004, 
    6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106, 6112, 6123, 
    6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547, 6565, 6566, 6567, 
    6580, 6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 
    6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004, 7007, 
    7019, 7025, 7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496, 
    7512, 7625, 7627, 7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921, 
    7937, 7938, 7999, 8001, 8002, 8007, 8010, 8011, 8021, 8022, 8031, 
    8042, 8045, 8050, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 
    8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200, 8222, 
    8254, 8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402, 8500, 8600, 
    8649, 8651, 8652, 8654, 8701, 8800, 8873, 8880, 8881, 8888, 8899, 
    8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071, 
    9080, 9081, 9090, 9091, 9099, 9101, 9102, 9103, 9110, 9111, 9200, 
    9207, 9220, 9290, 9415, 9418, 9485, 9500, 9502, 9503, 9535, 9575, 
    9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917, 
    9929, 9943, 9944, 9968, 9998, 10000, 10001, 10002, 10003, 10004, 
    10009, 10010, 10012, 10024, 10025, 10082, 10180, 10215, 10243, 
    10566, 10616, 10617, 10621, 10626, 10628, 10629, 11110, 11111, 
    11967, 12000, 12174, 12265, 13456, 13722, 13782, 13783, 14000, 
    14238, 14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742, 
    16000, 16001, 16012, 16016, 16018, 16080, 16113, 16992, 16993, 
    17877, 17988, 18040, 18101, 18988, 19101, 19283, 19315, 19350, 
    19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828, 
    21571, 22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 
    27352, 27353, 27355, 27356, 27715, 28201, 30000, 30718, 30951, 
    31038, 31337, 32768, 32769, 32770, 32771, 32772, 32773, 32774, 
    32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 
    32784, 33354, 33899, 34571, 34572, 34573, 35500, 38292, 40193, 
    40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100, 48080, 
    49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 
    49161, 49163, 49165, 49167, 49175, 49176, 49400, 49999, 50000, 
    50001, 50002, 50003, 50006, 50300, 50389, 50500, 50636, 50800, 
    51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055, 
    55056, 55555, 55600, 56737, 56738, 57294, 57797, 58080, 60020, 
    60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000, 65129, 
    65389
]))


def get_ports_for_profile(profile: PortScanProfile) -> List[int]:
    """Returns the list of ports to scan for the given profile."""
    if profile == PortScanProfile.LIGHT:
        return PORTS_LIGHT.copy()
    elif profile == PortScanProfile.MID:
        return PORTS_MID.copy()
    elif profile == PortScanProfile.HIGH:
        return PORTS_HIGH.copy()
    return PORTS_LIGHT.copy()


def get_profile_metadata(profile: PortScanProfile) -> Dict:
    """
    Returns metadata about the port scan profile.
    Useful for UI display and logging.
    """
    metadata = {
        PortScanProfile.LIGHT: {
            "name": "light",
            "label": "Light",
            "port_count": len(PORTS_LIGHT),
            "description": "Common service ports only",
            "estimated_time": "< 5 seconds",
            "impact": "fast"
        },
        PortScanProfile.MID: {
            "name": "mid",
            "label": "Balanced",
            "port_count": len(PORTS_MID),
            "description": "Top 100 most common ports",
            "estimated_time": "~30 seconds",
            "impact": "medium"
        },
        PortScanProfile.HIGH: {
            "name": "high",
            "label": "Comprehensive",
            "port_count": len(PORTS_HIGH),
            "description": "Top 1000 ports (thorough scan)",
            "estimated_time": "2-5 minutes",
            "impact": "slow"
        }
    }
    return metadata.get(profile, metadata[PortScanProfile.LIGHT])


# =============================================================================
# PORT SCAN RESULT MODEL
# =============================================================================

class PortScanResult(BaseModel):
    port: int
    state: Literal["open", "closed", "filtered"]
    service_guess: Optional[str] = None
    banner: Optional[str] = None
    risk_level: Optional[Literal["info", "low", "medium", "high"]] = None
    risk_reason: Optional[str] = None
    owasp_refs: List[str] = []
    # Enhanced fields for nmap integration
    nmap_service: Optional[str] = None
    nmap_version: Optional[str] = None


class PortScanSummary(BaseModel):
    """Summary of a port scan run."""
    profile: str
    ports_scanned: int
    open_count: int
    filtered_count: int
    closed_count: int
    duration_ms: int
    scan_method: str  # "tcp_connect" or "nmap"
    nmap_available: bool


# =============================================================================
# SERVICE DETECTION
# =============================================================================

def guess_service(port: int) -> str:
    """Guess service name from well-known port numbers."""
    services = {
        7: "echo", 9: "discard", 13: "daytime", 17: "qotd",
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        53: "dns", 69: "tftp", 70: "gopher", 79: "finger",
        80: "http", 81: "http-alt", 88: "kerberos",
        110: "pop3", 111: "rpcbind", 113: "ident", 119: "nntp",
        123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
        139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap",
        179: "bgp", 194: "irc", 389: "ldap", 443: "https",
        445: "microsoft-ds", 465: "smtps", 500: "isakmp",
        512: "rexec", 513: "rlogin", 514: "syslog", 515: "printer",
        520: "rip", 521: "ripng", 543: "klogin", 544: "kshell",
        548: "afp", 554: "rtsp", 587: "submission", 631: "ipp",
        636: "ldaps", 873: "rsync", 902: "vmware-auth",
        990: "ftps", 993: "imaps", 995: "pop3s",
        1080: "socks", 1194: "openvpn", 1433: "mssql", 1434: "mssql-m",
        1521: "oracle", 1723: "pptp", 1883: "mqtt", 1900: "upnp",
        2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
        2181: "zookeeper", 2222: "ssh-alt", 2375: "docker",
        2376: "docker-ssl", 2379: "etcd", 3000: "ppp",
        3128: "squid", 3306: "mysql", 3389: "rdp", 3690: "svn",
        4369: "epmd", 4443: "https-alt", 5000: "upnp",
        5432: "postgresql", 5672: "amqp", 5900: "vnc",
        5984: "couchdb", 5985: "wsman", 5986: "wsmans",
        6379: "redis", 6443: "kubernetes", 6667: "irc",
        7001: "weblogic", 7002: "weblogic-ssl", 8000: "http-alt",
        8008: "http-alt", 8009: "ajp13", 8080: "http-proxy",
        8081: "http-alt", 8443: "https-alt", 8888: "http-alt",
        9000: "cslistener", 9042: "cassandra", 9090: "prometheus",
        9092: "kafka", 9200: "elasticsearch", 9300: "elasticsearch",
        11211: "memcached", 15672: "rabbitmq-mgmt",
        27017: "mongodb", 27018: "mongodb", 27019: "mongodb",
        28017: "mongodb-web", 50000: "db2"
    }
    return services.get(port, "unknown")


def assess_risk(port: int, service: str, banner: Optional[str]) -> Tuple[Optional[str], Optional[str], List[str]]:
    """
    Assess the security risk of an open port.
    Returns (risk_level, risk_reason, owasp_refs)
    """
    # Safe standard web ports
    if port in [80, 443, 8080, 8443]:
        return "info", "Standard web port", []

    # High risk: Insecure protocols
    HIGH_RISK_PORTS = {
        21: ("Insecure protocol (FTP) exposed - plaintext credentials", ["A02:2021-Cryptographic Failures"]),
        23: ("Insecure protocol (Telnet) exposed - plaintext credentials", ["A02:2021-Cryptographic Failures"]),
        69: ("TFTP exposed - no authentication", ["A01:2021-Broken Access Control"]),
        512: ("rexec exposed - legacy insecure protocol", ["A02:2021-Cryptographic Failures"]),
        513: ("rlogin exposed - legacy insecure protocol", ["A02:2021-Cryptographic Failures"]),
    }
    
    if port in HIGH_RISK_PORTS:
        reason, refs = HIGH_RISK_PORTS[port]
        return "high", reason, ["A05:2021-Security Misconfiguration"] + refs

    # Medium risk: Database and sensitive services
    MEDIUM_RISK_PORTS = {
        3306: "MySQL database exposed",
        5432: "PostgreSQL database exposed", 
        6379: "Redis exposed (often no auth by default)",
        27017: "MongoDB exposed",
        9200: "Elasticsearch exposed",
        11211: "Memcached exposed",
        2375: "Docker daemon exposed (unencrypted)",
        5984: "CouchDB exposed",
        9042: "Cassandra exposed",
        1433: "MSSQL database exposed",
        1521: "Oracle database exposed"
    }
    
    if port in MEDIUM_RISK_PORTS:
        return "medium", f"{MEDIUM_RISK_PORTS[port]} to public internet", [
            "A05:2021-Security Misconfiguration",
            "A01:2021-Broken Access Control"
        ]

    # Low risk: SSH, RDP (generally okay if properly secured)
    LOW_RISK_PORTS = {
        22: "SSH exposed (ensure strong auth/keys)",
        3389: "RDP exposed (verify firewall rules)",
        5900: "VNC exposed (verify access controls)"
    }
    
    if port in LOW_RISK_PORTS:
        return "low", LOW_RISK_PORTS[port], ["A05:2021-Security Misconfiguration"]

    # Default: informational
    return "info", f"Open port {port} ({service})", []


# =============================================================================
# BANNER GRABBING
# =============================================================================

async def grab_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int) -> Optional[str]:
    """Attempt to grab a banner from an open port."""
    banner = None
    try:
        # For HTTP ports, send a GET request
        if port in HTTP_PORTS:
            request = b"GET / HTTP/1.0\r\n\r\n"
            writer.write(request)
            await writer.drain()
        
        # Read banner with timeout
        data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
        if data:
            text = data.decode('utf-8', errors='replace').strip()
            lines = text.split('\n')
            if lines:
                banner = lines[0].strip()
            
            if banner and len(banner) > 200:
                banner = banner[:197] + "..."
                
    except Exception:
        pass
        
    return banner


# =============================================================================
# TCP CONNECT SCAN (Pure Python)
# =============================================================================

async def scan_single_port(
    ip: str, 
    port: int, 
    timeout: float,
    log_callback: Optional[Callable[[str, str], Awaitable[None]]]
) -> PortScanResult:
    """Scan a single port using TCP connect."""
    state = "closed"
    banner = None
    service_guess = guess_service(port)
    
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        
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


async def scan_ports_tcp(
    ip_address: str,
    ports: List[int],
    timeout: float,
    concurrency: int,
    log_callback: Optional[Callable[[str, str], Awaitable[None]]] = None
) -> List[PortScanResult]:
    """
    Perform TCP connect scan on specified ports.
    Uses semaphore to limit concurrency.
    """
    semaphore = asyncio.Semaphore(concurrency)
    
    async def scan_with_limit(port: int) -> PortScanResult:
        async with semaphore:
            return await scan_single_port(ip_address, port, timeout, log_callback)
    
    tasks = [scan_with_limit(port) for port in ports]
    results = await asyncio.gather(*tasks)
    
    return sorted(results, key=lambda x: x.port)


# =============================================================================
# NMAP INTEGRATION (Optional)
# =============================================================================

def is_nmap_available() -> bool:
    """Check if nmap is installed and accessible."""
    return shutil.which("nmap") is not None


async def run_nmap_scan(
    target: str,
    ports: List[int],
    timeout_seconds: int = 300,
    log_callback: Optional[Callable[[str, str], Awaitable[None]]] = None
) -> Optional[List[PortScanResult]]:
    """
    Run nmap scan for service detection.
    Returns None if nmap fails or is not available.
    """
    if not is_nmap_available():
        return None
    
    # Build port specification
    if len(ports) <= 100:
        port_spec = ",".join(str(p) for p in ports)
    else:
        # For large port lists, use ranges where possible
        port_spec = ",".join(str(p) for p in ports[:100])  # Limit for safety
    
    cmd = [
        "nmap",
        "-sT",  # TCP connect (works without root)
        "-sV",  # Service version detection
        "--version-light",  # Light version detection (faster)
        "-T4",  # Aggressive timing
        f"--max-retries=1",
        f"-p{port_spec}",
        "-oX", "-",  # XML output to stdout
        target
    ]
    
    if log_callback:
        await log_callback("INFO", f"Running nmap service detection on {len(ports)} ports...")
    
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout_seconds
        )
        
        if proc.returncode != 0:
            if log_callback:
                await log_callback("WARNING", f"nmap returned non-zero: {stderr.decode()[:200]}")
            return None
        
        # Parse XML output
        return parse_nmap_xml(stdout.decode('utf-8', errors='replace'))
        
    except asyncio.TimeoutError:
        if log_callback:
            await log_callback("WARNING", "nmap scan timed out")
        try:
            proc.kill()
        except:
            pass
        return None
    except Exception as e:
        if log_callback:
            await log_callback("WARNING", f"nmap scan failed: {e}")
        return None


def parse_nmap_xml(xml_content: str) -> List[PortScanResult]:
    """Parse nmap XML output into PortScanResult objects."""
    results = []
    
    try:
        root = ET.fromstring(xml_content)
        
        for host in root.findall('.//host'):
            for port_elem in host.findall('.//port'):
                port_id = int(port_elem.get('portid', 0))
                protocol = port_elem.get('protocol', 'tcp')
                
                if protocol != 'tcp':
                    continue
                
                state_elem = port_elem.find('state')
                state = state_elem.get('state', 'closed') if state_elem is not None else 'closed'
                
                # Map nmap states to our states
                state_map = {
                    'open': 'open',
                    'closed': 'closed',
                    'filtered': 'filtered',
                    'open|filtered': 'filtered',
                    'unfiltered': 'open'
                }
                state = state_map.get(state, 'closed')
                
                service_elem = port_elem.find('service')
                nmap_service = None
                nmap_version = None
                
                if service_elem is not None:
                    nmap_service = service_elem.get('name')
                    product = service_elem.get('product', '')
                    version = service_elem.get('version', '')
                    if product or version:
                        nmap_version = f"{product} {version}".strip()
                
                # Assess risk
                service_name = nmap_service or guess_service(port_id)
                risk_level, risk_reason, owasp_refs = assess_risk(port_id, service_name, None)
                
                results.append(PortScanResult(
                    port=port_id,
                    state=state,
                    service_guess=service_name if state == 'open' else None,
                    banner=None,
                    risk_level=risk_level if state == 'open' else None,
                    risk_reason=risk_reason if state == 'open' else None,
                    owasp_refs=owasp_refs if state == 'open' else [],
                    nmap_service=nmap_service,
                    nmap_version=nmap_version
                ))
                
    except ET.ParseError as e:
        pass  # Return empty list on parse error
    
    return sorted(results, key=lambda x: x.port)


# =============================================================================
# MAIN SCAN FUNCTION
# =============================================================================

async def scan_ports(
    ip_address: str, 
    log_callback: Optional[Callable[[str, str], Awaitable[None]]] = None,
    profile: PortScanProfile = PortScanProfile.LIGHT,
    use_nmap: bool = True,
    timeout: Optional[float] = None,
    concurrency: int = 100
) -> Tuple[List[PortScanResult], PortScanSummary]:
    """
    Perform port scan with specified profile.
    
    Args:
        ip_address: Target IP address
        log_callback: Optional async logging callback
        profile: Scan profile (LIGHT, MID, HIGH)
        use_nmap: Whether to use nmap for service detection (if available)
        timeout: Per-port timeout (defaults based on profile)
        concurrency: Max concurrent port scans (default: 100)
    
    Returns:
        Tuple of (list of PortScanResult, PortScanSummary)
    """
    start_time = datetime.utcnow()
    
    # Get ports for profile
    ports = get_ports_for_profile(profile)
    profile_meta = get_profile_metadata(profile)
    
    # Set timeout based on profile if not specified
    if timeout is None:
        timeout = settings.PORT_SCAN_TIMEOUT
        # Slightly faster timeout for larger scans
        if profile == PortScanProfile.HIGH:
            timeout = min(timeout, 0.5)  # Cap at 0.5s for speed
        elif profile == PortScanProfile.MID:
            timeout = min(timeout, 0.8)
    
    if log_callback:
        await log_callback(
            "INFO", 
            f"Starting TCP port scan on {ip_address} "
            f"[profile: {profile_meta['label']}, ports: {len(ports)}]..."
        )
    
    # Perform TCP connect scan
    scan_method = "tcp_connect"
    results = await scan_ports_tcp(
        ip_address, 
        ports, 
        timeout, 
        concurrency,
        log_callback
    )
    
    # Try nmap for service detection on open ports (if requested and available)
    nmap_available = is_nmap_available()
    open_ports = [r.port for r in results if r.state == "open"]
    
    if use_nmap and nmap_available and open_ports and len(open_ports) <= 50:
        if log_callback:
            await log_callback("INFO", f"Using nmap for service detection on {len(open_ports)} open ports...")
        
        nmap_results = await run_nmap_scan(
            ip_address,
            open_ports,
            timeout_seconds=60,
            log_callback=log_callback
        )
        
        if nmap_results:
            scan_method = "tcp_connect+nmap"
            # Merge nmap service info into results
            nmap_by_port = {r.port: r for r in nmap_results}
            for result in results:
                if result.port in nmap_by_port:
                    nmap_data = nmap_by_port[result.port]
                    if nmap_data.nmap_service:
                        result.nmap_service = nmap_data.nmap_service
                        result.nmap_version = nmap_data.nmap_version
    
    # Calculate summary
    duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
    open_count = sum(1 for r in results if r.state == "open")
    filtered_count = sum(1 for r in results if r.state == "filtered")
    closed_count = sum(1 for r in results if r.state == "closed")
    
    summary = PortScanSummary(
        profile=profile.value,
        ports_scanned=len(ports),
        open_count=open_count,
        filtered_count=filtered_count,
        closed_count=closed_count,
        duration_ms=duration_ms,
        scan_method=scan_method,
        nmap_available=nmap_available
    )
    
    if log_callback:
        await log_callback(
            "INFO", 
            f"Port scan completed in {duration_ms}ms. "
            f"Found {open_count} open, {filtered_count} filtered ports."
        )
    
    return results, summary


# =============================================================================
# BACKWARD COMPATIBILITY
# =============================================================================

# Legacy function signature for existing code
async def scan_ports_legacy(
    ip_address: str, 
    log_callback: Optional[Callable[[str, str], Awaitable[None]]] = None
) -> List[PortScanResult]:
    """
    Legacy scan_ports function for backward compatibility.
    Uses LIGHT profile (original behavior).
    """
    results, _ = await scan_ports(
        ip_address, 
        log_callback, 
        profile=PortScanProfile.LIGHT
    )
    return results
