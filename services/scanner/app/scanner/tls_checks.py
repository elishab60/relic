import ssl
import socket
from datetime import datetime
from typing import List, Optional, Dict, Any, Dict, Any
from .models import Finding

def check_tls(hostname: str, port: int = 443) -> tuple[List[Finding], Optional[Dict[str, Any]]]:
    """
    Checks for TLS configuration issues.
    Returns a list of findings and a dictionary with raw certificate info.
    """
    findings = []
    cert_info = None
    
    # print(f"DEBUG: check_tls start for {hostname}:{port}")
    
    try:
        # Combined check: Get cert and version in one go if possible, 
        # but we need CERT_NONE for version check sometimes if cert is bad, 
        # and CERT_OPTIONAL/REQUIRED for getpeercert().
        # Let's do one robust pass with CERT_OPTIONAL which allows both usually.
        
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_OPTIONAL
        
        # Enforce strict timeout on socket
        with socket.create_connection((hostname, port), timeout=3.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Check version
                version = ssock.version()
                if version in ["TLSv1", "TLSv1.1"]:
                    findings.append(Finding(
                        title="Obsolete TLS Protocol",
                        severity="medium",
                        category="tls",
                        description=f"The server supports an obsolete TLS version: {version}.",
                        recommendation="Disable TLS 1.0 and 1.1. Upgrade to TLS 1.2 or 1.3.",
                        owasp_refs=["A02:2021-Cryptographic Failures", "A05:2021-Security Misconfiguration"]
                    ))
                
                # Get cert
                cert = ssock.getpeercert()
                if cert:
                    # Extract raw info
                    not_after = cert.get('notAfter')
                    days_left = None
                    
                    if not_after:
                        try:
                            # Format: 'May 26 23:59:59 2025 GMT'
                            expire_date = datetime.strptime(not_after.replace(" GMT", ""), "%b %d %H:%M:%S %Y")
                            days_left = (expire_date - datetime.utcnow()).days
                        except ValueError:
                            pass

                    cert_info = {
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "issuer": dict(x[0] for x in cert.get('issuer', [])),
                        "version": cert.get('version'),
                        "serialNumber": cert.get('serialNumber'),
                        "notBefore": cert.get('notBefore'),
                        "notAfter": not_after,
                        "cipher": ssock.cipher(),
                        "protocol": version,
                        "days_to_expire": days_left
                    }
                        
                    if days_left is not None:
                        if days_left < 0:
                            findings.append(Finding(
                                title="Certificate Expired",
                                severity="high",
                                category="tls",
                                description=f"The SSL certificate expired on {not_after}.",
                                recommendation="Renew the SSL certificate immediately.",
                                owasp_refs=["A02:2021-Cryptographic Failures"]
                            ))
                        elif days_left < 30:
                            findings.append(Finding(
                                title="Certificate Near Expiration",
                                severity="medium",
                                category="tls",
                                description=f"The SSL certificate will expire in {days_left} days ({not_after}).",
                                recommendation="Renew the SSL certificate soon.",
                                owasp_refs=["A02:2021-Cryptographic Failures"]
                            ))

    except Exception as e:
        # print(f"DEBUG: check_tls error: {e}")
        pass
        
    # print(f"DEBUG: check_tls end")
    return findings, cert_info
