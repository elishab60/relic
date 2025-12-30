from typing import List, Dict, Callable, Awaitable
from .models import Finding, ScanLogEntry
from .http_client import HttpClient
from ..constants import Severity, Category

async def check_exposure(headers: Dict[str, str]) -> List[Finding]:
    """
    Checks for information disclosure in headers.
    """
    findings = []
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    if "server" in headers_lower:
        findings.append(Finding(
            title="Server Header Exposed",
            severity=Severity.INFO,
            category=Category.EXPOSURE,
            description=f"The 'Server' header is exposed: {headers_lower['server']}.",
            recommendation="Configure the server to suppress or obscure the 'Server' header.",
            owasp_refs=["A05:2021-Security Misconfiguration"]
        ))
        
    if "x-powered-by" in headers_lower:
        findings.append(Finding(
            title="X-Powered-By Header Exposed",
            severity=Severity.LOW,
            category=Category.EXPOSURE,
            description=f"The 'X-Powered-By' header is exposed: {headers_lower['x-powered-by']}.",
            recommendation="Remove the 'X-Powered-By' header to hide the underlying technology.",
            owasp_refs=["A05:2021-Security Misconfiguration"]
        ))
        
    return findings

import time
import random
import string
import urllib.parse
from typing import List, Dict, Callable, Awaitable, Tuple, Set
from ..config import settings
from .models import Finding
from .http_client import HttpClient
from .xss_detector import XSSDetector
from .scope import EndpointClass
from .utils.redaction import prepare_evidence_snippet
from .utils.repro_curl import build_xss_repro_curl, build_sqli_repro_curl, build_sensitive_file_repro_curl

async def extract_params(url: str) -> Dict[str, Set[str]]:
    """Extracts parameters from a URL."""
    params_map = {}
    parsed = urllib.parse.urlparse(url)
    if parsed.query:
        qs = urllib.parse.parse_qs(parsed.query)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if base_url not in params_map:
            params_map[base_url] = set()
        for k in qs.keys():
            params_map[base_url].add(k)
    return params_map

async def check_xss_url(url: str, http_client: HttpClient, log_callback: Callable[[str, str], Awaitable[None]] = None, classification: EndpointClass = EndpointClass.UNKNOWN) -> Tuple[List[Finding], List[Dict]]:
    """
    Checks a single URL for XSS vulnerabilities using context-aware analysis.
    """
    findings = []
    evidence_list = []
    
    # Strategy based on classification
    if classification == EndpointClass.STATIC_ASSET:
        return findings, evidence_list
    
    if classification == EndpointClass.AUTH_SSO:
        # Skip XSS on Auth/SSO to avoid account lockouts or noise
        if log_callback:
            await log_callback("INFO", f"Skipping XSS check on AUTH_SSO: {url}")
        return findings, evidence_list

    # Prepare Detector
    detector = XSSDetector()
    canary_token = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
    payloads = detector.generate_payloads(canary_token)
    
    # Limit payloads for Content pages
    if classification == EndpointClass.CONTENT_HTML:
        payloads = payloads[:settings.XSS_PAYLOAD_LIMIT]

    params_map = await extract_params(url)
    if not params_map:
        return findings, evidence_list

    for base_url, params in params_map.items():
        for param in params:
            for payload in payloads:
                test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                try:
                    response = await http_client.get(test_url)
                    if response:
                        evidence_list.append({
                            "url": test_url,
                            "payload": payload,
                            "status_code": response.status_code
                        })
                        
                        if "text/html" in response.headers.get("Content-Type", "").lower():
                            contexts = detector.analyze_response(response.text, canary_token)
                            
                            for ctx in contexts:
                                # Filter False Positives
                                if not ctx.is_executable:
                                    continue
                                    
                                # If it's just a redirect param and context is not dangerous, ignore
                                if classification == EndpointClass.REDIRECTOR and ctx.context_type == 'url_param':
                                    continue

                                severity = Severity.HIGH
                                description = f"Reflected XSS detected on parameter '{param}'."
                                description += f" Context: {ctx.context_type}."
                                if ctx.tag_name:
                                    description += f" Tag: <{ctx.tag_name}>."
                                if ctx.attribute_name:
                                    description += f" Attribute: {ctx.attribute_name}."
                                
                                evidence_str = f"Payload: {payload}\nURL: {test_url}\nContext: {ctx.context_type}\nEvidence: {ctx.evidence}"
                                
                                # Prepare evidence with redaction and hash
                                raw_evidence = f"{response.text}" if response else ""
                                snippet, evidence_hash = prepare_evidence_snippet(raw_evidence)
                                
                                # Build reproducible cURL
                                repro_curl = build_xss_repro_curl(base_url, param, payload)
                                
                                findings.append(Finding(
                                    title="Reflected XSS Vulnerability",
                                    severity=severity,
                                    category=Category.XSS,
                                    description=description,
                                    recommendation="Implement context-aware output encoding and validate all input.",
                                    evidence=evidence_str,
                                    owasp_refs=["A03:2021-Injection"],
                                    confidence="high",  # Executable context = high confidence
                                    repro_curl=repro_curl,
                                    evidence_snippet=snippet,
                                    evidence_hash=evidence_hash
                                ))
                                
                                if log_callback:
                                    await log_callback("WARNING", f"XSS detected on {base_url} param {param} ({ctx.context_type})")
                                
                                # Stop testing this param if vulnerable
                                break
                    if findings:
                        break # Stop testing payloads for this param
                except Exception as e:
                    if log_callback:
                        await log_callback("ERROR", f"XSS check error for {test_url}: {e}")
                        
    return findings, evidence_list

async def check_sqli_url(url: str, http_client: HttpClient, log_callback: Callable[[str, str], Awaitable[None]] = None, classification: EndpointClass = EndpointClass.UNKNOWN) -> Tuple[List[Finding], List[Dict]]:
    """
    Checks a single URL for SQLi vulnerabilities, including rigorous Time-based Blind SQLi.
    """
    findings = []
    evidence_list = []
    
    if classification in [EndpointClass.STATIC_ASSET, EndpointClass.AUTH_SSO]:
        return findings, evidence_list

    params_map = await extract_params(url)
    if not params_map:
        return findings, evidence_list
        
    # Error-based Payloads
    error_payloads = [
        "' OR 1=1--",
        '" OR 1=1--',
    ]
    
    # Time-based Payloads
    sleep_delay = int(settings.BLIND_SQLI_THRESHOLD)
    time_payloads = [
        f"'; SELECT SLEEP({sleep_delay})--", 
        f"'; WAITFOR DELAY '00:00:{sleep_delay:02d}'--",
    ]
    
    error_signatures = [
        "you have an error in your sql syntax",
        "warning: mysql_",
        "sqlstate[hy000]",
        "ora-00933",
        "unclosed quotation mark after the character string",
        "microsoft ole db provider for sql server",
        "syntax error at or near",
        "sqlstate"
    ]

    for base_url, params in params_map.items():
        for param in params:
            # Error-based checks
            param_vulnerable = False
            for payload in error_payloads:
                if param_vulnerable: break
                
                test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                try:
                    response = await http_client.get(test_url)
                    if response:
                        evidence_list.append({"url": test_url, "payload": payload, "status_code": response.status_code, "type": "error_based"})
                        body = response.text.lower()
                        for sig in error_signatures:
                            if sig in body:
                                # Prepare evidence with redaction and hash
                                snippet, evidence_hash = prepare_evidence_snippet(response.text)
                                repro_curl = build_sqli_repro_curl(base_url, param, payload)
                                
                                findings.append(Finding(
                                    title="Potential SQL Injection Error",
                                    severity=Severity.HIGH,
                                    category=Category.SQLI,
                                    description="Database error message found.",
                                    recommendation="Use parameterized queries.",
                                    evidence=f"Signature: '{sig}'\nPayload: {payload}",
                                    owasp_refs=["A03:2021-Injection"],
                                    confidence="high",  # Error-based = high confidence
                                    repro_curl=repro_curl,
                                    evidence_snippet=snippet,
                                    evidence_hash=evidence_hash
                                ))
                                if log_callback:
                                    await log_callback("WARNING", f"SQL Error found on {param}")
                                param_vulnerable = True
                                break
                except Exception: pass
            
            if param_vulnerable:
                continue # Move to next param, skip time-based checks for this param

            # Time-based checks (Rigorous)
            # Measure baseline
            baseline_latencies = []
            try:
                for _ in range(3):
                    start = time.time()
                    await http_client.get(base_url)
                    baseline_latencies.append(time.time() - start)
                avg_baseline = sum(baseline_latencies) / len(baseline_latencies)
            except Exception:
                avg_baseline = 0.5 # Fallback

            for payload in time_payloads:
                test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                try:
                    # Confirmation loop
                    confirmed = True
                    total_duration = 0
                    attempts = 2 # Try twice to be sure
                    
                    for _ in range(attempts):
                        start_time = time.time()
                        response = await http_client.get(test_url)
                        duration = time.time() - start_time
                        total_duration += duration
                        
                        # Check if duration is significantly higher than baseline + delay
                        # Allow some jitter, so say 80% of delay
                        if duration < (avg_baseline + sleep_delay * 0.8):
                            confirmed = False
                            break
                    
                    if confirmed:
                        avg_duration = total_duration / attempts
                        repro_curl = build_sqli_repro_curl(base_url, param, payload)
                        
                        findings.append(Finding(
                            title="Blind SQL Injection (Time-based)",
                            severity=Severity.CRITICAL,
                            category=Category.SQLI,
                            description=f"Response delayed by ~{avg_duration:.2f}s (Baseline: {avg_baseline:.2f}s).",
                            recommendation="Use parameterized queries.",
                            evidence=f"Payload: {payload}\nAvg Duration: {avg_duration:.2f}s\nBaseline: {avg_baseline:.2f}s",
                            owasp_refs=["A03:2021-Injection"],
                            confidence="medium",  # Time-based = medium confidence (timing can vary)
                            repro_curl=repro_curl,
                            evidence_snippet=None,  # No response body evidence for time-based
                            evidence_hash=None
                        ))
                        if log_callback:
                            await log_callback("WARNING", f"Blind SQLi confirmed on {param}")
                        break
                except Exception as e:
                    if "timeout" in str(e).lower():
                         findings.append(Finding(
                                title="Blind SQL Injection (Timeout)",
                                severity=Severity.CRITICAL,
                                category=Category.SQLI,
                                description="Request timed out consistently with sleep payload.",
                                recommendation="Use parameterized queries.",
                                evidence=f"Payload: {payload}\nResult: Timeout",
                                owasp_refs=["A03:2021-Injection"]
                            ))
                         break

    return findings, evidence_list

async def check_xss(target: str, http_client: HttpClient, log_callback: Callable[[str, str], Awaitable[None]] = None, discovered_urls: List[str] = None) -> tuple[List[Finding], Dict[str, any]]:
    """
    Wrapper for check_xss with deduplication.
    Aggregates parameters by base URL to ensure each parameter is tested only once.
    """
    findings = []
    evidence = []
    urls = [target] + (discovered_urls or [])
    
    # Deduplication: BaseURL -> Set[Params]
    global_params_map: Dict[str, Set[str]] = {}
    
    # 1. Aggregate parameters from all URLs
    for u in urls:
        try:
            # We use extract_params to parse the URL
            p_map = await extract_params(u)
            for base_url, params in p_map.items():
                if base_url not in global_params_map:
                    global_params_map[base_url] = set()
                global_params_map[base_url].update(params)
        except Exception:
            continue

    # 2. Test each Base URL with all its unique parameters
    # We construct a single "merged" URL for each base URL containing all parameters
    # This works because check_xss_url extracts params from the URL provided
    
    # Limit to 20 base URLs to prevent scanning too long
    base_urls = list(global_params_map.keys())[:20]
    
    for base_url in base_urls:
        params = global_params_map[base_url]
        if not params:
            continue
            
        # Construct merged URL: base_url?p1=1&p2=1...
        # We assign a dummy value '1' to each param
        query_string = "&".join([f"{p}=1" for p in params])
        merged_url = f"{base_url}?{query_string}"
        
        f, e = await check_xss_url(merged_url, http_client, log_callback)
        findings.extend(f)
        evidence.extend(e)
        
    return findings, {"outcome": "done", "evidence": evidence}

async def check_sqli(target: str, http_client: HttpClient, log_callback: Callable[[str, str], Awaitable[None]] = None, discovered_urls: List[str] = None) -> tuple[List[Finding], Dict[str, any]]:
    """
    Wrapper for check_sqli with deduplication.
    Aggregates parameters by base URL to ensure each parameter is tested only once.
    """
    findings = []
    evidence = []
    urls = [target] + (discovered_urls or [])
    
    # Deduplication: BaseURL -> Set[Params]
    global_params_map: Dict[str, Set[str]] = {}
    
    # 1. Aggregate parameters from all URLs
    for u in urls:
        try:
            p_map = await extract_params(u)
            for base_url, params in p_map.items():
                if base_url not in global_params_map:
                    global_params_map[base_url] = set()
                global_params_map[base_url].update(params)
        except Exception:
            continue

    # 2. Test each Base URL with all its unique parameters
    base_urls = list(global_params_map.keys())[:20]
    
    for base_url in base_urls:
        params = global_params_map[base_url]
        if not params:
            continue
            
        # Construct merged URL
        query_string = "&".join([f"{p}=1" for p in params])
        merged_url = f"{base_url}?{query_string}"
        
        f, e = await check_sqli_url(merged_url, http_client, log_callback)
        findings.extend(f)
        evidence.extend(e)
        
    return findings, {"outcome": "done", "evidence": evidence}

async def check_https_enforcement(target_info: 'TargetInfo', http_client: HttpClient, log_callback: Callable[[str, str], Awaitable[None]] = None) -> tuple[List[Finding], Dict[str, any]]:
    """
    Checks if HTTPS is enforced when accessing via HTTP.
    Returns findings and raw debug info.
    """
    findings = []
    
    if log_callback:
        await log_callback("INFO", f"Entering check_https_enforcement. Scheme: {target_info.scheme}")

    # Only run if scheme is http
    if target_info.scheme != "http":
        debug_data = {
            "checked": False,
            "reason": "target already HTTPS",
            "https_reachable": True,
            "http_redirected_to_https": None,
            "http_final_url": None
        }
        if log_callback:
            await log_callback("INFO", "HTTPS enforcement: skipped (target already HTTPS).")
        return findings, debug_data

    debug_data = {
        "checked": True,
        "http_redirected_to_https": False,
        "http_final_url": None,
        "https_reachable": False,
        "outcome": "pass", # Default to pass, will update if fail or blocked
        "reason": "HTTPS enforced"
    }

    if log_callback:
        await log_callback("INFO", "Checking HTTP -> HTTPS redirection...")

    # 1. Check HTTP redirection
    # target_info.full_url should be the http url since scheme is http
    http_url = target_info.full_url
    
    try:
        response = await http_client.get(http_url)
        if response:
            final_url = str(response.url)
            debug_data["http_final_url"] = final_url
            if final_url.startswith("https://"):
                debug_data["http_redirected_to_https"] = True
                if log_callback:
                    await log_callback("INFO", "HTTP redirects to HTTPS.")
            else:
                if log_callback:
                    await log_callback("INFO", "HTTP does NOT redirect to HTTPS.")
    except Exception as e:
        if log_callback:
            await log_callback("ERROR", f"HTTP check failed: {e}")

    # 2. Check HTTPS reachability
    https_url = f"https://{target_info.hostname}/" # Default port 443
    if log_callback:
        await log_callback("INFO", f"Checking HTTPS reachability at {https_url}...")
        
    try:
        # Use a short timeout for this check
        response_https = await http_client.get(https_url)
        if response_https:
            debug_data["https_reachable"] = True
            debug_data["https_status_code"] = response_https.status_code
            if log_callback:
                await log_callback("INFO", "HTTPS is reachable.")
        else:
            if log_callback:
                await log_callback("INFO", "HTTPS is NOT reachable.")
    except Exception:
        pass

    # Generate finding
    if not debug_data["http_redirected_to_https"] and debug_data["https_reachable"]:
        findings.append(Finding(
            title="Le site est accessible en HTTP (HTTPS non imposé)",
            severity=Severity.HIGH,
            category=Category.TLS,
            description="Le site est accessible en HTTP sans redirection automatique vers HTTPS, bien que HTTPS soit disponible.",
            recommendation="Forcer la redirection 301 vers HTTPS, servir HSTS uniquement sur HTTPS, envisager includeSubDomains.",
            evidence=f"HTTP URL: {debug_data['http_final_url']}\nHTTPS is reachable.",
            owasp_refs=["A02:2021-Cryptographic Failures", "A05:2021-Security Misconfiguration"]
        ))
        debug_data["outcome"] = "fail"
        debug_data["reason"] = "HTTPS not enforced"
        if log_callback:
            await log_callback("WARNING", "HTTPS enforcement missing!")

    return findings, debug_data

async def check_sensitive_url(url: str, http_client: HttpClient, log_callback: Callable[[str, str], Awaitable[None]] = None, classification: EndpointClass = EndpointClass.UNKNOWN) -> Tuple[List[Finding], List[Dict]]:
    """
    Checks if a discovered URL contains sensitive information (e.g. env dump, config).
    """
    findings = []
    evidence_list = []
    
    # Keywords that suggest a sensitive file
    SENSITIVE_KEYWORDS = ["env", "config", "backup", "dump", "secret", "credentials", "password", "key"]
    
    # Check if URL looks suspicious
    url_lower = url.lower()
    is_suspicious = any(k in url_lower for k in SENSITIVE_KEYWORDS)
    
    if not is_suspicious:
        return findings, evidence_list

    try:
        # Perform GET request
        response = await http_client.get(url)
        if not response:
            return findings, evidence_list
            
        evidence_list.append({
            "url": url,
            "status_code": response.status_code,
            "type": "sensitive_check"
        })

        if response.status_code == 200:
            content = response.text
            
            # Check for sensitive content patterns
            patterns = [
                ("AWS_ACCESS_KEY", "AWS Access Key"),
                ("DB_PASSWORD", "Database Password"),
                ("API_KEY", "Generic API Key"),
                ("SECRET_KEY", "Secret Key"),
                ("POSTGRES_PASSWORD", "Postgres Password"),
                ("MYSQL_PWD", "MySQL Password"),
                ("BEGIN RSA PRIVATE KEY", "RSA Private Key"),
            ]
            
            found_secrets = []
            for pattern, name in patterns:
                if pattern in content:
                    found_secrets.append(name)
            
            # Also check if it looks like a .env file (key=value pairs)
            if "APP_ENV=" in content or "NODE_ENV=" in content or "DEBUG=" in content:
                if "Environment Configuration" not in found_secrets:
                    found_secrets.append("Environment Configuration")

            if found_secrets:
                description = f"Sensitive file detected at {url}. It appears to contain: {', '.join(found_secrets)}."
                
                # Prepare evidence with redaction and hash
                snippet, evidence_hash = prepare_evidence_snippet(content)
                repro_curl = build_sensitive_file_repro_curl(url)
                
                findings.append(Finding(
                    title="Sensitive Information Exposure",
                    severity=Severity.CRITICAL,
                    category=Category.EXPOSURE,
                    description=description,
                    recommendation="Remove this file immediately and rotate any exposed credentials.",
                    evidence=f"URL: {url}\nSecrets found: {', '.join(found_secrets)}\nSnippet: {content[:200]}...",
                    owasp_refs=["A05:2021-Security Misconfiguration", "A02:2021-Cryptographic Failures"],
                    confidence="high",  # Confirmed secrets = high confidence
                    repro_curl=repro_curl,
                    evidence_snippet=snippet,
                    evidence_hash=evidence_hash
                ))
                if log_callback:
                    await log_callback("WARNING", f"Sensitive file confirmed: {url} ({', '.join(found_secrets)})")

    except Exception as e:
        if log_callback:
            await log_callback("ERROR", f"Sensitive check failed for {url}: {e}")

    return findings, evidence_list
