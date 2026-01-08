import asyncio
import socket
from datetime import datetime
from typing import List, Callable, Awaitable, Optional, Dict, Any
import httpx

from .models import ScanResult, ScanLogEntry, Finding
from .normalizer import normalize_target
from .http_client import HttpClient
from .tls_checks import check_tls
from .header_checks import check_security_headers
from .cookies_checks import analyze_cookies
from .vuln_checks import check_exposure, check_xss, check_sqli, check_https_enforcement, check_xss_url, check_sqli_url, check_sensitive_url
from .scoring import calculate_score
from .port_scanner_v2 import scan_ports_v2 as scan_ports, PortScanProfile, ScanSummary as PortScanSummary, PortState, PortResult
from .path_discovery import PathDiscoverer, PathDiscoveryProfile, get_crawl_limit_for_profile
from .waf_detection import detect_waf_and_visibility
from .tech_fingerprint import TechFingerprinter
from ..config import settings
from ..constants import Severity, Category, ScanStatus, VisibilityLevel

from .scope import ScopeManager, EndpointClass

class ScanEngine:
    def __init__(self):
        self.http_client = None
        self.scope_manager = ScopeManager()

    async def run_scan(
        self, 
        target_input: str, 
        log_callback: Callable[[ScanLogEntry], Awaitable[None]] = None,
        config: Optional[Dict[str, Any]] = None
    ) -> ScanResult:
        """
        Orchestrates the scan process.
        
        Args:
            target_input: URL or hostname to scan
            log_callback: Optional async callback for real-time logging
            config: Optional scan configuration dict with:
                    - path_profile: "minimal", "standard", or "thorough"
                    - port_scan_profile: "light", "mid", or "high"
        """
        logs: List[ScanLogEntry] = []
        findings: List[Finding] = []
        start_time = datetime.utcnow()
        
        # Extract path discovery profile from config (PR-02a)
        path_profile_str = (config or {}).get("path_profile", "standard")
        try:
            path_profile = PathDiscoveryProfile(path_profile_str)
        except ValueError:
            path_profile = PathDiscoveryProfile.STANDARD
        
        # Extract port scan profile from config (PR-03)
        port_scan_profile_str = (config or {}).get("port_scan_profile", "light")
        try:
            port_scan_profile = PortScanProfile(port_scan_profile_str)
        except ValueError:
            port_scan_profile = PortScanProfile.LIGHT
        
        async def log(level: str, message: str):
            entry = ScanLogEntry(timestamp=datetime.utcnow(), level=level, message=message)
            logs.append(entry)
            if log_callback:
                await log_callback(entry)
            # Force yield to allow SSE to pick up the log immediately
            await asyncio.sleep(0)

        # Initialize HttpClient with logger
        async def http_log_adapter(level: str, msg: str):
            await log(level, msg)
            
        # Use HttpClient as context manager to ensure cleanup
        async with HttpClient(config=settings, log_callback=http_log_adapter) as http_client:
            self.http_client = http_client
            
            # ASCII indicators for logs (no emojis for terminal compatibility)
            SPIN = "/"
            CHECK = "[OK]"
            FAIL = "[!!]"
            WARN = "[!]"
            ARROW = "-->"
            
            await log("INFO", "[SECURITY-SCAN] SCAN INITIATED")
            await log("INFO", f"{ARROW} Target: {target_input}")
            await log("INFO", f"{ARROW} Path Profile: {path_profile.value}")
            await log("INFO", f"{ARROW} Port Profile: {port_scan_profile.value}")

            # Normalization
            await log("INFO", f"{SPIN} Normalizing target URL...")
            try:
                target_info = normalize_target(target_input)
                await log("INFO", f"{CHECK} Target normalized: {target_info.full_url}")
            except Exception as e:
                await log("ERROR", f"{FAIL} Failed to normalize target: {e}")
                return self._build_error_result(target_input, logs, start_time, "Normalization Error")

            # Parallelize Initial Checks: DNS, Port Scan, Initial HTTP
            await log("INFO", "[INIT] PARALLEL INITIALIZATION (DNS + Ports + HTTP)")
            
            async def task_dns():
                try:
                    loop = asyncio.get_running_loop()
                    ip_info = await loop.run_in_executor(None, socket.getaddrinfo, target_info.hostname, target_info.port)
                    return ip_info[0][4][0]
                except Exception as e:
                    await log("ERROR", f"DNS resolution failed: {e}")
                    raise e

            # Port scan summary for debug_info
            port_scan_summary: Optional[PortScanSummary] = None
            
            async def task_ports(hostname):
                """
                Port scan using hostname (not IP) to properly detect CDN catch-all.
                The v2 scanner handles DNS resolution and CDN detection internally.
                """
                nonlocal port_scan_summary
                if not hostname:
                    return []
                try:
                    results, summary = await scan_ports(
                        hostname,  # Use hostname for CDN detection & SNI
                        log_callback=log,
                        profile=port_scan_profile,
                        use_nmap=port_scan_profile == PortScanProfile.HIGH
                    )
                    port_scan_summary = summary
                    return results
                except Exception as e:
                    await log("ERROR", f"Port scan failed: {e}")
                    return []

            async def task_http():
                try:
                    # Enforce a hard timeout on the initial request
                    return await asyncio.wait_for(self.http_client.get(target_info.full_url), timeout=15.0)
                except Exception as e:
                    await log("ERROR", f"Initial HTTP request failed: {e}")
                    return None

            ip_address = None
            port_scan_results = []
            response = None
            
            async def chain_dns_ports():
                nonlocal ip_address, port_scan_results
                try:
                    ip_address = await task_dns()
                    await log("INFO", f"DNS resolved to {ip_address}")
                    # Use hostname for port scan (CDN detection + SNI)
                    port_scan_results = await task_ports(target_info.hostname)
                except socket.gaierror:
                    await log("ERROR", "Host unreachable (DNS resolution failed)")
                    raise
                except Exception as e:
                    await log("ERROR", f"DNS/Port chain error: {e}")
                    raise

            try:
                results = await asyncio.gather(chain_dns_ports(), task_http(), return_exceptions=True)
                
                # Check DNS result
                if isinstance(results[0], Exception):
                    findings.append(Finding(
                        title="Host Unreachable",
                        severity=Severity.HIGH,
                        category=Category.AVAILABILITY,
                        description="Could not resolve the hostname via DNS.",
                        recommendation="Check if the hostname is correct and accessible."
                    ))
                    return self._build_result(target_info.full_url, findings, logs, start_time)
                
                # Check HTTP result
                if isinstance(results[1], Exception) or results[1] is None:
                    await log("ERROR", "Failed to establish HTTP connection")
                    findings.append(Finding(
                        title="HTTP Connection Failed",
                        severity=Severity.HIGH,
                        category=Category.AVAILABILITY,
                        description="Could not connect to the web server via HTTP/HTTPS.",
                        recommendation="Ensure the web server is running and accessible."
                    ))
                    return self._build_result(target_info.full_url, findings, logs, start_time)
                
                response = results[1]
                await log("INFO", f"{CHECK} HTTP response received: {response.status_code}")
                
            except Exception as e:
                await log("ERROR", f"{FAIL} Parallel checks failed: {e}")
                return self._build_error_result(target_info.full_url, logs, start_time, str(e))

            # ===========================================================
            # PHASE: TLS/SSL Analysis
            # ===========================================================
            tls_details = None
            final_scheme = response.url.scheme
            final_host = response.url.host
            final_port = response.url.port or (443 if final_scheme == "https" else 80)
            
            if final_scheme == "https":
                await log("INFO", f"{'-'*60}")
                await log("INFO", f"[TLS] TLS/SSL ANALYSIS")
                await log("INFO", f"{'-'*60}")
                await log("INFO", f"{SPIN} Analyzing TLS certificate for {final_host}...")
                loop = asyncio.get_running_loop()
                try:
                    tls_result = await asyncio.wait_for(
                        loop.run_in_executor(None, check_tls, final_host, final_port),
                        timeout=5.0
                    )
                    tls_findings, tls_details = tls_result
                    if tls_details:
                        await log("INFO", f"{CHECK} TLS certificate validated")
                        if tls_details.get('days_until_expiry'):
                            await log("INFO", f"   {ARROW} Expires in {tls_details.get('days_until_expiry')} days")
                    if tls_findings:
                        await log("WARNING", f"   [!]  {len(tls_findings)} TLS issue(s) found")
                        findings.extend(tls_findings)
                except asyncio.TimeoutError:
                    await log("WARNING", f"{FAIL} TLS check timed out")
                except Exception as e:
                    await log("ERROR", f"{FAIL} TLS check failed: {e}")
            
            # ===========================================================
            # PHASE: Technology Fingerprinting
            # ===========================================================
            await log("INFO", f"{'-'*60}")
            await log("INFO", f"[TECH] TECHNOLOGY FINGERPRINTING")
            await log("INFO", f"{'-'*60}")
            tech_fingerprint_data = None
            try:
                await log("INFO", f"{SPIN} Detecting technologies...")
                fingerprinter = TechFingerprinter(
                    http_client=self.http_client,
                    log_callback=log,
                    max_probes=3,
                    timeout=settings.DEFAULT_TIMEOUT
                )
                tech_result = await fingerprinter.fingerprint(
                    url=target_info.full_url,
                    response_html=response.text if hasattr(response, 'text') else "",
                    response_headers=dict(response.headers),
                    status_code=response.status_code,
                    perform_404_probe=True
                )
                tech_fingerprint_data = tech_result.to_dict()
                
                # Log detected technologies summary
                if tech_result.technologies:
                    tech_names = [t.name for t in tech_result.technologies[:5]]
                    suffix = f" (+{len(tech_result.technologies) - 5} more)" if len(tech_result.technologies) > 5 else ""
                    await log("INFO", f"{CHECK} Detected: {', '.join(tech_names)}{suffix}")
                else:
                    await log("INFO", f"{FAIL} No technologies detected")
                    
            except Exception as e:
                await log("WARNING", f"{FAIL} Tech fingerprinting failed: {e}")
                tech_fingerprint_data = {"error": str(e)}

            # ===========================================================
            # PHASE: Security Headers & Cookies Analysis  
            # ===========================================================
            await log("INFO", f"{'-'*60}")
            await log("INFO", f"[HEADERS] SECURITY HEADERS & COOKIES")
            await log("INFO", f"{'-'*60}")
            
            await log("INFO", f"{SPIN} Analyzing HTTP security headers...")
            header_findings = check_security_headers(response.headers)
            if header_findings:
                await log("WARNING", f"   [!]  {len(header_findings)} missing security header(s)")
                findings.extend(header_findings)
            else:
                await log("INFO", f"{CHECK} All recommended headers present")

            await log("INFO", f"{SPIN} Analyzing cookies...")
            cookies_list, cookies_summary, cookie_findings = analyze_cookies(self.http_client.history)
            cookies_debug = {"cookies": cookies_list, "cookies_summary": cookies_summary}
            if cookie_findings:
                await log("WARNING", f"   [!]  {len(cookie_findings)} cookie security issue(s)")
                findings.extend(cookie_findings)
            else:
                await log("INFO", f"{CHECK} Cookies analyzed: {len(cookies_list)} found")
            cookies_present = len(cookies_list) > 0

            await log("INFO", f"{SPIN} Probing CORS configuration...")
            from .cors_checks import check_cors
            cors_findings, cors_info = await check_cors(target_info.full_url, response.headers, self.http_client, log, cookies_present=cookies_present)
            if cors_findings:
                await log("WARNING", f"   [!]  {len(cors_findings)} CORS misconfiguration(s)")
                findings.extend(cors_findings)
            else:
                await log("INFO", f"{CHECK} CORS configuration OK")

            # Streaming Crawler & Vuln Checks
            discovery_results = []
            discovered_paths = []
            checks_outcomes = []
            
            vuln_findings = []
            checked_urls = set()
            all_urls = [] # Collect all URLs for deduplicated scanning
            
            async def process_url(url_info):
                if isinstance(url_info, dict):
                    url = url_info["url"]
                    classification = url_info.get("classification", EndpointClass.UNKNOWN)
                else:
                    url = url_info
                    # Classify initial target
                    ct = response.headers.get("Content-Type") if url == target_info.full_url else None
                    classification = self.scope_manager.classify_endpoint(url, content_type=ct)

                if url in checked_urls:
                    return
                checked_urls.add(url)
                all_urls.append(url)
                
                # Log interesting classifications
                if classification != EndpointClass.STATIC_ASSET:
                    # await log("INFO", f"Testing {url} [{classification}]")
                    pass
                
                # Only run sensitive file check per-URL here
                # XSS and SQLi are now run in batch after crawling
                res = await asyncio.gather(
                    check_sensitive_url(url, self.http_client, log, classification),
                    return_exceptions=True
                )
                
                if not isinstance(res[0], Exception):
                    sens_findings, sens_evidence = res[0]
                    vuln_findings.extend(sens_findings)
                    if sens_findings or sens_evidence:
                        checks_outcomes.append({
                            "name": "sensitive_file",
                            "url": url,
                            "outcome": "fail" if sens_findings else "pass",
                            "evidence": sens_evidence
                        })

            # ===========================================================
            # PHASE: Content Crawling & Discovery
            # ===========================================================
            try:
                content_type = response.headers.get("Content-Type", "").lower()
                if "text/html" in content_type:
                    crawl_limit = get_crawl_limit_for_profile(path_profile)
                    await log("INFO", f"{'-'*60}")
                    await log("INFO", f"[CRAWL]  CONTENT CRAWLING")
                    await log("INFO", f"{'-'*60}")
                    await log("INFO", f"{SPIN} Crawling pages (max {crawl_limit} URLs)...")
                    
                    from .crawler import SimpleCrawler
                    crawler = SimpleCrawler(self.http_client, log)
                    
                    tasks = []
                    tasks.append(asyncio.create_task(process_url(target_info.full_url)))
                    
                    async for asset in crawler.crawl_generator(target_info.full_url, response.text, max_urls=crawl_limit):
                        discovery_results.append(asset)
                        tasks.append(asyncio.create_task(process_url(asset)))
                    
                    if tasks:
                        await asyncio.gather(*tasks)
                    
                    await log("INFO", f"{CHECK} Crawled {len(discovery_results)} pages/assets")
                        
                else:
                    await log("INFO", f"{SPIN} Non-HTML content, skipping crawler")
                    await process_url(target_info.full_url)
                    
            except Exception as e:
                await log("ERROR", f"{FAIL} Crawler failed: {e}")

            # ===========================================================
            # PHASE: Vulnerability Scanning (XSS, SQLi)
            # ===========================================================
            if all_urls:
                await log("INFO", f"{'-'*60}")
                await log("INFO", f"[VULN] VULNERABILITY SCANNING")
                await log("INFO", f"{'-'*60}")
                await log("INFO", f"{SPIN} Testing {len(all_urls)} URLs for XSS/SQLi...")
                
                batch_results = await asyncio.gather(
                    check_xss(target_info.full_url, self.http_client, log, discovered_urls=all_urls),
                    check_sqli(target_info.full_url, self.http_client, log, discovered_urls=all_urls),
                    return_exceptions=True
                )
                
                # Process XSS Results
                if not isinstance(batch_results[0], Exception):
                    x_findings, x_debug = batch_results[0]
                    vuln_findings.extend(x_findings)
                    if x_findings:
                        await log("WARNING", f"   [HIGH] XSS vulnerabilities found: {len(x_findings)}")
                    else:
                        await log("INFO", f"{CHECK} No XSS vulnerabilities detected")
                    checks_outcomes.append({
                        "name": "xss_batch",
                        "outcome": "fail" if x_findings else "pass",
                        "evidence": x_debug.get("evidence", [])
                    })
                else:
                    await log("ERROR", f"{FAIL} XSS check failed: {batch_results[0]}")

                # Process SQLi Results
                if not isinstance(batch_results[1], Exception):
                    s_findings, s_debug = batch_results[1]
                    vuln_findings.extend(s_findings)
                    if s_findings:
                        await log("WARNING", f"   [HIGH] SQLi vulnerabilities found: {len(s_findings)}")
                    else:
                        await log("INFO", f"{CHECK} No SQLi vulnerabilities detected")
                    checks_outcomes.append({
                        "name": "sqli_batch",
                        "outcome": "fail" if s_findings else "pass",
                        "evidence": s_debug.get("evidence", [])
                    })
                else:
                    await log("ERROR", f"{FAIL} SQLi check failed: {batch_results[1]}")

            # ===========================================================
            # PHASE: Path Discovery
            # ===========================================================
            await log("INFO", f"{'-'*60}")
            await log("INFO", f"📂 PATH DISCOVERY ({path_profile.value.upper()})")
            await log("INFO", f"{'-'*60}")
            try:
                path_discoverer = PathDiscoverer(self.http_client, log, profile=path_profile)
                await log("INFO", f"{SPIN} Probing common paths and directories...")
                discovered_paths = await path_discoverer.run(target_info.full_url)
                if discovered_paths:
                    await log("INFO", f"{CHECK} Found {len(discovered_paths)} interesting paths")
                else:
                    await log("INFO", f"{CHECK} No exposed paths found")
            except Exception as e:
                await log("ERROR", f"{FAIL} Path discovery failed: {e}")

            # HTTPS Enforcement
            try:
                https_findings, https_debug = await check_https_enforcement(target_info, self.http_client, log)
                if https_findings:
                    findings.extend(https_findings)
                if https_debug:
                     checks_outcomes.append({
                        "name": "https_enforcement",
                        "outcome": https_debug.get("outcome", "pass"),
                        "evidence": https_debug
                    })
            except Exception as e:
                await log("ERROR", f"HTTPS enforcement check failed: {e}")

            # Exposure Check
            exposure_findings = await check_exposure(response.headers)
            findings.extend(exposure_findings)
            
            findings.extend(vuln_findings)
            
            if any(f.category == "xss" for f in vuln_findings):
                await log("WARNING", "   [HIGH] Potential XSS vulnerability detected!")
            if any(f.category == "sqli" for f in vuln_findings):
                await log("WARNING", "   [HIGH] Potential SQL Injection detected!")

            # ===========================================================
            # SCAN COMPLETE
            # ===========================================================
            scan_duration = (datetime.utcnow() - start_time).total_seconds()
            await log("INFO", f"{'='*60}")
            await log("INFO", f"[DONE] SCAN COMPLETE")
            await log("INFO", f"{'='*60}")
            await log("INFO", f"   Duration: {scan_duration:.1f}s")
            await log("INFO", f"   Findings: {len(findings)}")
            
            # Count by severity
            critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
            high = sum(1 for f in findings if f.severity == Severity.HIGH)
            medium = sum(1 for f in findings if f.severity == Severity.MEDIUM)
            low = sum(1 for f in findings if f.severity == Severity.LOW)
            
            if critical or high:
                await log("WARNING", f"   [HIGH] Critical: {critical}, High: {high}")
            if medium:
                await log("INFO", f"   [MED] Medium: {medium}")
            if low:
                await log("INFO", f"   [LOW] Low: {low}")
            await log("INFO", f"{'='*60}")
            
            # Network Exposure Analysis (v2 with CDN detection)
            network_exposure = {}
            if port_scan_results:
                confirmed_open = []
                suspected_open = []
                cdn_catchall = []
                unexpected_services = []
                filtered_count = 0
                EXPECTED_PORTS = {80, 443, 8080, 8443}
                
                for p in port_scan_results:
                    if p.final_state == PortState.OPEN_CONFIRMED:
                        port_num = p.port
                        service = p.service_confirmed or p.service_guess or "unknown"
                        confirmed_open.append({
                            "port": port_num, 
                            "service": service, 
                            "risk": p.risk_level,
                            "version": p.version,
                            "product": p.product
                        })
                        if port_num not in EXPECTED_PORTS:
                            unexpected_services.append({"port": port_num, "service": service, "risk": p.risk_level})
                    elif p.final_state == PortState.OPEN_SUSPECTED:
                        suspected_open.append({"port": p.port, "reason": p.risk_reason})
                    elif p.final_state == PortState.CDN_CATCHALL:
                        cdn_catchall.append(p.port)
                    elif p.final_state == PortState.FILTERED:
                        filtered_count += 1
                
                # Build summary
                if confirmed_open:
                    open_list = ", ".join([f"{op['port']} ({op['service'].upper()})" for op in confirmed_open])
                    summary = f"{len(confirmed_open)} confirmed open ports: {open_list}."
                else:
                    summary = "No confirmed open ports detected."
                
                if cdn_catchall:
                    summary += f" {len(cdn_catchall)} ports ignored (CDN catch-all)."
                
                if unexpected_services:
                    unexpected_list = ", ".join([f"{u['port']} ({u['service'].upper()})" for u in unexpected_services])
                    summary += f" Unexpected exposed services: {unexpected_list}."
                else:
                    summary += " No unexpected services detected."
                    
                network_exposure = {
                    "confirmed_open": confirmed_open,
                    "suspected_open": suspected_open,
                    "unexpected_services": unexpected_services,
                    "cdn_catchall_count": len(cdn_catchall) if cdn_catchall else 0,
                    "filtered_count": filtered_count,
                    "cdn_detected": port_scan_summary.cdn_detected if port_scan_summary else False,
                    "cdn_provider": port_scan_summary.cdn_provider if port_scan_summary else None,
                    "total_scanned": port_scan_summary.ports_scanned if port_scan_summary else 0,
                    "scan_duration_ms": port_scan_summary.duration_ms if port_scan_summary else 0,
                    "scan_method": port_scan_summary.scan_method if port_scan_summary else "tcp_connect",
                    "summary": summary
                }

            debug_info = {
                "dns_resolution": {
                    "hostname": target_info.hostname,
                    "port": target_info.port,
                    "resolved_ip": ip_address
                },
                "tls_info": tls_details,
                "cors": cors_info if 'cors_info' in locals() else None,
                "https_enforcement": https_debug if 'https_debug' in locals() else None,
                "cookies": cookies_debug["cookies"],
                "cookies_summary": cookies_debug["cookies_summary"],
                "checks": checks_outcomes,
                "discovery": discovery_results,
                "discovered_paths": discovered_paths,
                "ports": [
                    {
                        "port": p.port,
                        "state": p.tcp_state,
                        "final_state": p.final_state.value if p.final_state else None,
                        "service_guess": p.service_guess,
                        "service_confirmed": p.service_confirmed,
                        "product": p.product,
                        "cpe": p.cpe,
                        "extra_info": p.extra_info,
                        "banner": p.banner,
                        "version": p.version,
                        "risk_level": p.risk_level,
                        "risk_reason": p.risk_reason,
                        "owasp_refs": p.owasp_refs,
                        "latency_ms": p.latency_ms
                    } for p in port_scan_results
                ],
                "port_scan_summary": {
                    "profile": port_scan_summary.profile,
                    "ports_scanned": port_scan_summary.ports_scanned,
                    "open_confirmed": port_scan_summary.open_confirmed_count,
                    "open_suspected": port_scan_summary.open_suspected_count,
                    "cdn_catchall": port_scan_summary.cdn_catchall_count,
                    "filtered": port_scan_summary.filtered_count,
                    "closed": port_scan_summary.closed_count,
                    "duration_ms": port_scan_summary.duration_ms,
                    "scan_method": port_scan_summary.scan_method,
                    "cdn_detected": port_scan_summary.cdn_detected,
                    "cdn_provider": port_scan_summary.cdn_provider,
                    "resolved_ips": port_scan_summary.resolved_ips
                } if port_scan_summary else None,
                "network_exposure": network_exposure,
                "http_traffic": self.http_client.history,
                "tech_fingerprint": tech_fingerprint_data
            }
            
            waf_info = detect_waf_and_visibility(debug_info)
            
            if waf_info.get("scan_status") == "blocked":
                findings = [] 
                findings.append(Finding(
                    title="Scan blocked by WAF / challenge page",
                    severity=Severity.INFO,
                    category=Category.AVAILABILITY,
                    description=f"The scanner was blocked by a security mechanism ({waf_info.get('blocking_mechanism')}). Only the challenge page was analyzed.",
                    recommendation="Allowlist the scanner IP or perform an authenticated scan."
                ))
                findings.append(Finding(
                    title="Limited visibility on the real application",
                    severity=Severity.INFO,
                    category=Category.AVAILABILITY,
                    description="No application content was discovered because of the WAF blocking.",
                    recommendation="Review the WAF configuration."
                ))
                checks_outcomes.append({
                    "name": "scan_visibility",
                    "outcome": "limited",
                    "reason": "Scan blocked by WAF/challenge page.",
                    "evidence": waf_info
                })
                debug_info["checks"] = checks_outcomes

            return self._build_result(target_info.full_url, findings, logs, start_time, debug_info, waf_info)

    def _build_result(self, target: str, findings: List[Finding], logs: List[ScanLogEntry], start_time: datetime, debug_info: dict = None, waf_info: dict = None) -> ScanResult:
        
        if waf_info is None:
            waf_info = {
                "scan_status": "ok",
                "blocking_mechanism": None,
                "visibility_level": "good"
            }
            
        # Calculate score/grade
        if waf_info.get("scan_status") == "blocked":
            score = 0
            grade = "N/A" # Special grade for blocked scans
        else:
            score, grade = calculate_score(findings)
            
        response_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        
        return ScanResult(
            target=target,
            grade=grade,
            score=score,
            findings=findings,
            logs=logs,
            scanned_at=datetime.utcnow(),
            response_time_ms=response_time,
            debug_info=debug_info,
            scan_status=waf_info.get("scan_status", "ok"),
            blocking_mechanism=waf_info.get("blocking_mechanism"),
            visibility_level=waf_info.get("visibility_level", "good")
        )

    def _build_error_result(self, target: str, logs: List[ScanLogEntry], start_time: datetime, error_message: str = "Unknown Error") -> ScanResult:
        # Add a finding for the error
        findings = [
            Finding(
                title="Scan Failed",
                severity=Severity.HIGH,
                category=Category.ERROR,
                description=f"The scan could not complete due to an error: {error_message}",
                recommendation="Check the logs and target availability."
            )
        ]
        
        return ScanResult(
            target=target,
            grade="F",
            score=0,
            findings=findings,
            logs=logs,
            scanned_at=datetime.utcnow(),
            response_time_ms=int((datetime.utcnow() - start_time).total_seconds() * 1000),
            scan_status=ScanStatus.FAILED,
            blocking_mechanism=None,
            visibility_level=VisibilityLevel.BLOCKED
        )

