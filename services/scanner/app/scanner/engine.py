import asyncio
import socket
from datetime import datetime
from typing import List, Callable, Awaitable
import httpx

from .models import ScanResult, ScanLogEntry, Finding
from .normalizer import normalize_target
from .http_client import HttpClient
from .tls_checks import check_tls
from .header_checks import check_security_headers
from .cookies_checks import analyze_cookies
from .vuln_checks import check_exposure, check_xss, check_sqli, check_https_enforcement, check_xss_url, check_sqli_url, check_sensitive_url
from .scoring import calculate_score
from .port_scanner import scan_ports
from .path_discovery import PathDiscoverer
from .waf_detection import detect_waf_and_visibility
from ..config import settings
from ..constants import Severity, Category, ScanStatus, VisibilityLevel

from .scope import ScopeManager, EndpointClass

class ScanEngine:
    def __init__(self):
        self.http_client = None
        self.scope_manager = ScopeManager()

    async def run_scan(self, target_input: str, log_callback: Callable[[ScanLogEntry], Awaitable[None]] = None) -> ScanResult:
        """
        Orchestrates the scan process.
        """
        logs: List[ScanLogEntry] = []
        findings: List[Finding] = []
        start_time = datetime.utcnow()
        
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
            
            await log("INFO", f"Starting scan for target: {target_input}")

            # Normalization
            try:
                target_info = normalize_target(target_input)
                await log("INFO", f"Normalized target: {target_info.full_url}")
            except Exception as e:
                await log("ERROR", f"Failed to normalize target: {e}")
                return self._build_error_result(target_input, logs, start_time, "Normalization Error")

            # Parallelize Initial Checks: DNS, Port Scan, Initial HTTP
            await log("INFO", "Starting parallel checks: DNS, Ports, Initial HTTP...")
            
            async def task_dns():
                try:
                    loop = asyncio.get_running_loop()
                    ip_info = await loop.run_in_executor(None, socket.getaddrinfo, target_info.hostname, target_info.port)
                    return ip_info[0][4][0]
                except Exception as e:
                    await log("ERROR", f"DNS resolution failed: {e}")
                    raise e

            async def task_ports(ip_addr):
                if not ip_addr:
                    return []
                try:
                    return await scan_ports(ip_addr, log)
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
                    port_scan_results = await task_ports(ip_address)
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
                await log("INFO", f"Received response: {response.status_code}")
                
            except Exception as e:
                await log("ERROR", f"Parallel checks failed: {e}")
                return self._build_error_result(target_info.full_url, logs, start_time, str(e))

            # TLS Checks
            tls_details = None
            final_scheme = response.url.scheme
            final_host = response.url.host
            final_port = response.url.port or (443 if final_scheme == "https" else 80)
            
            if final_scheme == "https":
                await log("INFO", f"Collecting TLS info for host {final_host}...")
                loop = asyncio.get_running_loop()
                try:
                    await log("INFO", "Starting TLS check with 5s timeout...")
                    tls_result = await asyncio.wait_for(
                        loop.run_in_executor(None, check_tls, final_host, final_port),
                        timeout=5.0
                    )
                    tls_findings, tls_details = tls_result
                    if tls_details:
                        await log("INFO", "TLS info collected.")
                    if tls_findings:
                        findings.extend(tls_findings)
                except asyncio.TimeoutError:
                    await log("WARNING", "TLS check timed out, skipping.")
                except Exception as e:
                    await log("ERROR", f"TLS check failed: {e}")
            
            # Header Checks
            await log("INFO", "Analyzing HTTP headers...")
            header_findings = check_security_headers(response.headers)
            if header_findings:
                findings.extend(header_findings)

            # Cookie Checks
            await log("INFO", "Analyzing cookies...")
            cookies_list, cookies_summary, cookie_findings = analyze_cookies(self.http_client.history)
            cookies_debug = {"cookies": cookies_list, "cookies_summary": cookies_summary}
            if cookie_findings:
                findings.extend(cookie_findings)
            cookies_present = len(cookies_list) > 0

            # CORS Check
            await log("INFO", "Analyzing CORS headers...")
            from .cors_checks import check_cors
            cors_findings, cors_info = await check_cors(target_info.full_url, response.headers, self.http_client, log, cookies_present=cookies_present)
            if cors_findings:
                findings.extend(cors_findings)

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

            try:
                content_type = response.headers.get("Content-Type", "").lower()
                if "text/html" in content_type:
                    await log("INFO", "HTML content detected, starting streaming crawler & vuln pipeline...")
                    from .crawler import SimpleCrawler
                    crawler = SimpleCrawler(self.http_client, log)
                    
                    tasks = []
                    tasks.append(asyncio.create_task(process_url(target_info.full_url)))
                    
                    async for asset in crawler.crawl_generator(target_info.full_url, response.text):
                        discovery_results.append(asset)
                        tasks.append(asyncio.create_task(process_url(asset)))
                    
                    if tasks:
                        await asyncio.gather(*tasks)
                        
                else:
                    await log("INFO", "Non-HTML content, skipping crawler.")
                    await process_url(target_info.full_url)
                    
            except Exception as e:
                await log("ERROR", f"Crawler/Pipeline failed: {e}")

            # Batch Vulnerability Checks (XSS & SQLi) with Deduplication
            if all_urls:
                await log("INFO", f"Running batch XSS/SQLi checks on {len(all_urls)} unique URLs...")
                
                # Run XSS and SQLi checks in parallel on the collected URLs
                batch_results = await asyncio.gather(
                    check_xss(target_info.full_url, self.http_client, log, discovered_urls=all_urls),
                    check_sqli(target_info.full_url, self.http_client, log, discovered_urls=all_urls),
                    return_exceptions=True
                )
                
                # Process XSS Results
                if not isinstance(batch_results[0], Exception):
                    x_findings, x_debug = batch_results[0]
                    vuln_findings.extend(x_findings)
                    checks_outcomes.append({
                        "name": "xss_batch",
                        "outcome": "fail" if x_findings else "pass",
                        "evidence": x_debug.get("evidence", [])
                    })
                else:
                    await log("ERROR", f"Batch XSS check failed: {batch_results[0]}")

                # Process SQLi Results
                if not isinstance(batch_results[1], Exception):
                    s_findings, s_debug = batch_results[1]
                    vuln_findings.extend(s_findings)
                    checks_outcomes.append({
                        "name": "sqli_batch",
                        "outcome": "fail" if s_findings else "pass",
                        "evidence": s_debug.get("evidence", [])
                    })
                else:
                    await log("ERROR", f"Batch SQLi check failed: {batch_results[1]}")

            # Path Discovery
            try:
                path_discoverer = PathDiscoverer(self.http_client, log)
                discovered_paths = await path_discoverer.run(target_info.full_url)
            except Exception as e:
                await log("ERROR", f"Path discovery failed: {e}")

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
                await log("WARNING", "Potential XSS vulnerability detected!")
            if any(f.category == "sqli" for f in vuln_findings):
                await log("WARNING", "Potential SQL Injection detected!")

            await log("INFO", "Scan completed.")
            
            # Network Exposure Analysis
            network_exposure = {}
            if port_scan_results:
                open_ports = []
                unexpected_services = []
                filtered_count = 0
                EXPECTED_PORTS = {80, 443}
                for p in port_scan_results:
                    if p.state == "open":
                        port_num = p.port
                        service = p.service_guess or "unknown"
                        open_ports.append({"port": port_num, "service": service})
                        if port_num not in EXPECTED_PORTS:
                            unexpected_services.append({"port": port_num, "service": service})
                    elif p.state == "filtered":
                        filtered_count += 1
                
                open_ports_list = ", ".join([f"{op['port']} ({op['service'].upper()})" for op in open_ports])
                summary = f"{len(open_ports)} open ports detected: {open_ports_list}." if open_ports else "No open ports detected."
                if unexpected_services:
                    unexpected_list = ", ".join([f"{u['port']} ({u['service'].upper()})" for u in unexpected_services])
                    summary += f" Unexpected exposed services found: {unexpected_list}."
                else:
                    summary += " No additional exposed services detected on common ports."
                    
                network_exposure = {
                    "open_ports": open_ports,
                    "filtered_ports_count": filtered_count,
                    "unexpected_services": unexpected_services,
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
                "ports": [p.model_dump() for p in port_scan_results],
                "network_exposure": network_exposure,
                "http_traffic": self.http_client.history
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

