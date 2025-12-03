from typing import Dict, Any, List, Optional

def build_ai_scan_view(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Constructs a simplified view of the scan result optimized for AI analysis.
    Extracts only the most relevant security information.
    Robustly handles missing fields and varying data structures.
    """
    if not raw:
        print("DEBUG: build_ai_scan_view received empty raw input")
        return {}
        
    print(f"DEBUG: build_ai_scan_view input keys: {list(raw.keys())}")

    ai_view = {}

    # Helper to safely get value from dict or object
    def safe_get(data: Any, key: str, default: Any = None) -> Any:
        if isinstance(data, dict):
            return data.get(key, default)
        return default

    # 1. Basic Info
    ai_view["target"] = raw.get("target")
    ai_view["grade"] = raw.get("grade")
    ai_view["score"] = raw.get("score")
    ai_view["scan_status"] = raw.get("scan_status")
    ai_view["blocking_mechanism"] = raw.get("blocking_mechanism")
    ai_view["visibility_level"] = raw.get("visibility_level")

    # 2. DNS
    try:
        dns_raw = raw.get("dns_resolution", {})
        if dns_raw:
            ai_view["dns"] = {
                "ip": dns_raw.get("resolved_ip") or dns_raw.get("ip"),
                "hostname": dns_raw.get("hostname"),
                "port": dns_raw.get("port"),
                "cloud_provider": dns_raw.get("cloud_provider")
            }
    except Exception:
        pass

    # 3. Network Exposure
    try:
        net_raw = raw.get("network_exposure", {})
        ports_raw = raw.get("ports", [])
        
        # Build detailed ports list if available
        detailed_ports = []
        if isinstance(ports_raw, list):
            for p in ports_raw:
                if isinstance(p, dict) and p.get("state") == "open":
                    detailed_ports.append({
                        "port": p.get("port"),
                        "state": p.get("state"),
                        "service_guess": p.get("service_guess"),
                        "banner": p.get("banner"),
                        "risk_level": p.get("risk_level"),
                        "risk_reason": p.get("risk_reason"),
                        "owasp_refs": p.get("owasp_refs", [])
                    })

        if net_raw:
            ai_view["network_exposure"] = {
                "open_ports": net_raw.get("open_ports", []),
                "summary": net_raw.get("summary"),
                "unexpected_services": net_raw.get("unexpected_services", []),
                "details": detailed_ports # Add full details here
            }
        else:
            # Fallback
            ai_view["network_exposure"] = {
                "open_ports": [p["port"] for p in detailed_ports if p.get("state") == "open"],
                "details": detailed_ports
            }
    except Exception:
        pass

    # 4. TLS
    try:
        tls_raw = raw.get("tls_info", {})
        if tls_raw:
            # Handle issuer being a dict or string
            issuer = tls_raw.get("issuer")
            issuer_name = issuer
            if isinstance(issuer, dict):
                issuer_name = issuer.get("organizationName") or issuer.get("commonName") or issuer.get("O")
            
            # Handle subject
            subject = tls_raw.get("subject")
            subject_cn = subject
            if isinstance(subject, dict):
                subject_cn = subject.get("commonName") or subject.get("CN")

            ai_view["tls"] = {
                "protocol": tls_raw.get("protocol"),
                "cipher": tls_raw.get("cipher"), # Might be list or string
                "issuer": issuer_name,
                "subject_cn": subject_cn,
                "days_to_expire": tls_raw.get("days_to_expire"),
                "valid": tls_raw.get("valid", True) # Default to True if not specified but present
            }
    except Exception:
        pass

    # 5. HTTPS Enforcement
    try:
        https_raw = raw.get("https_enforcement", {})
        if https_raw:
            ai_view["https_enforcement"] = {
                "enforced": https_raw.get("outcome") == "pass" or https_raw.get("enforced"),
                "hsts": https_raw.get("hsts"), # Might be missing in user data, but good to keep
                "reachable": https_raw.get("https_reachable"),
                "reason": https_raw.get("reason")
            }
    except Exception:
        pass

    # 6. CORS
    try:
        cors_raw = raw.get("cors", {})
        if cors_raw:
            ai_view["cors"] = {
                "allow_origin": cors_raw.get("allow_origin"),
                "allow_credentials": cors_raw.get("allow_credentials"),
                "risk_level": cors_raw.get("context", {}).get("risk_level") or cors_raw.get("risk_level"),
                "notes": cors_raw.get("notes", [])
            }
    except Exception:
        pass

    # 7. Cookies
    try:
        cookies_raw = raw.get("cookies_summary", {})
        if cookies_raw:
            ai_view["cookies_summary"] = {
                "count": cookies_raw.get("count") if "count" in cookies_raw else cookies_raw.get("total"),
                "notes": cookies_raw.get("notes", [])
            }
    except Exception:
        pass

    # 8. Discovery (Crawler)
    try:
        discovery_raw = raw.get("discovery", [])
        # Handle if it's a list (user data) or dict (my assumption)
        urls = []
        if isinstance(discovery_raw, list):
            # Extract URLs from list of dicts
            urls = [item.get("url") for item in discovery_raw if isinstance(item, dict) and item.get("url")]
        elif isinstance(discovery_raw, dict):
            urls = discovery_raw.get("internal_urls", [])

        if urls:
            ai_view["discovery"] = {
                "pages_count": len(urls),
                "examples": urls[:10]
            }
    except Exception:
        pass

    # 9. Findings (Top findings)
    try:
        findings_raw = raw.get("findings", [])
        if findings_raw:
            simplified_findings = []
            for f in findings_raw:
                if not isinstance(f, dict): continue
                simplified_findings.append({
                    "title": f.get("title"),
                    "severity": f.get("severity"),
                    "category": f.get("category"),
                    "description": f.get("description"),
                    "recommendation": f.get("recommendation"),
                    "owasp_refs": f.get("owasp_refs", [])
                })
            ai_view["findings"] = simplified_findings
    except Exception:
        pass
        
    # 10. HTTP Traffic (Latency summary)
    try:
        traffic = raw.get("http_traffic", [])
        if traffic and isinstance(traffic, list):
            latencies = [t.get("latency", 0) for t in traffic if isinstance(t, dict)]
            if latencies:
                avg_latency = sum(latencies) / len(latencies)
                ai_view["performance"] = {
                    "avg_latency_s": round(avg_latency, 3),
                    "requests_count": len(traffic)
                }
    except Exception:
        pass

    return ai_view
