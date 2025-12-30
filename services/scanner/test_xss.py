import asyncio
from app.scanner.vuln_checks import check_xss_url
from app.scanner.http_client import HttpClient
from app.config import settings

async def test():
    async with HttpClient(config=settings) as client:
        url = "http://testphp.vulnweb.com/listproducts.php?cat=1"
        print(f"Testing XSS on: {url}")
        
        findings, evidence = await check_xss_url(url, client, None)
        print(f"Findings: {len(findings)}")
        
        if findings:
            f = findings[0]
            print("\n=== XSS FINDING WITH NEW METADATA ===")
            print(f"Title: {f.title}")
            print(f"Severity: {f.severity}")
            print(f"Confidence: {f.confidence}")
            print(f"Repro cURL: {f.repro_curl}")
            print(f"Evidence Hash: {f.evidence_hash}")
        else:
            print("No XSS found on this URL")

asyncio.run(test())
