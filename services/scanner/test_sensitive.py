import asyncio
from app.scanner.vuln_checks import check_sensitive_url
from app.scanner.http_client import HttpClient
from app.config import settings

async def test():
    async with HttpClient(config=settings) as client:
        print("Testing check_sensitive_url on https://relic-test-lab.vercel.app/.env")
        try:
            findings, evidence = await check_sensitive_url(
                'https://relic-test-lab.vercel.app/.env', 
                client, 
                None
            )
            print(f"Findings: {len(findings)}")
            for f in findings:
                print(f"  - {f.title}: {f.description[:50]}...")
                print(f"    confidence: {f.confidence}")
                print(f"    repro_curl: {f.repro_curl[:50] if f.repro_curl else None}...")
        except Exception as e:
            print(f"ERROR: {e}")
            import traceback
            traceback.print_exc()

asyncio.run(test())
