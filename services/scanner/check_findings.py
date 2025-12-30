import sqlite3
import json

conn = sqlite3.connect('auditai.db')
c = conn.cursor()
c.execute('SELECT result_json FROM scan WHERE id = ?', ('d80acdf5-1969-43e6-ba7d-84a5bc821008',))
r = c.fetchone()
d = json.loads(r[0])

print('=== ALL FINDINGS ===')
for f in d.get('findings', []):
    title = f.get('title', 'N/A')[:40]
    conf = f.get('confidence') or 'None'
    has_curl = 'Yes' if f.get('repro_curl') else 'No'
    has_hash = 'Yes' if f.get('evidence_hash') else 'No'
    print(f'{title:40} | confidence: {conf:8} | repro_curl: {has_curl} | evidence_hash: {has_hash}')
