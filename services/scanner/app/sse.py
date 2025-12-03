import asyncio
import json
from typing import AsyncGenerator
from .models import ScanLog

async def event_generator(scan_id: str, store) -> AsyncGenerator[str, None]:
    """
    Yields SSE events for a given scan_id.
    """
    # Wait for scan to start
    while True:
        scan = store.get_scan(scan_id)
        if scan:
            break
        await asyncio.sleep(0.1)
    
    sent_logs_count = 0
    
    while True:
        # Check for new logs
        # Try to get live logs first
        current_logs = store.get_live_logs(scan_id)
        
        # If no live logs, maybe scan is done and logs are in DB
        if not current_logs:
            scan = store.get_scan(scan_id)
            if scan and scan.logs_json:
                current_logs = scan.logs_json
        
        if len(current_logs) > sent_logs_count:
            for log in current_logs[sent_logs_count:]:
                # Format: event: log\ndata: {...}\n\n
                yield f"event: log\ndata: {json.dumps(log)}\n\n"
            sent_logs_count = len(current_logs)
        
        # Check if done
        scan = store.get_scan(scan_id)
        if scan and scan.status in ["completed", "failed", "done"]:
            # Send any remaining logs if we switched from live to DB
            if scan.logs_json and len(scan.logs_json) > sent_logs_count:
                for log in scan.logs_json[sent_logs_count:]:
                    yield f"event: log\ndata: {json.dumps(log)}\n\n"
            
            status = "done" if scan.status == "completed" else scan.status
            yield f"event: done\ndata: {json.dumps({'scan_id': scan_id, 'status': status})}\n\n"
            break
            
        await asyncio.sleep(0.1)
