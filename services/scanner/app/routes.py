import asyncio
import uuid
import logging
from datetime import datetime
from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse, Response
from .models import ScanRequest, ScanResponse, ScanResult, ScanLog, Finding, ScanListItem
from . import store
from .policy import validate_scan_request, PolicyError
from .sse import event_generator
from .pdf import generate_pdf, generate_markdown, generate_ai_pdf
from .ai.schema import build_ai_scan_view
from .ai.validation import validate_ai_report
from .ai.prompt_loader import load_prompt, PromptLoadError
from .config import settings
import json

logger = logging.getLogger(__name__)

# Prompt version constant - change this to use a different prompt version
SECURITY_REPORT_PROMPT_NAME = "security_report_system_v1"

router = APIRouter()

from .scanner.engine import ScanEngine
from .scanner.models import ScanLogEntry

async def run_scan_task(scan_id: str, target: str):
    """Runs the real scan using ScanEngine."""
    engine = ScanEngine()
    
    # Initialize log buffer and callback for real-time updates
    logs_buffer = []

    async def log_callback(entry: ScanLogEntry):
        # Convert to dict
        log_dict = {
            "timestamp": entry.timestamp.isoformat(),
            "level": entry.level,
            "message": entry.message
        }
        logs_buffer.append(log_dict)
        # Update active logs in store for SSE
        store.append_log(scan_id, log_dict)

    # Run the scan
    try:
        store.update_scan_status(scan_id, "running")

        result = await engine.run_scan(target, log_callback)

        # Convert dataclass result to Pydantic model dict
        findings_dicts = [
            {
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "description": f.description,
                "recommendation": f.recommendation,
                "evidence": f.evidence,
                "owasp_refs": f.owasp_refs
            } for f in result.findings
        ]

        logs_dicts = [
            {
                "timestamp": l.timestamp,
                "level": l.level,
                "message": l.message
            } for l in result.logs
        ]

        # Create ScanResult Pydantic model
        scan_result = ScanResult(
            scan_id=scan_id,
            target=result.target,
            status="done",
            score=result.score,
            grade=result.grade,
            findings=findings_dicts,
            logs=logs_dicts,
            timestamp=result.scanned_at,
            response_time_ms=result.response_time_ms,
            debug_info=result.debug_info,
            scan_status=result.scan_status,
            blocking_mechanism=result.blocking_mechanism,
            visibility_level=result.visibility_level
        )

        # Save to DB
        store.save_scan_result(scan_id, scan_result)

    except Exception as e:
        print(f"Scan failed: {e}")
        store.fail_scan(scan_id, str(e))

from fastapi.responses import JSONResponse

@router.post("/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Start a security scan against a target.
    
    Requires:
    - authorized: true (user acknowledgement of permission to scan)
    - target: valid http/https URL
    
    Returns:
    - 200: Scan started, returns scan_id
    - 400: Missing authorization acknowledgement or invalid URL
    """
    # Validate request (acknowledgement + valid URL format)
    policy_result = validate_scan_request(request.target, request.authorized)
    
    if not policy_result.allowed:
        return JSONResponse(
            status_code=400,
            content={
                "error_code": policy_result.error_code.value,
                "message": policy_result.message,
                "details": policy_result.details
            }
        )

    # Create scan in DB
    scan = store.create_scan(request.target)

    background_tasks.add_task(run_scan_task, scan.id, request.target)

    return ScanResponse(scan_id=scan.id)

@router.get("/scan/{scan_id}/events")
async def scan_events(scan_id: str):
    # We need to check if scan exists
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Stream events using the generator
    return StreamingResponse(
        event_generator(scan_id, store),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

@router.get("/scan/{scan_id}")
async def get_scan_result(scan_id: str):
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status != "completed":
        return {"status": scan.status}

    # Return the stored JSON result
    return scan.result_json

@router.get("/scan/{scan_id}/report.pdf")
async def get_scan_pdf(scan_id: str):
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status != "completed" or not scan.result_json:
        raise HTTPException(status_code=400, detail="Report not ready")

    # Generate PDF on the fly from stored result
    # Reconstruct ScanResult object
    try:
        result_obj = ScanResult(**scan.result_json)
        pdf_bytes = generate_pdf(result_obj)
        return Response(content=pdf_bytes, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.pdf"})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {e}")

@router.get("/scan/{scan_id}/report.json")
async def get_scan_json(scan_id: str):
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status != "completed" or not scan.result_json:
        raise HTTPException(status_code=400, detail="Report not ready")

    return Response(content=json.dumps(scan.result_json, indent=2), media_type="application/json", headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.json"})

@router.get("/scan/{scan_id}/report.md")
async def get_scan_markdown(scan_id: str):
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status != "completed" or not scan.result_json:
        raise HTTPException(status_code=400, detail="Report not ready")

    try:
        result_obj = ScanResult(**scan.result_json)
        md_content = generate_markdown(result_obj)
        return Response(content=md_content, media_type="text/markdown", headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.md"})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate Markdown: {e}")

@router.get("/scan/{scan_id}/ai-debug")
async def get_scan_ai_debug(scan_id: str):
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status != "completed" or not scan.result_json:
        raise HTTPException(status_code=400, detail="Report not ready")

    try:
        raw_scan = scan.result_json
        if "debug_info" in raw_scan:
             pass

        # Prepare data for AI view builder
        debug_info = raw_scan.get("debug_info", {})
        if not isinstance(debug_info, dict):
            debug_info = {}

        ai_input = debug_info.copy()

        # Ensure top-level fields override or supplement debug_info
        ai_input["target"] = raw_scan.get("target")
        ai_input["grade"] = raw_scan.get("grade")
        ai_input["score"] = raw_scan.get("score")
        ai_input["scan_status"] = raw_scan.get("scan_status")
        ai_input["blocking_mechanism"] = raw_scan.get("blocking_mechanism")
        ai_input["visibility_level"] = raw_scan.get("visibility_level")
        ai_input["findings"] = raw_scan.get("findings")

        ai_view = build_ai_scan_view(ai_input)

        return {
            "scan_id": scan_id,
            "raw_scan": raw_scan,
            "ai_view": ai_view
        }
    except Exception as e:
        print(f"ERROR in get_scan_ai_debug: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to generate AI view: {e}")

@router.post("/scan/{scan_id}/ai-analysis")
async def generate_scan_ai_analysis(scan_id: str, provider: str = None):
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status != "completed" or not scan.result_json:
        raise HTTPException(status_code=400, detail="Report not ready")

    try:
        raw_scan = scan.result_json

        # Prepare data for AI view builder (reuse logic from ai-debug)
        debug_info = raw_scan.get("debug_info")
        if not isinstance(debug_info, dict):
            debug_info = {}

        ai_input = debug_info.copy()
        ai_input["target"] = raw_scan.get("target")
        ai_input["grade"] = raw_scan.get("grade")
        ai_input["score"] = raw_scan.get("score")
        ai_input["scan_status"] = raw_scan.get("scan_status")
        ai_input["blocking_mechanism"] = raw_scan.get("blocking_mechanism")
        ai_input["visibility_level"] = raw_scan.get("visibility_level")
        ai_input["findings"] = raw_scan.get("findings")

        ai_view = build_ai_scan_view(ai_input)

        # Load versioned system prompt
        try:
            system_prompt = load_prompt(SECURITY_REPORT_PROMPT_NAME)
        except PromptLoadError as e:
            logger.error("Failed to load AI prompt (error_type=PROMPT_LOAD_ERROR): %s", e)
            raise HTTPException(
                status_code=500,
                detail="AI prompt missing or unreadable"
            )

        # Construct User Prompt
        user_prompt = f"""Here is the scan result for {ai_input.get('target')}:
{json.dumps(ai_view, indent=2)}

Analyze this data and provide the security report in the requested JSON format.
"""

        # Call AI Analyzer (returns an async generator)
        from .ai.analyzer import analyzer
        response_generator = await analyzer.analyze(system_prompt, user_prompt, provider)

        # Resolve provider and model name in outer scope to avoid UnboundLocalError in closure
        resolved_provider = provider if provider else "ollama"
        if resolved_provider == "ollama":
            resolved_model = settings.OLLAMA_MODEL
        elif resolved_provider == "groq":
            resolved_model = settings.GROQ_MODEL
        else:
            resolved_model = settings.OPENROUTER_MODEL
        model_name_str = f"{resolved_provider}:{resolved_model}"

        async def stream_and_persist():
            full_response_text = ""
            try:
                async for chunk in response_generator:
                    full_response_text += chunk
                    yield chunk
                
                # After streaming is done, parse and save
                # Validate AI response against schema
                analysis_result, ai_valid = validate_ai_report(
                    full_response_text,
                    scan_id=scan_id,
                    model_name=model_name_str
                )
                
                # Add validation flag to response
                analysis_result["ai_valid"] = ai_valid
                
                # Save analysis to scan result for persistence
                current_scan = store.get_scan(scan_id)
                if current_scan:
                    if not current_scan.result_json:
                        current_scan.result_json = {}
                    current_scan.result_json["ai_analysis"] = analysis_result
                    
                    try:
                        updated_result = ScanResult(**current_scan.result_json)
                        store.save_scan_result(scan_id, updated_result)
                        import logging
                        logging.getLogger(__name__).info(
                            "Persisted AI analysis for scan %s (ai_valid=%s)",
                            scan_id, ai_valid
                        )
                    except Exception as e:
                        import logging
                        logging.getLogger(__name__).warning(
                            "Failed to persist AI analysis for scan %s: %s",
                            scan_id, str(e)
                        )
                    
            except asyncio.CancelledError:
                print(f"Client disconnected during AI streaming for scan {scan_id}")
                # We can try to save partial result if needed, but usually better to just stop
                raise
            except Exception as e:
                print(f"Error during streaming: {e}")
                yield f"\n\n[ERROR] Stream interrupted: {str(e)}"

        return StreamingResponse(
            stream_and_persist(),
            media_type="text/plain",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no"
            }
        )

    except ValueError as e:
        # Likely missing API key or configuration
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        print(f"ERROR in generate_scan_ai_analysis: {e}")
        import traceback
        traceback.print_exc()
        error_msg = str(e)
        if "Connection refused" in error_msg or "ConnectError" in error_msg:
             raise HTTPException(status_code=503, detail="Could not connect to AI provider. Is Ollama running?")
        if "Read timed out" in error_msg or "Timeout" in error_msg:
             raise HTTPException(status_code=504, detail="AI analysis timed out. The model took too long to respond.")
        raise HTTPException(status_code=500, detail=f"Failed to generate AI analysis: {error_msg}")

@router.get("/scans")
async def list_scans(limit: int = 50, offset: int = 0):
    """List all scans with summary metadata."""
    scans = store.list_scans(limit=limit, offset=offset)
    return [
        {
            "scan_id": s.id,
            "target": s.target,
            "status": s.status,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "finished_at": s.finished_at.isoformat() if s.finished_at else None,
            "score": s.score,
            "grade": s.grade,
            "findings_count": len(s.result_json.get("findings", [])) if s.result_json else 0
        }
        for s in scans
    ]


@router.get("/scan/{scan_id}/ai-report.pdf")
async def get_scan_ai_report_pdf(scan_id: str, provider: str = None):
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status != "completed" or not scan.result_json:
        raise HTTPException(status_code=400, detail="Report not ready")

    try:
        raw_scan = scan.result_json

        # Check if we already have the analysis saved
        if raw_scan.get("ai_analysis"):
            ai_summary = raw_scan["ai_analysis"]
            
            # Generate PDF
            result_obj = ScanResult(**scan.result_json)
            pdf_bytes = generate_ai_pdf(result_obj, ai_summary)
            
            return Response(
                content=pdf_bytes, 
                media_type="application/pdf", 
                headers={"Content-Disposition": f"attachment; filename=ai_report_{scan_id}.pdf"}
            )

        # Prepare data for AI view builder
        debug_info = raw_scan.get("debug_info")
        if not isinstance(debug_info, dict):
            debug_info = {}

        ai_input = debug_info.copy()
        ai_input["target"] = raw_scan.get("target")
        ai_input["grade"] = raw_scan.get("grade")
        ai_input["score"] = raw_scan.get("score")
        ai_input["scan_status"] = raw_scan.get("scan_status")
        ai_input["blocking_mechanism"] = raw_scan.get("blocking_mechanism")
        ai_input["visibility_level"] = raw_scan.get("visibility_level")
        ai_input["findings"] = raw_scan.get("findings")

        ai_view = build_ai_scan_view(ai_input)

        # Load versioned system prompt
        try:
            system_prompt = load_prompt(SECURITY_REPORT_PROMPT_NAME)
        except PromptLoadError as e:
            logger.error("Failed to load AI prompt (error_type=PROMPT_LOAD_ERROR): %s", e)
            raise HTTPException(
                status_code=500,
                detail="AI prompt missing or unreadable"
            )

        # Construct User Prompt
        user_prompt = f"""Here is the scan result for {ai_input.get('target')}:
{json.dumps(ai_view, indent=2)}

Analyze this data and provide the security report in the requested JSON format.
"""

        # Call AI Analyzer
        from .ai.analyzer import analyzer
        response_generator = await analyzer.analyze(system_prompt, user_prompt, provider)
        
        response_text = ""
        async for chunk in response_generator:
            response_text += chunk

        # Validate AI response against schema
        provider_name = provider or "ollama"
        if provider_name == "ollama":
            actual_model = settings.OLLAMA_MODEL
        elif provider_name == "groq":
            actual_model = settings.GROQ_MODEL
        else:
            actual_model = settings.OPENROUTER_MODEL
        model_name_str = f"{provider_name}:{actual_model}"
        
        ai_summary, ai_valid = validate_ai_report(
            response_text,
            scan_id=scan_id,
            model_name=model_name_str
        )
        ai_summary["ai_valid"] = ai_valid
        
        # Save analysis to scan result for persistence
        if not scan.result_json:
            scan.result_json = {}
        scan.result_json["ai_analysis"] = ai_summary
        
        try:
            updated_result = ScanResult(**scan.result_json)
            store.save_scan_result(scan_id, updated_result)
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(
                "Failed to save AI analysis to DB for scan %s: %s",
                scan_id, str(e)
            )

        # Generate PDF
        result_obj = ScanResult(**scan.result_json)
        pdf_bytes = generate_ai_pdf(result_obj, ai_summary)
        
        return Response(
            content=pdf_bytes, 
            media_type="application/pdf", 
            headers={"Content-Disposition": f"attachment; filename=ai_report_{scan_id}.pdf"}
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        print(f"ERROR in get_scan_ai_report_pdf: {e}")
        import traceback
        traceback.print_exc()
        error_msg = str(e)
        if "Connection refused" in error_msg or "ConnectError" in error_msg:
             raise HTTPException(status_code=503, detail="Could not connect to AI provider. Is Ollama running?")
        if "Read timed out" in error_msg or "Timeout" in error_msg:
             raise HTTPException(status_code=504, detail="AI analysis timed out. The model took too long to respond.")
        raise HTTPException(status_code=500, detail=f"Failed to generate AI PDF: {error_msg}")
