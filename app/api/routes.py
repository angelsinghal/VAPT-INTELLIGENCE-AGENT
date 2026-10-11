"""FastAPI route definitions for the VAPT Intelligence Agent."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import PlainTextResponse

from app.agent.graph import run_analysis
from app.agent.state import VAPTState
from app.models.vapt import (
    AnalyzeResponse,
    BatchAnalyzeRequest,
    BatchAnalyzeResponse,
    VAPTRequest,
    VAPTResult,
)
from app.rag.vectorstore import is_ready
from app.services.report import generate_consolidated_report, generate_markdown

logger = logging.getLogger(__name__)
router = APIRouter()


def _get_semaphore(app: Any) -> asyncio.Semaphore:
    """Retrieve the shared semaphore stored on the FastAPI app state."""
    return app.state.semaphore


def _rag_not_ready_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={
            "error": "Knowledge base not initialised.",
            "message": "Run `uv run python scripts/ingest_knowledge.py` to enable RAG, then restart the server.",
        },
    )


def _state_to_response(final_state: VAPTState) -> AnalyzeResponse:
    """Convert the LangGraph final state into an API response."""
    result = final_state.get("result")
    errors = final_state.get("errors") or []

    if not result:
        error_msg = "; ".join(errors) if errors else "Analysis failed: unknown error."
        raise HTTPException(status_code=500, detail=error_msg)
        
    if isinstance(result, dict):
        try:
            result = VAPTResult(**result)
        except Exception:
            raise HTTPException(status_code=500, detail="Invalid result format.")

    report = final_state.get("report") or generate_markdown(result)
    return AnalyzeResponse(success=True, result=result, report=report)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


@router.get("/health", tags=["System"])
async def health_check() -> dict[str, Any]:
    """Always returns 200.  ``rag_ready`` indicates whether the knowledge base
    has been ingested.  The service can start without a knowledge base."""
    rag_ready = is_ready()
    response: dict[str, Any] = {"status": "ok", "rag_ready": rag_ready}
    if not rag_ready:
        response["message"] = (
            "Knowledge base not initialised. "
            "Run `uv run python scripts/ingest_knowledge.py` to enable RAG."
        )
    return response


# ---------------------------------------------------------------------------
# Single analysis
# ---------------------------------------------------------------------------


@router.post(
    "/api/v1/analyze",
    response_model=AnalyzeResponse,
    tags=["Analysis"],
    summary="Analyse a single VAPT finding",
)
async def analyze(request: Request, finding: VAPTRequest) -> AnalyzeResponse:
    """Analyse a single VAPT finding through the LangGraph pipeline."""
    if not is_ready():
        raise _rag_not_ready_error()

    semaphore: asyncio.Semaphore = _get_semaphore(request.app)
    async with semaphore:
        logger.info("Analysing finding: %r", finding.title)
        try:
            final_state = await run_analysis(finding)
        except Exception as exc:
            logger.exception("Graph execution failed for finding: %r", finding.title)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Analysis pipeline error: {exc!s}",
            ) from exc

    return _state_to_response(final_state)


# ---------------------------------------------------------------------------
# Batch analysis
# ---------------------------------------------------------------------------


@router.post(
    "/api/v1/analyze/batch",
    response_model=BatchAnalyzeResponse,
    tags=["Analysis"],
    summary="Analyse multiple VAPT findings concurrently",
)
async def analyze_batch(request: Request, batch: BatchAnalyzeRequest) -> BatchAnalyzeResponse:
    """Analyse up to 20 VAPT findings concurrently (limited by MAX_CONCURRENT_ANALYSES)."""
    if not is_ready():
        raise _rag_not_ready_error()

    semaphore: asyncio.Semaphore = _get_semaphore(request.app)

    async def _run_one(finding: VAPTRequest) -> AnalyzeResponse:
        async with semaphore:
            logger.info("Batch: analysing finding %r", finding.title)
            try:
                final_state = await run_analysis(finding)
                return _state_to_response(final_state)
            except Exception as exc:
                logger.exception("Batch: graph execution failed for %r", finding.title)
                return AnalyzeResponse(success=False, error=f"Analysis pipeline error: {exc!s}")

    tasks = [_run_one(f) for f in batch.findings]
    results: list[AnalyzeResponse] = await asyncio.gather(*tasks)

    successful = sum(1 for r in results if r.success)
    return BatchAnalyzeResponse(
        success=successful > 0,
        results=results,
        total=len(results),
        successful=successful,
        failed=len(results) - successful,
    )


# ---------------------------------------------------------------------------
# Report generation from an existing result
# ---------------------------------------------------------------------------


@router.post(
    "/api/v1/report",
    response_class=PlainTextResponse,
    tags=["Report"],
    summary="Generate a Markdown report from a VAPTResult",
)
async def generate_report_endpoint(result: VAPTResult) -> str:
    """Generate a Markdown report for a single validated VAPTResult."""
    return generate_markdown(result)


@router.post(
    "/api/v1/report/consolidated",
    response_class=PlainTextResponse,
    tags=["Report"],
    summary="Generate a consolidated Markdown report for multiple results",
)
async def generate_consolidated_report_endpoint(results: list[VAPTResult]) -> str:
    """Generate a consolidated Markdown report for a list of VAPTResult objects."""
    if not results:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one VAPTResult is required.",
        )
    return generate_consolidated_report(results)
