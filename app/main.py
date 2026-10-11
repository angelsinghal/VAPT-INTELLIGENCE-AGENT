"""FastAPI application entry point."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import router
from app.config import configure_logging, get_settings

logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager for graceful startup and shutdown."""
    settings = get_settings()
    logger.info(
        "VAPT Intelligence Agent starting up (model=%s, embedding=%s)",
        settings.groq_model,
        settings.embedding_model,
    )
    # Initialize shared resources
    app.state.semaphore = asyncio.Semaphore(settings.max_concurrent_analyses)
    
    yield  # Server is running
    
    logger.info("VAPT Intelligence Agent shutting down gracefully... Cleaning up resources.")
    # Resources like db connections would be closed here


def create_app() -> FastAPI:
    """Application factory - creates and configures the FastAPI app."""
    settings = get_settings()
    configure_logging(settings)

    app = FastAPI(
        title="VAPT Intelligence Agent",
        description=(
            "AI-powered VAPT finding analysis and report generation. "
            "Uses LangGraph + ChromaDB RAG + deterministic security tools + Groq."
        ),
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Timeout and Panic Recovery Middleware
    @app.middleware("http")
    async def timeout_and_recovery_middleware(request: Request, call_next: object) -> Response:
        try:
            return await asyncio.wait_for(call_next(request), timeout=settings.request_timeout)
        except asyncio.TimeoutError:
            logger.warning("Request timed out after %d seconds: %s %s", settings.request_timeout, request.method, request.url)
            return JSONResponse(status_code=504, content={"detail": "Request timed out."})
        except Exception as exc:
            logger.exception("Panic recovered in middleware: %s %s", request.method, request.url)
            return JSONResponse(status_code=500, content={"detail": "Internal server error."})

    # Rate limiting (optional per-IP)
    if not settings.disable_rate_limit:
        try:
            from aiolimiter import AsyncLimiter
            _limiters: dict[str, AsyncLimiter] = {}

            @app.middleware("http")
            async def rate_limit_middleware(request: Request, call_next: object) -> Response:
                client_ip = request.client.host if request.client else "unknown"
                if client_ip not in _limiters:
                    _limiters[client_ip] = AsyncLimiter(max_rate=5, time_period=1)
                limiter = _limiters[client_ip]
                try:
                    async with limiter:
                        return await call_next(request)
                except Exception:
                    return JSONResponse(
                        status_code=429,
                        content={"detail": "Too many requests. Please slow down."},
                    )
        except ImportError:
            logger.warning("aiolimiter not installed; rate limiting disabled.")

    # Routes
    app.include_router(router)

    # Global exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled exception on %s %s", request.method, request.url)
        return JSONResponse(
            status_code=500,
            content={"detail": "An internal server error occurred."},
        )

    return app

app = create_app()

if __name__ == "__main__":
    import uvicorn
    s = get_settings()
    uvicorn.run("app.main:app", host="0.0.0.0", port=s.port, reload=False)
