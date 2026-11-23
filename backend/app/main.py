"""ForensicOps AI - Main FastAPI Application Server.

Standards:
- Local-first, modular, workflow-driven cyber-forensics platform
- 4-Layer Evidence Sandbox & Hash-Chained Custody Enforcement
- Zero Shell Interpolation & Air-Gapped Tool Workers
- Real-time SSE Node State Streaming
"""
from __future__ import annotations

import os
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.api import api_router
from backend.app.core.config import get_settings, validate_production_configuration
from backend.app.core.exceptions import (
    CitationValidationError,
    CredentialEncryptionError,
    ForensicOpsError,
    ReadOnlyViolationError,
    UnauthorizedCollectorExecutionError,
    ZipSlipError,
)
from backend.app.core.network_validator import sanitize_credentials
from backend.app.core.logging_config import setup_structured_logging
from backend.app.core.maintenance import get_health_metrics


def create_app() -> FastAPI:
    """FastAPI application factory."""
    app = FastAPI(
        title="ForensicOps AI",
        description="Local-first, modular, workflow-driven cyber-forensics platform API",
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    cors_origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    env_origins = os.getenv("FORENSICOPS_CORS_ORIGINS")
    if env_origins:
        cors_origins.extend([o.strip() for o in env_origins.split(",") if o.strip()])

    # CORS configuration for Vite frontend
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Global Exception Handlers
    @app.exception_handler(UnauthorizedCollectorExecutionError)
    async def unauthorized_collector_handler(request: Request, exc: UnauthorizedCollectorExecutionError):
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": "UnauthorizedCollectorExecution", "detail": str(exc)},
        )

    @app.exception_handler(ReadOnlyViolationError)
    async def read_only_violation_handler(request: Request, exc: ReadOnlyViolationError):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "ReadOnlyViolation", "detail": str(exc)},
        )

    @app.exception_handler(CitationValidationError)
    async def citation_validation_handler(request: Request, exc: CitationValidationError):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"error": "CitationValidationError", "detail": str(exc)},
        )

    @app.exception_handler(ZipSlipError)
    async def zip_slip_handler(request: Request, exc: ZipSlipError):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "ZipSlipSecurityViolation", "detail": str(exc)},
        )

    @app.exception_handler(CredentialEncryptionError)
    async def credential_encryption_handler(request: Request, exc: CredentialEncryptionError):
        clean_detail = sanitize_credentials(str(exc))
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "CredentialEncryptionError", "detail": clean_detail},
        )

    @app.exception_handler(ForensicOpsError)
    async def forensic_ops_error_handler(request: Request, exc: ForensicOpsError):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "ForensicOpsError", "detail": str(exc)},
        )

    # Include Main API Router
    app.include_router(api_router)

    # Health Checks & Liveness/Readiness Probes
    @app.get("/health", tags=["System"])
    @app.get("/api/health", tags=["System"])
    async def health_check():
        return {
            "status": "healthy",
            "service": "ForensicOps AI API",
            "version": "0.1.0",
            "phase": 6,
        }

    @app.get("/health/live", tags=["System"])
    async def liveness_probe():
        return {"status": "alive", "service": "ForensicOps AI API"}

    @app.get("/health/ready", tags=["System"])
    async def readiness_probe():
        metrics = get_health_metrics()
        if metrics["status"] != "healthy":
            return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content=metrics)
        return metrics

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    setup_structured_logging()
    cfg_errors = validate_production_configuration()
    if cfg_errors:
        for err in cfg_errors:
            print(f"[FATAL CONFIG ERROR] {err}")
        if os.getenv("ENVIRONMENT", "").lower() == "production":
            raise SystemExit(1)
    host = os.getenv("FORENSICOPS_HOST", "127.0.0.1")
    uvicorn.run("backend.app.main:app", host=host, port=8000, reload=True)
