from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from .billing import PayPalVerifier
from .billing import router as billing_router
from .config import get_settings
from .onboarding import HybridTenantTokenCodec, MLDSASigner, SupabaseJWTVerifier
from .onboarding import router as onboarding_router
from .supabase_client import SupabaseError, SupabaseService


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    timeout = httpx.Timeout(settings.paypal_timeout_seconds, connect=5.0)
    limits = httpx.Limits(max_connections=100, max_keepalive_connections=20)
    async with httpx.AsyncClient(
        timeout=timeout, limits=limits, follow_redirects=False
    ) as http:
        pqc_signer = None
        pqc_values = (
            settings.pqc_key_id,
            settings.pqc_private_key_file,
            settings.pqc_public_key_file,
        )
        if all(pqc_values):
            pqc_signer = MLDSASigner(
                settings.pqc_algorithm,
                settings.pqc_key_id,  # type: ignore[arg-type]
                settings.pqc_private_key_file,  # type: ignore[arg-type]
                settings.pqc_public_key_file,  # type: ignore[arg-type]
            )
        app.state.http = http
        app.state.paypal_verifier = PayPalVerifier(settings, http)
        app.state.supabase_jwt_verifier = SupabaseJWTVerifier(settings)
        app.state.tenant_token_codec = HybridTenantTokenCodec(settings, pqc_signer)
        yield


app = FastAPI(
    title="ApexSovereign.ai Institutional Pilot API",
    version="3.0.0",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)
app.include_router(billing_router)
app.include_router(onboarding_router)


@app.get("/", include_in_schema=False)
def root() -> dict[str, str]:
    return {
        "service": "ApexSovereign.ai Institutional Pilot API",
        "status": "ACTIVE",
        "health": "/v1/health",
    }


@app.get("/v1/health", include_in_schema=False)
async def institutional_health(request: Request) -> JSONResponse:
    settings = get_settings()
    try:
        database_ready = await SupabaseService(
            settings, request.app.state.http
        ).rpc_service("apex_healthcheck", {})
    except SupabaseError:
        database_ready = False
    ready = database_ready is True
    payload: dict[str, Any] = {
        "service": "ApexSovereign.ai Institutional Pilot API",
        "status": "ACTIVE" if ready else "DEGRADED",
        "environment": settings.app_env,
        "database": "READY" if ready else "UNAVAILABLE",
        "payment_mode": "LIVE"
        if settings.paypal_base_url == "https://api-m.paypal.com"
        else "SANDBOX",
        "payment_webhook": "READY"
        if settings.paypal_webhook_configured
        else "PENDING_MANUAL_CONFIGURATION",
        "pqc_required": settings.require_pqc,
    }
    return JSONResponse(
        status_code=status.HTTP_200_OK
        if ready
        else status.HTTP_503_SERVICE_UNAVAILABLE,
        content=payload,
    )


@app.get("/health", include_in_schema=False)
async def render_health(request: Request) -> JSONResponse:
    return await institutional_health(request)


@app.get("/healthz", include_in_schema=False)
async def healthz(request: Request) -> JSONResponse:
    return await institutional_health(request)
