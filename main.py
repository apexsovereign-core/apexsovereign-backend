"""
ApexSovereign.ai - Main FastAPI Application & Lifecycle Manager
Production-grade deployment entrypoint for Render.
"""

import os
import time
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

load_dotenv()

from compute_broker import init_db, get_db_health, compute_router
from payment_router import payment_router

START_TIME = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[ApexSovereign] Initializing system engine & database schemas...")
    try:
        init_db()
        print("[ApexSovereign] Database connection and schema verified successfully.")
    except Exception as exc:
        print(f"[ApexSovereign] WARNING: Database auto-initialization error: {exc}")
        print("[ApexSovereign] Server will continue to start. Please verify DATABASE_URL.")

    yield

    print("[ApexSovereign] Graceful shutdown completed. Releasing thread pools.")


app = FastAPI(
    title="ApexSovereign.ai API",
    description="Autonomous Work OS & Sovereign Compute Broker Platform",
    version="2.4.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

custom_origins = [
    origin.strip() 
    for origin in os.getenv("ALLOWED_ORIGINS", "").split(",") 
    if origin.strip()
]

allowed_origins = custom_origins if custom_origins else ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"https://.*\.vercel\.app" if allowed_origins != ["*"] else None,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["Health"])
async def root_status() -> Dict[str, Any]:
    uptime_seconds = round(time.time() - START_TIME, 2)
    db_status = get_db_health()

    return {
        "service": "ApexSovereign.ai Autonomous Compute Broker",
        "status": "OPERATIONAL",
        "version": "2.4.0",
        "uptime_seconds": uptime_seconds,
        "database": db_status,
        "endpoints": {
            "docs": "/docs",
            "health": "/health",
            "compute": "/compute",
            "billing": "/billing",
        },
    }


@app.get("/health", tags=["Health"])
async def health_check() -> Dict[str, Any]:
    uptime_seconds = round(time.time() - START_TIME, 2)
    db_status = get_db_health()

    return JSONResponse(
        status_code=200,
        content={
            "status": "HEALTHY" if db_status.get("connected") else "DEGRADED",
            "uptime_seconds": uptime_seconds,
            "database": db_status,
            "environment": os.getenv("RENDER_ENVIRONMENT", "production"),
        },
    )


app.include_router(compute_router)
app.include_router(payment_router)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 10000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
@app.on_event("startup")
def on_startup():
    init_db()
    # Autonomous 24/7 background worker thread
    try:
        import threading
        from worker_engine import run_asynchronous_worker
        if os.getenv("SUPABASE_URL") and os.getenv("SUPABASE_SERVICE_ROLE_KEY"):
            worker_thread = threading.Thread(target=run_asynchronous_worker, daemon=True)
            worker_thread.start()
            print("[ApexSovereign] Autonomous 24/7 worker thread running.")
    except Exception as worker_exc:
        print(f"[ApexSovereign Worker] Worker startup note: {worker_exc}")

# Mount Routers
app.include_router(compute_router)

try:
    from payment_router import payment_router
    app.include_router(payment_router)
except Exception:
    pass

try:
    from paypal_gateway import paypal_gateway_router
    app.include_router(paypal_gateway_router)
except Exception:
    pass
