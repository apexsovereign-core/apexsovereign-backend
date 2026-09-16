import os
from contextlib import asynccontextmanager
from fastapi import FastAPI

def require_env(name: str) -> str:
    val = os.getenv(name)
    if not val:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return val

# Core Environment & Secret Vault Configuration
DATABASE_URL = require_env("DATABASE_URL")
PAYPAL_CLIENT_ID = require_env("PAYPAL_CLIENT_ID")
PAYPAL_CLIENT_SECRET = require_env("PAYPAL_CLIENT_SECRET")
PAYPAL_WEBHOOK_ID = require_env("PAYPAL_WEBHOOK_ID")
APP_SECRET_API_KEY = require_env("APP_SECRET_API_KEY")
PAYPAL_MODE = require_env("PAYPAL_MODE")
LEASE_HMAC_SECRET = require_env("LEASE_HMAC_SECRET")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup actions
    print("ApexSovereign.ai Compute Broker starting up successfully...")
    yield
    # Shutdown actions
    print("ApexSovereign.ai Compute Broker shutting down...")

app = FastAPI(title="ApexSovereign.ai Compute Broker", lifespan=lifespan)

@app.get("/")
async def health_check():
    return {"status": "healthy", "service": "ApexSovereign.ai Compute Broker v2.4"}