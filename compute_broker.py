import json
import os
import secrets
from contextlib import asynccontextmanager

import asyncpg
import httpx
from fastapi import FastAPI, HTTPException, Request, Security, status
from fastapi.responses import HTMLResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

def require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(
            f"Missing required environment variable: {name}. "
            "Add it under Environment in the Render dashboard."
        )
    return value


DATABASE_URL = require_env("postgresql://postgres.eeclrffbjbnapsajmtqn:koddaksaintqwert@aws-0-ap-southeast-1.pooler.supabase.com:5432/postgres")
PAYPAL_CLIENT_ID = require_env("BAAnJ3a3oIIe5LKdWQwr10uR8Uc4nayYYlfkHNtaTcJhZD5E5QQo9ULhoBQ5eCYB24P1LJL3VTltrNLaE8")
PAYPAL_CLIENT_SECRET = require_env("EDze29dnVH0Bgmz29XmpgavSEXv7OxbKP6ziB-QqOndkgnNo-ntTytBQmjATri6zPVAFGl3C5J1uC6Ci")
PAYPAL_WEBHOOK_ID = require_env("0GS90368KN5946222")
APP_SECRET_API_KEY = require_env("0f1e949703be5e566425059d98d795f8")

PAYPAL_API_BASE = os.getenv("PAYPAL_API_BASE", "https://api-m.paypal.com")

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.db_pool = await asyncpg.create_pool(
        DATABASE_URL,
        min_size=1,
        max_size=2,
        ssl="require",
    )
    app.state.http = httpx.AsyncClient(timeout=15.0)
    print("Database pool connected successfully.")
    try:
        yield
    finally:
        await app.state.http.aclose()
        await app.state.db_pool.close()

app = FastAPI(
    title="ApexSovereign Enterprise Compute Broker API",
    version="1.1.0",
    lifespan=lifespan,
)

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(api_key: str | None = Security(api_key_header)) -> str:
    if api_key is None or not secrets.compare_digest(api_key, APP_SECRET_API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
        )
    return api_key

async def get_paypal_token() -> str:
    response = await app.state.http.post(
        f"{PAYPAL_API_BASE}/v1/oauth2/token",
        auth=(PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET),
        data={"grant_type": "client_credentials"},
    )
    if response.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail="Failed to authenticate with the PayPal API.",
        )
    return response.json()["access_token"]

@app.get("/", response_class=HTMLResponse)
async def root():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ApexSovereign Enterprise Compute Broker</title>
    </head>
    <body style="background: #0f172a; color: #f8fafc; font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh;">
        <div style="text-align: center;">
            <h1>ApexSovereign</h1>
            <p>Enterprise Compute Broker API is live and operational.</p>
        </div>
    </body>
    </html>
    """

@app.get("/health")
async def health():
    async with app.state.db_pool.acquire() as connection:
        await connection.fetchval("SELECT 1")
    return {"status": "ok"}
