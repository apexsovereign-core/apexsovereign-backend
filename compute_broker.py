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

# Loads a local .env file when running on your own machine. On Render this
# does nothing, because Render injects the variables directly. Wrapped in a
# try/except so the app still boots if python-dotenv isn't installed.
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Configuration
#
# Nothing secret is written in this file. Every value below comes from the
# Environment tab in your Render dashboard. If one is missing the app refuses
# to boot, so you find out from the deploy log instead of from a 500 at 2am.
# ---------------------------------------------------------------------------

def require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(
            f"Missing required environment variable: {name}. "
            "Add it under Environment in the Render dashboard."
        )
    return value


DATABASE_URL = require_env("DATABASE_URL = require_env("postgresql://postgres.eeclrffbjbnapsajmtqn:Kodakksaint7@aws-0-ap-southeast-1.pooler.supabase.com:5432/postgres")
PAYPAL_CLIENT_ID = require_env("BAAnJ3a3oIIe5LKdWQwr10uR8Uc4nayYYlfkHNtaTcJhZD5E5QQo9ULhoBQ5eCYB24P1LJL3VTltrNLaE8")
PAYPAL_CLIENT_SECRET = require_env("EDze29dnVH0Bgmz29XmpgavSEXv7OxbKP6ziB-QqOndkgnNo-ntTytBQmjATri6zPVAFGl3C5J1uC6Ci")
PAYPAL_WEBHOOK_ID = require_env("0GS90368KN5946222")
APP_SECRET_API_KEY = require_env("APP_SECRET_API_KEY")

PAYPAL_API_BASE = os.getenv("PAYPAL_API_BASE", "https://api-m.paypal.com")


# ---------------------------------------------------------------------------
# Lifespan (replaces the deprecated @app.on_event handlers)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# API key authentication
# ---------------------------------------------------------------------------

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: str | None = Security(api_key_header)) -> str:
    """Reject any request without a valid X-API-Key header.

    secrets.compare_digest is used instead of != so the comparison takes the
    same amount of time whether the key is wrong on the first character or the
    last. A plain != leaks the key one character at a time to anyone patient
    enough to measure response times.
    """
    if api_key is None or not secrets.compare_digest(api_key, APP_SECRET_API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
        )
    return api_key


# ---------------------------------------------------------------------------
# PayPal helpers
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Public landing page
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def root():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ApexSovereign Enterprise Compute Broker</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .container { text-align: center; max-width: 600px; padding: 2rem; background: #1e293b; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.3); }
            h1 { color: #38bdf8; margin-bottom: 0.5rem; }
            p { color: #94a3b8; margin-bottom: 1.5rem; }
            a { display: inline-block; background: #38bdf8; color: #0f172a; padding: 0.75rem 1.5rem; border-radius: 6px; text-decoration: none; font-weight: bold; transition: background 0.2s; }
            a:hover { background: #0ea5e9; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>ApexSovereign</h1>
            <p>Enterprise Compute Broker API is live and operational.</p>
            <a href="/docs">Explore API Documentation</a>
        </div>
    </body>
    </html>
    """


@app.get("/health")
async def health():
    async with app.state.db_pool.acquire() as connection:
        await connection.fetchval("SELECT 1")
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Payment verification
#
# Protected by the API key. That means it must be called from a server-side
# route (a Vercel Route Handler or serverless function), never from browser
# JavaScript -- anything in browser JS is readable by the user, so putting
# APP_SECRET_API_KEY there would hand your key to every visitor.
# ---------------------------------------------------------------------------

class PaymentVerificationRequest(BaseModel):
    order_id: str
    client_id: str


@app.post("/api/v1/payments/verify", dependencies=[Security(verify_api_key)])
async def verify_and_record_payment(payload: PaymentVerificationRequest):
    access_token = await get_paypal_token()

    order_response = await app.state.http.get(
        f"{PAYPAL_API_BASE}/v2/checkout/orders/{payload.order_id}",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if order_response.status_code != 200:
        raise HTTPException(status_code=400, detail="Invalid PayPal order ID.")

    order_data = order_response.json()
    if order_data.get("status") != "COMPLETED":
        raise HTTPException(status_code=400, detail="Payment has not been completed.")

    purchase_unit = order_data["purchase_units"][0]
    amount_usd = float(purchase_unit["amount"]["value"])
    currency = purchase_unit["amount"]["currency_code"]
    if currency != "USD":
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported currency: {currency}.",
        )
    external_reference = order_data["id"]

    async with app.state.db_pool.acquire() as connection:
        async with connection.transaction():
            tenant = await connection.fetchrow(
                "SELECT tenant_id FROM tenants WHERE account_vector = $1",
                payload.client_id,
            )
            if not tenant:
                tenant = await connection.fetchrow(
                    "INSERT INTO tenants (corporate_name, account_vector) "
                    "VALUES ($1, $2) RETURNING tenant_id",
                    f"Enterprise Client ({payload.client_id})",
                    payload.client_id,
                )
            tenant_id = tenant["tenant_id"]

            try:
                await connection.execute(
                    """
                    INSERT INTO credit_transactions
                        (tenant_id, amount_usd, transaction_type,
                         external_reference, metadata)
                    VALUES ($1, $2, 'DEPOSIT', $3, $4::jsonb)
                    """,
                    tenant_id,
                    amount_usd,
                    external_reference,
                    json.dumps({"source": "paypal_direct_verification"}),
                )
            except asyncpg.exceptions.UniqueViolationError:
                raise HTTPException(
                    status_code=409,
                    detail="Transaction already processed.",
                )

    return {
        "status": "success",
        "message": "Payment verified and credited to ledger.",
        "order_id": external_reference,
        "amount": amount_usd,
    }


# ---------------------------------------------------------------------------
# PayPal webhook
#
# Every incoming event is verified against PayPal's signature endpoint before
# it is allowed to touch the database. Without this, anyone who finds the URL
# can activate or cancel subscriptions by posting fake JSON.
# ---------------------------------------------------------------------------

async def verify_webhook_signature(request: Request, payload: dict) -> None:
    required_headers = {
        "auth_algo": request.headers.get("paypal-auth-algo"),
        "cert_url": request.headers.get("paypal-cert-url"),
        "transmission_id": request.headers.get("paypal-transmission-id"),
        "transmission_sig": request.headers.get("paypal-transmission-sig"),
        "transmission_time": request.headers.get("paypal-transmission-time"),
    }
    if not all(required_headers.values()):
        raise HTTPException(status_code=400, detail="Missing PayPal signature headers.")

    access_token = await get_paypal_token()
    response = await app.state.http.post(
        f"{PAYPAL_API_BASE}/v1/notifications/verify-webhook-signature",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            **required_headers,
            "webhook_id": PAYPAL_WEBHOOK_ID,
            "webhook_event": payload,
        },
    )
    verified = (
        response.status_code == 200
        and response.json().get("verification_status") == "SUCCESS"
    )
    if not verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Webhook signature verification failed.",
        )


@app.post("/api/v1/webhooks/paypal")
async def paypal_webhook(request: Request):
    payload = await request.json()
    await verify_webhook_signature(request, payload)

    event_type = payload.get("event_type")
    resource = payload.get("resource", {})
    sub_id = resource.get("id")

    status_map = {
        "BILLING.SUBSCRIPTION.ACTIVATED": "ACTIVE",
        "BILLING.SUBSCRIPTION.CANCELLED": "CANCELLED",
        "BILLING.SUBSCRIPTION.SUSPENDED": "SUSPENDED",
        "BILLING.SUBSCRIPTION.EXPIRED": "EXPIRED",
    }

    new_status = status_map.get(event_type)
    if new_status and sub_id:
        async with app.state.db_pool.acquire() as connection:
            await connection.execute(
                "UPDATE subscriptions SET status = $1 WHERE subscription_id = $2",
                new_status,
                sub_id,
            )

    return {"status": "received"}