import os
import hashlib
import httpx
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import asyncpg

app = FastAPI(title="ApexSovereign Enterprise Compute Broker API", version="1.0.0")

# Database connection pool configuration
DATABASE_URL = "postgresql://postgres.eeclrffbjbnapsajmtqn:Kodakksaint777@aws-0-ap-southeast-1.pooler.supabase.com:5432/postgres"
PAYPAL_CLIENT_ID = os.getenv("BAAnJ3a3oIIe5LKdWQwr10uR8Uc4nayYYlfkHNtaTcJhZD5E5QQo9ULhoBQ5eCYB24P1LJL3VTltrNLaE8", "")
PAYPAL_CLIENT_SECRET = os.getenv("EDze29dnVH0Bgmz29XmpgavSEXv7OxbKP6ziB-QqOndkgnNo-ntTytBQmjATri6zPVAFGl3C5J1uC6Ci", "")
PAYPAL_API_BASE = os.getenv("PAYPAL_API_BASE", "https://api-m.paypal.com")

@app.on_event("startup")
async def startup_db():
    try:
        app.state.db_pool = await asyncpg.create_pool(
            DATABASE_URL, 
            min_size=1, 
            max_size=2, 
            ssl="require"
        )
        print("Database pool connected successfully!")
    except Exception as e:
        print(f"Failed to connect to database: {e}")
        raise e

@app.on_event("shutdown")
async def shutdown_db():
    await app.state.db_pool.close()

# --- Full HTML Landing Page Root Route ---
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

class PaymentVerificationRequest(BaseModel):
    order_id: str
    client_id: str

@app.post("/api/v1/payments/verify")
async def verify_and_record_payment(payload: PaymentVerificationRequest):
    async with httpx.AsyncClient() as client:
        auth_response = await client.post(
            f"{PAYPAL_API_BASE}/v1/oauth2/token",
            auth=(PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET),
            data={"grant_type": "client_credentials"}
        )
        if auth_response.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to authenticate with PayPal API.")
        access_token = auth_response.json().get("access_token")

        order_response = await client.get(
            f"{PAYPAL_API_BASE}/v2/checkout/orders/{payload.order_id}",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        if order_response.status_code != 200:
            raise HTTPException(status_code=400, detail="Invalid PayPal Order ID.")

        order_data = order_response.json()
        if order_data.get("status") != "COMPLETED":
            raise HTTPException(status_code=400, detail="Payment has not been completed.")

        purchase_unit = order_data["purchase_units"][0]
        amount_str = purchase_unit["amount"]["value"]
        amount_usd = float(amount_str)
        external_reference = order_data["id"]

    async with app.state.db_pool.acquire() as connection:
        async with connection.transaction():
            tenant = await connection.fetchrow(
                "SELECT tenant_id FROM tenants WHERE account_vector = $1", payload.client_id
            )
            if not tenant:
                tenant = await connection.fetchrow(
                    "INSERT INTO tenants (corporate_name, account_vector) VALUES ($1, $2) RETURNING tenant_id",
                    f"Enterprise Client ({payload.client_id})", payload.client_id
                )
            tenant_id = tenant["tenant_id"]

            try:
                await connection.execute(
                    """
                    INSERT INTO credit_transactions (tenant_id, amount_usd, transaction_type, external_reference, metadata)
                    VALUES ($1, $2, 'DEPOSIT', $3, $4)
                    """,
                    tenant_id, amount_usd, external_reference, '{"source": "paypal_direct_verification"}'
                )
            except asyncpg.exceptions.UniqueViolationError:
                raise HTTPException(status_code=409, detail="Transaction already processed (Idempotency check triggered).")

    return {"status": "success", "message": "Payment verified and credited to ledger.", "order_id": external_reference, "amount": amount_usd}

@app.post("/api/v1/webhooks/paypal")
async def paypal_webhook(request: Request):
    payload = await request.json()
    event_type = payload.get("event_type")
    resource = payload.get("resource", {})

    async with app.state.db_pool.acquire() as connection:
        if event_type == "BILLING.SUBSCRIPTION.ACTIVATED":
            sub_id = resource.get("id")
            await connection.execute(
                "UPDATE subscriptions SET status = $1 WHERE subscription_id = $2",
                "ACTIVE", sub_id
            )
        elif event_type == "BILLING.SUBSCRIPTION.CANCELLED":
            sub_id = resource.get("id")
            await connection.execute(
                "UPDATE subscriptions SET status = $1 WHERE subscription_id = $2",
                "CANCELLED", sub_id
            )

    return {"status": "received"}