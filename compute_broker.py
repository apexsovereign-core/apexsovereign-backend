import os
import hashlib
import httpx
from fastapi import FastAPI, Request, HTTPException, status
from pydantic import BaseModel
import asyncpg

app = FastAPI(title="ApexSovereign Enterprise Compute Broker API", version="1.0.0")

# Database connection pool configuration
postgresql://postgres.eeclrffbjbnapsajmtqn:Kodakksaint777@aws-0-ap-southeast-1.pooler.supabase.com:6543/postgres
PAYPAL_CLIENT_ID = os.getenv("BAAnJ3a3oIIe5LKdWQwr10uR8Uc4nayYYlfkHNtaTcJhZD5E5QQo9ULhoBQ5eCYB24P1LJL3VTltrNLaE8", "")
PAYPAL_CLIENT_SECRET = os.getenv("EDze29dnVH0Bgmz29XmpgavSEXv7OxbKP6ziB-QqOndkgnNo-ntTytBQmjATri6zPVAFGl3C5J1uC6Ci", "")
PAYPAL_API_BASE = os.getenv("PAYPAL_API_BASE", "https://api-m.paypal.com") # Use sandbox.paypal.com for testing

@app.on_event("startup")
async def startup_db():
    app.state.db_pool = await asyncpg.create_pool(DATABASE_URL, ssl="require")

@app.on_event("shutdown")
async def shutdown_db():
    await app.state.db_pool.close()

class PaymentVerificationRequest(BaseModel):
    order_id: str
    client_id: str

@app.post("/api/v1/payments/verify")
async def verify_and_record_payment(payload: PaymentVerificationRequest):
    """
    Server-side verification of PayPal Orders to prevent client-side spoofing.
    Fetches the authorized order directly from PayPal API before writing to the immutable ledger.
    """
    async with httpx.AsyncClient() as client:
        # 1. Obtain OAuth token from PayPal
        auth_response = await client.post(
            f"{PAYPAL_API_BASE}/v1/oauth2/token",
            auth=(PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET),
            data={"grant_type": "client_credentials"}
        )
        
        if auth_response.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to authenticate with PayPal API.")
        
        access_token = auth_response.json().get("access_token")

        # 2. Query PayPal order details securely
        order_response = await client.get(
            f"{PAYPAL_API_BASE}/v2/checkout/orders/{payload.order_id}",
            headers={"Authorization": f"Bearer {access_token}"}
        )

        if order_response.status_code != 200:
            raise HTTPException(status_code=400, detail="Invalid PayPal Order ID.")

        order_data = order_response.json()
        if order_data.get("status") != "COMPLETED":
            raise HTTPException(status_code=400, detail="Payment has not been completed.")

        # Extract transaction parameters
        purchase_unit = order_data["purchase_units"][0]
        amount_str = purchase_unit["amount"]["value"]
        amount_usd = float(amount_str)
        external_reference = order_data["id"]

    # 3. Write securely to the PostgreSQL append-only ledger via connection pool
    async with app.state.db_pool.acquire() as connection:
        async with connection.transaction():
            # Check or create tenant record
            tenant = await connection.fetchrow(
                "SELECT tenant_id FROM tenants WHERE account_vector = $1", payload.client_id
            )
            
            if not tenant:
                tenant = await connection.fetchrow(
                    "INSERT INTO tenants (corporate_name, account_vector) VALUES ($1, $2) RETURNING tenant_id",
                    f"Enterprise Client ({payload.client_id})", payload.client_id
                )
            
            tenant_id = tenant["tenant_id"]

            # Insert ledger entry with idempotency check on external_reference
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
from fastapi import Request, status

@app.post("/api/v1/webhooks/paypal")
async def paypal_webhook(request: Request):
    payload = await request.json()
    event_type = payload.get("event_type")
    resource = payload.get("resource", {})

    # Handle subscription events
    async with app.state.db_pool.acquire() as connection:
        if event_type == "BILLING.SUBSCRIPTION.ACTIVATED":
            sub_id = resource.get("id")
            plan_id = resource.get("plan_id")
            subscriber = resource.get("subscriber", {}).get("email_address")
            
            # Update your Supabase immutable ledger / subscriptions table
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