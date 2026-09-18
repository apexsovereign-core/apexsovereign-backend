# ApexSovereign.ai Institutional Pilot API

This repository deploys the controlled institutional pilot and billing API for `apexsovereign.ai`. The production entrypoint exposes only the verified PayPal webhook, institutional application workflow, administrative approval and deposit controls, revocable tenant tokens, and health endpoints.

Legacy compute and simulated payment modules are retained under `legacy/` for audit. They are **not imported** by the production application because they permit development defaults, mock funding, or unauthenticated balance mutation.

## Production endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/health` | Institutional service and Supabase RPC readiness |
| `POST` | `/v1/billing/paypal/webhook` | Locally verified PayPal webhook ingestion |
| `POST` | `/v1/pilot/applications` | Idempotent public pilot application intake |
| `POST` | `/v1/pilot/applications/{id}/approve` | Authenticated platform-administrator approval |
| `POST` | `/v1/pilot/applications/{id}/payment-intents` | Idempotent PayPal correlation intent creation |
| `POST` | `/v1/pilot/applications/{id}/clear-deposit` | Authenticated manual deposit clearance |
| `POST` | `/v1/pilot/applications/{id}/tokens` | Financially gated tenant token issuance |

The webhook verifier calculates PayPal's CRC32 signature input over the unchanged request bytes. It downloads certificates only from allowlisted PayPal HTTPS hosts and verifies `SHA256withRSA` locally. A verified event then enters one PostgreSQL function that enforces event and transmission idempotency, merchant and payment-intent correlation, amount and currency matching, and balanced double-entry ledger posting.[1]

## Database migrations

The production database already contained an incompatible `public.tenants` table. The migration therefore creates `public.institutional_tenants` and related pilot billing tables without modifying the existing compute schema.

Apply migrations in filename order through the Supabase migration system:

```text
supabase/migrations/20260918_institutional_pilot_billing.sql
supabase/migrations/20260918_function_privilege_hardening.sql
```

Every exposed institutional table has Row Level Security enabled. Tenant reads are resolved through `tenant_memberships`. Direct financial writes are revoked. Administrator functions independently require membership in `apex_private.platform_admins`. Webhook ingestion and token-grant validation are executable only by `service_role`. Supabase recommends combining RLS with explicit grants and indexing policy columns.[2]

## Local validation

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
ruff check --ignore B008,TRY004 app tests main.py compute_broker.py
python3 -m compileall -q app main.py compute_broker.py
pytest -q
```

Copy `.env.example` to `.env` only for local development. Production values belong in Render's encrypted environment settings. The application fails startup when required PayPal, Supabase, or token-signing values are missing.

## Deployment

Render is configured to start:

```bash
uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

Its health check is `/v1/health`. The health endpoint returns HTTP 200 only when the application can invoke the service-role-only Supabase health function. The custom PayPal webhook URL is:

```text
https://apexsovereign.ai/v1/billing/paypal/webhook
```

`REQUIRE_PQC=false` retains HMAC-SHA-256 tenant signing while preserving the optional ML-DSA integration. Do not enable mandatory PQC until an audited key-management or signing service supplies the private key. Open Quantum Safe describes liboqs as an evaluation and prototyping library and recommends hybrid deployment rather than replacing conventional cryptography.[3]

## References

[1]: https://developer.paypal.com/api/rest/webhooks/rest "PayPal: Integrate webhooks"
[2]: https://supabase.com/docs/guides/database/postgres/row-level-security "Supabase: Row Level Security"
[3]: https://github.com/open-quantum-safe/liboqs-python "Open Quantum Safe: liboqs-python"
