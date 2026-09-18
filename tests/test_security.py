import asyncio
import base64
import json
import os
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from fastapi import HTTPException
from fastapi.testclient import TestClient

KEY = base64.urlsafe_b64encode(b"k" * 32).rstrip(b"=").decode()
os.environ.update(
    {
        "SUPABASE_URL": "https://example.supabase.co",
        "SUPABASE_PUBLISHABLE_KEY": "publishable",
        "SUPABASE_SERVICE_ROLE_KEY": "service-secret",
        "PAYPAL_CLIENT_ID": "client-id",
        "PAYPAL_CLIENT_SECRET": "client-secret",
        "PAYPAL_WEBHOOK_ID": "WH-registered",
        "PAYPAL_MERCHANT_ID": "MERCHANT-1",
        "TENANT_TOKEN_HMAC_KEYS_JSON": json.dumps({"2026-09": KEY}),
        "TENANT_TOKEN_CURRENT_KID": "2026-09",
        "TENANT_TOKEN_ISSUER": "https://api.example.test",
        "TENANT_TOKEN_AUDIENCE": "test-api",
    }
)

from app.billing import (
    PayPalTransmission,
    PayPalUnavailable,
    PayPalVerifier,
    _required_header,
)
from app.config import Settings
from app.main import app
from app.onboarding import HybridTenantTokenCodec


def _certificate(private_key: rsa.RSAPrivateKey) -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api-m.paypal.com")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .sign(private_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


def test_application_lifespan_and_health_route():
    with TestClient(app) as client:
        response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "ACTIVE"


def test_hmac_token_round_trip_and_tamper_rejection():
    codec = HybridTenantTokenCodec(Settings(), None)
    token, expires_at = codec.issue(
        "00000000-0000-0000-0000-000000000001",
        "00000000-0000-0000-0000-000000000002",
        ["compute:read"],
    )
    claims = codec.verify(token)
    assert claims["sub"].endswith("0001")
    assert claims["scope"] == ["compute:read"]
    assert claims["exp"] == expires_at
    parts = token.split(".")
    parts[1] = parts[1][:-1] + ("A" if parts[1][-1] != "A" else "B")
    with pytest.raises(ValueError, match="HMAC"):
        codec.verify(".".join(parts))


def test_token_rejects_non_object_header_without_server_error():
    codec = HybridTenantTokenCodec(Settings(), None)
    bad_header = base64.urlsafe_b64encode(b"[]").rstrip(b"=").decode()
    with pytest.raises(ValueError, match="header"):
        codec.verify(f"{bad_header}.e30.AA")


def test_pqc_required_fails_closed_without_signer():
    settings = Settings(
        require_pqc=True,
        pqc_key_id="key-1",
        pqc_private_key_file=Path("/tmp/private"),
        pqc_public_key_file=Path("/tmp/public"),
    )
    codec = HybridTenantTokenCodec(settings, None)
    with pytest.raises(RuntimeError, match="required"):
        codec.issue("tenant", "jti", ["compute:read"])


def test_hybrid_token_requires_and_verifies_second_signature():
    class FakePQCSigner:
        algorithm = "ML-DSA-65"
        key_id = "pqc-test"

        def sign(self, message: bytes) -> bytes:
            return b"pqc:" + message

        def verify(self, message: bytes, signature: bytes) -> bool:
            return signature == b"pqc:" + message

    settings = Settings(
        require_pqc=True,
        pqc_key_id="pqc-test",
        pqc_private_key_file=Path("/tmp/private"),
        pqc_public_key_file=Path("/tmp/public"),
    )
    codec = HybridTenantTokenCodec(settings, FakePQCSigner())  # type: ignore[arg-type]
    token, _ = codec.issue(
        "00000000-0000-0000-0000-000000000001",
        "00000000-0000-0000-0000-000000000002",
        ["compute:read"],
    )
    assert codec.verify(token)["sub"].endswith("0001")
    with pytest.raises(ValueError, match="PQC"):
        codec.verify(".".join(token.split(".")[:3]))


def test_required_paypal_header_rejects_missing_and_newlines():
    with pytest.raises(HTTPException):
        _required_header("X", None)
    with pytest.raises(HTTPException):
        _required_header("X", "bad\nheader")


def test_paypal_local_signature_verifies_exact_raw_event():
    settings = Settings()
    raw = b'{ "id" : "WH-1", "event_type" : "PAYMENT.CAPTURE.COMPLETED", "resource" : {} }'
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _certificate(private_key)
    transmission_id = "T-1"
    transmission_time = "2026-09-18T09:00:00Z"
    crc = zlib.crc32(raw) & 0xFFFFFFFF
    message = f"{transmission_id}|{transmission_time}|{settings.paypal_webhook_id}|{crc}".encode()
    signature = base64.b64encode(
        private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    ).decode()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=cert)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            verifier = PayPalVerifier(settings, client)
            transmission = PayPalTransmission(
                transmission_id,
                transmission_time,
                "https://api-m.paypal.com/v1/notifications/certs/CERT-1",
                "SHA256withRSA",
                signature,
            )
            assert await verifier.verify(raw, transmission) is True
            assert await verifier.verify(raw + b" ", transmission) is False

    asyncio.run(run())


def test_paypal_certificate_url_blocks_ssrf_without_network_call():
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            verifier = PayPalVerifier(Settings(), client)
            valid = await verifier.verify(
                b"{}",
                PayPalTransmission(
                    "T", "now", "https://attacker.example/cert", "SHA256withRSA", "c2ln"
                ),
            )
            assert valid is False

    asyncio.run(run())
    assert called is False


def test_paypal_certificate_dependency_failure_does_not_validate_event():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            verifier = PayPalVerifier(Settings(), client)
            with pytest.raises(PayPalUnavailable):
                await verifier.verify(
                    b"{}",
                    PayPalTransmission(
                        "T",
                        "now",
                        "https://api-m.paypal.com/v1/notifications/certs/CERT-1",
                        "SHA256withRSA",
                        "c2ln",
                    ),
                )

    asyncio.run(run())


def test_rls_migration_contains_expected_boundaries():
    sql = Path(
        "supabase/migrations/20260918_institutional_pilot_billing.sql"
    ).read_text()
    assert "enable row level security" in sql
    assert "revoke all on public.institutional_tenants" in sql
    assert "ingest_verified_paypal_event" in sql
    assert "grant execute on function public.ingest_verified_paypal_event" in sql
    assert "to service_role" in sql
    assert "constraint trigger ledger_entries_balanced" in sql
    assert "constraint trigger ledger_transaction_complete" in sql
    assert "revoke all on function apex_private.ensure_ledger_accounts" in sql
