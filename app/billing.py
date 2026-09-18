from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import time
import zlib
from dataclasses import dataclass
from datetime import timezone
from typing import Any
from urllib.parse import urlparse

import httpx
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .config import Settings, get_settings
from .supabase_client import SupabaseError, SupabaseService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/billing/paypal", tags=["billing"])


class PayPalWebhookEvent(BaseModel):
    """Minimum authenticated envelope needed before database processing."""

    model_config = ConfigDict(extra="allow")
    id: str = Field(min_length=1, max_length=255)
    event_type: str = Field(min_length=1, max_length=255)
    resource: dict[str, Any]


@dataclass(frozen=True)
class PayPalTransmission:
    transmission_id: str
    transmission_time: str
    cert_url: str
    auth_algo: str
    transmission_sig: str


class PayPalUnavailable(RuntimeError):
    pass


class PayPalVerifier:
    """Locally verifies PayPal's RSA signature over the exact webhook bytes.

    PayPal signs: transmission_id|transmission_time|webhook_id|crc32(raw_body).
    Certificate URLs are restricted before any network request to prevent SSRF.
    Certificates are fetched over validated TLS, checked for validity and cached.
    """

    def __init__(self, settings: Settings, http: httpx.AsyncClient):
        self.settings = settings
        self.http = http
        self._cert_cache: dict[str, tuple[x509.Certificate, float]] = {}
        self._cert_lock = asyncio.Lock()

    def _cert_url_allowed(self, cert_url: str) -> bool:
        parsed = urlparse(cert_url)
        sandbox = ".sandbox." in self.settings.paypal_base_url
        allowed_hosts = (
            {"api-m.sandbox.paypal.com", "api.sandbox.paypal.com"}
            if sandbox
            else {"api-m.paypal.com", "api.paypal.com"}
        )
        return (
            parsed.scheme == "https"
            and parsed.hostname in allowed_hosts
            and parsed.port in (None, 443)
            and parsed.username is None
            and parsed.password is None
            and not parsed.query
            and not parsed.fragment
            and parsed.path.startswith("/v1/notifications/certs/")
        )

    @staticmethod
    def _certificate_expiry(certificate: x509.Certificate) -> float:
        expiry = getattr(certificate, "not_valid_after_utc", None)
        if expiry is None:  # cryptography < 42 compatibility
            expiry = certificate.not_valid_after.replace(tzinfo=timezone.utc)
        return expiry.timestamp()

    @staticmethod
    def _certificate_not_before(certificate: x509.Certificate) -> float:
        value = getattr(certificate, "not_valid_before_utc", None)
        if value is None:  # cryptography < 42 compatibility
            value = certificate.not_valid_before.replace(tzinfo=timezone.utc)
        return value.timestamp()

    async def _get_certificate(self, cert_url: str) -> x509.Certificate | None:
        if not self._cert_url_allowed(cert_url):
            return None
        now = time.time()
        cached = self._cert_cache.get(cert_url)
        if cached and now < cached[1]:
            return cached[0]

        async with self._cert_lock:
            cached = self._cert_cache.get(cert_url)
            if cached and now < cached[1]:
                return cached[0]
            try:
                response = await self.http.get(
                    cert_url,
                    headers={
                        "Accept": "application/x-pem-file, application/pkix-cert, text/plain"
                    },
                )
            except httpx.HTTPError as exc:
                raise PayPalUnavailable("PayPal certificate request failed") from exc
            if response.status_code == 404:
                return None
            if response.status_code != 200:
                raise PayPalUnavailable(
                    f"PayPal certificate endpoint returned HTTP {response.status_code}"
                )
            if not response.content or len(response.content) > 65_536:
                return None
            try:
                certificate = x509.load_pem_x509_certificate(response.content)
            except ValueError:
                return None
            expiry = self._certificate_expiry(certificate)
            if now < self._certificate_not_before(certificate) or now >= expiry:
                return None
            if len(self._cert_cache) >= 16:
                oldest = min(self._cert_cache, key=lambda key: self._cert_cache[key][1])
                self._cert_cache.pop(oldest, None)
            self._cert_cache[cert_url] = (certificate, min(expiry, now + 3_600))
            return certificate

    async def verify(self, raw_event: bytes, transmission: PayPalTransmission) -> bool:
        if transmission.auth_algo != "SHA256withRSA":
            return False
        certificate = await self._get_certificate(transmission.cert_url)
        if certificate is None:
            return False
        public_key = certificate.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 2_048:
            return False
        crc32 = zlib.crc32(raw_event) & 0xFFFFFFFF
        signed_message = (
            f"{transmission.transmission_id}|{transmission.transmission_time}|"
            f"{self.settings.paypal_webhook_id}|{crc32}"
        ).encode()
        try:
            signature = base64.b64decode(transmission.transmission_sig, validate=True)
            public_key.verify(
                signature, signed_message, padding.PKCS1v15(), hashes.SHA256()
            )
        except (ValueError, InvalidSignature):
            return False
        return True


def _required_header(name: str, value: str | None, max_length: int = 2_048) -> str:
    if not value:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Missing {name} header")
    if len(value) > max_length or "\r" in value or "\n" in value:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Invalid {name} header")
    return value


def get_http(request: Request) -> httpx.AsyncClient:
    return request.app.state.http


def get_paypal_verifier(request: Request) -> PayPalVerifier:
    return request.app.state.paypal_verifier


@router.post("/webhook", status_code=status.HTTP_200_OK)
async def receive_paypal_webhook(
    request: Request,
    paypal_transmission_id: str | None = Header(None, alias="PAYPAL-TRANSMISSION-ID"),
    paypal_transmission_time: str | None = Header(
        None, alias="PAYPAL-TRANSMISSION-TIME"
    ),
    paypal_cert_url: str | None = Header(None, alias="PAYPAL-CERT-URL"),
    paypal_auth_algo: str | None = Header(None, alias="PAYPAL-AUTH-ALGO"),
    paypal_transmission_sig: str | None = Header(None, alias="PAYPAL-TRANSMISSION-SIG"),
    settings: Settings = Depends(get_settings),
    http: httpx.AsyncClient = Depends(get_http),
    verifier: PayPalVerifier = Depends(get_paypal_verifier),
) -> dict[str, Any]:
    if not settings.paypal_webhook_configured:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "PayPal webhook configuration is pending",
        )
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > settings.max_webhook_bytes:
                raise HTTPException(
                    status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Webhook body too large"
                )
        except ValueError as exc:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "Invalid Content-Length"
            ) from exc

    raw_body = await request.body()
    if not raw_body or len(raw_body) > settings.max_webhook_bytes:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            "Webhook body is empty or too large",
        )

    transmission = PayPalTransmission(
        transmission_id=_required_header(
            "PAYPAL-TRANSMISSION-ID", paypal_transmission_id, 255
        ),
        transmission_time=_required_header(
            "PAYPAL-TRANSMISSION-TIME", paypal_transmission_time, 128
        ),
        cert_url=_required_header("PAYPAL-CERT-URL", paypal_cert_url),
        auth_algo=_required_header("PAYPAL-AUTH-ALGO", paypal_auth_algo, 128),
        transmission_sig=_required_header(
            "PAYPAL-TRANSMISSION-SIG", paypal_transmission_sig, 4_096
        ),
    )

    try:
        decoded = json.loads(raw_body)
        event = PayPalWebhookEvent.model_validate(decoded)
    except (json.JSONDecodeError, ValidationError) as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Malformed PayPal webhook event"
        ) from exc

    try:
        verified = await verifier.verify(raw_body, transmission)
    except PayPalUnavailable as exc:
        # HTTP 503 makes PayPal retry instead of acknowledging an unverified event.
        logger.error("paypal_verification_unavailable event_id=%s", event.id)
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "Webhook verification unavailable"
        ) from exc
    if not verified:
        logger.warning("paypal_signature_rejected event_id=%s", event.id)
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Invalid PayPal webhook signature"
        )

    db = SupabaseService(settings, http)
    try:
        result = await db.rpc_service(
            "ingest_verified_paypal_event",
            {
                "p_transmission_id": transmission.transmission_id,
                "p_paypal_event_id": event.id,
                "p_event_type": event.event_type,
                "p_payload": decoded,
                "p_payload_sha256": hashlib.sha256(raw_body).hexdigest(),
                "p_expected_merchant_id": settings.paypal_merchant_id,
            },
        )
    except SupabaseError as exc:
        logger.error(
            "paypal_event_persistence_failed event_id=%s request_id=%s",
            event.id,
            exc.request_id,
        )
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "Webhook persistence unavailable"
        ) from exc

    return {"accepted": True, **result}
