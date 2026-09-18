from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import httpx
import jwt
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from jwt import InvalidTokenError, PyJWKClient
from jwt.exceptions import PyJWKClientConnectionError
from pydantic import BaseModel, ConfigDict, EmailStr, Field, HttpUrl

from .config import Settings, decode_b64url, get_settings
from .supabase_client import SupabaseError, SupabaseService

router = APIRouter(prefix="/v1/pilot", tags=["pilot"])


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


class PilotApplication(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    legal_name: str = Field(min_length=2, max_length=200)
    registration_country: str = Field(pattern=r"^[A-Za-z]{2}$")
    registration_number: str = Field(min_length=2, max_length=100)
    website: HttpUrl | None = None
    admin_email: EmailStr
    intended_workload: str = Field(min_length=20, max_length=4_000)
    expected_monthly_usd: int = Field(ge=0, le=10_000_000)


class ApprovalRequest(BaseModel):
    owner_user_id: uuid.UUID
    review_reference: str = Field(min_length=4, max_length=200)


class ManualDepositRequest(BaseModel):
    external_reference: str = Field(min_length=4, max_length=200)
    amount_minor: int = Field(gt=0, le=1_000_000_000_00)
    currency: str = Field(pattern=r"^[A-Z]{3}$")


class PaymentIntentRequest(BaseModel):
    amount_minor: int = Field(gt=0, le=1_000_000_000_00)
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    paypal_order_id: str | None = Field(default=None, min_length=1, max_length=255)


AllowedScope = Literal["compute:submit", "compute:read", "billing:read"]


class TokenRequest(BaseModel):
    scopes: list[AllowedScope] = Field(
        default=["compute:read"], min_length=1, max_length=3
    )


@dataclass(frozen=True)
class AdminIdentity:
    user_id: uuid.UUID
    access_token: str


@dataclass(frozen=True)
class TenantIdentity:
    tenant_id: uuid.UUID
    token_id: uuid.UUID
    scopes: frozenset[str]


class SupabaseJWTVerifier:
    """Verifies Supabase user JWTs with asymmetric keys from the project JWKS."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.client = PyJWKClient(
            f"{settings.supabase_url}/auth/v1/.well-known/jwks.json",
            cache_keys=True,
            lifespan=600,
        )

    def _verify_sync(self, token: str) -> dict[str, Any]:
        signing_key = self.client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "ES256", "EdDSA"],
            audience=self.settings.supabase_jwt_audience,
            issuer=self.settings.supabase_jwt_issuer,
            options={"require": ["exp", "iat", "sub", "aud", "iss"]},
        )
        if claims.get("role") != "authenticated":
            raise InvalidTokenError("authenticated role required")
        return claims

    async def verify(self, token: str) -> dict[str, Any]:
        return await asyncio.to_thread(self._verify_sync, token)


class MLDSASigner:
    """Optional local ML-DSA signer for a hybrid HMAC + PQC token.

    Use a production KMS/HSM-backed signer when available. liboqs is a useful
    integration boundary, but its own maintainers describe it as a prototyping
    library; enabling this adapter requires an explicit risk decision.
    """

    def __init__(
        self, algorithm: str, key_id: str, private_key_file: Path, public_key_file: Path
    ):
        self.algorithm = algorithm
        self.key_id = key_id
        self.private_key_file = private_key_file
        self.public_key_file = public_key_file
        if os.name == "posix" and stat.S_IMODE(private_key_file.stat().st_mode) & 0o077:
            raise RuntimeError(
                "PQC private key file must not be group/world accessible"
            )

    @staticmethod
    def _read_key(path: Path) -> bytes:
        return decode_b64url(path.read_text(encoding="ascii").strip())

    def sign(self, message: bytes) -> bytes:
        try:
            import oqs  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "liboqs-python is required when PQC signing is enabled"
            ) from exc
        with oqs.Signature(
            self.algorithm, self._read_key(self.private_key_file)
        ) as signer:
            return signer.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            import oqs  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "liboqs-python is required when PQC signing is enabled"
            ) from exc
        with oqs.Signature(self.algorithm) as verifier:
            return bool(
                verifier.verify(
                    message, signature, self._read_key(self.public_key_file)
                )
            )


class HybridTenantTokenCodec:
    """Versioned, compact HMAC token with an optional independent ML-DSA signature.

    Format: base64url(header).base64url(claims).base64url(hmac)[.base64url(ml-dsa)]
    This is an ApexSovereign token, not a standards-compliant JWT. Consumers
    must verify HMAC, expiry/issuer/audience, the database grant, and—when
    required—the ML-DSA signature.
    """

    def __init__(self, settings: Settings, pqc_signer: MLDSASigner | None):
        self.settings = settings
        self.pqc_signer = pqc_signer

    def issue(self, tenant_id: str, jti: str, scopes: list[str]) -> tuple[str, int]:
        if self.settings.require_pqc and self.pqc_signer is None:
            raise RuntimeError("PQC signing is required but no signer is configured")
        now = int(time.time())
        expires_at = now + self.settings.tenant_token_ttl_seconds
        header: dict[str, Any] = {
            "alg": "HS256",
            "kid": self.settings.tenant_token_current_kid,
            "typ": "ASTv1",
        }
        if self.pqc_signer:
            header.update(
                {
                    "pqc_alg": self.pqc_signer.algorithm,
                    "pqc_kid": self.pqc_signer.key_id,
                }
            )
        claims = {
            "iss": self.settings.tenant_token_issuer,
            "aud": self.settings.tenant_token_audience,
            "sub": tenant_id,
            "jti": jti,
            "scope": sorted(set(scopes)),
            "iat": now,
            "nbf": now - 5,
            "exp": expires_at,
            "nonce": secrets.token_urlsafe(16),
        }
        signing_input = f"{_b64url(_canonical_json(header))}.{_b64url(_canonical_json(claims))}".encode(
            "ascii"
        )
        hmac_signature = hmac.new(
            self.settings.hmac_keys[self.settings.tenant_token_current_kid],
            signing_input,
            hashlib.sha256,
        ).digest()
        token = f"{signing_input.decode('ascii')}.{_b64url(hmac_signature)}"
        if self.pqc_signer:
            token = f"{token}.{_b64url(self.pqc_signer.sign(signing_input))}"
        return token, expires_at

    def verify(self, token: str) -> dict[str, Any]:
        if len(token) > 32_768:
            raise ValueError("token too large")
        parts = token.split(".")
        if len(parts) not in (3, 4):
            raise ValueError("invalid token format")
        try:
            header = json.loads(decode_b64url(parts[0]))
        except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid token header") from exc
        if not isinstance(header, dict):
            raise ValueError("invalid token header")
        if header.get("typ") != "ASTv1" or header.get("alg") != "HS256":
            raise ValueError("unsupported token")
        kid = header.get("kid")
        if not isinstance(kid, str):
            raise ValueError("invalid HMAC key ID")
        key = self.settings.hmac_keys.get(kid)
        if key is None:
            raise ValueError("unknown HMAC key")
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        expected = hmac.new(key, signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, decode_b64url(parts[2])):
            raise ValueError("invalid HMAC signature")
        try:
            claims = json.loads(decode_b64url(parts[1]))
        except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid token claims") from exc
        if not isinstance(claims, dict):
            raise ValueError("invalid token claims")
        now = int(time.time())
        if (
            claims.get("iss") != self.settings.tenant_token_issuer
            or claims.get("aud") != self.settings.tenant_token_audience
        ):
            raise ValueError("invalid token issuer or audience")
        if not isinstance(claims.get("exp"), int) or now >= claims["exp"]:
            raise ValueError("expired token")
        if not isinstance(claims.get("nbf"), int) or now < claims["nbf"]:
            raise ValueError("token not active")
        if not all(
            isinstance(claims.get(k), str) and claims[k] for k in ("sub", "jti")
        ):
            raise ValueError("invalid token claims")
        if self.settings.require_pqc and len(parts) != 4:
            raise ValueError("PQC signature required")
        if len(parts) == 4:
            if self.pqc_signer is None:
                raise ValueError("PQC verifier unavailable")
            if (
                header.get("pqc_alg") != self.pqc_signer.algorithm
                or header.get("pqc_kid") != self.pqc_signer.key_id
            ):
                raise ValueError("unexpected PQC key")
            if not self.pqc_signer.verify(signing_input, decode_b64url(parts[3])):
                raise ValueError("invalid PQC signature")
        return claims


def get_http(request: Request) -> httpx.AsyncClient:
    return request.app.state.http


def get_jwt_verifier(request: Request) -> SupabaseJWTVerifier:
    return request.app.state.supabase_jwt_verifier


def get_token_codec(request: Request) -> HybridTenantTokenCodec:
    return request.app.state.tenant_token_codec


async def require_authenticated_admin(
    authorization: str | None = Header(None, alias="Authorization"),
    verifier: SupabaseJWTVerifier = Depends(get_jwt_verifier),
) -> AdminIdentity:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Bearer token required")
    token = authorization[7:].strip()
    try:
        claims = await verifier.verify(token)
        user_id = uuid.UUID(claims["sub"])
    except PyJWKClientConnectionError as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "Identity verification unavailable"
        ) from exc
    except (InvalidTokenError, ValueError, KeyError) as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Invalid administrator token"
        ) from exc
    return AdminIdentity(user_id=user_id, access_token=token)


async def require_tenant_token(
    authorization: str | None = Header(None, alias="Authorization"),
    settings: Settings = Depends(get_settings),
    http: httpx.AsyncClient = Depends(get_http),
    codec: HybridTenantTokenCodec = Depends(get_token_codec),
) -> TenantIdentity:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Bearer token required")
    try:
        claims = await asyncio.to_thread(codec.verify, authorization[7:].strip())
        tenant_id = uuid.UUID(claims["sub"])
        token_id = uuid.UUID(claims["jti"])
        scopes = frozenset(claims["scope"])
        if not scopes or not scopes <= {
            "compute:submit",
            "compute:read",
            "billing:read",
        }:
            raise ValueError("invalid token scope")
        active = await SupabaseService(settings, http).rpc_service(
            "is_tenant_token_active",
            {"p_jti": str(token_id), "p_tenant_id": str(tenant_id)},
        )
    except (ValueError, KeyError, TypeError, SupabaseError) as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Invalid tenant token"
        ) from exc
    if active is not True:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Revoked or expired tenant token"
        )
    return TenantIdentity(tenant_id=tenant_id, token_id=token_id, scopes=scopes)


def _map_supabase_error(exc: SupabaseError) -> HTTPException:
    if exc.status_code in (401, 403) or exc.code == "42501":
        return HTTPException(
            status.HTTP_403_FORBIDDEN, "Administrator authorization failed"
        )
    if exc.status_code == 409 or exc.code in ("23505", "23514"):
        return HTTPException(
            status.HTTP_409_CONFLICT, "Operation conflicts with current state"
        )
    if exc.code == "P0002":
        return HTTPException(status.HTTP_404_NOT_FOUND, "Application not found")
    if exc.code == "22023":
        return HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid operation parameters"
        )
    return HTTPException(
        status.HTTP_503_SERVICE_UNAVAILABLE, "Application persistence unavailable"
    )


@router.post("/applications", status_code=status.HTTP_202_ACCEPTED)
async def submit_application(
    application: PilotApplication,
    request: Request,
    idempotency_key: str = Header(
        ..., alias="Idempotency-Key", min_length=16, max_length=128
    ),
    settings: Settings = Depends(get_settings),
    http: httpx.AsyncClient = Depends(get_http),
) -> dict[str, Any]:
    db = SupabaseService(settings, http)
    client_ip = request.client.host if request.client else "unknown"
    application_payload = application.model_dump(mode="json")
    try:
        receipt = await db.rpc_service(
            "submit_pilot_application",
            {
                "p_idempotency_key": idempotency_key,
                "p_application": application_payload,
                "p_request_sha256": hashlib.sha256(
                    _canonical_json(application_payload)
                ).hexdigest(),
                "p_source_ip_hash": hashlib.sha256(client_ip.encode()).hexdigest(),
            },
        )
    except SupabaseError as exc:
        raise _map_supabase_error(exc) from exc
    return {"status": "received", "application": receipt}


@router.post("/applications/{application_id}/approve")
async def approve_application(
    application_id: uuid.UUID,
    body: ApprovalRequest,
    admin: AdminIdentity = Depends(require_authenticated_admin),
    settings: Settings = Depends(get_settings),
    http: httpx.AsyncClient = Depends(get_http),
) -> dict[str, Any]:
    try:
        return await SupabaseService(settings, http).rpc_as_user(
            "admin_approve_pilot_application",
            {
                "p_application_id": str(application_id),
                "p_owner_user_id": str(body.owner_user_id),
                "p_review_reference": body.review_reference,
            },
            admin.access_token,
        )
    except SupabaseError as exc:
        raise _map_supabase_error(exc) from exc


@router.post("/applications/{application_id}/clear-deposit")
async def clear_manual_deposit(
    application_id: uuid.UUID,
    body: ManualDepositRequest,
    admin: AdminIdentity = Depends(require_authenticated_admin),
    settings: Settings = Depends(get_settings),
    http: httpx.AsyncClient = Depends(get_http),
) -> dict[str, Any]:
    try:
        return await SupabaseService(settings, http).rpc_as_user(
            "admin_record_manual_deposit",
            {"p_application_id": str(application_id), **body.model_dump()},
            admin.access_token,
        )
    except SupabaseError as exc:
        raise _map_supabase_error(exc) from exc


@router.post(
    "/applications/{application_id}/payment-intents",
    status_code=status.HTTP_201_CREATED,
)
async def create_payment_intent(
    application_id: uuid.UUID,
    body: PaymentIntentRequest,
    idempotency_key: str = Header(
        ..., alias="Idempotency-Key", min_length=16, max_length=128
    ),
    admin: AdminIdentity = Depends(require_authenticated_admin),
    settings: Settings = Depends(get_settings),
    http: httpx.AsyncClient = Depends(get_http),
) -> dict[str, Any]:
    request_payload = body.model_dump(mode="json")
    try:
        return await SupabaseService(settings, http).rpc_as_user(
            "admin_create_payment_intent",
            {
                "p_application_id": str(application_id),
                "p_amount_minor": body.amount_minor,
                "p_currency": body.currency,
                "p_paypal_order_id": body.paypal_order_id,
                "p_idempotency_key": idempotency_key,
                "p_request_sha256": hashlib.sha256(
                    _canonical_json(request_payload)
                ).hexdigest(),
            },
            admin.access_token,
        )
    except SupabaseError as exc:
        raise _map_supabase_error(exc) from exc


@router.post(
    "/applications/{application_id}/tokens", status_code=status.HTTP_201_CREATED
)
async def issue_tenant_token(
    application_id: uuid.UUID,
    body: TokenRequest,
    response: Response,
    admin: AdminIdentity = Depends(require_authenticated_admin),
    settings: Settings = Depends(get_settings),
    http: httpx.AsyncClient = Depends(get_http),
    codec: HybridTenantTokenCodec = Depends(get_token_codec),
) -> dict[str, Any]:
    jti = str(uuid.uuid4())
    expires_at = int(time.time()) + settings.tenant_token_ttl_seconds
    db = SupabaseService(settings, http)
    try:
        context = await db.rpc_as_user(
            "admin_create_tenant_token_grant",
            {
                "p_application_id": str(application_id),
                "p_jti": jti,
                "p_scopes": sorted(set(body.scopes)),
                "p_expires_at": expires_at,
            },
            admin.access_token,
        )
        token, actual_expiry = await asyncio.to_thread(
            codec.issue, context["tenant_id"], jti, body.scopes
        )
    except SupabaseError as exc:
        raise _map_supabase_error(exc) from exc
    except RuntimeError as exc:
        # The grant exists but no bearer token was returned. Revoke it before
        # reporting failure so an audit record remains without an active token.
        try:
            await db.rpc_as_user(
                "admin_revoke_tenant_token_grant", {"p_jti": jti}, admin.access_token
            )
        finally:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE, "Token signer unavailable"
            ) from exc

    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return {
        "tenant_id": context["tenant_id"],
        "access_token": token,
        "token_type": "Bearer",
        "expires_at": actual_expiry,
        "expires_in": settings.tenant_token_ttl_seconds,
        "pqc": codec.pqc_signer is not None,
    }
