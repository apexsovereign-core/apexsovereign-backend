from __future__ import annotations

import base64
import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def decode_b64url(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:  # pragma: no cover - defensive boundary
        raise ValueError("invalid base64url value") from exc


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", extra="ignore", case_sensitive=False
    )

    app_env: str = "production"

    supabase_url: str
    supabase_publishable_key: SecretStr
    supabase_service_role_key: SecretStr
    supabase_jwt_issuer: str | None = None
    supabase_jwt_audience: str = "authenticated"

    paypal_base_url: str = "https://api-m.paypal.com"
    paypal_client_id: SecretStr = SecretStr("")
    paypal_client_secret: SecretStr = SecretStr("")
    paypal_webhook_id: str = "PENDING_MANUAL_CONFIGURATION"
    paypal_merchant_id: str = "PENDING_MANUAL_CONFIGURATION"
    paypal_timeout_seconds: float = Field(default=10.0, ge=1.0, le=30.0)
    max_webhook_bytes: int = Field(default=1_048_576, ge=1_024, le=10_485_760)

    tenant_token_issuer: str = "https://api.apexsovereign.ai"
    tenant_token_audience: str = "apexsovereign-api"
    tenant_token_hmac_keys_json: SecretStr
    tenant_token_current_kid: str
    tenant_token_ttl_seconds: int = Field(default=900, ge=60, le=3600)

    require_pqc: bool = False
    pqc_algorithm: str = "ML-DSA-65"
    pqc_key_id: str | None = None
    pqc_private_key_file: Path | None = None
    pqc_public_key_file: Path | None = None

    @field_validator("supabase_url", "paypal_base_url", "tenant_token_issuer")
    @classmethod
    def normalize_url(cls, value: str) -> str:
        return value.rstrip("/")

    @field_validator("paypal_base_url")
    @classmethod
    def known_paypal_origin(cls, value: str) -> str:
        allowed = {"https://api-m.paypal.com", "https://api-m.sandbox.paypal.com"}
        if value not in allowed:
            raise ValueError(f"PAYPAL_BASE_URL must be one of {sorted(allowed)}")
        return value

    @model_validator(mode="after")
    def validate_security_configuration(self) -> Settings:
        keys = self.hmac_keys
        if self.tenant_token_current_kid not in keys:
            raise ValueError(
                "TENANT_TOKEN_CURRENT_KID is absent from TENANT_TOKEN_HMAC_KEYS_JSON"
            )
        if self.supabase_jwt_issuer is None:
            self.supabase_jwt_issuer = f"{self.supabase_url}/auth/v1"
        pqc_fields = (
            self.pqc_key_id,
            self.pqc_private_key_file,
            self.pqc_public_key_file,
        )
        if self.require_pqc and not all(pqc_fields):
            raise ValueError(
                "PQC is required but PQC_KEY_ID/private/public key files are not all configured"
            )
        return self

    @property
    def hmac_keys(self) -> dict[str, bytes]:
        try:
            raw: Any = json.loads(self.tenant_token_hmac_keys_json.get_secret_value())
        except json.JSONDecodeError as exc:
            raise ValueError("TENANT_TOKEN_HMAC_KEYS_JSON must be valid JSON") from exc
        if not isinstance(raw, dict) or not raw:
            raise ValueError("TENANT_TOKEN_HMAC_KEYS_JSON must be a non-empty object")
        decoded: dict[str, bytes] = {}
        for kid, encoded in raw.items():
            if not isinstance(kid, str) or not kid or not isinstance(encoded, str):
                raise ValueError("invalid HMAC keyring entry")
            key = decode_b64url(encoded)
            if len(key) < 32:
                raise ValueError(f"HMAC key {kid!r} must decode to at least 32 bytes")
            decoded[kid] = key
        return decoded

    @property
    def paypal_webhook_configured(self) -> bool:
        pending = "PENDING_MANUAL_CONFIGURATION"
        return self.paypal_webhook_id != pending and self.paypal_merchant_id != pending


@lru_cache
def get_settings() -> Settings:
    return Settings()
