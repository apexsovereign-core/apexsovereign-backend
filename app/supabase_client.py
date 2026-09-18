from __future__ import annotations

from typing import Any

import httpx

from .config import Settings


class SupabaseError(RuntimeError):
    def __init__(
        self,
        operation: str,
        status_code: int,
        request_id: str | None = None,
        code: str | None = None,
    ):
        super().__init__(
            f"Supabase {operation} failed with HTTP {status_code}; request_id={request_id or '-'}"
        )
        self.status_code = status_code
        self.request_id = request_id
        self.code = code


class SupabaseService:
    """Supabase Data API client with explicit privilege selection."""

    def __init__(self, settings: Settings, http: httpx.AsyncClient):
        self.settings = settings
        self.http = http
        self.base = f"{settings.supabase_url}/rest/v1"

    def _service_headers(self) -> dict[str, str]:
        key = self.settings.supabase_service_role_key.get_secret_value()
        return {
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _user_headers(self, user_token: str) -> dict[str, str]:
        if not user_token or not user_token.strip():
            raise ValueError("non-empty authenticated user token required")
        return {
            "apikey": self.settings.supabase_publishable_key.get_secret_value(),
            "Authorization": f"Bearer {user_token.strip()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def _rpc(
        self, function: str, arguments: dict[str, Any], headers: dict[str, str]
    ) -> Any:
        response = await self.http.post(
            f"{self.base}/rpc/{function}", headers=headers, json=arguments
        )
        if response.status_code >= 400:
            try:
                code = response.json().get("code")
            except (ValueError, AttributeError):
                code = None
            raise SupabaseError(
                function,
                response.status_code,
                response.headers.get("x-request-id"),
                code,
            )
        return response.json() if response.content else None

    async def rpc_service(self, function: str, arguments: dict[str, Any]) -> Any:
        return await self._rpc(function, arguments, self._service_headers())

    async def rpc_as_user(
        self, function: str, arguments: dict[str, Any], user_token: str
    ) -> Any:
        return await self._rpc(function, arguments, self._user_headers(user_token))
