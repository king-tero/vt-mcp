"""A bounded, authenticated HTTP client for the VTAI report contract."""

import json
import math
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import anyio
import httpx

from vt_mcp import __version__
from vt_mcp.reports import (
    HASH_PATTERN,
    MAX_RESPONSE_BYTES,
    VTAIError,
    format_file_report,
    format_indicator_report,
    report_http_error,
    validate_indicator,
    validate_report_values,
)

DEFAULT_BASE_URL = "https://ai.virustotal.com/api/v3"


class ConfigurationError(ValueError):
    """A configuration error safe to display without secret values."""


@dataclass(frozen=True)
class Settings:
    token: str = field(repr=False)
    base_url: str = DEFAULT_BASE_URL
    timeout: float = 15.0

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[\x21-\x7e]{1,512}", self.token):
            raise ConfigurationError(
                "VTAI_TOKEN must contain a nonempty credential without whitespace."
            )
        try:
            url = urlsplit(self.base_url)
            port = url.port
        except ValueError:
            raise ConfigurationError("VTAI_BASE_URL is not a valid service URL.") from None
        local_http = url.scheme == "http" and url.hostname in {"127.0.0.1", "localhost", "::1"}
        if (
            not url.hostname
            or (url.scheme != "https" and not local_http)
            or url.username is not None
            or url.password is not None
            or url.query
            or url.fragment
            or (port is not None and port < 1)
            or any(c.isspace() for c in self.base_url)
        ):
            raise ConfigurationError(
                "VTAI_BASE_URL must use HTTPS, without credentials, query or fragment. "
                "HTTP is permitted only for a local test server."
            )
        if not math.isfinite(self.timeout) or not 1 <= self.timeout <= 60:
            raise ConfigurationError("VTAI_TIMEOUT must be between 1 and 60 seconds.")

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "Settings":
        values = os.environ if environ is None else environ
        token = values.get("VTAI_TOKEN")
        token_file = values.get("VTAI_TOKEN_FILE")
        if token is not None and token_file is not None:
            raise ConfigurationError("Set only one of VTAI_TOKEN and VTAI_TOKEN_FILE.")
        if token_file:
            try:
                with Path(token_file).expanduser().open(encoding="ascii") as file:
                    token = file.read(514).strip()
            except (OSError, UnicodeError):
                raise ConfigurationError("Cannot read the VTAI_TOKEN_FILE credential.") from None
        if not token:
            raise ConfigurationError(
                "Set VTAI_TOKEN or VTAI_TOKEN_FILE to an existing VTAI credential. "
                "Registration is a separate setup step."
            )
        try:
            timeout = float(values.get("VTAI_TIMEOUT", "15"))
        except ValueError:
            raise ConfigurationError("VTAI_TIMEOUT must be a number of seconds.") from None
        return cls(token, values.get("VTAI_BASE_URL", DEFAULT_BASE_URL), timeout)


class VTAIClient:
    def __init__(
        self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self.settings = settings
        self._http = httpx.AsyncClient(
            base_url=settings.base_url.rstrip("/") + "/",
            headers={
                "x-apikey": settings.token,
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "User-Agent": f"vt-mcp/{__version__}",
            },
            timeout=settings.timeout,
            follow_redirects=False,
            transport=transport,
        )

    async def __aenter__(self) -> "VTAIClient":
        await self._http.__aenter__()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self._http.__aexit__(*args)

    async def get_file_report(self, file_hash: str) -> dict[str, Any]:
        if not isinstance(file_hash, str) or not re.fullmatch(HASH_PATTERN, file_hash):
            raise VTAIError("invalid_hash", "Provide a hexadecimal MD5, SHA-1 or SHA-256 hash.")
        file_hash = file_hash.lower()
        raw = await self._request("GET", f"files/{file_hash}", "hash")
        return format_file_report(raw, file_hash, retrieved_at=datetime.now(UTC))

    async def get_url_report(self, url: str) -> dict[str, Any]:
        validate_indicator(url, "url")
        raw = await self._request("POST", "urls/lookup", "url", body={"url": url})
        return format_indicator_report(raw, "url", retrieved_at=datetime.now(UTC))

    async def get_domain_report(self, domain: str) -> dict[str, Any]:
        validate_indicator(domain, "domain")
        raw = await self._request("GET", f"domains/{quote(domain, safe='')}", "domain")
        return format_indicator_report(raw, "domain", retrieved_at=datetime.now(UTC))

    async def get_ip_report(self, ip: str) -> dict[str, Any]:
        validate_indicator(ip, "ip")
        raw = await self._request("GET", f"ip_addresses/{quote(ip, safe='')}", "ip")
        return format_indicator_report(raw, "ip", retrieved_at=datetime.now(UTC))

    async def _request(self, method: str, path: str, kind: str, *, body: dict | None = None) -> Any:
        try:
            with anyio.fail_after(self.settings.timeout):
                async with self._http.stream(method, path, json=body) as response:
                    if response.headers.get("Content-Encoding", "identity").strip().lower() not in {
                        "",
                        "identity",
                    }:
                        raise VTAIError(
                            "invalid_response", "VTAI returned an unsupported response encoding."
                        )
                    payload = bytearray()
                    async for chunk in response.aiter_bytes(chunk_size=64 * 1024):
                        payload.extend(chunk)
                        if len(payload) > MAX_RESPONSE_BYTES:
                            raise VTAIError(
                                "response_too_large",
                                "The VTAI response exceeds the supported size.",
                            )
                    if response.status_code != 200:
                        self._raise_http_error(response, payload, kind)
                    try:
                        raw = json.loads(payload)
                        validate_report_values(raw, forbidden_values=(self.settings.token,))
                        return raw["data"]
                    except (ValueError, TypeError, KeyError, RecursionError):
                        raise VTAIError(
                            "invalid_response", "VTAI returned an invalid report."
                        ) from None
        except (httpx.TimeoutException, TimeoutError):
            raise VTAIError(
                "timeout", "The VTAI request timed out. Retry later.", retryable=True
            ) from None
        except httpx.RequestError:
            raise VTAIError(
                "unavailable", "Cannot reach VTAI. Retry later.", retryable=True
            ) from None

    @staticmethod
    def _raise_http_error(response: httpx.Response, payload: bytearray, kind: str) -> None:
        status = response.status_code
        upstream_error = False
        if status in {401, 403}:
            try:
                upstream_error = isinstance(json.loads(payload).get("detail"), dict)
            except (ValueError, AttributeError, RecursionError):
                pass
        retry_after = response.headers.get("Retry-After", "")
        seconds = int(retry_after) if re.fullmatch(r"[0-9]{1,8}", retry_after) else None
        if status == 429 and seconds is None and 0 < len(retry_after) <= 64:
            try:
                if any(ord(char) < 32 or ord(char) > 126 for char in retry_after):
                    raise ValueError("Invalid retry delay")
                retry_at = parsedate_to_datetime(retry_after)
                if retry_at.utcoffset() is not None:
                    seconds = max(0, math.ceil((retry_at - datetime.now(UTC)).total_seconds()))
            except (TypeError, ValueError, OverflowError):
                pass
        raise report_http_error(
            status,
            kind,
            retry_after_seconds=seconds,
            upstream_access_denied=upstream_error,
        )
