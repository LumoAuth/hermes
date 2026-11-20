"""LumoAuth agent API client (SPEC §7, §8.2).

Identity: ``private_key_jwt`` client assertions (RFC 7523) signed with the
agent key, and DPoP (RFC 9449) with a short-lived key that exists only in this
process. Never logs or returns the key, tokens or proofs.
"""

from __future__ import annotations

import os
import ssl
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from . import jose
from ._version import __version__
from .config import GuardConfig
from .keys import AgentKey

USER_AGENT = f"lumoauth-hermes/{__version__}"
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
DEFAULT_TIMEOUT = 10.0


class LumoAuthError(Exception):
    """A request to LumoAuth failed. The message never holds secrets."""

    def __init__(self, message: str, *, status: int | None = None, error: str | None = None,
                 description: str | None = None, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.error = error
        self.description = description
        self.retry_after = retry_after

    @property
    def retryable(self) -> bool:
        return self.status is None or self.status == 429 or self.status >= 500


class NetworkError(LumoAuthError):
    """LumoAuth could not be reached (DNS, TLS, timeout, connection)."""


class AuthError(LumoAuthError):
    """LumoAuth refused the agent's identity (invalid_client, 401, 403 on /me)."""


class ApiError(LumoAuthError):
    """LumoAuth answered with an error status."""


def ssl_context() -> ssl.SSLContext:
    """The system's trust store (plus ``SSL_CERT_FILE``); never an unverified context."""
    try:
        import truststore  # type: ignore[import-not-found]

        context: ssl.SSLContext = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    except Exception:
        context = ssl.create_default_context()
        if not context.cert_store_stats().get("x509_ca"):
            try:
                import certifi  # type: ignore[import-not-found]

                context.load_verify_locations(certifi.where())
            except Exception:  # noqa: S110 (no certifi: system store only)
                pass
    cafile = os.environ.get("SSL_CERT_FILE", "").strip()
    if cafile and os.path.isfile(cafile):
        context.load_verify_locations(cafile)
    return context


def _http_client(transport: httpx.BaseTransport | None = None, timeout: float = DEFAULT_TIMEOUT) -> httpx.Client:
    kwargs: dict[str, Any] = {"timeout": timeout, "follow_redirects": False,
                              "headers": {"User-Agent": USER_AGENT, "Accept": "application/json"}}
    if transport is not None:
        kwargs["transport"] = transport
    else:
        kwargs["verify"] = ssl_context()
    return httpx.Client(**kwargs)


def _json(response: httpx.Response) -> dict[str, Any]:
    try:
        value = response.json()
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def _retry_after(response: httpx.Response) -> float | None:
    raw = response.headers.get("Retry-After")
    if not raw:
        return None
    try:
        return max(0.0, min(float(raw), 3600.0))
    except ValueError:
        return None


def _error(response: httpx.Response, what: str) -> LumoAuthError:
    body = _json(response)
    error = body.get("error") if isinstance(body.get("error"), str) else None
    description = body.get("error_description") if isinstance(body.get("error_description"), str) else None
    text = f"{what}: HTTP {response.status_code}" + (f" {error}" if error else "")
    return ApiError(text, status=response.status_code, error=error, description=description,
                    retry_after=_retry_after(response))


def _send(client: httpx.Client, method: str, url: str, **kwargs: Any) -> httpx.Response:
    try:
        return client.request(method, url, **kwargs)
    except httpx.TimeoutException as exc:
        raise NetworkError(f"LumoAuth did not answer in time ({urlsplit(url).netloc})") from exc
    except httpx.HTTPError as exc:
        raise NetworkError(f"cannot reach LumoAuth at {urlsplit(url).netloc}: {type(exc).__name__}") from exc


def htu(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}{parts.path or '/'}"


class DpopSigner:
    """DPoP proofs with a key that lives only in this process (SPEC §7.1)."""

    def __init__(self) -> None:
        self._key = jose.generate_key()
        self._jwk = jose.public_jwk(self._key)
        self._nonces: dict[str, str] = {}
        self._lock = threading.Lock()

    @property
    def thumbprint(self) -> str:
        return jose.thumbprint(self._jwk)

    def observe(self, url: str, headers: Mapping[str, str]) -> str | None:
        nonce = headers.get("DPoP-Nonce")
        if nonce:
            parts = urlsplit(url)
            with self._lock:
                self._nonces[f"{parts.scheme}://{parts.netloc}".lower()] = nonce
        return nonce

    def proof(self, method: str, url: str, access_token: str | None = None) -> str:
        parts = urlsplit(url)
        with self._lock:
            nonce = self._nonces.get(f"{parts.scheme}://{parts.netloc}".lower())
        claims: dict[str, Any] = {"jti": jose.random_id(24), "htm": method.upper(), "htu": htu(url),
                                  "iat": int(time.time())}
        if access_token:
            claims["ath"] = jose.access_token_hash(access_token)
        if nonce:
            claims["nonce"] = nonce
        return jose.sign_jws(self._key, {"typ": "dpop+jwt", "alg": jose.ALG, "jwk": self._jwk}, claims)


def _wants_nonce(response: httpx.Response) -> bool:
    if not response.headers.get("DPoP-Nonce"):
        return False
    if response.status_code == 400:
        return _json(response).get("error") == "use_dpop_nonce"
    if response.status_code == 401:
        return "use_dpop_nonce" in response.headers.get("WWW-Authenticate", "")
    return False


@dataclass
class _Token:
    value: str
    scheme: str  # "DPoP" or "Bearer"
    refresh_at: float


class AgentClient:
    """Calls the LumoAuth agent API as the enrolled agent."""

    def __init__(self, config: GuardConfig, key: AgentKey, *, transport: httpx.BaseTransport | None = None,
                 timeout: float = DEFAULT_TIMEOUT) -> None:
        self.config = config
        self.key = key
        self.timeout = timeout
        self._http = _http_client(transport, timeout)
        self._dpop = DpopSigner()
        self._token: _Token | None = None
        self._token_lock = threading.Lock()
        self.sender_constrained = True

    def close(self) -> None:
        self._http.close()

    # -- URLs -----------------------------------------------------------------
    def api_url(self, path: str) -> str:
        return f"{self.config.base_url}/orgs/{quote(self.config.org_id, safe='')}/api/v1{path}"

    # -- Token ----------------------------------------------------------------
    def _assertion(self) -> str:
        now = int(time.time())
        header = {"alg": jose.ALG, "typ": "client-authentication+jwt", "kid": self.config.key_id}
        claims = {"iss": self.config.agent_id, "sub": self.config.agent_id, "aud": self.config.issuer,
                  "iat": now, "exp": now + 60, "jti": jose.random_id(16)}
        return jose.sign_jws(self.key.private_key, header, claims)

    def invalidate_token(self) -> None:
        with self._token_lock:
            self._token = None

    def token(self, timeout: float | None = None) -> _Token:
        """A valid access token; one token request at a time (SPEC §7.1)."""
        current = self._token
        if current is not None and time.monotonic() < current.refresh_at:
            return current
        wait = timeout if timeout is not None else self.timeout
        if not self._token_lock.acquire(timeout=max(wait, 0.1)):
            raise NetworkError("another token request is still running")
        try:
            current = self._token
            if current is not None and time.monotonic() < current.refresh_at:
                return current
            self._token = self._fetch_token(wait)
            return self._token
        finally:
            self._token_lock.release()

    def _fetch_token(self, timeout: float) -> _Token:
        url = self.config.token_endpoint
        response: httpx.Response | None = None
        for attempt in range(2):
            form = {"grant_type": "client_credentials", "client_id": self.config.agent_id,
                    "client_assertion_type": ASSERTION_TYPE, "client_assertion": self._assertion()}
            headers = {"DPoP": self._dpop.proof("POST", url)}
            response = _send(self._http, "POST", url, data=form, headers=headers, timeout=timeout)
            self._dpop.observe(url, response.headers)
            if attempt == 0 and _wants_nonce(response):
                continue
            break
        assert response is not None
        body = _json(response)
        if response.status_code == 200 and isinstance(body.get("access_token"), str):
            scheme = "DPoP" if str(body.get("token_type", "")).lower() == "dpop" else "Bearer"
            self.sender_constrained = scheme == "DPoP"
            try:
                expires_in = float(body.get("expires_in", 300))
            except (TypeError, ValueError):
                expires_in = 300.0
            lead = 60.0 if expires_in > 120 else expires_in / 2
            return _Token(body["access_token"], scheme, time.monotonic() + max(expires_in - lead, 1.0))
        error = body.get("error") if isinstance(body.get("error"), str) else None
        if response.status_code == 401 or error in ("invalid_client", "unauthorized_client", "invalid_grant"):
            raise AuthError(f"LumoAuth refused the agent's credentials ({error or response.status_code})",
                            status=response.status_code, error=error)
        raise _error(response, "token request failed")

    # -- Resource requests ------------------------------------------------------
    def request(self, method: str, path: str, *, json_body: Any = None,
                timeout: float | None = None) -> httpx.Response:
        """An authenticated request; retries once for a DPoP nonce and once with a new token."""
        url = self.api_url(path)
        wait = timeout if timeout is not None else self.timeout
        token = self.token(wait)
        renewed = False
        nonce_retried = False
        while True:
            if token.scheme == "DPoP":
                headers = {"Authorization": f"DPoP {token.value}",
                           "DPoP": self._dpop.proof(method, url, access_token=token.value)}
            else:
                headers = {"Authorization": f"Bearer {token.value}"}
            kwargs: dict[str, Any] = {"headers": headers, "timeout": wait}
            if json_body is not None:
                kwargs["json"] = json_body
            response = _send(self._http, method, url, **kwargs)
            self._dpop.observe(url, response.headers)
            if response.status_code == 401:
                if not nonce_retried and _wants_nonce(response):
                    nonce_retried = True
                    continue
                if not renewed:
                    renewed = True
                    self.invalidate_token()
                    token = self.token(wait)
                    continue
            return response

    def me(self, timeout: float | None = None) -> dict[str, Any]:
        response = self.request("GET", "/agents/me", timeout=timeout)
        if response.status_code in (401, 403):
            raise AuthError(f"LumoAuth refused the agent ({response.status_code})", status=response.status_code,
                            error=_json(response).get("error"))
        if response.status_code != 200:
            raise _error(response, "agent lookup failed")
        return _json(response)

    def ask(self, capability: str, context: Mapping[str, Any], timeout: float | None = None) -> dict[str, Any]:
        body = {"action": capability, "context": dict(context), "audit": "always"}
        response = self.request("POST", "/agents/ask", json_body=body, timeout=timeout)
        if response.status_code != 200:
            raise _error(response, "Ask API call failed")
        return _json(response)

    def report_tool_calls(self, calls: list[dict[str, Any]], timeout: float | None = None) -> httpx.Response:
        return self.request("POST", "/agents/me/tool-calls", json_body={"calls": calls}, timeout=timeout)

    def report_usage(self, tokens: int, timeout: float | None = None) -> httpx.Response:
        return self.request("POST", "/agents/me/usage", json_body={"tokens": int(tokens)}, timeout=timeout)

    def request_approval(self, body: Mapping[str, Any], timeout: float | None = None) -> httpx.Response:
        return self.request("POST", "/agents/me/approvals", json_body=dict(body), timeout=timeout)

    def approval_status(self, approval_token: str, timeout: float | None = None) -> httpx.Response:
        return self.request("GET", f"/agents/me/approvals/{quote(approval_token, safe='')}/status", timeout=timeout)


# -- Enrollment (SPEC §8.2): no credential -------------------------------------

def enrollment_url(base_url: str, org_id: str, suffix: str = "") -> str:
    return f"{base_url.rstrip('/')}/orgs/{quote(org_id, safe='')}/api/v1/agents/enrollments{suffix}"


def start_enrollment(base_url: str, org_id: str, body: Mapping[str, Any], *,
                     transport: httpx.BaseTransport | None = None, timeout: float = 20.0) -> dict[str, Any]:
    with _http_client(transport, timeout) as http:
        response = _send(http, "POST", enrollment_url(base_url, org_id), json=dict(body))
    if response.status_code == 201:
        return _json(response)
    if response.status_code == 404:
        raise ApiError(f"LumoAuth does not know the organization {org_id!r}", status=404, error="not_found")
    raise _error(response, "enrollment could not start")


def poll_enrollment(base_url: str, org_id: str, enrollment_code: str, *,
                    transport: httpx.BaseTransport | None = None,
                    timeout: float = 20.0) -> tuple[int, dict[str, Any]]:
    """``(status, body)``: 200 with the result, or 400 with ``error`` while it is not done."""
    with _http_client(transport, timeout) as http:
        response = _send(http, "POST", enrollment_url(base_url, org_id, "/token"),
                         json={"enrollment_code": enrollment_code})
    return response.status_code, _json(response)
