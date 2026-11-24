"""A local LumoAuth stand-in for tests: a real HTTP server on 127.0.0.1.

It checks what the real server checks for the agent API: the client
assertion (signature, typ, iss/sub/aud, lifetime, single-use jti), DPoP
proofs (signature, htm, htu, iat, jti, ath, nonce, key binding) and the
tool-call receipt rules of AgentToolCallReporter.
"""

from __future__ import annotations

import json
import re
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from lumoauth_hermes import jose

ORG = "acme"
AGENT = "agt_0123456789abcdef"
OWNER = "0197aaaa-bbbb-7ccc-8ddd-eeeeffff0000"
_FIELDS = {"tool", "server_id", "decision", "outcome", "duration_ms", "arguments_sha256", "audit_id", "occurred_at",
           "error_code"}
_NOT_RUN = {"denied", "refused", "expired", "blocked"}
_CANONICAL = re.compile(r"^[a-z0-9_*-]+(:[a-z0-9_*-]+)*$")


@dataclass
class MockState:
    capabilities: list[str] = field(default_factory=lambda: ["files:read", "web:search", "web:fetch", "memory:write",
                                                             "messages:send", "mcp:github:read:*"])
    status: str = "active"
    me_status_code: int = 200
    token_error: str | None = None
    require_nonce: bool = False
    nonce: str = "n-1"
    token_type: str = "DPoP"
    jwks: dict[str, dict[str, str]] = field(default_factory=dict)
    agent_id: str = AGENT
    used_jti: set[str] = field(default_factory=set)
    tokens: dict[str, str] = field(default_factory=dict)  # token -> jkt
    token_requests: int = 0
    me_requests: int = 0
    receipts: list[dict[str, Any]] = field(default_factory=list)
    receipt_batches: list[int] = field(default_factory=list)
    receipt_responses: deque = field(default_factory=deque)  # status codes to answer before 200
    usage: list[int] = field(default_factory=list)
    asks: list[dict[str, Any]] = field(default_factory=list)
    ask_allowed: bool = True
    ask_status: int = 200
    approvals: list[dict[str, Any]] = field(default_factory=list)
    approval_create_status: int = 201
    #: ``delivery`` of the 201 answer; None leaves it out (an older server).
    approval_delivery: list[str] | None = field(default_factory=lambda: ["push"])
    approval_statuses: deque = field(default_factory=deque)
    approval_polls: int = 0
    enrollments: list[dict[str, Any]] = field(default_factory=list)
    enroll_polls: deque = field(default_factory=deque)  # sequence of "pending", "slow_down", "denied", "expired", "ok"
    enroll_result: dict[str, Any] = field(default_factory=dict)
    enroll_fingerprint_override: str | None = None
    last_enrolled_kid: str = ""
    errors: list[str] = field(default_factory=list)


class MockLumoAuth:
    def __init__(self) -> None:
        self.state = MockState()
        self.lock = threading.Lock()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    @property
    def issuer(self) -> str:
        return f"{self.base}/orgs/{ORG}/api/v1"

    @property
    def token_endpoint(self) -> str:
        return f"{self.issuer}/oauth/token"

    def start(self) -> "MockLumoAuth":
        self.thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def register_key(self, jwk: dict[str, str], kid: str) -> None:
        self.state.jwks[kid] = dict(jwk)

    def config(self, kid: str, **overrides: Any) -> dict[str, Any]:
        data = {"version": 1, "baseUrl": self.base, "orgId": ORG, "agentId": self.state.agent_id,
                "issuer": self.issuer, "tokenEndpoint": self.token_endpoint, "keyId": kid, "ownerUserId": OWNER,
                "canActOnBehalfOfUsers": False, "preset": "assistant", "decisionMode": "local", "approvals": "auto",
                "onUngranted": "ask", "taint": {"enabled": True, "windowSeconds": 1800, "escalate": ["external"]},
                "refreshSeconds": 60, "offlineGraceSeconds": 300, "receipts": True, "reportUsage": True,
                "rememberApprovals": True,
                "extraProtectedPaths": [], "allowPaths": []}
        data.update(overrides)
        return data

    # ── verification helpers ──────────────────────────────────────────────
    def _fail(self, message: str) -> None:
        self.state.errors.append(message)

    def check_dpop(self, proof: str | None, method: str, url: str, token: str | None) -> str | None:
        """The proof's jkt, or None (and an error recorded) when it is not acceptable."""
        if not proof:
            self._fail("missing DPoP proof")
            return None
        try:
            header, claims, _input, _sig = jose.decode_jws(proof)
            if header.get("typ") != "dpop+jwt" or header.get("alg") != "ES256" or "jwk" not in header:
                raise ValueError("bad DPoP header")
            if any(k in header["jwk"] for k in ("d", "p", "q")):
                raise ValueError("private key in DPoP header")
            jose.verify_jws(proof, jose.public_key_from_jwk(header["jwk"]))
            if claims.get("htm") != method or claims.get("htu") != url:
                raise ValueError(f"htm/htu mismatch: {claims.get('htm')} {claims.get('htu')} != {method} {url}")
            if abs(time.time() - int(claims.get("iat", 0))) > 60:
                raise ValueError("stale iat")
            jti = claims.get("jti", "")
            if len(jti) < 16 or jti in self.state.used_jti:
                raise ValueError("DPoP jti reused or short")
            self.state.used_jti.add(jti)
            if token is not None and claims.get("ath") != jose.access_token_hash(token):
                raise ValueError("ath mismatch")
            if token is None and "ath" in claims:
                raise ValueError("ath on a token request")
            return jose.thumbprint(header["jwk"])
        except Exception as exc:  # noqa: BLE001
            self._fail(f"DPoP: {exc}")
            return None

    def check_assertion(self, form: dict[str, str]) -> bool:
        try:
            if form.get("grant_type") != "client_credentials":
                raise ValueError("grant_type")
            if form.get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer":
                raise ValueError("client_assertion_type")
            if form.get("client_id") != self.state.agent_id:
                raise ValueError("client_id")
            assertion = form["client_assertion"]
            header, claims, _i, _s = jose.decode_jws(assertion)
            if header.get("typ") != "client-authentication+jwt" or header.get("alg") != "ES256":
                raise ValueError("assertion header")
            jwk = self.state.jwks.get(header.get("kid", ""))
            if jwk is None:
                raise ValueError("unknown kid")
            jose.verify_jws(assertion, jose.public_key_from_jwk(jwk))
            if claims.get("iss") != self.state.agent_id or claims.get("sub") != self.state.agent_id:
                raise ValueError("iss/sub")
            if claims.get("aud") != self.issuer:
                raise ValueError(f"aud {claims.get('aud')!r}")
            if not 0 < int(claims["exp"]) - int(claims["iat"]) <= 60 or int(claims["exp"]) < time.time():
                raise ValueError("lifetime")
            if claims.get("jti") in self.state.used_jti or len(claims.get("jti", "")) < 16:
                raise ValueError("assertion jti reused")
            self.state.used_jti.add(claims["jti"])
            return True
        except Exception as exc:  # noqa: BLE001
            self._fail(f"assertion: {exc}")
            return False

    def check_receipts(self, body: Any) -> str | None:
        calls = body.get("calls") if isinstance(body, dict) else None
        if not isinstance(calls, list) or not calls:
            return "calls must be a non-empty list of tool calls."
        if len(calls) > 50:
            return "Report at most 50 calls at a time."
        for index, call in enumerate(calls):
            unknown = set(call) - _FIELDS
            if unknown:
                return f"calls[{index}]: unknown field {', '.join(sorted(unknown))}."
            if not isinstance(call.get("tool"), str) or not call["tool"]:
                return f"calls[{index}].tool is required"
            if call.get("decision") not in ("allowed", "approved", "denied", "refused", "expired", "blocked"):
                return f"calls[{index}].decision"
            if "outcome" in call and (call["outcome"] not in ("succeeded", "failed", "not_run") or (
                    call["outcome"] != "not_run" and call["decision"] in _NOT_RUN)):
                return f"calls[{index}].outcome"
            if "arguments_sha256" in call and not re.fullmatch(r"[0-9a-f]{64}", call["arguments_sha256"]):
                return f"calls[{index}].arguments_sha256"
            if "server_id" in call and not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", call["server_id"]):
                return f"calls[{index}].server_id"
            if "error_code" in call and not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", call["error_code"]):
                return f"calls[{index}].error_code"
            if "occurred_at" in call and not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{3})?Z",
                                                          call["occurred_at"]):
                return f"calls[{index}].occurred_at"
        return None

    def _handler(self):
        mock = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:  # quiet
                pass

            def _body(self) -> bytes:
                length = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(length) if length else b""

            def _send(self, status: int, body: Any = None, headers: dict[str, str] | None = None) -> None:
                data = json.dumps(body if body is not None else {}).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def _url(self) -> str:
                return mock.base + urlsplit(self.path).path

            def _auth(self, method: str) -> bool:
                auth = self.headers.get("Authorization", "")
                scheme, _, token = auth.partition(" ")
                jkt = mock.state.tokens.get(token)
                if jkt is None:
                    self._send(401, {"error": "invalid_token"})
                    return False
                if mock.state.token_type == "DPoP":
                    if scheme != "DPoP":
                        mock._fail("resource request without the DPoP scheme")
                        self._send(401, {"error": "invalid_token"})
                        return False
                    proof_jkt = mock.check_dpop(self.headers.get("DPoP"), method, self._url(), token)
                    if proof_jkt != jkt:
                        mock._fail("DPoP key does not match the token binding")
                        self._send(401, {"error": "invalid_dpop_proof"})
                        return False
                return True

            def do_POST(self) -> None:  # noqa: N802
                path = urlsplit(self.path).path
                raw = self._body()
                with mock.lock:
                    self._post(path, raw)

            def do_GET(self) -> None:  # noqa: N802
                path = urlsplit(self.path).path
                with mock.lock:
                    self._get(path)

            def _post(self, path: str, raw: bytes) -> None:
                st = mock.state
                prefix = f"/orgs/{ORG}/api/v1"
                if path == f"{prefix}/oauth/token":
                    st.token_requests += 1
                    form = {k: v[0] for k, v in parse_qs(raw.decode()).items()}
                    proof = self.headers.get("DPoP")
                    if st.require_nonce:
                        _h, claims, _i, _s = jose.decode_jws(proof) if proof else ({}, {}, b"", b"")
                        if claims.get("nonce") != st.nonce:
                            self._send(400, {"error": "use_dpop_nonce"}, {"DPoP-Nonce": st.nonce})
                            return
                    jkt = mock.check_dpop(proof, "POST", self._url(), None)
                    if st.token_error:
                        self._send(401 if st.token_error == "invalid_client" else 400, {"error": st.token_error})
                        return
                    if jkt is None or not mock.check_assertion(form):
                        self._send(401, {"error": "invalid_client"})
                        return
                    token = secrets.token_urlsafe(24)
                    st.tokens[token] = jkt
                    self._send(200, {"access_token": token, "token_type": st.token_type, "expires_in": 300})
                    return
                if path == f"{prefix}/agents/enrollments":
                    body = json.loads(raw or b"{}")
                    st.enrollments.append(body)
                    problem = self._check_enrollment(body)
                    if problem:
                        self._send(400, {"error": "invalid_request", "error_description": problem})
                        return
                    jwk = body["jwks"]["keys"][0]
                    st.last_enrolled_kid = jwk["kid"]
                    mock.register_key({k: jwk[k] for k in ("kty", "crv", "x", "y")}, jwk["kid"])
                    fingerprint = st.enroll_fingerprint_override or jose.fingerprint(jose.thumbprint(jwk))
                    self._send(201, {"enrollment_code": "E" * 43, "user_code": "BCDF-GHJK",
                                     "verification_uri": f"{mock.base}/orgs/{ORG}/portal/agents/enroll",
                                     "verification_uri_complete":
                                         f"{mock.base}/orgs/{ORG}/portal/agents/enroll?code=BCDF-GHJK",
                                     "key_fingerprint": fingerprint, "expires_in": 900, "interval": 5})
                    return
                if path == f"{prefix}/agents/enrollments/token":
                    step = st.enroll_polls.popleft() if st.enroll_polls else "ok"
                    errors = {"pending": "authorization_pending", "slow_down": "slow_down",
                              "denied": "access_denied", "expired": "expired_token"}
                    if step in errors:
                        self._send(400, {"error": errors[step]})
                        return
                    result = {"agent_id": st.agent_id, "client_id": st.agent_id, "issuer": mock.issuer,
                              "key_id": st.last_enrolled_kid,
                              "token_endpoint": mock.token_endpoint, "capabilities": list(st.capabilities),
                              "can_act_on_behalf_of_users": True, "owner_user_id": OWNER,
                              "agent_url": f"{mock.base}/orgs/{ORG}/portal/agents/{st.agent_id}"}
                    result.update(st.enroll_result)
                    self._send(200, result)
                    return
                if not self._auth("POST"):
                    return
                body = json.loads(raw or b"{}")
                if path == f"{prefix}/agents/me/tool-calls":
                    if st.receipt_responses:
                        status = st.receipt_responses.popleft()
                        self._send(status, {"error": "rate_limited" if status == 429 else "server_error"},
                                   {"Retry-After": "1"} if status == 429 else None)
                        return
                    problem = mock.check_receipts(body)
                    if problem:
                        self._send(400, {"error": "invalid_request", "error_description": problem})
                        return
                    st.receipts.extend(body["calls"])
                    st.receipt_batches.append(len(body["calls"]))
                    self._send(200, {"recorded": len(body["calls"])})
                    return
                if path == f"{prefix}/agents/me/usage":
                    st.usage.append(body.get("tokens"))
                    self._send(200, {"recorded": body, "budget": {}})
                    return
                if path == f"{prefix}/agents/ask":
                    st.asks.append(body)
                    if st.ask_status != 200:
                        self._send(st.ask_status, {"error": "plan_limit_reached"})
                        return
                    self._send(200, {"allowed": st.ask_allowed, "action": body.get("action"),
                                     "audit_id": "0123456789abcdef", "decided_by": "capability"})
                    return
                if path == f"{prefix}/agents/me/approvals":
                    st.approvals.append(body)
                    code = st.approval_create_status
                    ttl = body.get("expires_in", 120)
                    if not isinstance(ttl, int) or not 60 <= ttl <= 600:
                        self._send(400, {"error": "invalid_request", "error_description": "expires_in"})
                        return
                    if code == 201:
                        expires = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(time.time() + ttl))
                        answer = {"approval_token": "apr_" + secrets.token_hex(8), "status": "pending",
                                  "expires_at": expires, "task_id": body.get("task_id"), "impact": body.get("impact")}
                        if st.approval_delivery is not None:
                            answer["delivery"] = st.approval_delivery
                        self._send(201, answer)
                    elif code == 202:
                        self._send(202, {"status": "email_fallback_sent"})
                    elif code == 403:
                        self._send(403, {"error": "delegation_not_permitted"})
                    else:
                        self._send(code, {"error": "no_enrolled_device"})
                    return
                self._send(404, {"error": "not_found"})

            def _check_enrollment(self, body: dict[str, Any]) -> str | None:
                if not isinstance(body.get("name"), str) or not 0 < len(body["name"]) <= 100:
                    return "name"
                if body.get("host") not in ("openclaw", "hermes", "other"):
                    return "host"
                keys = (body.get("jwks") or {}).get("keys")
                if not isinstance(keys, list) or not 1 <= len(keys) <= 2:
                    return "jwks"
                for key in keys:
                    if any(m in key for m in ("d", "p", "q", "dp", "dq", "qi", "k")):
                        return "jwks: private members"
                caps = body.get("capabilities")
                if not isinstance(caps, list) or not 1 <= len(caps) <= 200:
                    return "capabilities"
                for cap in caps:
                    if not _CANONICAL.match(cap.get("scope", "")) or cap.get("risk") not in (
                            "read", "write", "execute", "external", "destructive", "admin"):
                        return f"capabilities: {cap.get('scope')}"
                    if not isinstance(cap.get("checked"), bool) or len(cap.get("label", "")) > 120:
                        return "capabilities: label/checked"
                if not isinstance(body.get("delegation"), bool):
                    return "delegation"
                return None

            def _get(self, path: str) -> None:
                st = mock.state
                prefix = f"/orgs/{ORG}/api/v1"
                if not self._auth("GET"):
                    return
                if path == f"{prefix}/agents/me":
                    st.me_requests += 1
                    if st.me_status_code != 200:
                        self._send(st.me_status_code, {"error": "forbidden"})
                        return
                    self._send(200, {"identity": {"id": st.agent_id, "type": "agent", "agent_id": st.agent_id,
                                                  "status": st.status},
                                     "capabilities": list(st.capabilities), "scope": list(st.capabilities)})
                    return
                match = re.fullmatch(rf"{prefix}/agents/me/approvals/([^/]+)/status", path)
                if match:
                    st.approval_polls += 1
                    status = st.approval_statuses.popleft() if st.approval_statuses else "pending"
                    self._send(200, {"approval_token": match.group(1), "status": status})
                    return
                self._send(404, {"error": "not_found"})

        return Handler
