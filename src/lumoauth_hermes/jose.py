"""Minimal JOSE for ES256 (P-256): keys, JWK, RFC 7638 thumbprints, compact JWS.

Built on ``cryptography`` only. The agent's private key is a PKCS#8 PEM file
(``agent-key.pem``, mode 0600); the DPoP key is generated per process and
never written anywhere.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from collections.abc import Mapping
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

ALG = "ES256"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _json_b64(value: Mapping[str, Any]) -> str:
    return b64url(json.dumps(value, separators=(",", ":")).encode("utf-8"))


def generate_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def private_key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def load_private_key(pem: bytes) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        raise ValueError("the agent key must be an EC P-256 private key")
    return key


def public_jwk(key: ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey) -> dict[str, str]:
    public = key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key
    numbers = public.public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": b64url(numbers.x.to_bytes(32, "big")),
            "y": b64url(numbers.y.to_bytes(32, "big"))}


def thumbprint(jwk: Mapping[str, str]) -> str:
    """RFC 7638 SHA-256 thumbprint of an EC public JWK."""
    canonical = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")}, sort_keys=True, separators=(",", ":"))
    return b64url(hashlib.sha256(canonical.encode("utf-8")).digest())


def fingerprint(kid: str) -> str:
    """The first 4 groups of 4 characters of the thumbprint: ``Zx3a-91Kc-p0Qe-7tLm`` (SPEC §8.1)."""
    return "-".join(kid[i:i + 4] for i in range(0, 16, 4))


def public_key_from_jwk(jwk: Mapping[str, str]) -> ec.EllipticCurvePublicKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("only EC P-256 keys are supported")
    x = int.from_bytes(b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(b64url_decode(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def sign_jws(key: ec.EllipticCurvePrivateKey, header: Mapping[str, Any], claims: Mapping[str, Any]) -> str:
    signing_input = f"{_json_b64(header)}.{_json_b64(claims)}"
    der = key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return f"{signing_input}.{b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def decode_jws(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    """``(header, claims, signing_input, signature)`` of a compact JWS. Nothing is verified."""
    head, body, sig = token.split(".")
    return (json.loads(b64url_decode(head)), json.loads(b64url_decode(body)), f"{head}.{body}".encode("ascii"),
            b64url_decode(sig))


def verify_jws(token: str, public: ec.EllipticCurvePublicKey) -> tuple[dict[str, Any], dict[str, Any]]:
    """Verify an ES256 compact JWS; returns ``(header, claims)`` or raises ``ValueError``."""
    from cryptography.exceptions import InvalidSignature

    header, claims, signing_input, signature = decode_jws(token)
    if header.get("alg") != ALG or len(signature) != 64:
        raise ValueError("not an ES256 JWS")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    try:
        public.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise ValueError("bad signature") from exc
    return header, claims


def random_id(nbytes: int = 16) -> str:
    return b64url(secrets.token_bytes(nbytes))


def access_token_hash(token: str) -> str:
    return b64url(hashlib.sha256(token.encode("ascii")).digest())
