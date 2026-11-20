"""The agent's key pair: P-256, PKCS#8 PEM in the Guard home, kid = RFC 7638 thumbprint."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from . import jose
from .config import GuardHome


@dataclass
class AgentKey:
    private_key: ec.EllipticCurvePrivateKey
    kid: str

    @property
    def public_jwk(self) -> dict[str, str]:
        return jose.public_jwk(self.private_key)

    @property
    def fingerprint(self) -> str:
        return jose.fingerprint(self.kid)

    def jwks(self) -> dict[str, Any]:
        """``{"keys": [...]}`` with the public members only."""
        return {"keys": [{**self.public_jwk, "kid": self.kid, "use": "sig", "alg": jose.ALG}]}

    def __repr__(self) -> str:  # never print key material
        return f"AgentKey(kid={self.kid!r})"


def generate(home: GuardHome) -> AgentKey:
    """Create a new key and write ``agent-key.pem`` (mode 0600)."""
    key = jose.generate_key()
    home.write_private(home.key_path, jose.private_key_pem(key))
    return AgentKey(key, jose.thumbprint(jose.public_jwk(key)))


def load(home: GuardHome) -> AgentKey:
    """Load ``agent-key.pem``; raises OSError or ValueError."""
    key = jose.load_private_key(home.key_path.read_bytes())
    return AgentKey(key, jose.thumbprint(jose.public_jwk(key)))
