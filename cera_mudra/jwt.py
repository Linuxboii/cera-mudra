"""Minimal JWT (JWS compact serialisation) encode / decode / HMAC verify."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from dataclasses import dataclass

HMAC_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")


class JWTError(ValueError):
    """Raised for malformed tokens or unsupported operations."""


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    text = text.strip()
    if not _B64URL.match(text) or len(text) % 4 == 1:
        raise JWTError(f"invalid base64url segment: {text[:24]!r}")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise JWTError(f"invalid base64url segment: {exc}") from None


def _json_segment(segment: str, what: str) -> dict:
    raw = b64url_decode(segment)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise JWTError(f"{what} is not valid JSON") from None
    if not isinstance(value, dict):
        raise JWTError(f"{what} must be a JSON object")
    return value


def _compact(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass
class Token:
    raw: str
    header: dict
    payload: dict
    signature: bytes
    signing_input: bytes

    @property
    def alg(self) -> str:
        return str(self.header.get("alg", ""))


def clean_token(token: str) -> str:
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    return token


def decode(token: str) -> Token:
    """Split and decode a compact JWS. Does **not** verify the signature."""
    token = clean_token(token)
    parts = token.split(".")
    if len(parts) == 5:
        raise JWTError("this is a JWE (encrypted token, 5 parts); its payload cannot be read without the key")
    if len(parts) != 3:
        raise JWTError(f"expected 3 dot-separated parts, found {len(parts)}")
    h, p, s = parts
    header = _json_segment(h, "header")
    payload = _json_segment(p, "payload")
    signature = b64url_decode(s)
    return Token(token, header, payload, signature, f"{h}.{p}".encode("ascii"))


def _hmac(alg: str, secret: bytes, data: bytes) -> bytes:
    return hmac.new(secret, data, HMAC_ALGS[alg]).digest()


def _secret_bytes(secret) -> bytes:
    return secret if isinstance(secret, bytes) else str(secret).encode("utf-8")


def sign(payload: dict, secret, alg: str = "HS256", headers: dict | None = None) -> str:
    """Create a token. ``alg`` is HS256/HS384/HS512 or ``none`` (unsigned)."""
    if alg not in HMAC_ALGS and alg.lower() != "none":
        raise JWTError(f"unsupported algorithm for signing: {alg} (use HS256, HS384, HS512 or none)")
    header = {"alg": alg, "typ": "JWT"}
    if headers:
        header.update(headers)
    signing_input = f"{b64url_encode(_compact(header))}.{b64url_encode(_compact(payload))}"
    if alg.lower() == "none":
        return signing_input + "."
    if secret is None:
        raise JWTError("a secret is required for HMAC signing")
    sig = _hmac(alg, _secret_bytes(secret), signing_input.encode("ascii"))
    return f"{signing_input}.{b64url_encode(sig)}"


def verify_decoded(token: Token, secret) -> bool:
    if token.alg not in HMAC_ALGS:
        raise JWTError(f"cannot verify alg {token.alg or '(missing)'!r}: only HS256/HS384/HS512 are supported")
    expected = _hmac(token.alg, _secret_bytes(secret), token.signing_input)
    return hmac.compare_digest(expected, token.signature)


def verify(token: str, secret) -> bool:
    """Constant-time HMAC verification of an HS256/384/512 token."""
    return verify_decoded(decode(token), secret)
