"""Security review of a decoded JWT."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Iterable

from .jwt import HMAC_ALGS, Token, verify_decoded
from .timeutil import format_utc, humanize_seconds
from .wordlist import WEAK_SECRETS

SEVERITIES = ("info", "low", "medium", "high", "critical")
DEFAULT_MAX_LIFETIME = 24 * 3600
TIME_CLAIMS = ("exp", "nbf", "iat", "auth_time")
SENSITIVE_CLAIM = re.compile(r"(?i)(passw|pwd|secret|ssn|social.?security|credit.?card|card.?number|cvv|private.?key|api.?key)")
KID_SUSPICIOUS = [
    (re.compile(r"\.\./|\.\.\\|^/|^[A-Za-z]:\\"), "path traversal / absolute path"),
    (re.compile(r"['\"]|--|;|/\*|\bunion\b|\bselect\b|\bor\b\s+\S+\s*=", re.IGNORECASE), "SQL metacharacters"),
    (re.compile(r"[|`$&<>]|\$\("), "shell metacharacters"),
    (re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE), "URL"),
    (re.compile(r"[\x00-\x1f]"), "control characters"),
]


@dataclass
class Finding:
    severity: str
    code: str
    message: str

    def to_dict(self) -> dict:
        return {"severity": self.severity, "code": self.code, "message": self.message}


def crack(token: Token, words: Iterable[str] | None = None) -> str | None:
    """Try each candidate as the HMAC secret. Returns the secret or ``None``."""
    if token.alg not in HMAC_ALGS:
        return None
    for word in (WEAK_SECRETS if words is None else words):
        if verify_decoded(token, word):
            return word
    return None


def _num(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    return None


def analyze(token: Token, now: float | None = None, max_lifetime: int = DEFAULT_MAX_LIFETIME,
            words: Iterable[str] | None = None, cracked: str | None = None,
            skip_crack: bool = False) -> list[Finding]:
    now = time.time() if now is None else now
    h, p = token.header, token.payload
    out: list[Finding] = []
    alg = token.alg

    # --- algorithm -------------------------------------------------------
    if "alg" not in h:
        out.append(Finding("high", "missing-alg", "Header has no 'alg'; libraries may fall back to unsafe defaults."))
    elif alg.lower() == "none":
        out.append(Finding("critical", "alg-none",
                           f"alg is '{alg}': the token is unsigned. Any server accepting it lets anyone forge claims."))
        if token.signature:
            out.append(Finding("medium", "none-with-signature",
                               "alg 'none' but a signature is present - a classic bypass probe."))
    elif alg in HMAC_ALGS:
        secret = cracked
        if secret is None and not skip_crack:
            secret = crack(token, words)
        if secret is not None:
            shown = repr(secret)
            out.append(Finding("critical", "weak-secret",
                               f"Signed with a guessable secret {shown}: anyone can mint valid tokens. Rotate it and "
                               f"use >= 32 random bytes."))
    elif alg.startswith(("RS", "PS", "ES", "Ed")) or alg == "EdDSA":
        out.append(Finding("info", "asymmetric",
                           f"{alg} is asymmetric. Make sure the verifier pins the algorithm so an attacker cannot "
                           f"switch to HS256 and sign with your public key (algorithm confusion)."))
    else:
        out.append(Finding("medium", "unknown-alg", f"Unrecognised alg '{alg}'."))

    # --- header parameters ----------------------------------------------
    kid = h.get("kid")
    if kid is not None:
        reasons = [label for rx, label in KID_SUSPICIOUS if rx.search(str(kid))]
        if reasons:
            out.append(Finding("high", "kid-injection",
                               f"kid {str(kid)!r} contains {', '.join(reasons)}; if the server uses kid in a file "
                               f"path, SQL query or command, this is an injection vector."))
    if "jku" in h:
        out.append(Finding("high", "jku-header",
                           f"jku points to {h['jku']!r}: the verifier must only fetch keys from an allow-listed URL."))
    if "x5u" in h:
        out.append(Finding("high", "x5u-header",
                           f"x5u points to {h['x5u']!r}: the verifier must only trust allow-listed certificate URLs."))
    if "jwk" in h:
        out.append(Finding("high", "embedded-jwk",
                           "Header embeds its own key (jwk). Servers that trust it accept self-signed forgeries "
                           "(CVE-2018-0114 pattern)."))
    if "crit" in h:
        out.append(Finding("low", "crit-header", f"crit lists {h['crit']!r}; verifiers must reject unknown critical extensions."))
    if h.get("zip"):
        out.append(Finding("low", "compressed", "zip header present (compression is a JWE feature; unusual in a JWS)."))

    # --- time claims ------------------------------------------------------
    exp, nbf, iat = _num(p.get("exp")), _num(p.get("nbf")), _num(p.get("iat"))
    for claim in TIME_CLAIMS:
        if claim in p and _num(p[claim]) is None:
            out.append(Finding("medium", "bad-time-claim", f"{claim} is {p[claim]!r}, not a NumericDate (seconds since epoch)."))
    if "exp" not in p:
        out.append(Finding("high", "missing-exp", "No exp claim: the token never expires. Stolen tokens stay valid forever."))
    elif exp is not None:
        if exp < now:
            out.append(Finding("info", "expired", f"Expired {humanize_seconds(now - exp)} ago ({format_utc(exp)})."))
        start = iat if iat is not None else nbf
        if start is not None:
            life = exp - start
            if life < 0:
                out.append(Finding("medium", "negative-lifetime", "exp is earlier than iat/nbf."))
            elif life > max_lifetime:
                out.append(Finding("medium", "long-lifetime",
                                   f"Lifetime is {humanize_seconds(life)} (limit {humanize_seconds(max_lifetime)}). "
                                   f"Prefer short-lived access tokens plus refresh tokens."))
        elif exp - now > max_lifetime:
            out.append(Finding("low", "long-remaining", f"Still valid for {humanize_seconds(exp - now)}."))
    if nbf is not None and nbf > now:
        out.append(Finding("info", "not-yet-valid", f"Not valid for another {humanize_seconds(nbf - now)} (nbf)."))
    if iat is not None and iat > now + 60:
        out.append(Finding("medium", "future-iat", f"iat is {humanize_seconds(iat - now)} in the future; check clocks or forgery."))
    if "iat" not in p:
        out.append(Finding("low", "missing-iat", "No iat claim; token age cannot be checked."))

    # --- payload contents -------------------------------------------------
    for key in ("iss", "aud"):
        if key not in p:
            out.append(Finding("low", f"missing-{key}", f"No {key} claim; verifiers cannot check who the token is "
                                                        f"{'from' if key == 'iss' else 'for'}."))
    sensitive = sorted(k for k in p if SENSITIVE_CLAIM.search(str(k)))
    if sensitive:
        out.append(Finding("high", "sensitive-claim",
                           f"Payload contains {', '.join(sensitive)}. JWT payloads are only base64-encoded, "
                           f"not encrypted - anyone holding the token can read them."))

    order = {s: i for i, s in enumerate(reversed(SEVERITIES))}
    out.sort(key=lambda f: order[f.severity])
    return out
