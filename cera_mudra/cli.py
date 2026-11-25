"""Command-line interface for cera-mudra."""

from __future__ import annotations

import argparse
import json
import sys
import time

from . import __version__
from .analysis import DEFAULT_MAX_LIFETIME, SEVERITIES, analyze, crack
from .colors import Painter, should_color
from .jwt import HMAC_ALGS, JWTError, decode, sign, verify_decoded
from .timeutil import describe_timestamp, parse_duration
from .wordlist import WEAK_SECRETS

SEV_STYLE = {"critical": ("bold", "red"), "high": ("red",), "medium": ("yellow",), "low": ("cyan",), "info": ("grey",)}
TIME_CLAIMS = ("exp", "nbf", "iat", "auth_time")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cera-mudra",
        description="Inspect, verify, crack-check and create JSON Web Tokens. "
                    "Only test tokens and systems you own or are authorized to assess.",
    )
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")

    def token_arg(sp):
        sp.add_argument("token", help="the JWT (a leading 'Bearer ' is stripped); use - to read stdin")

    ins = sub.add_parser("inspect", help="decode a token and review it for security issues")
    token_arg(ins)
    ins.add_argument("--secret", help="also verify the signature with this HMAC secret")
    ins.add_argument("--wordlist", metavar="FILE", help="extra candidate secrets, one per line")
    ins.add_argument("--no-crack", action="store_true", help="skip the weak-secret check")
    ins.add_argument("--max-lifetime", default=str(DEFAULT_MAX_LIFETIME), metavar="DURATION",
                     help="flag tokens living longer than this (default 24h; e.g. 15m, 12h, 7d)")
    ins.add_argument("--fail-on", choices=SEVERITIES, default="critical",
                     help="exit 1 if a finding of this severity or worse exists (default critical)")
    ins.add_argument("--json", action="store_true", help="JSON output")
    ins.add_argument("--no-color", action="store_true", help="disable coloured output")

    ver = sub.add_parser("verify", help="verify an HS256/HS384/HS512 signature (exit 0 valid, 1 invalid)")
    token_arg(ver)
    g = ver.add_mutually_exclusive_group(required=True)
    g.add_argument("--secret", help="HMAC secret")
    g.add_argument("--secret-file", metavar="FILE", help="read the secret (raw bytes) from FILE")
    ver.add_argument("--json", action="store_true", help="JSON output")

    cr = sub.add_parser("crack", help="test the token against a weak-secret wordlist")
    token_arg(cr)
    cr.add_argument("--wordlist", metavar="FILE", help="candidate secrets, one per line (added to the bundled list)")
    cr.add_argument("--only-wordlist", action="store_true", help="do not use the bundled list")
    cr.add_argument("--json", action="store_true", help="JSON output")

    cre = sub.add_parser("create", help="create a signed test token")
    cre.add_argument("--secret", help="HMAC secret (required unless --alg none)")
    cre.add_argument("--alg", default="HS256", choices=[*HMAC_ALGS, "none"], help="algorithm (default HS256)")
    cre.add_argument("--payload", default="{}", help="base payload as a JSON object")
    cre.add_argument("--claim", action="append", default=[], metavar="KEY=VALUE",
                     help="add a claim; VALUE is parsed as JSON when possible (repeatable)")
    cre.add_argument("--header", action="append", default=[], metavar="KEY=VALUE",
                     help="add a header parameter such as kid=key-1 (repeatable)")
    cre.add_argument("--exp", metavar="DURATION", help="set exp this far in the future (e.g. 15m, 1h, 7d)")
    cre.add_argument("--no-iat", action="store_true", help="do not add an iat claim")
    return p


def _read_token(value: str, stdin) -> str:
    if value == "-":
        return (stdin or sys.stdin).read().strip()
    return value


def _read_words(path: str) -> list[str]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return [line.rstrip("\r\n") for line in fh if line.rstrip("\r\n")]


def _kv(items: list[str]) -> dict:
    out = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"expected KEY=VALUE, got {item!r}")
        k, v = item.split("=", 1)
        try:
            out[k] = json.loads(v)
        except json.JSONDecodeError:
            out[k] = v
    return out


def _render_claims(title: str, data: dict, paint: Painter, now: float, annotate_time: bool) -> list[str]:
    lines = [paint(title, "bold", "magenta")]
    if not data:
        lines.append("  (empty)")
    width = max((len(k) for k in data), default=0)
    for k, v in data.items():
        shown = json.dumps(v, ensure_ascii=False) if not isinstance(v, str) else v
        line = f"  {paint(k.ljust(width), 'cyan')}  {shown}"
        if annotate_time and k in TIME_CLAIMS:
            line += "  " + paint("-> " + describe_timestamp(v, now=now), "dim")
        lines.append(line)
    return lines


def cmd_inspect(args, stdin) -> int:
    token = decode(_read_token(args.token, stdin))
    now = time.time()
    words = list(WEAK_SECRETS) + (_read_words(args.wordlist) if args.wordlist else [])
    cracked = None if args.no_crack else crack(token, words)
    findings = analyze(token, now=now, max_lifetime=parse_duration(args.max_lifetime),
                       cracked=cracked, skip_crack=True)
    verified = None
    if args.secret is not None:
        verified = verify_decoded(token, args.secret)
    threshold = SEVERITIES.index(args.fail_on)
    failing = any(SEVERITIES.index(f.severity) >= threshold for f in findings) or verified is False

    if args.json:
        print(json.dumps({
            "header": token.header,
            "payload": token.payload,
            "signature": {"alg": token.alg, "bytes": len(token.signature), "hex": token.signature.hex()},
            "times": {k: describe_timestamp(token.payload[k], now=now) for k in TIME_CLAIMS if k in token.payload},
            "verified": verified,
            "cracked_secret": cracked,
            "findings": [f.to_dict() for f in findings],
        }, indent=2, ensure_ascii=False))
        return 1 if failing else 0

    paint = Painter(should_color(sys.stdout) and not args.no_color)
    lines = _render_claims("Header", token.header, paint, now, False)
    lines.append("")
    lines += _render_claims("Payload", token.payload, paint, now, True)
    lines.append("")
    sig = f"{token.alg or '?'}, {len(token.signature)} bytes" if token.signature else "none (unsigned)"
    lines.append(f"{paint('Signature', 'bold', 'magenta')}  {sig}")
    if verified is not None:
        lines.append("  " + (paint("valid for the given secret", "green") if verified
                             else paint("INVALID for the given secret", "bold", "red")))
    lines.append("")
    lines.append(paint(f"Findings ({len(findings)})", "bold", "magenta"))
    if not findings:
        lines.append("  " + paint("no issues found", "green"))
    for f in findings:
        lines.append(f"  {paint(f.severity.upper().ljust(8), *SEV_STYLE[f.severity])}  {f.code:<18} {f.message}")
    print("\n".join(lines))
    return 1 if failing else 0


def cmd_verify(args, stdin) -> int:
    token = decode(_read_token(args.token, stdin))
    if args.secret_file:
        with open(args.secret_file, "rb") as fh:
            secret = fh.read().rstrip(b"\r\n")
    else:
        secret = args.secret
    ok = verify_decoded(token, secret)
    if args.json:
        print(json.dumps({"alg": token.alg, "valid": ok}))
    else:
        print(f"signature {'valid' if ok else 'INVALID'} ({token.alg})")
    return 0 if ok else 1


def cmd_crack(args, stdin) -> int:
    token = decode(_read_token(args.token, stdin))
    if token.alg not in HMAC_ALGS:
        raise JWTError(f"alg {token.alg!r} is not HMAC; there is no shared secret to guess")
    words = [] if args.only_wordlist else list(WEAK_SECRETS)
    if args.wordlist:
        words += _read_words(args.wordlist)
    secret = crack(token, words)
    if args.json:
        print(json.dumps({"alg": token.alg, "tried": len(words), "secret": secret}))
    elif secret is not None:
        print(f"secret found: {secret!r}  ({token.alg}, {len(words)} candidates)")
    else:
        print(f"no match in {len(words)} candidates")
    return 0 if secret is not None else 1


def cmd_create(args) -> int:
    payload = json.loads(args.payload)
    if not isinstance(payload, dict):
        raise ValueError("--payload must be a JSON object")
    now = int(time.time())
    if not args.no_iat:
        payload.setdefault("iat", now)
    if args.exp:
        payload["exp"] = int(payload.get("iat", now)) + parse_duration(args.exp)
    payload.update(_kv(args.claim))
    if args.alg != "none" and args.secret is None:
        raise ValueError("--secret is required for HMAC algorithms")
    print(sign(payload, args.secret, alg=args.alg, headers=_kv(args.header)))
    return 0


def main(argv: list[str] | None = None, stdin=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "inspect":
            return cmd_inspect(args, stdin)
        if args.command == "verify":
            return cmd_verify(args, stdin)
        if args.command == "crack":
            return cmd_crack(args, stdin)
        return cmd_create(args)
    except (JWTError, ValueError, OSError) as exc:
        print(f"cera-mudra: error: {exc}", file=sys.stderr)
        return 2
