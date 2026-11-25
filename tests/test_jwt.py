import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout

from cera_mudra import cli
from cera_mudra.analysis import analyze, crack
from cera_mudra.jwt import (JWTError, b64url_decode, b64url_encode, decode, sign, verify)
from cera_mudra.timeutil import describe_timestamp, parse_duration

NOW = 1_800_000_000  # fixed clock for deterministic tests


def codes(findings):
    return {f.code for f in findings}


class Base64Tests(unittest.TestCase):
    def test_roundtrip_without_padding(self):
        for raw in (b"", b"f", b"fo", b"foo", b"\xff\xfe\xfd\x00"):
            enc = b64url_encode(raw)
            self.assertNotIn("=", enc)
            self.assertEqual(b64url_decode(enc), raw)

    def test_urlsafe_alphabet(self):
        self.assertEqual(b64url_encode(b"\xfb\xff"), "-_8")

    def test_invalid_base64_raises(self):
        with self.assertRaises(JWTError):
            b64url_decode("abc$")


class SignVerifyTests(unittest.TestCase):
    def test_sign_and_decode(self):
        token = sign({"sub": "42", "name": "Ada"}, "k3y", alg="HS256")
        t = decode(token)
        self.assertEqual(t.header, {"alg": "HS256", "typ": "JWT"})
        self.assertEqual(t.payload["name"], "Ada")
        self.assertEqual(len(t.signature), 32)

    def test_known_vector(self):
        # Signature computed independently with hmac.new(b"secret", ..., sha256).
        token = sign({"sub": "1234567890"}, "secret", alg="HS256")
        self.assertEqual(token,
                         "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
                         "Rq8IxqeX7eA6GgYxlcHdPFVRNFFZc5rEI3MQTZZbK3I")

    def test_verify_each_hs_alg(self):
        for alg, size in (("HS256", 32), ("HS384", 48), ("HS512", 64)):
            with self.subTest(alg=alg):
                token = sign({"a": 1}, "pw", alg=alg)
                self.assertEqual(len(decode(token).signature), size)
                self.assertTrue(verify(token, "pw"))
                self.assertFalse(verify(token, "wrong"))

    def test_tampered_payload_fails(self):
        token = sign({"admin": False}, "pw")
        h, p, s = token.split(".")
        forged = ".".join([h, b64url_encode(json.dumps({"admin": True}).encode()), s])
        self.assertFalse(verify(forged, "pw"))

    def test_verify_rejects_non_hmac(self):
        token = sign({"a": 1}, None, alg="none")
        self.assertTrue(token.endswith("."))
        with self.assertRaises(JWTError):
            verify(token, "x")

    def test_malformed_tokens(self):
        for bad in ("", "abc", "a.b", "a.b.c.d", "!!!.e30.", "e30.bm90IGpzb24.sig"):
            with self.subTest(bad=bad):
                with self.assertRaises(JWTError):
                    decode(bad)

    def test_bearer_prefix_and_whitespace_stripped(self):
        token = sign({"a": 1}, "pw")
        self.assertEqual(decode(f"  Bearer {token}\n").payload, {"a": 1})


class AnalysisTests(unittest.TestCase):
    def test_alg_none_is_critical(self):
        token = sign({"sub": "x", "exp": NOW + 60}, None, alg="none")
        findings = analyze(decode(token), now=NOW)
        crit = [f for f in findings if f.code == "alg-none"]
        self.assertEqual(crit[0].severity, "critical")

    def test_weak_secret_cracked(self):
        token = sign({"sub": "x", "exp": NOW + 60, "iat": NOW}, "secret")
        self.assertEqual(crack(decode(token)), "secret")
        findings = analyze(decode(token), now=NOW)
        self.assertIn("weak-secret", codes(findings))

    def test_strong_secret_not_cracked(self):
        token = sign({"sub": "x"}, "Lk2#9vQ!pX7@mZ4$wR8^tY1&")
        self.assertIsNone(crack(decode(token)))

    def test_custom_wordlist(self):
        token = sign({"a": 1}, "correct horse battery staple")
        self.assertEqual(crack(decode(token), ["nope", "correct horse battery staple"]), "correct horse battery staple")

    def test_missing_exp_and_long_lifetime(self):
        no_exp = analyze(decode(sign({"sub": "x"}, "Lk2#9vQ!pX7@mZ4")), now=NOW)
        self.assertIn("missing-exp", codes(no_exp))
        long = analyze(decode(sign({"iat": NOW, "exp": NOW + 90 * 86400}, "Lk2#9vQ!pX7@mZ4")), now=NOW)
        self.assertIn("long-lifetime", codes(long))
        self.assertNotIn("missing-exp", codes(long))

    def test_expired_and_not_yet_valid(self):
        f = analyze(decode(sign({"exp": NOW - 10, "nbf": NOW + 100}, "Lk2#9vQ!pX7@mZ4")), now=NOW)
        self.assertIn("expired", codes(f))
        self.assertIn("not-yet-valid", codes(f))

    def test_kid_injection_hints(self):
        for kid in ("../../../../dev/null", "1' OR '1'='1", "key|whoami", "http://evil.example/k"):
            with self.subTest(kid=kid):
                token = sign({"exp": NOW + 60}, "Lk2#9vQ!pX7@mZ4", headers={"kid": kid})
                self.assertIn("kid-injection", codes(analyze(decode(token), now=NOW)))
        safe = sign({"exp": NOW + 60}, "Lk2#9vQ!pX7@mZ4", headers={"kid": "2024-key-01"})
        self.assertNotIn("kid-injection", codes(analyze(decode(safe), now=NOW)))

    def test_jku_and_embedded_jwk_flagged(self):
        token = sign({"exp": NOW + 60}, "Lk2#9vQ!pX7@mZ4",
                     headers={"jku": "https://x.example/jwks.json", "jwk": {"kty": "oct"}})
        c = codes(analyze(decode(token), now=NOW))
        self.assertIn("jku-header", c)
        self.assertIn("embedded-jwk", c)

    def test_sensitive_claims(self):
        token = sign({"exp": NOW + 60, "password": "hunter2"}, "Lk2#9vQ!pX7@mZ4")
        self.assertIn("sensitive-claim", codes(analyze(decode(token), now=NOW)))


class TimeTests(unittest.TestCase):
    def test_describe_timestamp(self):
        self.assertEqual(describe_timestamp(NOW + 7200, now=NOW), "2027-01-15 10:00:00 UTC (in 2 hours)")
        self.assertIn("3 days ago", describe_timestamp(NOW - 3 * 86400, now=NOW))

    def test_parse_duration(self):
        self.assertEqual(parse_duration("90"), 90)
        self.assertEqual(parse_duration("15m"), 900)
        self.assertEqual(parse_duration("2h"), 7200)
        self.assertEqual(parse_duration("7d"), 604800)
        self.assertEqual(parse_duration("1w"), 604800)
        with self.assertRaises(ValueError):
            parse_duration("soon")


class CliTests(unittest.TestCase):
    def run_cli(self, *argv, stdin=None):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(list(argv), stdin=io.StringIO(stdin) if stdin is not None else None)
        return code, out.getvalue(), err.getvalue()

    def test_create_then_verify(self):
        code, out, _ = self.run_cli("create", "--secret", "pw", "--claim", "sub=alice",
                                    "--claim", "admin=true", "--exp", "1h", "--alg", "HS384")
        self.assertEqual(code, 0)
        token = out.strip()
        t = decode(token)
        self.assertEqual(t.header["alg"], "HS384")
        self.assertIs(t.payload["admin"], True)
        self.assertEqual(t.payload["exp"] - t.payload["iat"], 3600)
        self.assertEqual(self.run_cli("verify", token, "--secret", "pw")[0], 0)
        self.assertEqual(self.run_cli("verify", token, "--secret", "nope")[0], 1)

    def test_inspect_json_from_stdin(self):
        token = sign({"sub": "x"}, "password")
        code, out, _ = self.run_cli("inspect", "-", "--json", stdin=token + "\n")
        data = json.loads(out)
        self.assertEqual(data["header"]["alg"], "HS256")
        self.assertEqual(data["cracked_secret"], "password")
        self.assertIn("weak-secret", {w["code"] for w in data["findings"]})
        self.assertEqual(code, 1)  # critical finding -> non-zero

    def test_inspect_text_output(self):
        token = sign({"sub": "x", "iat": 1700000000, "exp": 1700003600}, "Lk2#9vQ!pX7@mZ4")
        code, out, _ = self.run_cli("inspect", token, "--no-color")
        self.assertIn("2023-11-14 22:13:20 UTC", out)
        self.assertIn("Header", out)

    def test_crack_command(self):
        token = sign({"a": 1}, "changeme")
        code, out, _ = self.run_cli("crack", token)
        self.assertEqual(code, 0)
        self.assertIn("changeme", out)

    def test_bad_token_exit_2(self):
        code, _, err = self.run_cli("inspect", "not-a-token")
        self.assertEqual(code, 2)
        self.assertIn("error", err)


if __name__ == "__main__":
    unittest.main()
