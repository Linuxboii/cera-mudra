# cera-mudra

A zero-dependency JWT inspector: decode tokens, review them for security problems, catch weak HMAC secrets, verify signatures and mint test tokens.

*cera* (Latin, wax - as in a wax seal) + *mudra* (Sanskrit, seal, stamp) - every JWT is a seal; this tool checks whether it can be trusted.

> Only test tokens and systems you own or are authorized to assess.

## Features

- **Decode** header and payload without verifying, with `exp`/`nbf`/`iat`/`auth_time` rendered as UTC dates plus relative time ("in 2 hours", "3 days ago"). Accepts `Bearer ...` strings and stdin; detects JWE (5-part) tokens.
- **Security review** with severities:
  - `alg: none` (any casing), missing `alg`, unknown algorithms, algorithm-confusion reminder for RS/PS/ES tokens
  - **weak HMAC secret**: a bundled list of ~160 tutorial/default secrets (`secret`, `your-256-bit-secret`, `changeme`, ...) is tried in milliseconds; add your own with `--wordlist`
  - missing or non-numeric `exp`, expired tokens, `nbf` in the future, `iat` in the future, lifetime above a limit (default 24h, `--max-lifetime 15m`)
  - `kid` injection hints: path traversal, SQL and shell metacharacters, URLs, control characters
  - `jku` / `x5u` key URLs and embedded `jwk` headers (CVE-2018-0114 pattern)
  - sensitive-looking claims (`password`, `ssn`, `api_key`, ...) in a payload that is only base64-encoded
  - missing `iss` / `aud` / `iat`
- **Verify** HS256 / HS384 / HS512 signatures with a secret or secret file (constant-time comparison).
- **Create** test tokens: any claims (values parsed as JSON), header parameters such as `kid`, relative `exp`, or `alg none` for negative tests.
- `--json` on every read command, coloured output that turns itself off for pipes and `NO_COLOR`, CI-friendly exit codes.

## Install

```sh
pip install .
# or without installing
python -m cera_mudra --help
```

## Usage

```sh
cera-mudra inspect "$TOKEN"
cera-mudra inspect - --json < token.txt
cera-mudra inspect "$TOKEN" --secret "$KEY" --max-lifetime 1h --fail-on high
cera-mudra verify "$TOKEN" --secret-file hmac.key
cera-mudra crack "$TOKEN" --wordlist my-candidates.txt
cera-mudra create --secret dev-key --claim sub=alice --claim admin=true --exp 15m --header kid=2026-01
```

Example - create a deliberately bad token and inspect it:

```text
$ TOKEN=$(cera-mudra create --secret secret --claim sub=alice --claim role=admin --exp 30d --header kid=../../keys/hmac.pem)
$ cera-mudra inspect "$TOKEN"
Header
  alg  HS256
  typ  JWT
  kid  ../../keys/hmac.pem

Payload
  iat   1795591448  -> 2026-11-25 07:24:08 UTC (now)
  exp   1798183448  -> 2026-12-25 07:24:08 UTC (in 29 days)
  sub   alice
  role  admin

Signature  HS256, 32 bytes

Findings (5)
  CRITICAL  weak-secret        Signed with a guessable secret 'secret': anyone can mint valid tokens. Rotate it and use >= 32 random bytes.
  HIGH      kid-injection      kid '../../keys/hmac.pem' contains path traversal / absolute path; if the server uses kid in a file path, SQL query or command, this is an injection vector.
  MEDIUM    long-lifetime      Lifetime is 30 days (limit 1 day). Prefer short-lived access tokens plus refresh tokens.
  LOW       missing-iss        No iss claim; verifiers cannot check who the token is from.
  LOW       missing-aud        No aud claim; verifiers cannot check who the token is for.
```

Exit codes:

| Command | 0 | 1 | 2 |
|---|---|---|---|
| `inspect` | no finding at `--fail-on` level (default `critical`) | such a finding, or `--secret` did not verify | malformed token / error |
| `verify` | signature valid | invalid | malformed / non-HMAC token |
| `crack` | secret found | not found | error |
| `create` | token printed | - | bad arguments |

## How it works

A compact JWS is `base64url(header).base64url(payload).base64url(signature)`. cera-mudra decodes each part strictly (URL-safe alphabet, padding restored, JSON objects required), then runs the checks above against the decoded header and claims. HMAC verification recomputes `HMAC-SHA{256,384,512}(secret, "header.payload")` and compares it with `hmac.compare_digest`; the weak-secret check is the same computation repeated over the wordlist. Tokens are created with compact JSON (`{"alg":...,"typ":"JWT"}` first), matching what common libraries emit.

Asymmetric algorithms (RS*, PS*, ES*, EdDSA) are decoded and reviewed but not verified - that would need a crypto library, and this tool is standard-library only.

## Running the tests

```sh
python -m unittest discover -s tests
```

## License

MIT - see [LICENSE](LICENSE).
