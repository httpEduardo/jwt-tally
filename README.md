# jwt-tally

Decodes JSON Web Tokens and flags the header and claim problems that most often lead to authentication bugs: unsigned tokens, missing expiry, remote key references, mismatched issuer or audience, and secrets hiding in the payload.

Handy for looking at tokens pulled from logs, proxy traffic or bug reports without pasting them into a website.

> **Signatures are not verified.** jwt-tally inspects what a token *claims*; it doesn't prove the token is authentic.

## Checks

**Header**
- `alg` missing, or `none` in any casing (`None`, `NONE`) — unsigned tokens must be rejected
- a non-`none` algorithm with an empty signature segment
- `jku` / `x5u` pointing to a remote key set, or an embedded `jwk` — classic key-confusion vectors
- `kid` containing path or SQL metacharacters

**Claims**
- no `exp`, a non-numeric `exp`, or an already expired token
- `nbf` in the future and `iat` in the future
- lifetime (`exp - iat`) longer than `-max-lifetime` (24h by default)
- `iss` / `aud` not matching the expected values (`aud` can be a string or an array)
- payload keys that look like secrets: `password`, `secret`, `api_key`, `private_key`, …

## Usage

```bash
go run . -token "eyJhbGciOi..." -issuer https://auth.example.com -audience api
go run . -file sample_tokens.txt -audience suite
```

```text
== line 4
Header:
  {
    "alg": "none",
    "typ": "JWT"
  }
Payload:
  {
    "iat": 1680000000,
    "sub": "tester"
  }
Checks:
  FAIL  alg=none: the token is unsigned and must be rejected
  WARN  no exp claim: the token never expires
  FAIL  audience [] does not include "suite"
```

| Flag | Description |
|------|-------------|
| `-token` | A single JWT (a `Bearer ` prefix is fine) |
| `-file` | One token per line; `-` reads stdin; `#` lines are skipped |
| `-issuer` | Expected `iss` |
| `-audience` | Expected `aud` |
| `-max-lifetime` | Warn above this lifetime, e.g. `1h`, `72h`; `0` disables |

Exit codes: `0` no failures, `1` at least one `FAIL`, `2` usage error or unreadable file.

## Build & test

```bash
go build -o jwt-tally .
go test ./...
```

## License

[MIT](LICENSE)
