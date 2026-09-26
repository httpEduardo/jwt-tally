# jwt-tally

`jwt-tally` is a small command-line tool for inspecting JSON Web Tokens. It decodes a token and reports potentially risky headers and claims, helping developers review tokens found in logs, test fixtures, or incident reports.

> **Important:** jwt-tally does not verify signatures or establish that a token is authentic. Use it for inspection only; never use its output to authorize a request.

## What it checks

- Missing or `none` signing algorithms and empty signature segments
- Remote key references (`jku`, `x5u`) and embedded `jwk` headers
- Suspicious characters in `kid` values
- Missing, malformed, expired, or future-dated time claims
- Token lifetime above a configurable limit
- Expected issuer and audience values
- Payload field names that may indicate exposed secrets

Findings are reported as `OK`, `WARN`, or `FAIL`. JWT payloads are encoded, not encrypted, so do not put secrets in them.

## Requirements

- Go 1.21 or later

## Usage

Inspect one token:

```bash
go run . -token "eyJhbGciOi..."
```

Compare issuer and audience claims:

```bash
go run . -token "eyJhbGciOi..." -issuer https://auth.example.com -audience api
```

Inspect tokens from a file or standard input (one token per line):

```bash
go run . -file sample_tokens.txt -audience api
cat tokens.txt | go run . -file -
```

The tool accepts a `Bearer` prefix, skips blank lines and lines beginning with `#`, and supports long token lines.

## Options

| Option | Description |
| --- | --- |
| `-token` | Inspect a single JWT. |
| `-file` | Read one JWT per line; use `-` for standard input. |
| `-issuer` | Require the `iss` claim to match this value. |
| `-audience` | Require the `aud` claim to contain this value. |
| `-max-lifetime` | Warn when `exp - iat` exceeds this duration. Defaults to `24h`; `0` disables the check. |

## Exit status

- `0` — no failed checks
- `1` — one or more checks failed
- `2` — invalid usage or an input file could not be read

## Build

```bash
go build -o jwt-tally .
```

## License

[MIT](LICENSE)
