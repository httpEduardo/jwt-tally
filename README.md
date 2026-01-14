# JWT Tally

JWT Tally decodes JWT headers/payloads and highlights risky or expired claims.

## Quick start

```bash
go run main.go --token "<jwt>"
```

## Features

- Decodes header and payload segments.
- Flags `alg=none`, missing `exp`, or expired tokens.
- Optional checks for issuer and audience.

## Sample

```bash
go run main.go --file sample_tokens.txt --issuer auth.local
```
