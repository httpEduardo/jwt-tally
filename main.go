// Command jwt-tally decodes JSON Web Tokens and flags risky headers and claims.
//
// It never verifies signatures: the goal is to inspect tokens found in logs,
// traffic captures or bug reports, not to authenticate them.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// Finding is the result of one check.
type Finding struct {
	Level   string // "ok", "warn" or "fail"
	Message string
}

// Token is a decoded (unverified) JWT.
type Token struct {
	Header    map[string]any
	Payload   map[string]any
	Signature string
}

// Options holds optional expectations to check against.
type Options struct {
	Issuer      string
	Audience    string
	MaxLifetime time.Duration
	Now         time.Time
}

func decodeSegment(segment string) (map[string]any, error) {
	// Tolerate padded input even though JWTs should use unpadded base64url.
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(segment, "="))
	if err != nil {
		return nil, fmt.Errorf("invalid base64url: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	return out, nil
}

// Parse splits and decodes a compact JWT. A "Bearer " prefix is accepted.
func Parse(raw string) (*Token, error) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(raw, "Bearer "), "bearer "))
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected 3 dot-separated segments, got %d", len(parts))
	}
	header, err := decodeSegment(parts[0])
	if err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	payload, err := decodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	return &Token{Header: header, Payload: payload, Signature: parts[2]}, nil
}

func numericDate(v any) (time.Time, bool) {
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(int64(f), 0).UTC(), true
	case float64:
		return time.Unix(int64(n), 0).UTC(), true
	}
	return time.Time{}, false
}

// audiences normalizes "aud", which may be a string or an array of strings.
func audiences(v any) []string {
	switch a := v.(type) {
	case string:
		return []string{a}
	case []any:
		var out []string
		for _, x := range a {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

var sensitiveKeys = []string{"password", "passwd", "pwd", "secret", "api_key", "apikey", "private_key", "ssn", "credit_card", "card_number"}

// Check runs every check on a decoded token.
func Check(t *Token, opts Options) []Finding {
	var out []Finding
	add := func(level, format string, args ...any) {
		out = append(out, Finding{level, fmt.Sprintf(format, args...)})
	}

	alg, _ := t.Header["alg"].(string)
	switch {
	case alg == "":
		add("fail", "header has no alg")
	case strings.EqualFold(alg, "none"):
		add("fail", "alg=%s: the token is unsigned and must be rejected", alg)
	default:
		add("ok", "alg=%s", alg)
		if t.Signature == "" {
			add("fail", "alg=%s but the signature segment is empty", alg)
		}
	}
	for _, h := range []string{"jku", "x5u"} {
		if v, ok := t.Header[h]; ok {
			add("warn", "header %s=%v points to a remote key; make sure the server ignores or allowlists it", h, v)
		}
	}
	if _, ok := t.Header["jwk"]; ok {
		add("warn", "header embeds a jwk; a server that trusts it would accept attacker-signed tokens")
	}
	if kid, ok := t.Header["kid"].(string); ok && strings.ContainsAny(kid, "/\\'\"; ") {
		add("warn", "kid %q contains path or SQL metacharacters", kid)
	}

	now := opts.Now
	exp, hasExp := numericDate(t.Payload["exp"])
	switch {
	case t.Payload["exp"] == nil:
		add("warn", "no exp claim: the token never expires")
	case !hasExp:
		add("fail", "exp is not a numeric date")
	case now.After(exp):
		add("warn", "expired at %s", exp.Format(time.RFC3339))
	default:
		add("ok", "expires at %s", exp.Format(time.RFC3339))
	}
	if nbf, ok := numericDate(t.Payload["nbf"]); ok && nbf.After(now) {
		add("warn", "not valid before %s", nbf.Format(time.RFC3339))
	}
	iat, hasIat := numericDate(t.Payload["iat"])
	if hasIat && iat.After(now.Add(5*time.Minute)) {
		add("warn", "issued in the future (%s)", iat.Format(time.RFC3339))
	}
	if hasExp && hasIat && opts.MaxLifetime > 0 && exp.Sub(iat) > opts.MaxLifetime {
		add("warn", "lifetime of %s exceeds %s", exp.Sub(iat).Round(time.Minute), opts.MaxLifetime)
	}

	if opts.Issuer != "" {
		if iss, _ := t.Payload["iss"].(string); iss == opts.Issuer {
			add("ok", "issuer matches")
		} else {
			add("fail", "issuer %q does not match %q", iss, opts.Issuer)
		}
	}
	if opts.Audience != "" {
		auds := audiences(t.Payload["aud"])
		found := false
		for _, a := range auds {
			if a == opts.Audience {
				found = true
			}
		}
		if found {
			add("ok", "audience matches")
		} else {
			add("fail", "audience %v does not include %q", auds, opts.Audience)
		}
	}

	var leaked []string
	for key := range t.Payload {
		for _, s := range sensitiveKeys {
			if strings.Contains(strings.ToLower(key), s) {
				leaked = append(leaked, key)
				break
			}
		}
	}
	if len(leaked) > 0 {
		sort.Strings(leaked)
		add("warn", "payload contains sensitive-looking claims (%s); JWT payloads are only encoded, not encrypted", strings.Join(leaked, ", "))
	}
	return out
}

func pretty(v map[string]any) string {
	b, err := json.MarshalIndent(v, "  ", "  ")
	if err != nil {
		return fmt.Sprint(v)
	}
	return "  " + string(b)
}

func report(w io.Writer, label, raw string, opts Options) (fails int) {
	fmt.Fprintf(w, "== %s\n", label)
	t, err := Parse(raw)
	if err != nil {
		fmt.Fprintf(w, "  FAIL  cannot decode token: %v\n\n", err)
		return 1
	}
	fmt.Fprintf(w, "Header:\n%s\nPayload:\n%s\nChecks:\n", pretty(t.Header), pretty(t.Payload))
	for _, f := range Check(t, opts) {
		fmt.Fprintf(w, "  %-4s  %s\n", strings.ToUpper(f.Level), f.Message)
		if f.Level == "fail" {
			fails++
		}
	}
	fmt.Fprintln(w)
	return fails
}

func main() {
	token := flag.String("token", "", "JWT to inspect")
	file := flag.String("file", "", `file with one JWT per line ("-" for stdin)`)
	issuer := flag.String("issuer", "", "expected iss claim")
	audience := flag.String("audience", "", "expected aud claim")
	maxLifetime := flag.Duration("max-lifetime", 24*time.Hour, "warn when exp - iat is longer than this (0 disables)")
	flag.Parse()

	if *token == "" && *file == "" {
		fmt.Fprintln(os.Stderr, "usage: jwt-tally -token <jwt> | -file <path> [-issuer ISS] [-audience AUD]")
		os.Exit(2)
	}
	opts := Options{Issuer: *issuer, Audience: *audience, MaxLifetime: *maxLifetime, Now: time.Now().UTC()}

	fails := 0
	if *token != "" {
		fails += report(os.Stdout, "token", *token, opts)
	}
	if *file != "" {
		var r io.Reader = os.Stdin
		if *file != "-" {
			f, err := os.Open(*file)
			if err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(2)
			}
			defer f.Close()
			r = f
		}
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64*1024), 1024*1024) // long tokens exceed the default 64 KB line limit
		n := 0
		for sc.Scan() {
			n++
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fails += report(os.Stdout, fmt.Sprintf("line %d", n), line, opts)
		}
		if err := sc.Err(); err != nil {
			fmt.Fprintln(os.Stderr, "error reading input:", err)
			os.Exit(2)
		}
	}
	if fails > 0 {
		os.Exit(1)
	}
}
