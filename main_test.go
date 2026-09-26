package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var now = time.Unix(1_800_000_000, 0).UTC()

func makeToken(t *testing.T, header, payload map[string]any, sig string) string {
	t.Helper()
	enc := func(v map[string]any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(header) + "." + enc(payload) + "." + sig
}

func levels(t *testing.T, tok string, opts Options) map[string]string {
	t.Helper()
	parsed, err := Parse(tok)
	if err != nil {
		t.Fatal(err)
	}
	opts.Now = now
	out := map[string]string{}
	for _, f := range Check(parsed, opts) {
		out[f.Message] = f.Level
	}
	return out
}

func hasLevel(m map[string]string, level, substr string) bool {
	for msg, l := range m {
		if l == level && strings.Contains(msg, substr) {
			return true
		}
	}
	return false
}

func TestAlgNoneIsCaseInsensitive(t *testing.T) {
	for _, alg := range []string{"none", "None", "NONE"} {
		tok := makeToken(t, map[string]any{"alg": alg}, map[string]any{"exp": 1_900_000_000}, "")
		if !hasLevel(levels(t, tok, Options{}), "fail", "unsigned") {
			t.Errorf("alg=%s should fail", alg)
		}
	}
}

func TestExpiry(t *testing.T) {
	expired := makeToken(t, map[string]any{"alg": "HS256"}, map[string]any{"exp": 1_700_000_000}, "sig")
	if !hasLevel(levels(t, expired, Options{}), "warn", "expired") {
		t.Error("expected expired warning")
	}
	noExp := makeToken(t, map[string]any{"alg": "HS256"}, map[string]any{"sub": "x"}, "sig")
	if !hasLevel(levels(t, noExp, Options{}), "warn", "never expires") {
		t.Error("expected missing exp warning")
	}
}

func TestAudienceArray(t *testing.T) {
	tok := makeToken(t, map[string]any{"alg": "RS256"}, map[string]any{"exp": 1_900_000_000, "aud": []string{"web", "api"}}, "sig")
	if !hasLevel(levels(t, tok, Options{Audience: "api"}), "ok", "audience matches") {
		t.Error("audience in array should match")
	}
}

func TestLifetimeAndHeaders(t *testing.T) {
	tok := makeToken(t,
		map[string]any{"alg": "RS256", "jku": "https://evil.test/keys", "kid": "../../dev/null"},
		map[string]any{"iat": 1_799_000_000, "exp": 1_899_000_000, "password": "hunter2"},
		"sig")
	got := levels(t, tok, Options{MaxLifetime: 24 * time.Hour})
	for _, want := range []string{"lifetime", "jku", "kid", "password"} {
		if !hasLevel(got, "warn", want) {
			t.Errorf("expected a warning about %s, got %v", want, got)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, bad := range []string{"abc", "a.b", "!!!.e30.x"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
	if _, err := Parse("Bearer " + makeToken(t, map[string]any{"alg": "HS256"}, map[string]any{}, "s")); err != nil {
		t.Errorf("Bearer prefix should be accepted: %v", err)
	}
}
