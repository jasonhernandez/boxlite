package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// ============================================================================
// Basic-auth secret substitution
//
// HTTP Basic base64-encodes `user:password`, so a placeholder in either field
// is invisible to the literal replacer that handles every other scheme. These
// tests pin the decode → substitute → re-encode path, and the boundaries it
// must not cross.
// ============================================================================

func basicHeader(credentials string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials))
}

// decodeBasic returns the decoded credentials of a `Basic …` header value.
func decodeBasic(t *testing.T, value string) string {
	t.Helper()
	encoded, ok := strings.CutPrefix(value, "Basic ")
	if !ok {
		t.Fatalf("header %q is not a Basic credential", value)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("header %q does not carry valid base64: %v", value, err)
	}
	return string(decoded)
}

func requestWithAuth(value string) *http.Request {
	req := &http.Request{Header: http.Header{}}
	req.Header.Set("Authorization", value)
	return req
}

func TestSubstituteHeaders_BasicAuthPasswordPlaceholder(t *testing.T) {
	req := requestWithAuth(basicHeader("x-access-token:<BOXLITE_SECRET:gh>"))

	substituteHeaders(req, []SecretConfig{
		{Placeholder: "<BOXLITE_SECRET:gh>", Value: "ghp-real-token"},
	})

	if got, want := decodeBasic(t, req.Header.Get("Authorization")), "x-access-token:ghp-real-token"; got != want {
		t.Errorf("decoded credentials = %q, want %q", got, want)
	}
}

func TestSubstituteHeaders_BasicAuthUserPlaceholder(t *testing.T) {
	req := requestWithAuth(basicHeader("<BOXLITE_SECRET:gh>:x-oauth-basic"))

	substituteHeaders(req, []SecretConfig{
		{Placeholder: "<BOXLITE_SECRET:gh>", Value: "ghp-real-token"},
	})

	if got, want := decodeBasic(t, req.Header.Get("Authorization")), "ghp-real-token:x-oauth-basic"; got != want {
		t.Errorf("decoded credentials = %q, want %q", got, want)
	}
}

// A payload with no colon is what a client sending a bare token produces.
func TestSubstituteHeaders_BasicAuthBarePlaceholder(t *testing.T) {
	req := requestWithAuth(basicHeader("<BOXLITE_SECRET:gh>"))

	substituteHeaders(req, []SecretConfig{
		{Placeholder: "<BOXLITE_SECRET:gh>", Value: "ghp-real-token"},
	})

	if got, want := decodeBasic(t, req.Header.Get("Authorization")), "ghp-real-token"; got != want {
		t.Errorf("decoded credentials = %q, want %q", got, want)
	}
}

// Unpadded base64 is legal in the wild; it must decode and round-trip too.
func TestSubstituteHeaders_BasicAuthUnpaddedBase64(t *testing.T) {
	raw := "u:<BOXLITE_SECRET:gh>"
	req := requestWithAuth("Basic " + base64.RawStdEncoding.EncodeToString([]byte(raw)))

	substituteHeaders(req, []SecretConfig{
		{Placeholder: "<BOXLITE_SECRET:gh>", Value: "ghp-real-token"},
	})

	if got, want := decodeBasic(t, req.Header.Get("Authorization")), "u:ghp-real-token"; got != want {
		t.Errorf("decoded credentials = %q, want %q", got, want)
	}
}

// The scheme token is case-insensitive per RFC 7235.
func TestSubstituteHeaders_BasicAuthSchemeIsCaseInsensitive(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("u:<BOXLITE_SECRET:gh>"))
	req := requestWithAuth("basic " + encoded)

	substituteHeaders(req, []SecretConfig{
		{Placeholder: "<BOXLITE_SECRET:gh>", Value: "ghp-real-token"},
	})

	if got, want := decodeBasic(t, req.Header.Get("Authorization")), "u:ghp-real-token"; got != want {
		t.Errorf("decoded credentials = %q, want %q", got, want)
	}
}

// A secret bound to another host is not in this request's table, so its
// placeholder must survive the proxy untouched — the host binding is the whole
// point of `Secret.hosts`.
func TestSubstituteHeaders_BasicAuthUnboundHostIsUntouched(t *testing.T) {
	matcher := NewSecretHostMatcher([]SecretConfig{
		{Name: "gh", Hosts: []string{"github.com"}, Placeholder: "<BOXLITE_SECRET:gh>", Value: "ghp-real-token"},
	})

	original := basicHeader("x-access-token:<BOXLITE_SECRET:gh>")
	req := requestWithAuth(original)

	substituteHeaders(req, matcher.SecretsForHost("gitlab.com"))

	if got := req.Header.Get("Authorization"); got != original {
		t.Errorf("Authorization = %q, want it untouched (%q)", got, original)
	}
	if strings.Contains(decodeBasic(t, req.Header.Get("Authorization")), "ghp-real-token") {
		t.Error("a secret bound to github.com must never reach gitlab.com")
	}
}

// A Basic header with no placeholder in it must go upstream byte for byte,
// padding included — the proxy has no business re-encoding it.
func TestSubstituteHeaders_BasicAuthWithoutPlaceholderIsUntouched(t *testing.T) {
	original := basicHeader("alice:hunter2")
	req := requestWithAuth(original)

	substituteHeaders(req, []SecretConfig{
		{Placeholder: "<BOXLITE_SECRET:gh>", Value: "ghp-real-token"},
	})

	if got := req.Header.Get("Authorization"); got != original {
		t.Errorf("Authorization = %q, want it untouched (%q)", got, original)
	}
}

// A value that is not base64 at all must not be mangled.
func TestSubstituteHeaders_BasicAuthUndecodableIsUntouched(t *testing.T) {
	original := "Basic not-base64-!!!"
	req := requestWithAuth(original)

	substituteHeaders(req, []SecretConfig{
		{Placeholder: "<BOXLITE_SECRET:gh>", Value: "ghp-real-token"},
	})

	if got := req.Header.Get("Authorization"); got != original {
		t.Errorf("Authorization = %q, want it untouched (%q)", got, original)
	}
}

// Bearer credentials keep taking the literal path.
func TestSubstituteHeaders_BearerStillSubstitutedLiterally(t *testing.T) {
	req := requestWithAuth("Bearer <BOXLITE_SECRET:gh>")

	substituteHeaders(req, []SecretConfig{
		{Placeholder: "<BOXLITE_SECRET:gh>", Value: "ghp-real-token"},
	})

	if got, want := req.Header.Get("Authorization"), "Bearer ghp-real-token"; got != want {
		t.Errorf("Authorization = %q, want %q", got, want)
	}
}

// End to end through the MITM proxy against a local HTTPS upstream: the guest
// sends the placeholder, the origin server must see the real credential. This
// is the shape of `git push` over HTTPS.
func TestMITM_BasicAuthReachesUpstreamSubstituted(t *testing.T) {
	var seen string
	addr, cleanup := startTestUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
		user, pass, ok := r.BasicAuth()
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "%s|%s", user, pass)
	})
	defer cleanup()

	ca := newTestCA(t)
	secrets := []SecretConfig{
		{Name: "gh", Hosts: []string{"github.com"}, Placeholder: "<BOXLITE_SECRET:gh>", Value: "fake-token-123"},
	}
	client := dialThroughMITM(t, ca, "github.com", addr, secrets)

	req, err := http.NewRequest(http.MethodGet, "https://github.com/repo.git/info/refs", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.SetBasicAuth("x-access-token", "<BOXLITE_SECRET:gh>")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through MITM: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if got, want := string(body), "x-access-token|fake-token-123"; got != want {
		t.Errorf("upstream saw %q, want %q", got, want)
	}
	if strings.Contains(seen, "BOXLITE_SECRET") {
		t.Error("the placeholder reached the upstream server verbatim")
	}
}
