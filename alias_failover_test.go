package trustedrouter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The domain is a single point of failure above the whole deployment. These
// prove a client actually reaches a second domain when the first stops
// answering — which it could not do before, for two independent reasons: the
// candidate list had one entry, and the loop pinned baseURLs[0] once and never
// advanced it.

func TestCandidateListHasMoreThanOneEntry(t *testing.T) {
	urls := inferenceBaseURLs(DefaultAPIBaseURL)
	if len(urls) < 2 {
		t.Fatalf("failover cannot engage with %d candidate(s): %v", len(urls), urls)
	}
	if urls[0] != strings.TrimRight(DefaultAPIBaseURL, "/") {
		t.Errorf("primary must be tried first, got %v", urls)
	}
	joined := strings.Join(urls, " ")
	for _, alias := range AliasAPIBaseURLs {
		if !strings.Contains(joined, strings.TrimRight(alias, "/")) {
			t.Errorf("alias %q missing from %v", alias, urls)
		}
	}
}

func TestACustomBaseURLIsNeverRedirectedToAPublicAlias(t *testing.T) {
	// A private deployment or test server must get exactly what it asked for.
	got := inferenceBaseURLs("https://my.internal/v1")
	if len(got) != 1 || got[0] != "https://my.internal/v1" {
		t.Fatalf("custom base was rewritten: %v", got)
	}
}

func TestA503AdvancesToTheNextCandidate(t *testing.T) {
	t.Setenv("TRUSTEDROUTER_TELEMETRY", "")
	t.Setenv("DO_NOT_TRACK", "")
	defer stubSleep(func(context.Context, time.Duration) error { return nil })()
	var seen []string
	var headers []string
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, "primary")
		headers = append(headers, r.Header.Get("x-tr-client"))
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"down"}`))
	}))
	defer primary.Close()
	alias := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, "alias")
		headers = append(headers, r.Header.Get("x-tr-client"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer alias.Close()

	// A custom BaseURL never gains aliases, so inject the pair directly: this
	// test is about the ADVANCE, which is the half that never existed. The
	// candidates keep their real domains — routed to the local servers by
	// host — so the telemetry channel sees apex and ally, not "custom".
	c, err := NewClient(Options{APIKey: "k", MaxRetries: intPtr(2), HTTPClient: &http.Client{
		Transport: newHostRoutingTransport(map[string]string{
			"api.trustedrouter.com": primary.URL,
			"api.allyrouter.com":    alias.URL,
		}),
	}})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.rawRequestWithBaseURLs(context.Background(), "GET", "/models", nil, nil,
		[]string{DefaultAPIBaseURL, strings.TrimRight(AliasAPIBaseURLs[0], "/")}, true)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if len(seen) < 2 || seen[0] != "primary" || seen[1] != "alias" {
		t.Fatalf("did not advance to the second candidate: %v", seen)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 from the alias", resp.StatusCode)
	}

	// Telemetry header channel (contract v1 §3.2): the first attempt is the
	// bare vector, and the alias attempt describes the failed apex attempt.
	if headers[0] != "v=1;a=0;s=0" {
		t.Fatalf("attempt 0 x-tr-client = %q, want %q", headers[0], "v=1;a=0;s=0")
	}
	fields := parseTelemetryHeader(t, headers[1])
	for key, want := range map[string]string{
		"v": "1", "a": "1", "po": "http_error", "pc": "none", "ph": "apex", "s": "0", "fo": "1",
	} {
		if fields[key] != want {
			t.Errorf("alias attempt %s = %q, want %q (header %q)", key, fields[key], want, headers[1])
		}
	}
	requireBoundedMs(t, fields, "pm")
	requireBoundedMs(t, fields, "sm")
}

func TestA500DoesNotAdvanceToAnotherDomain(t *testing.T) {
	// A 500 means a server received and processed the request. Inference is not
	// idempotent. The caller is not charged twice (authorization is idempotent
	// per Idempotency-Key, settlement is exactly-once) but the work would run
	// again, costing TrustedRouter a second upstream generation.
	var seen []string
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, "primary")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer primary.Close()
	alias := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, "alias")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer alias.Close()

	c, err := NewClient(Options{APIKey: "k", BaseURL: primary.URL, MaxRetries: intPtr(2)})
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := c.rawRequestWithBaseURLs(context.Background(), "GET", "/models", nil, nil,
		[]string{primary.URL, alias.URL}, true)
	if resp != nil {
		defer resp.Body.Close()
	}
	for _, h := range seen {
		if h == "alias" {
			t.Fatalf("a 500 leaked to another domain: %v", seen)
		}
	}
}

func intPtr(v int) *int { return &v }
