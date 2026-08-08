package trustedrouter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	var seen []string
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, "primary")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"down"}`))
	}))
	defer primary.Close()
	alias := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, "alias")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer alias.Close()

	c, err := NewClient(Options{APIKey: "k", BaseURL: primary.URL, MaxRetries: intPtr(2)})
	if err != nil {
		t.Fatal(err)
	}
	// A custom BaseURL never gains aliases, so inject the pair directly: this
	// test is about the ADVANCE, which is the half that never existed.
	resp, err := c.rawRequestWithBaseURLs(context.Background(), "GET", "/models", nil, nil,
		[]string{primary.URL, alias.URL}, true)
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
}

func TestA500DoesNotAdvanceToAnotherDomain(t *testing.T) {
	// A 500 means a server received and processed the request. Inference is not
	// idempotent, so moving it to another domain risks charging twice.
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
