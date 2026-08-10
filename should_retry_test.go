package trustedrouter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The gateway's x-should-retry verdict overrides our status heuristics. A
// status code cannot say whether a provider already ran: a 502 from "could not
// reach the provider" and a 502 from "the generation succeeded and then
// settlement failed" are indistinguishable here, and only the second is
// dangerous to re-send.

func TestShouldRetryVerdictOnlySpeaksWhenTheServerDid(t *testing.T) {
	if got := shouldRetryVerdict(http.Header{}); got != nil {
		t.Fatalf("absent header should be nil, got %v", *got)
	}
	if got := shouldRetryVerdict(http.Header{"X-Should-Retry": []string{"TRUE"}}); got == nil || !*got {
		t.Fatalf("true should parse, got %v", got)
	}
	if got := shouldRetryVerdict(http.Header{"X-Should-Retry": []string{"false"}}); got == nil || *got {
		t.Fatalf("false should parse, got %v", got)
	}
	if got := shouldRetryVerdict(http.Header{"X-Should-Retry": []string{"perhaps"}}); got != nil {
		t.Fatalf("junk must not be read as a verdict, got %v", *got)
	}
}

func TestALabelledSpent502IsNotRetried(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("X-Should-Retry", "false")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":{"message":"settlement failed"}}`))
	}))
	defer server.Close()

	client, err := NewClient(Options{APIKey: "sk-test", BaseURL: server.URL + "/v1", MaxRetries: intPtr(3)})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	var out map[string]any
	if err := client.Request(context.Background(), http.MethodGet, "/models", nil, &out, nil); err == nil {
		t.Fatal("expected the 502 to surface")
	}
	if calls != 1 {
		t.Fatalf("a labelled 502 was sent %d times; the gateway said not to retry it", calls)
	}
}

func TestALabelledRetryableStatusIsRetriedEvenWhenTheStatusSaysOtherwise(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			w.Header().Set("X-Should-Retry", "true")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"message":"transient"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client, err := NewClient(Options{APIKey: "sk-test", BaseURL: server.URL + "/v1", MaxRetries: intPtr(2)})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	var out map[string]any
	if err := client.Request(context.Background(), http.MethodGet, "/models", nil, &out, nil); err != nil {
		t.Fatalf("request: %v", err)
	}
	if calls != 2 {
		t.Fatalf("server said retry and we sent %d times", calls)
	}
}

// TestPinnedClientStillRetriesInPlace covers the semantic split: RegionalFailover
// used to answer two questions at once, so turning it off also stopped retrying
// 502/503/504 entirely. It now governs only WHERE a retry goes.
func TestPinnedClientStillRetriesInPlace(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":{"message":"draining"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	disabled := false
	client, err := NewClient(Options{
		APIKey:           "sk-test",
		BaseURL:          server.URL + "/v1",
		MaxRetries:       intPtr(2),
		RegionalFailover: &disabled,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	var out map[string]any
	if err := client.Request(context.Background(), http.MethodGet, "/models", nil, &out, nil); err != nil {
		t.Fatalf("a pinned client should still retry a 503 on its own host: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected one retry in place, got %d attempts", calls)
	}
}

func TestRetryAfterMsIsHonoredAndBeatsRetryAfter(t *testing.T) {
	only := retryAfterSeconds(http.Header{"Retry-After-Ms": []string{"250"}})
	if only == nil || *only != 0.25 {
		t.Fatalf("retry-after-ms = %v, want 0.25", only)
	}
	both := retryAfterSeconds(http.Header{
		"Retry-After-Ms": []string{"500"},
		"Retry-After":    []string{"9"},
	})
	if both == nil || *both != 0.5 {
		t.Fatalf("the precise header should win, got %v", both)
	}
	junk := retryAfterSeconds(http.Header{
		"Retry-After-Ms": []string{"soon"},
		"Retry-After":    []string{"3"},
	})
	if junk == nil || *junk != 3 {
		t.Fatalf("junk should fall through to retry-after, got %v", junk)
	}
}
