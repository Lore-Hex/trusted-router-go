package trustedrouter

// Streaming twins of the buffered retry-policy tests. Until the transport
// unification, NO test pinned stream-open retry policy — which is exactly
// where the drift lived (stream opens ignored x-should-retry, never walked
// candidates, and a pinned client did not retry a failed open at all).

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

const streamOKBody = `data: {"choices":[{"delta":{"content":"OK"},"finish_reason":"stop"}]}` + "\n\n"

func collectStreamText(t *testing.T, sdk *Client) (string, error) {
	t.Helper()
	var tokens []string
	for token, err := range sdk.ChatCompletionsText(context.Background(), ChatRequest{
		Messages: []map[string]any{{"role": "user", "content": "hi"}},
	}) {
		if err != nil {
			return strings.Join(tokens, ""), err
		}
		tokens = append(tokens, token)
	}
	return strings.Join(tokens, ""), nil
}

// Streaming twin of TestALabelledSpent502IsNotRetried: an explicit
// x-should-retry: false on a stream open forbids retry AND failover, even
// with retries left and multiple candidates available.
func TestALabelledSpent502IsNotRetriedOnStreamOpen(t *testing.T) {
	restore := stubSleep(func(context.Context, time.Duration) error { return nil })
	defer restore()

	calls := 0
	maxRetries := 3
	sdk, err := NewClient(Options{
		MaxRetries: &maxRetries,
		HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
			calls++
			return textResponse(http.StatusBadGateway, "settlement failed",
				http.Header{"X-Should-Retry": []string{"false"}}), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, gotErr := collectStreamText(t, sdk)
	var internal *InternalError
	if !errors.As(gotErr, &internal) || internal.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected the labelled 502 to surface, got %T %[1]v", gotErr)
	}
	if calls != 1 {
		t.Fatalf("a labelled 502 stream open was sent %d times; the gateway said not to retry it", calls)
	}
}

// Streaming twin of TestALabelledRetryableStatusIsRetriedEvenWhenTheStatusSaysOtherwise:
// an explicit x-should-retry: true forces a stream-open retry even on a
// status the heuristics would surface.
func TestALabelledRetryableStatusIsRetriedOnStreamOpen(t *testing.T) {
	restore := stubSleep(func(context.Context, time.Duration) error { return nil })
	defer restore()

	calls := 0
	maxRetries := 2
	sdk, err := NewClient(Options{
		MaxRetries: &maxRetries,
		HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return textResponse(http.StatusBadRequest, "transient",
					http.Header{"X-Should-Retry": []string{"true"}}), nil
			}
			return textResponse(200, streamOKBody, http.Header{"Content-Type": []string{"text/event-stream"}}), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	text, gotErr := collectStreamText(t, sdk)
	if gotErr != nil {
		t.Fatalf("server said retry and the stream open error surfaced instead: %v", gotErr)
	}
	if text != "OK" || calls != 2 {
		t.Fatalf("text = %q, calls = %d", text, calls)
	}
}

// Streaming twin of TestPinnedClientStillRetriesInPlace, covering BOTH branch
// families: a transport error on open (which previously returned immediately
// whenever RegionalFailover was off) and a retryable 503 open. The pinned
// client retries in place; every attempt stays on the host the caller named.
func TestPinnedStreamRetriesInPlace(t *testing.T) {
	restore := stubSleep(func(context.Context, time.Duration) error { return nil })
	defer restore()

	var seenHosts []string
	disabled := false
	maxRetries := 2
	sdk, err := NewClient(Options{
		RegionalFailover: &disabled,
		MaxRetries:       &maxRetries,
		HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
			seenHosts = append(seenHosts, r.URL.Host)
			switch len(seenHosts) {
			case 1:
				return nil, errors.New("dial failed")
			case 2:
				return textResponse(http.StatusServiceUnavailable, "draining", nil), nil
			default:
				return textResponse(200, streamOKBody, http.Header{"Content-Type": []string{"text/event-stream"}}), nil
			}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	text, gotErr := collectStreamText(t, sdk)
	if gotErr != nil {
		t.Fatalf("a pinned client should still retry a failed stream open on its own host: %v", gotErr)
	}
	if text != "OK" {
		t.Fatalf("text = %q", text)
	}
	if got := strings.Join(seenHosts, ","); got != "api.trustedrouter.com,api.trustedrouter.com,api.trustedrouter.com" {
		t.Fatalf("pinned stream moved hosts: %#v", seenHosts)
	}
}

// Streaming twin of TestA503AdvancesToTheNextCandidate: a failoverable status
// on stream open advances to the alias domain, and the server-supplied
// retry-after floors the backoff sleep (retry-after-ms wins, as buffered).
func TestStreamOpenWalksCandidatesAndHonorsRetryAfter(t *testing.T) {
	var sleeps []time.Duration
	restore := stubSleep(func(_ context.Context, d time.Duration) error {
		sleeps = append(sleeps, d)
		return nil
	})
	defer restore()

	var seenHosts []string
	maxRetries := 2
	sdk, err := NewClient(Options{
		MaxRetries: &maxRetries,
		HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
			seenHosts = append(seenHosts, r.URL.Host)
			if len(seenHosts) == 1 {
				return textResponse(http.StatusServiceUnavailable, "regional gateway unavailable",
					http.Header{"Retry-After-Ms": []string{"250"}}), nil
			}
			return textResponse(200, streamOKBody, http.Header{"Content-Type": []string{"text/event-stream"}}), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	text, gotErr := collectStreamText(t, sdk)
	if gotErr != nil {
		t.Fatal(gotErr)
	}
	if text != "OK" {
		t.Fatalf("text = %q", text)
	}
	if got := strings.Join(seenHosts, ","); got != "api.trustedrouter.com,api.allyrouter.com" {
		t.Fatalf("stream open did not walk to the alias: %#v", seenHosts)
	}
	if len(sleeps) != 1 || sleeps[0] < 250*time.Millisecond {
		t.Fatalf("stream open retry-after not honored: %#v", sleeps)
	}
}
