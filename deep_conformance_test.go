package trustedrouter

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSDKRedirectProtectionCoversOwnedAndInjectedClients(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/captured", http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	for name, supplied := range map[string]*http.Client{
		"owned":    nil,
		"injected": {},
	} {
		t.Run(name, func(t *testing.T) {
			zero := 0
			client, err := NewClient(Options{
				APIKey:      "secret",
				WorkspaceID: "workspace",
				BaseURL:     source.URL + "/v1",
				MaxRetries:  &zero,
				HTTPClient:  supplied,
			})
			if err != nil {
				t.Fatal(err)
			}
			err = client.Request(context.Background(), http.MethodPost, "/chat/completions", map[string]any{"prompt": "private"}, nil, &CallOptions{IdempotencyKey: "idem"})
			if err == nil {
				t.Fatal("redirect response was accepted")
			}
		})
	}
	if got := targetCalls.Load(); got != 0 {
		t.Fatalf("redirect target received %d requests", got)
	}
}

func TestCredentialFreeMetadataStripsDefaultCredentials(t *testing.T) {
	var seen http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()

	client, err := NewClient(Options{
		APIKey: "sdk-key",
		Headers: map[string]string{
			"Authorization":             "Bearer default-secret",
			"Cookie":                    "session=secret",
			"X-TrustedRouter-Workspace": "workspace",
			"Idempotency-Key":           "stale",
			"X-Tr-Client":               "stale",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Status(context.Background(), server.URL+"/status.json"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"authorization", "cookie", "x-trustedrouter-workspace", "idempotency-key", "x-tr-client"} {
		if got := seen.Get(name); got != "" {
			t.Fatalf("credential-free request carried %s=%q", name, got)
		}
	}
}

func TestCredentialFreeOAuthSuppressesInjectedCookieJar(t *testing.T) {
	var seenCookie string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenCookie = r.Header.Get("cookie")
		_, _ = io.WriteString(w, `{"key":"delegated"}`)
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(serverURL, []*http.Cookie{{Name: "session", Value: "secret"}})
	client, err := NewClient(Options{
		APIKey:         "sdk-key",
		ControlBaseURL: server.URL + "/v1",
		HTTPClient:     &http.Client{Jar: jar},
		MaxRetries:     intPtr(0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ExchangeOAuthKey(context.Background(), OAuthKeyExchangeRequest{Code: "code"}); err != nil {
		t.Fatal(err)
	}
	if seenCookie != "" {
		t.Fatalf("credential-free OAuth carried cookie %q", seenCookie)
	}
	if len(jar.Cookies(serverURL)) != 1 {
		t.Fatal("caller cookie Jar was mutated")
	}
}

func TestGenericUnsafeTransportFailureIsNotRetriedWithoutIdempotency(t *testing.T) {
	defer stubSleep(func(context.Context, time.Duration) error { return nil })()
	calls := 0
	client, err := NewClient(Options{
		MaxRetries: intPtr(2),
		HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
			calls++
			_, _ = io.ReadAll(r.Body)
			if got := r.Header.Get("idempotency-key"); got != "" {
				t.Fatalf("generic request unexpectedly minted idempotency key %q", got)
			}
			return nil, errors.New("connection reset after write")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = client.Request(context.Background(), http.MethodPost, "/custom-mutation", map[string]any{"value": 1}, nil, nil)
	if err == nil || calls != 1 {
		t.Fatalf("err = %v, calls = %d", err, calls)
	}
}

func TestHighLevelMutationRetriesWithOneStableGeneratedKey(t *testing.T) {
	defer stubSleep(func(context.Context, time.Duration) error { return nil })()
	var keys []string
	client, err := NewClient(Options{
		MaxRetries: intPtr(1),
		HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
			keys = append(keys, r.Header.Get("idempotency-key"))
			if len(keys) == 1 {
				return textResponse(http.StatusServiceUnavailable, `{"error":{"message":"retry"}}`, nil), nil
			}
			return textResponse(http.StatusOK, `{}`, nil), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Messages(context.Background(), MessagesRequest{}); err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0] == "" || keys[0] != keys[1] || !strings.HasPrefix(keys[0], "tr-req-") {
		t.Fatalf("retry keys = %#v", keys)
	}
}

func TestGeneratedIdempotencyKeysAreUniqueConcurrently(t *testing.T) {
	for name, generate := range map[string]func() string{
		"crypto":   newIdempotencyKey,
		"fallback": func() string { return newIdempotencyKeyWithEntropy(strings.NewReader("")) },
	} {
		t.Run(name, func(t *testing.T) {
			const count = 4096
			keys := make(chan string, count)
			var group sync.WaitGroup
			group.Add(count)
			for range count {
				go func() {
					defer group.Done()
					keys <- generate()
				}()
			}
			group.Wait()
			close(keys)

			seen := make(map[string]struct{}, count)
			for key := range keys {
				if !strings.HasPrefix(key, "tr-req-") {
					t.Fatalf("generated key %q has the wrong prefix", key)
				}
				if _, duplicate := seen[key]; duplicate {
					t.Fatalf("duplicate generated key %q", key)
				}
				seen[key] = struct{}{}
			}
			if len(seen) != count {
				t.Fatalf("generated %d unique keys; want %d", len(seen), count)
			}
		})
	}
}

func TestParsedSSERejectsMalformedAndPrematureStreams(t *testing.T) {
	t.Run("malformed JSON", func(t *testing.T) {
		var got error
		for _, err := range iterSSEChunks(strings.NewReader("data: {not-json}\n\ndata: [DONE]\n\n")) {
			got = err
			break
		}
		if got == nil || !strings.Contains(got.Error(), "invalid SSE JSON") {
			t.Fatalf("error = %v", got)
		}
	})

	t.Run("EOF before terminal marker", func(t *testing.T) {
		var sawChunk bool
		var got error
		for chunk, err := range iterSSEChunks(strings.NewReader("data: {\"choices\":[]}\n\n")) {
			if err != nil {
				got = err
				break
			}
			sawChunk = chunk != nil
		}
		if !sawChunk || !errors.Is(got, errSSEUnexpectedEOF) {
			t.Fatalf("sawChunk = %t, error = %v", sawChunk, got)
		}
	})

	t.Run("Responses terminal event", func(t *testing.T) {
		var events []map[string]any
		for event, err := range iterSSEEvents(strings.NewReader("event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{}}\n\n")) {
			if err != nil {
				t.Fatal(err)
			}
			events = append(events, event)
		}
		if len(events) != 1 || events[0]["type"] != "response.completed" {
			t.Fatalf("events = %#v", events)
		}
	})
}

func TestCollectCompletionPreservesChoicesAndReasoning(t *testing.T) {
	var chunks []ChatCompletionChunk
	for _, raw := range []string{
		`{"id":"chat","model":"model","system_fingerprint":"fp","choices":[{"index":1,"delta":{"role":"assistant","content":"B","reasoning_content":"think-"}},{"index":0,"delta":{"role":"assistant","content":"A","reasoning_content":"step-"}}]}`,
		`{"id":"chat","model":"model","system_fingerprint":"fp","choices":[{"index":0,"delta":{"content":"0","reasoning_content":"done"},"finish_reason":"stop"},{"index":1,"delta":{"content":"1","reasoning_content":"done"},"finish_reason":"length"}],"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}`,
	} {
		var chunk ChatCompletionChunk
		if err := json.Unmarshal([]byte(raw), &chunk); err != nil {
			t.Fatal(err)
		}
		chunks = append(chunks, chunk)
	}
	completion := CollectCompletion(chunks)
	if len(completion.Choices) != 2 || completion.Choices[0].Index != 0 || completion.Choices[1].Index != 1 {
		t.Fatalf("choices = %#v", completion.Choices)
	}
	if *completion.Choices[0].Message.Content != "A0" || *completion.Choices[1].Message.Content != "B1" {
		t.Fatalf("contents = %#v", completion.Choices)
	}
	if completion.Choices[0].Message.Extra["reasoning_content"] != "step-done" || completion.Choices[1].Message.Extra["reasoning_content"] != "think-done" {
		t.Fatalf("reasoning = %#v / %#v", completion.Choices[0].Message.Extra, completion.Choices[1].Message.Extra)
	}
	if completion.Extra["system_fingerprint"] != "fp" || completion.Usage == nil || completion.Usage.TotalTokens != 3 {
		t.Fatalf("completion metadata = %#v", completion)
	}
}
