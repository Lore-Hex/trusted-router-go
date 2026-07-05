package trustedrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestClientConstruction(t *testing.T) {
	client, err := NewClient(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if client.BaseURL() != DefaultAPIBaseURL {
		t.Fatalf("base url = %q", client.BaseURL())
	}
	if client.ControlBaseURL() != DefaultControlBaseURL {
		t.Fatalf("control base url = %q", client.ControlBaseURL())
	}
	if got := client.BaseURLs(); strings.Join(got, ",") != DefaultAPIBaseURL {
		t.Fatalf("base urls = %#v", got)
	}

	explicit, err := NewClient(Options{BaseURL: "https://example.test/v1/"})
	if err != nil {
		t.Fatal(err)
	}
	if explicit.BaseURL() != "https://example.test/v1" {
		t.Fatalf("explicit base url = %q", explicit.BaseURL())
	}
	if explicit.ControlBaseURL() != DefaultControlBaseURL {
		t.Fatalf("explicit control base url = %q", explicit.ControlBaseURL())
	}
	if len(explicit.BaseURLs()) != 1 {
		t.Fatalf("explicit default failover = %#v", explicit.BaseURLs())
	}

	enabled := true
	failover, err := NewClient(Options{
		BaseURL:          "https://example.test/v1",
		RegionalFailover: &enabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := failover.BaseURLs(); strings.Join(got, ",") != "https://example.test/v1" {
		t.Fatalf("explicit failover urls = %#v", got)
	}
}

func TestDefaultInferenceAndControlHostsByMethod(t *testing.T) {
	type seenRequest struct {
		method string
		path   string
		host   string
	}
	var seen []seenRequest
	sdk, err := NewClient(Options{
		HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
			seen = append(seen, seenRequest{
				method: r.Method,
				path:   r.URL.Path,
				host:   requestHost(r),
			})
			switch r.URL.Path {
			case "/v1/models":
				return jsonResponse(http.StatusOK, map[string]any{"data": []any{}}, nil), nil
			case "/v1/providers":
				return jsonResponse(http.StatusOK, map[string]any{"data": []any{}}, nil), nil
			case "/v1/credits":
				return jsonResponse(http.StatusOK, map[string]any{"data": map[string]any{"balance": 0}}, nil), nil
			case "/v1/auth/keys":
				return jsonResponse(http.StatusOK, map[string]any{"key": "sk-tr-v1-delegated"}, nil), nil
			case "/v1/broadcast/destinations":
				return jsonResponse(http.StatusOK, map[string]any{"data": []any{}}, nil), nil
			case "/v1/billing/checkout":
				return jsonResponse(http.StatusOK, map[string]any{"url": "https://checkout.example/session"}, nil), nil
			case "/v1/chat/completions":
				return textResponse(http.StatusOK, `data: {"id":"chat_1","choices":[{"delta":{"content":"ok"},"finish_reason":"stop"}]}`+"\n\n", http.Header{"Content-Type": []string{"text/event-stream"}}), nil
			case "/v1/messages":
				return jsonResponse(http.StatusOK, map[string]any{
					"id":      "msg_1",
					"role":    "assistant",
					"content": []map[string]any{{"type": "text", "text": "ok"}},
					"model":   "model/a",
				}, nil), nil
			case "/v1/responses":
				return jsonResponse(http.StatusOK, map[string]any{"id": "resp_1", "object": "response"}, nil), nil
			case "/v1/embeddings":
				return jsonResponse(http.StatusOK, map[string]any{
					"data":  []map[string]any{{"index": 0, "embedding": []float64{0.1}}},
					"model": "embed/model",
				}, nil), nil
			default:
				t.Fatalf("unexpected request = %s %s", r.Method, r.URL.String())
				return nil, nil
			}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sdk.Models(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := sdk.Providers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := sdk.Credits(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := sdk.ExchangeOAuthKey(context.Background(), OAuthKeyExchangeRequest{Code: "auth-code"}); err != nil {
		t.Fatal(err)
	}
	if _, err := sdk.BroadcastDestinations(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := sdk.BillingCheckout(context.Background(), BillingCheckoutRequest{Amount: 1}); err != nil {
		t.Fatal(err)
	}
	for text, err := range sdk.ChatCompletionsText(context.Background(), ChatRequest{
		Messages: []map[string]any{{"role": "user", "content": "hi"}},
	}) {
		if err != nil {
			t.Fatal(err)
		}
		if text != "ok" {
			t.Fatalf("chat text = %q", text)
		}
	}
	if _, err := sdk.Messages(context.Background(), MessagesRequest{
		Model:    "model/a",
		Messages: []map[string]any{{"role": "user", "content": "hi"}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := sdk.Responses(context.Background(), ResponsesRequest{Input: "hi"}); err != nil {
		t.Fatal(err)
	}
	if _, err := sdk.Embeddings(context.Background(), EmbeddingsRequest{
		Model: "embed/model",
		Input: "hi",
	}); err != nil {
		t.Fatal(err)
	}

	want := []seenRequest{
		{method: http.MethodGet, path: "/v1/models", host: "trustedrouter.com"},
		{method: http.MethodGet, path: "/v1/providers", host: "trustedrouter.com"},
		{method: http.MethodGet, path: "/v1/credits", host: "trustedrouter.com"},
		{method: http.MethodPost, path: "/v1/auth/keys", host: "trustedrouter.com"},
		{method: http.MethodGet, path: "/v1/broadcast/destinations", host: "trustedrouter.com"},
		{method: http.MethodPost, path: "/v1/billing/checkout", host: "trustedrouter.com"},
		{method: http.MethodPost, path: "/v1/chat/completions", host: "api.trustedrouter.com"},
		{method: http.MethodPost, path: "/v1/messages", host: "api.trustedrouter.com"},
		{method: http.MethodPost, path: "/v1/responses", host: "api.trustedrouter.com"},
		{method: http.MethodPost, path: "/v1/embeddings", host: "api.trustedrouter.com"},
	}
	if len(seen) != len(want) {
		t.Fatalf("seen = %#v", seen)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("request %d = %#v, want %#v", i, seen[i], want[i])
		}
	}
}

func TestControlBaseURLOverride(t *testing.T) {
	var seenURL string
	sdk, err := NewClient(Options{
		BaseURL:        "https://api.override.test/v1/",
		ControlBaseURL: "https://control.override.test/v1/",
		HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
			seenURL = r.URL.String()
			return jsonResponse(http.StatusOK, map[string]any{"data": []any{}}, nil), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if sdk.BaseURL() != "https://api.override.test/v1" || sdk.ControlBaseURL() != "https://control.override.test/v1" {
		t.Fatalf("bases = %q %q", sdk.BaseURL(), sdk.ControlBaseURL())
	}
	if _, err := sdk.Models(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if seenURL != "https://control.override.test/v1/models" {
		t.Fatalf("models URL = %s", seenURL)
	}
	authorizeURL, err := sdk.OAuthAuthorizeURL(OAuthAuthorizeURLOptions{CallbackURL: "https://app.example/cb"})
	if err != nil {
		t.Fatal(err)
	}
	parsed := mustParseURL(t, authorizeURL)
	if parsed.Scheme != "https" || parsed.Host != "control.override.test" || parsed.Path != "/v1/auth" {
		t.Fatalf("authorize URL = %s", authorizeURL)
	}
}

func TestControlRequestsDoNotUseRegionalFailover(t *testing.T) {
	restore := stubSleep(func(context.Context, time.Duration) error { return nil })
	defer restore()

	var seenHosts []string
	enabled := true
	maxRetries := 1
	sdk, err := NewClient(Options{
		RegionalFailover: &enabled,
		MaxRetries:       &maxRetries,
		HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
			seenHosts = append(seenHosts, requestHost(r))
			return jsonResponse(http.StatusServiceUnavailable, map[string]any{"error": map[string]any{"message": "down"}}, nil), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = sdk.Models(context.Background(), nil)
	var internal *InternalError
	if !errors.As(err, &internal) || internal.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected final 503 InternalError, got %T %[1]v", err)
	}
	if got := strings.Join(seenHosts, ","); got != "trustedrouter.com,trustedrouter.com" {
		t.Fatalf("control hosts = %#v", seenHosts)
	}
}

func TestClientTimeoutDefaultsAndIntrospection(t *testing.T) {
	client, err := NewClient(Options{
		APIKey:      "key",
		WorkspaceID: "workspace",
		Headers:     map[string]string{"x-default": "yes"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if client.APIKey() != "key" || client.WorkspaceID() != "workspace" || client.MaxRetries() != defaultMaxRetries {
		t.Fatalf("introspection mismatch: key=%q workspace=%q retries=%d", client.APIKey(), client.WorkspaceID(), client.MaxRetries())
	}
	if client.httpClient.Timeout != 0 {
		t.Fatalf("sdk-owned http client timeout = %s", client.httpClient.Timeout)
	}
	if client.timeout == nil || *client.timeout != DefaultRequestTimeout {
		t.Fatalf("default sdk timeout = %v", client.timeout)
	}
	headers := client.DefaultHeaders()
	headers["x-default"] = "changed"
	if client.DefaultHeaders()["x-default"] != "yes" {
		t.Fatal("DefaultHeaders did not return a copy")
	}

	noTimeout := time.Duration(0)
	client, err = NewClient(Options{Timeout: &noTimeout})
	if err != nil {
		t.Fatal(err)
	}
	if client.httpClient.Timeout != 0 {
		t.Fatalf("sdk-owned http client timeout = %s", client.httpClient.Timeout)
	}
	if client.timeout != nil {
		t.Fatalf("explicit zero sdk timeout = %v", client.timeout)
	}

	supplied := &http.Client{Timeout: 17 * time.Second}
	client, err = NewClient(Options{HTTPClient: supplied, Timeout: &noTimeout})
	if err != nil {
		t.Fatal(err)
	}
	if client.httpClient != supplied || client.httpClient.Timeout != 17*time.Second {
		t.Fatalf("supplied client not respected: %#v", client.httpClient)
	}
}

func TestCallOptionsAPIKeyAndWorkspacePointerSemantics(t *testing.T) {
	var seen []http.Header
	sdk, err := NewClient(Options{
		APIKey:      "client-key",
		WorkspaceID: "client-workspace",
		HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
			seen = append(seen, r.Header.Clone())
			return jsonResponse(200, map[string]any{"ok": true}, nil), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := sdk.Request(context.Background(), http.MethodGet, "/models", nil, &out, nil); err != nil {
		t.Fatal(err)
	}
	empty := ""
	if err := sdk.Request(context.Background(), http.MethodGet, "/models", nil, &out, &CallOptions{
		APIKey:      &empty,
		WorkspaceID: &empty,
	}); err != nil {
		t.Fatal(err)
	}
	if err := sdk.Request(context.Background(), http.MethodGet, "/models", nil, &out, &CallOptions{
		APIKey:      &empty,
		WorkspaceID: &empty,
		ExtraHeaders: map[string]string{
			"authorization":               "Bearer extra",
			"x-trustedrouter-workspace":   "extra-workspace",
			"x-call-suppression-survives": "yes",
		},
	}); err != nil {
		t.Fatal(err)
	}
	if got := seen[0].Get("authorization"); got != "Bearer client-key" {
		t.Fatalf("inherited authorization = %q", got)
	}
	if got := seen[0].Get("x-trustedrouter-workspace"); got != "client-workspace" {
		t.Fatalf("inherited workspace = %q", got)
	}
	if got := seen[1].Get("authorization"); got != "" {
		t.Fatalf("suppressed authorization = %q", got)
	}
	if got := seen[1].Get("x-trustedrouter-workspace"); got != "" {
		t.Fatalf("suppressed workspace = %q", got)
	}
	if got := seen[2].Get("authorization"); got != "Bearer extra" {
		t.Fatalf("extra authorization after suppression = %q", got)
	}
	if got := seen[2].Get("x-trustedrouter-workspace"); got != "extra-workspace" {
		t.Fatalf("extra workspace after suppression = %q", got)
	}
}

func TestHeaderPrecedenceAndUserAgentShape(t *testing.T) {
	var seen http.Header
	sdk, err := NewClient(Options{
		Headers: map[string]string{
			"user-agent": "constructor",
			"x-order":    "constructor",
		},
		HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
			seen = r.Header.Clone()
			return jsonResponse(200, map[string]any{"ok": true}, nil), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := sdk.Request(context.Background(), http.MethodPost, "/models", map[string]any{"ok": true}, &out, &CallOptions{
		ExtraHeaders: map[string]string{
			"user-agent": "call",
			"x-order":    "call",
		},
	}); err != nil {
		t.Fatal(err)
	}
	if seen.Get("user-agent") != "call" || seen.Get("x-order") != "call" {
		t.Fatalf("call headers did not win: %#v", seen)
	}

	apiKey := "k2"
	workspaceID := "w2"
	if err := sdk.Request(context.Background(), http.MethodPost, "/models", map[string]any{"ok": true}, &out, &CallOptions{
		APIKey:         &apiKey,
		WorkspaceID:    &workspaceID,
		IdempotencyKey: "typed-idem",
		ExtraHeaders: map[string]string{
			"authorization":             "Bearer header",
			"x-trustedrouter-workspace": "header-workspace",
			"idempotency-key":           "header-idem",
		},
	}); err != nil {
		t.Fatal(err)
	}
	if got := seen.Get("authorization"); got != "Bearer k2" {
		t.Fatalf("typed authorization did not win: %q", got)
	}
	if got := seen.Get("x-trustedrouter-workspace"); got != "w2" {
		t.Fatalf("typed workspace did not win: %q", got)
	}
	if got := seen.Get("idempotency-key"); got != "typed-idem" {
		t.Fatalf("typed idempotency did not win: %q", got)
	}

	if err := sdk.Request(context.Background(), http.MethodGet, "/models", nil, &out, nil); err != nil {
		t.Fatal(err)
	}
	wantUA := "trusted-router-go/" + Version + " go/" + runtime.Version() + " " + runtime.GOOS
	if seen.Get("user-agent") != wantUA {
		t.Fatalf("user-agent = %q, want %q", seen.Get("user-agent"), wantUA)
	}
}

func TestCallOptionsTimeoutSetsRequestDeadline(t *testing.T) {
	timeout := 5 * time.Second
	var sawDeadline bool
	sdk, err := NewClient(Options{HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		sawDeadline = ok && time.Until(deadline) <= timeout
		return jsonResponse(200, map[string]any{"ok": true}, nil), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := sdk.Request(context.Background(), http.MethodGet, "/models", nil, &out, &CallOptions{Timeout: &timeout}); err != nil {
		t.Fatal(err)
	}
	if !sawDeadline {
		t.Fatal("per-call timeout did not set a request deadline")
	}
}

func TestRawRequestSendsRawBodiesVerbatim(t *testing.T) {
	rawBody := []byte("{\n  \"html\": \"<b> & " + "\u2028" + "\"\n}\n")

	for _, tc := range []struct {
		name string
		body any
	}{
		{name: "json.RawMessage", body: json.RawMessage(rawBody)},
		{name: "[]byte", body: rawBody},
	} {
		t.Run(tc.name, func(t *testing.T) {
			captures := make(chan requestCapture, 1)
			server, client := newPipeHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				data, err := io.ReadAll(r.Body)
				captures <- requestCapture{
					body:        data,
					contentType: r.Header.Get("Content-Type"),
					err:         err,
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"ok":true}`))
			}))

			sdk, err := NewClient(Options{BaseURL: server.URL, HTTPClient: client})
			if err != nil {
				t.Fatal(err)
			}
			resp, err := sdk.RawRequest(context.Background(), http.MethodPost, "/passthrough", tc.body, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				t.Fatal(err)
			}

			capture := <-captures
			if capture.err != nil {
				t.Fatal(capture.err)
			}
			if !bytes.Equal(capture.body, rawBody) {
				t.Fatalf("body = %q, want byte-identical %q", capture.body, rawBody)
			}
			if capture.contentType != "application/json" {
				t.Fatalf("content-type = %q", capture.contentType)
			}
		})
	}
}

func TestRawRequestMarshalsStructBody(t *testing.T) {
	body := struct {
		HTML string `json:"html"`
	}{
		HTML: "<b> & \u2028",
	}
	want, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	captures := make(chan requestCapture, 1)
	server, client := newPipeHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		captures <- requestCapture{body: data, err: err}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))

	sdk, err := NewClient(Options{BaseURL: server.URL, HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := sdk.RawRequest(context.Background(), http.MethodPost, "/passthrough", body, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}

	capture := <-captures
	if capture.err != nil {
		t.Fatal(capture.err)
	}
	if !bytes.Equal(capture.body, want) {
		t.Fatalf("body = %q, want json.Marshal output %q", capture.body, want)
	}
}

func TestCallOptionsTimeoutOverridesClientDefaultPerAttempt(t *testing.T) {
	clientTimeout := 50 * time.Millisecond
	maxRetries := 0
	sdk, err := NewClient(Options{
		Timeout:    &clientTimeout,
		MaxRetries: &maxRetries,
		HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
			select {
			case <-time.After(200 * time.Millisecond):
				return jsonResponse(200, map[string]any{"ok": true}, nil), nil
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	var out map[string]any
	err = sdk.Request(context.Background(), http.MethodGet, "/models", nil, &out, nil)
	var internal *InternalError
	if !errors.As(err, &internal) {
		t.Fatalf("expected InternalError from client default timeout, got %T %[1]v", err)
	}

	callTimeout := time.Second
	if err := sdk.Request(context.Background(), http.MethodGet, "/models", nil, &out, &CallOptions{Timeout: &callTimeout}); err != nil {
		t.Fatalf("per-call timeout should override client default: %v", err)
	}
	if out["ok"] != true {
		t.Fatalf("out = %#v", out)
	}
}

func TestRequestTimeoutResetsForEachRetryAttempt(t *testing.T) {
	restore := stubSleep(func(context.Context, time.Duration) error { return nil })
	defer restore()

	timeout := 50 * time.Millisecond
	maxRetries := 1
	calls := 0
	sdk, err := NewClient(Options{
		MaxRetries: &maxRetries,
		HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				<-r.Context().Done()
				return nil, r.Context().Err()
			}
			select {
			case <-time.After(10 * time.Millisecond):
				return jsonResponse(200, map[string]any{"ok": true}, nil), nil
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	var out map[string]any
	if err := sdk.Request(context.Background(), http.MethodGet, "/models", nil, &out, &CallOptions{Timeout: &timeout}); err != nil {
		t.Fatalf("second attempt should get a fresh timeout budget: %v", err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d", calls)
	}
	if out["ok"] != true {
		t.Fatalf("out = %#v", out)
	}
}

func TestRequestRetries429AndHonorsRetryAfter(t *testing.T) {
	var sleeps []time.Duration
	restore := stubSleep(func(_ context.Context, d time.Duration) error {
		sleeps = append(sleeps, d)
		return nil
	})
	defer restore()

	calls := 0
	client := newRoundTripClient(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return jsonResponse(429, map[string]any{"error": map[string]any{"message": "slow"}}, http.Header{"Retry-After": []string{"0.25"}}), nil
		}
		return jsonResponse(200, map[string]any{"ok": true}, nil), nil
	})
	sdk, err := NewClient(Options{HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}

	var out map[string]any
	if err := sdk.Request(context.Background(), http.MethodGet, "/models", nil, &out, nil); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d", calls)
	}
	if len(sleeps) != 1 || sleeps[0] < 250*time.Millisecond {
		t.Fatalf("retry-after sleep not honored: %#v", sleeps)
	}
}

func TestRequestRetryAndErrorBehavior(t *testing.T) {
	restore := stubSleep(func(context.Context, time.Duration) error { return nil })
	defer restore()

	t.Run("500 then success", func(t *testing.T) {
		calls := 0
		sdk, err := NewClient(Options{HTTPClient: newRoundTripClient(func(*http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return jsonResponse(500, map[string]any{"error": map[string]any{"message": "down"}}, nil), nil
			}
			return jsonResponse(200, map[string]any{"ok": true}, nil), nil
		})})
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := sdk.Request(context.Background(), http.MethodGet, "/models", nil, &out, nil); err != nil {
			t.Fatal(err)
		}
		if calls != 2 {
			t.Fatalf("calls = %d", calls)
		}
	})

	t.Run("400 no retry", func(t *testing.T) {
		calls := 0
		sdk, err := NewClient(Options{HTTPClient: newRoundTripClient(func(*http.Request) (*http.Response, error) {
			calls++
			return jsonResponse(400, map[string]any{"error": map[string]any{"message": "bad"}}, nil), nil
		})})
		if err != nil {
			t.Fatal(err)
		}
		err = sdk.Request(context.Background(), http.MethodGet, "/models", nil, nil, nil)
		var bad *BadRequestError
		if !errors.As(err, &bad) {
			t.Fatalf("expected BadRequestError, got %T %[1]v", err)
		}
		var base *Error
		if !errors.As(err, &base) || base.StatusCode != 400 {
			t.Fatalf("expected base Error via errors.As, got %#v", base)
		}
		if calls != 1 {
			t.Fatalf("calls = %d", calls)
		}
	})

	t.Run("400 401 404 no retry", func(t *testing.T) {
		for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound} {
			t.Run(http.StatusText(status), func(t *testing.T) {
				maxRetries := 2
				calls := 0
				sdk, err := NewClient(Options{MaxRetries: &maxRetries, HTTPClient: newRoundTripClient(func(*http.Request) (*http.Response, error) {
					calls++
					return jsonResponse(status, map[string]any{"error": map[string]any{"message": "no retry"}}, nil), nil
				})})
				if err != nil {
					t.Fatal(err)
				}
				err = sdk.Request(context.Background(), http.MethodGet, "/models", nil, nil, nil)
				if err == nil {
					t.Fatal("expected error")
				}
				if calls != 1 {
					t.Fatalf("calls = %d", calls)
				}
			})
		}
	})

	t.Run("retries exhausted returns last error", func(t *testing.T) {
		maxRetries := 2
		calls := 0
		sdk, err := NewClient(Options{MaxRetries: &maxRetries, HTTPClient: newRoundTripClient(func(*http.Request) (*http.Response, error) {
			calls++
			return jsonResponse(503, map[string]any{"error": map[string]any{"message": "down"}}, nil), nil
		})})
		if err != nil {
			t.Fatal(err)
		}
		err = sdk.Request(context.Background(), http.MethodGet, "/models", nil, nil, nil)
		var internal *InternalError
		if !errors.As(err, &internal) || internal.StatusCode != 503 {
			t.Fatalf("expected InternalError 503, got %T %[1]v", err)
		}
		if calls != 3 {
			t.Fatalf("calls = %d", calls)
		}
	})
}

func TestTransportExhaustionRetriesApex(t *testing.T) {
	restore := stubSleep(func(context.Context, time.Duration) error { return nil })
	defer restore()

	var seenHosts []string
	maxRetries := 2
	sdk, err := NewClient(Options{
		MaxRetries: &maxRetries,
		HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
			seenHosts = append(seenHosts, r.URL.Host)
			return nil, errors.New("dial failed")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	err = sdk.Request(context.Background(), http.MethodGet, "/models", nil, nil, nil)
	var internal *InternalError
	if !errors.As(err, &internal) {
		t.Fatalf("expected InternalError, got %T %[1]v", err)
	}
	if !strings.HasPrefix(internal.Message, "TrustedRouter endpoint unavailable: ") || !strings.Contains(internal.Message, "dial failed") {
		t.Fatalf("message = %q", internal.Message)
	}
	wantHosts := "api.trustedrouter.com,api.trustedrouter.com,api.trustedrouter.com"
	if strings.Join(seenHosts, ",") != wantHosts {
		t.Fatalf("hosts = %#v", seenHosts)
	}
}

func TestRegionalFailoverAndChatIdempotency(t *testing.T) {
	restore := stubSleep(func(context.Context, time.Duration) error { return nil })
	defer restore()

	var seenHosts []string
	var seenKeys []string
	enabled := true
	maxRetries := 1
	sdk, err := NewClient(Options{
		RegionalFailover: &enabled,
		MaxRetries:       &maxRetries,
		HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
			seenHosts = append(seenHosts, r.URL.Host)
			seenKeys = append(seenKeys, r.Header.Get("idempotency-key"))
			if len(seenHosts) == 1 {
				return textResponse(503, "regional gateway unavailable", nil), nil
			}
			return textResponse(200, `data: {"choices":[{"delta":{"content":"OK"},"finish_reason":"stop"}]}`+"\n\n", http.Header{"Content-Type": []string{"text/event-stream"}}), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	var tokens []string
	for token, err := range sdk.ChatCompletionsText(context.Background(), ChatRequest{
		Messages: []map[string]any{{"role": "user", "content": "hi"}},
	}) {
		if err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, token)
	}
	if strings.Join(tokens, "") != "OK" {
		t.Fatalf("tokens = %#v", tokens)
	}
	if strings.Join(seenHosts, ",") != "api.trustedrouter.com,api.trustedrouter.com" {
		t.Fatalf("hosts = %#v", seenHosts)
	}
	if len(seenKeys) != 2 || seenKeys[0] == "" || seenKeys[0] != seenKeys[1] || !strings.HasPrefix(seenKeys[0], "tr-req-") {
		t.Fatalf("idempotency keys = %#v", seenKeys)
	}
}

func TestErrorTaxonomy(t *testing.T) {
	cases := []struct {
		status int
		check  func(error) bool
	}{
		{400, func(err error) bool { var target *BadRequestError; return errors.As(err, &target) }},
		{401, func(err error) bool { var target *AuthenticationError; return errors.As(err, &target) }},
		{403, func(err error) bool { var target *PermissionDeniedError; return errors.As(err, &target) }},
		{404, func(err error) bool { var target *NotFoundError; return errors.As(err, &target) }},
		{422, func(err error) bool { var target *BadRequestError; return errors.As(err, &target) }},
		{429, func(err error) bool {
			var target *RateLimitError
			return errors.As(err, &target) && target.RetryAfter != nil && *target.RetryAfter == 7
		}},
		{501, func(err error) bool { var target *EndpointNotSupportedError; return errors.As(err, &target) }},
		{500, func(err error) bool { var target *InternalError; return errors.As(err, &target) }},
	}

	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			maxRetries := 0
			sdk, err := NewClient(Options{MaxRetries: &maxRetries, HTTPClient: newRoundTripClient(func(*http.Request) (*http.Response, error) {
				headers := http.Header{}
				if tc.status == 429 {
					headers.Set("Retry-After", "7")
				}
				return jsonResponse(tc.status, map[string]any{"error": map[string]any{"message": "boom"}}, headers), nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			err = sdk.Request(context.Background(), http.MethodGet, "/models", nil, nil, nil)
			if !tc.check(err) {
				t.Fatalf("unexpected error type: %T %[1]v", err)
			}
		})
	}

	if retryAfterSeconds(http.Header{"Retry-After": []string{"Tue, 15 Nov 2025 12:00:00 GMT"}}) != nil {
		t.Fatal("HTTP-date Retry-After should be ignored to mirror Python")
	}
}

func TestErrorMessageParity(t *testing.T) {
	cases := []struct {
		name    string
		payload any
		want    string
	}{
		{
			name:    "empty error message falls to type",
			payload: map[string]any{"error": map[string]any{"message": "", "type": "x"}},
			want:    "x",
		},
		{
			name:    "error dict blocks outer message",
			payload: map[string]any{"error": map[string]any{}, "message": "outer"},
			want:    "TrustedRouter error",
		},
		{
			name:    "outer message without error",
			payload: map[string]any{"message": "outer"},
			want:    "outer",
		},
		{
			name:    "non-dict payload",
			payload: []any{"message", "outer"},
			want:    "TrustedRouter error",
		},
		{
			name:    "message non-string",
			payload: map[string]any{"error": map[string]any{"message": 42, "type": "x"}},
			want:    "42",
		},
		{
			name:    "non-dict error does not fall through",
			payload: map[string]any{"error": "bad", "message": "outer"},
			want:    "outer",
		},
		{
			name:    "non-dict error uses message",
			payload: map[string]any{"error": "upstream_failed", "message": "m"},
			want:    "m",
		},
		{
			name:    "null error uses message",
			payload: map[string]any{"error": nil, "message": "m"},
			want:    "m",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := errorMessage(tc.payload); got != tc.want {
				t.Fatalf("errorMessage() = %q, want %q", got, tc.want)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

type requestCapture struct {
	body        []byte
	contentType string
	err         error
}

func newPipeHTTPTestServer(t *testing.T, handler http.Handler) (*httptest.Server, *http.Client) {
	t.Helper()
	listener := newPipeListener()
	server := &httptest.Server{
		Listener: listener,
		Config:   &http.Server{Handler: handler},
	}
	server.Start()
	transport := &http.Transport{DialContext: listener.dial}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		server.Close()
	})
	return server, &http.Client{Transport: transport}
}

type pipeListener struct {
	conns chan net.Conn
	done  chan struct{}
	addr  net.Addr
}

func newPipeListener() *pipeListener {
	return &pipeListener{
		conns: make(chan net.Conn),
		done:  make(chan struct{}),
		addr:  pipeAddr("trusted-router.test"),
	}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}

func (l *pipeListener) Addr() net.Addr {
	return l.addr
}

func (l *pipeListener) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	clientConn, serverConn := net.Pipe()
	select {
	case l.conns <- serverConn:
		return clientConn, nil
	case <-l.done:
		_ = clientConn.Close()
		_ = serverConn.Close()
		return nil, net.ErrClosed
	case <-ctx.Done():
		_ = clientConn.Close()
		_ = serverConn.Close()
		return nil, ctx.Err()
	}
}

type pipeAddr string

func (a pipeAddr) Network() string {
	return "pipe"
}

func (a pipeAddr) String() string {
	return string(a)
}

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func requestHost(r *http.Request) string {
	if r.Host != "" {
		return r.Host
	}
	return r.URL.Host
}

func newRoundTripClient(f roundTripFunc) *http.Client {
	return &http.Client{Transport: f}
}

func jsonResponse(status int, payload any, headers http.Header) *http.Response {
	data, _ := json.Marshal(payload)
	resp := textResponse(status, string(data), headers)
	resp.Header.Set("Content-Type", "application/json")
	return resp
}

func textResponse(status int, body string, headers http.Header) *http.Response {
	if headers == nil {
		headers = http.Header{}
	}
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     headers.Clone(),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func stubSleep(fn func(context.Context, time.Duration) error) func() {
	sleepMu.Lock()
	old := sleepContext
	sleepContext = fn
	sleepMu.Unlock()
	return func() {
		sleepMu.Lock()
		sleepContext = old
		sleepMu.Unlock()
	}
}

var sleepMu sync.Mutex
