package trustedrouter

// Header-channel parity tests for the client-observed reliability telemetry
// contract v1 (§6.4 header subset). Every wire assertion drives the REAL
// engine loop — do() against httptest servers or an injected RoundTripper —
// never a reimplementation of the header logic.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// newHostRoutingTransport routes requests for real TrustedRouter hostnames
// to local test servers, so engine tests exercise the real candidate URLs —
// and therefore the real host mapping — without touching the network.
func newHostRoutingTransport(routes map[string]string) http.RoundTripper {
	return hostRoutingTransport(routes)
}

type hostRoutingTransport map[string]string

func (routes hostRoutingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	target, ok := routes[req.URL.Hostname()]
	if !ok {
		return nil, fmt.Errorf("unrouted host %q", req.URL.Host)
	}
	targetURL, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	clone := req.Clone(req.Context())
	clone.URL.Scheme = targetURL.Scheme
	clone.URL.Host = targetURL.Host
	clone.Host = ""
	return http.DefaultTransport.RoundTrip(clone)
}

func parseTelemetryHeader(t *testing.T, header string) map[string]string {
	t.Helper()
	if header == "" {
		t.Fatal("missing x-tr-client header")
	}
	fields := map[string]string{}
	for _, pair := range strings.Split(header, ";") {
		key, value, ok := strings.Cut(pair, "=")
		if !ok {
			t.Fatalf("malformed x-tr-client segment %q in %q", pair, header)
		}
		if _, duplicate := fields[key]; duplicate {
			t.Fatalf("duplicate x-tr-client key %q in %q", key, header)
		}
		fields[key] = value
	}
	return fields
}

func requireBoundedMs(t *testing.T, fields map[string]string, key string) {
	t.Helper()
	parsed, err := strconv.Atoi(fields[key])
	if err != nil || parsed < 0 || parsed > 3_600_000 {
		t.Fatalf("%s = %q, want an integer in 0..3600000", key, fields[key])
	}
}

func clearTelemetryEnv(t *testing.T) {
	t.Helper()
	t.Setenv("TRUSTEDROUTER_TELEMETRY", "")
	t.Setenv("DO_NOT_TRACK", "")
}

func TestXTRClientHeaderOnAttemptZero(t *testing.T) {
	clearTelemetryEnv(t)

	t.Run("buffered", func(t *testing.T) {
		var seen http.Header
		sdk, err := NewClient(Options{APIKey: "k", HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
			seen = r.Header.Clone()
			return jsonResponse(http.StatusOK, map[string]any{"ok": true}, nil), nil
		})})
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := sdk.Request(context.Background(), http.MethodGet, "/models", nil, &out, nil); err != nil {
			t.Fatal(err)
		}
		if got := seen.Values("x-tr-client"); len(got) != 1 || got[0] != "v=1;a=0;s=0" {
			t.Fatalf("x-tr-client = %#v, want exactly [%q]", got, "v=1;a=0;s=0")
		}
	})

	t.Run("streaming", func(t *testing.T) {
		var seen http.Header
		sdk, err := NewClient(Options{APIKey: "k", HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
			seen = r.Header.Clone()
			headers := http.Header{}
			headers.Set("Content-Type", "text/event-stream")
			return textResponse(http.StatusOK, "data: {\"id\":\"c\",\"choices\":[]}\n\ndata: [DONE]\n\n", headers), nil
		})})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sdk.ChatCompletions(context.Background(), ChatRequest{
			Messages: []map[string]any{{"role": "user", "content": "hi"}},
		}); err != nil {
			t.Fatal(err)
		}
		if got := seen.Values("x-tr-client"); len(got) != 1 || got[0] != "v=1;a=0;s=1" {
			t.Fatalf("x-tr-client = %#v, want exactly [%q]", got, "v=1;a=0;s=1")
		}
	})
}

func TestXTRClientRetryVectorMatchesContractExample(t *testing.T) {
	// ASSEMBLER-ONLY golden vector: the contract's §3.2 worked example
	// (as corrected upstream in quill-router#645 to po=timeout, matching
	// the executable trusted-router-py reference), byte for byte — a retry
	// after a connect timeout on the apex that moved to an alias. The
	// engine produces exactly this state live, but its pm/sm digits are
	// timing-dependent, so the state is laid out directly here and the
	// REAL assembler renders it; the engine path for the same failure is
	// pinned by TestDialTimeoutEmitsConnectTimeoutOnRetryHeader.
	start := time.Now()
	recorder := &requestRecorder{
		streaming: true,
		lastAttempt: telemetryAttempt{
			index:      0,
			host:       "apex",
			outcome:    "timeout",
			errorClass: "connect_timeout",
			elapsedMS:  10012,
		},
		hasLastAttempt: true,
		failoverUsed:   true,
		firstStarted:   start,
		attemptStart:   start.Add(10530 * time.Millisecond),
		currentHost:    "ally",
		currentIndex:   1,
		begun:          true,
	}
	want := "v=1;a=1;po=timeout;pc=connect_timeout;ph=apex;pm=10012;sm=10530;s=1;fo=1"
	if got := recorder.headerValue(); got != want {
		t.Fatalf("headerValue() = %q, want %q", got, want)
	}
}

func TestTransportErrorFailoverCarriesClassOnRetryHeader(t *testing.T) {
	clearTelemetryEnv(t)
	defer stubSleep(func(context.Context, time.Duration) error { return nil })()

	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddress := closed.Addr().String()
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}

	var seen http.Header
	alias := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer alias.Close()

	c, err := NewClient(Options{APIKey: "k", MaxRetries: intPtr(2), HTTPClient: &http.Client{
		Transport: newHostRoutingTransport(map[string]string{
			"api.trustedrouter.com": "http://" + closedAddress,
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

	want := regexp.MustCompile(`^v=1;a=1;po=transport_error;pc=connect_refused;ph=apex;pm=[0-9]{1,7};sm=[0-9]{1,7};s=0;fo=1$`)
	if got := seen.Get("x-tr-client"); !want.MatchString(got) {
		t.Fatalf("alias attempt x-tr-client = %q, want match for %q", got, want)
	}
}

func TestAttemptTimeoutClassifiedOnRetryHeader(t *testing.T) {
	clearTelemetryEnv(t)
	defer stubSleep(func(context.Context, time.Duration) error { return nil })()

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer slow.Close()
	var seen http.Header
	alias := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer alias.Close()

	c, err := NewClient(Options{APIKey: "k", MaxRetries: intPtr(2), HTTPClient: &http.Client{
		Transport: newHostRoutingTransport(map[string]string{
			"api.trustedrouter.com": slow.URL,
			"api.allyrouter.com":    alias.URL,
		}),
	}})
	if err != nil {
		t.Fatal(err)
	}
	timeout := 80 * time.Millisecond
	resp, err := c.rawRequestWithBaseURLs(context.Background(), "GET", "/models", nil, &CallOptions{Timeout: &timeout},
		[]string{DefaultAPIBaseURL, strings.TrimRight(AliasAPIBaseURLs[0], "/")}, true)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	want := regexp.MustCompile(`^v=1;a=1;po=timeout;pc=read_timeout;ph=apex;pm=[0-9]{1,7};sm=[0-9]{1,7};s=0;fo=1$`)
	if got := seen.Get("x-tr-client"); !want.MatchString(got) {
		t.Fatalf("alias attempt x-tr-client = %q, want match for %q", got, want)
	}
}

func TestDialTimeoutEmitsConnectTimeoutOnRetryHeader(t *testing.T) {
	clearTelemetryEnv(t)
	defer stubSleep(func(context.Context, time.Duration) error { return nil })()

	var seen http.Header
	alias := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer alias.Close()
	aliasRoutes := newHostRoutingTransport(map[string]string{"api.allyrouter.com": alias.URL})
	aliasAddress := strings.TrimPrefix(alias.URL, "http://")

	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Hostname() == "api.trustedrouter.com" {
			// A REAL dial whose deadline has already passed: the error is a
			// genuine *net.OpError{Op: "dial"} that reports Timeout().
			dialer := net.Dialer{Deadline: time.Now().Add(-time.Second)}
			conn, err := dialer.DialContext(req.Context(), "tcp", aliasAddress)
			if err != nil {
				return nil, err
			}
			_ = conn.Close()
			return nil, errors.New("dial unexpectedly succeeded")
		}
		return aliasRoutes.RoundTrip(req)
	})

	c, err := NewClient(Options{APIKey: "k", MaxRetries: intPtr(2), HTTPClient: &http.Client{Transport: transport}})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.rawRequestWithBaseURLs(context.Background(), "GET", "/models", nil, nil,
		[]string{DefaultAPIBaseURL, strings.TrimRight(AliasAPIBaseURLs[0], "/")}, true)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	// po=timeout, matching the executable trusted-router-py reference and
	// the corrected §3.2 example (quill-router#645).
	want := regexp.MustCompile(`^v=1;a=1;po=timeout;pc=connect_timeout;ph=apex;pm=[0-9]{1,7};sm=[0-9]{1,7};s=0;fo=1$`)
	if got := seen.Get("x-tr-client"); !want.MatchString(got) {
		t.Fatalf("alias attempt x-tr-client = %q, want match for %q", got, want)
	}
}

func TestProxyFailureEmitsProxyErrorOnRetryHeader(t *testing.T) {
	clearTelemetryEnv(t)
	defer stubSleep(func(context.Context, time.Duration) error { return nil })()

	// A refusing local port standing in for a dead HTTP proxy: net/http
	// wraps the failure as *net.OpError{Op: "proxyconnect"} around the
	// refused dial, and the refused inner error must NOT win (§8: a broken
	// user proxy is not a TrustedRouter fault).
	deadProxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadProxyURL, err := url.Parse("http://" + deadProxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := deadProxy.Close(); err != nil {
		t.Fatal(err)
	}
	proxied := &http.Transport{Proxy: http.ProxyURL(deadProxyURL)}

	var seen http.Header
	alias := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer alias.Close()
	aliasRoutes := newHostRoutingTransport(map[string]string{"api.allyrouter.com": alias.URL})

	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Hostname() == "api.trustedrouter.com" {
			return proxied.RoundTrip(req)
		}
		return aliasRoutes.RoundTrip(req)
	})

	c, err := NewClient(Options{APIKey: "k", MaxRetries: intPtr(2), HTTPClient: &http.Client{Transport: transport}})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.rawRequestWithBaseURLs(context.Background(), "GET", "/models", nil, nil,
		[]string{DefaultAPIBaseURL, strings.TrimRight(AliasAPIBaseURLs[0], "/")}, true)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	want := regexp.MustCompile(`^v=1;a=1;po=transport_error;pc=proxy_error;ph=apex;pm=[0-9]{1,7};sm=[0-9]{1,7};s=0;fo=1$`)
	if got := seen.Get("x-tr-client"); !want.MatchString(got) {
		t.Fatalf("alias attempt x-tr-client = %q, want match for %q", got, want)
	}
}

func TestTLSHandshakeTimeoutEmitsConnectTimeoutOnRetryHeader(t *testing.T) {
	clearTelemetryEnv(t)
	defer stubSleep(func(context.Context, time.Duration) error { return nil })()

	// A plain-TCP listener that accepts and swallows the ClientHello
	// without ever answering: the handshake stalls until net/http's
	// TLSHandshakeTimeout fires. Ruling: TLS establishment is connect
	// phase, as httpx folds TCP+TLS setup into ConnectTimeout.
	stall, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stall.Close()
	go func() {
		for {
			conn, err := stall.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(io.Discard, conn)
				_ = conn.Close()
			}()
		}
	}()
	stalled := &http.Transport{TLSHandshakeTimeout: 50 * time.Millisecond}
	stallAddress := stall.Addr().String()

	var seen http.Header
	alias := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer alias.Close()
	aliasRoutes := newHostRoutingTransport(map[string]string{"api.allyrouter.com": alias.URL})

	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Hostname() == "api.trustedrouter.com" {
			clone := req.Clone(req.Context())
			clone.URL.Scheme = "https"
			clone.URL.Host = stallAddress
			clone.Host = ""
			return stalled.RoundTrip(clone)
		}
		return aliasRoutes.RoundTrip(req)
	})

	c, err := NewClient(Options{APIKey: "k", MaxRetries: intPtr(2), HTTPClient: &http.Client{Transport: transport}})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.rawRequestWithBaseURLs(context.Background(), "GET", "/models", nil, nil,
		[]string{DefaultAPIBaseURL, strings.TrimRight(AliasAPIBaseURLs[0], "/")}, true)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	want := regexp.MustCompile(`^v=1;a=1;po=timeout;pc=connect_timeout;ph=apex;pm=[0-9]{1,7};sm=[0-9]{1,7};s=0;fo=1$`)
	if got := seen.Get("x-tr-client"); !want.MatchString(got) {
		t.Fatalf("alias attempt x-tr-client = %q, want match for %q", got, want)
	}
}

// hostileError panics in Error(): the shape of an instrumentation wrapper's
// bug arriving through a caller-injected http.Client.
type hostileError struct{}

func (hostileError) Error() string { panic("hostile Error method") }

func TestHostileErrorValuesCannotFailTheRequest(t *testing.T) {
	clearTelemetryEnv(t)
	defer stubSleep(func(context.Context, time.Duration) error { return nil })()

	calls := 0
	sdk, err := NewClient(Options{APIKey: "k", HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return nil, hostileError{}
		}
		return jsonResponse(http.StatusOK, map[string]any{"ok": true}, nil), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	// §2.2: telemetry classification walks the hostile error and must
	// swallow the panic; the retry then succeeds exactly as it did before
	// telemetry existed.
	if err := sdk.Request(context.Background(), http.MethodGet, "/models", nil, &out, nil); err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if calls != 2 {
		t.Fatalf("attempts = %d, want 2", calls)
	}
}

func TestForcedRetryOfSuccessReportsPoNone(t *testing.T) {
	clearTelemetryEnv(t)
	defer stubSleep(func(context.Context, time.Duration) error { return nil })()

	var headers []string
	verdictTrue := http.Header{}
	verdictTrue.Set("X-Should-Retry", "true")
	responses := []*http.Response{
		jsonResponse(http.StatusOK, map[string]any{"ok": true}, verdictTrue),
		jsonResponse(http.StatusOK, map[string]any{"ok": true}, nil),
	}
	sdk, err := NewClient(Options{APIKey: "k", HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
		headers = append(headers, r.Header.Get("x-tr-client"))
		resp := responses[0]
		responses = responses[1:]
		return resp, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := sdk.Request(context.Background(), http.MethodGet, "/models", nil, &out, nil); err != nil {
		t.Fatal(err)
	}
	if len(headers) != 2 {
		t.Fatalf("attempts = %d, want 2", len(headers))
	}
	// A forced x-should-retry retry of a 2xx records outcome "ok", which is
	// outside §3.2's po vocabulary; the ruling maps it to po=none;pc=none
	// with every other key intact rather than emitting a header the
	// enclave would drop whole.
	want := regexp.MustCompile(`^v=1;a=1;po=none;pc=none;ph=apex;pm=[0-9]{1,7};sm=[0-9]{1,7};s=0;fo=0$`)
	if !want.MatchString(headers[1]) {
		t.Fatalf("retry x-tr-client = %q, want match for %q", headers[1], want)
	}
}

func TestReservedHeaderStrippedOnEveryPath(t *testing.T) {
	stale := map[string]string{"x-tr-client": "v=1;a=9;s=0"}

	t.Run("opt-out", func(t *testing.T) {
		clearTelemetryEnv(t)
		var seen http.Header
		sdk, err := NewClient(Options{APIKey: "k", Telemetry: boolPtr(false), Headers: stale,
			HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
				seen = r.Header.Clone()
				return jsonResponse(http.StatusOK, map[string]any{"ok": true}, nil), nil
			})})
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := sdk.Request(context.Background(), http.MethodGet, "/models", nil, &out, &CallOptions{
			ExtraHeaders: map[string]string{"X-TR-Client": "v=1;a=8;s=1"},
		}); err != nil {
			t.Fatal(err)
		}
		if got := seen.Values("x-tr-client"); len(got) != 0 {
			t.Fatalf("stale x-tr-client survived opt-out: %#v", got)
		}
	})

	t.Run("custom base", func(t *testing.T) {
		clearTelemetryEnv(t)
		var seen http.Header
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = r.Header.Clone()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		defer server.Close()
		sdk, err := NewClient(Options{APIKey: "k", BaseURL: server.URL, Headers: stale})
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := sdk.Request(context.Background(), http.MethodGet, "/models", nil, &out, nil); err != nil {
			t.Fatal(err)
		}
		if got := seen.Values("x-tr-client"); len(got) != 0 {
			t.Fatalf("stale x-tr-client reached a custom base: %#v", got)
		}
	})

	t.Run("control plane", func(t *testing.T) {
		clearTelemetryEnv(t)
		var seen http.Header
		control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = r.Header.Clone()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[]}`))
		}))
		defer control.Close()
		c, err := NewClient(Options{APIKey: "k", Headers: stale, HTTPClient: &http.Client{
			Transport: newHostRoutingTransport(map[string]string{"trustedrouter.com": control.URL}),
		}})
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.rawControlRequest(context.Background(), http.MethodGet, "/credits", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		drainAndClose(resp.Body)
		if got := seen.Values("x-tr-client"); len(got) != 0 {
			t.Fatalf("stale x-tr-client reached the control plane: %#v", got)
		}
	})

	t.Run("absolute request", func(t *testing.T) {
		clearTelemetryEnv(t)
		var seen http.Header
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = r.Header.Clone()
			_, _ = w.Write([]byte(`{}`))
		}))
		defer server.Close()
		c, err := NewClient(Options{APIKey: "k", Headers: stale})
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.absoluteRequest(context.Background(), http.MethodGet, server.URL+"/status.json")
		if err != nil {
			t.Fatal(err)
		}
		drainAndClose(resp.Body)
		if got := seen.Values("x-tr-client"); len(got) != 0 {
			t.Fatalf("stale x-tr-client survived absoluteRequest: %#v", got)
		}
	})

	t.Run("recording replaces a stale value", func(t *testing.T) {
		clearTelemetryEnv(t)
		var seen http.Header
		sdk, err := NewClient(Options{APIKey: "k", Headers: stale,
			HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
				seen = r.Header.Clone()
				return jsonResponse(http.StatusOK, map[string]any{"ok": true}, nil), nil
			})})
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := sdk.Request(context.Background(), http.MethodGet, "/models", nil, &out, nil); err != nil {
			t.Fatal(err)
		}
		if got := seen.Values("x-tr-client"); len(got) != 1 || got[0] != "v=1;a=0;s=0" {
			t.Fatalf("x-tr-client = %#v, want the SDK's own [%q]", got, "v=1;a=0;s=0")
		}
	})
}

func TestPinnedRetryInPlaceReportsFoZero(t *testing.T) {
	clearTelemetryEnv(t)
	defer stubSleep(func(context.Context, time.Duration) error { return nil })()

	var headers []string
	responses := []*http.Response{
		jsonResponse(http.StatusServiceUnavailable, map[string]any{"error": "down"}, nil),
		jsonResponse(http.StatusOK, map[string]any{"ok": true}, nil),
	}
	off := false
	sdk, err := NewClient(Options{APIKey: "k", RegionalFailover: &off, HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
		headers = append(headers, r.Header.Get("x-tr-client"))
		resp := responses[0]
		responses = responses[1:]
		return resp, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := sdk.Request(context.Background(), http.MethodGet, "/models", nil, &out, nil); err != nil {
		t.Fatal(err)
	}
	if len(headers) != 2 {
		t.Fatalf("attempts = %d, want 2", len(headers))
	}
	// The failover flag governs WHERE, never WHETHER: the retry stays on the
	// apex and reports fo=0.
	want := regexp.MustCompile(`^v=1;a=1;po=http_error;pc=none;ph=apex;pm=[0-9]{1,7};sm=[0-9]{1,7};s=0;fo=0$`)
	if !want.MatchString(headers[1]) {
		t.Fatalf("retry x-tr-client = %q, want match for %q", headers[1], want)
	}
}

func TestCustomBaseURLSendsNoTelemetryHeader(t *testing.T) {
	clearTelemetryEnv(t)

	run := func(t *testing.T, telemetry *bool) {
		t.Helper()
		var seen http.Header
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = r.Header.Clone()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		defer server.Close()
		sdk, err := NewClient(Options{APIKey: "k", BaseURL: server.URL, Telemetry: telemetry})
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := sdk.Request(context.Background(), http.MethodGet, "/models", nil, &out, nil); err != nil {
			t.Fatal(err)
		}
		// A self-hosted gateway is not TrustedRouter's to measure (§3.2):
		// the request goes through untouched, with no x-tr-client.
		if got := seen.Values("x-tr-client"); len(got) != 0 {
			t.Fatalf("x-tr-client sent to a custom base URL: %#v", got)
		}
	}

	t.Run("default resolution disables custom bases", func(t *testing.T) {
		run(t, nil)
	})
	t.Run("explicit enable is still suppressed per attempt", func(t *testing.T) {
		run(t, boolPtr(true))
	})
}

func TestControlPlaneCallsCarryNoTelemetryHeader(t *testing.T) {
	clearTelemetryEnv(t)
	defer stubSleep(func(context.Context, time.Duration) error { return nil })()

	type controlHit struct {
		path   string
		header []string
	}
	var hits []controlHit
	first := true
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, controlHit{path: r.URL.Path, header: r.Header.Values("x-tr-client")})
		w.Header().Set("Content-Type", "application/json")
		if first {
			first = false
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"down"}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer control.Close()

	// Default base and default control URL: telemetry resolves ON, and the
	// control host maps to "control", not "custom" — so if a recorder were
	// active on this plane, every attempt below would carry a header.
	c, err := NewClient(Options{APIKey: "k", MaxRetries: intPtr(2), HTTPClient: &http.Client{
		Transport: newHostRoutingTransport(map[string]string{
			"trustedrouter.com": control.URL,
		}),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !c.telemetry {
		t.Fatal("telemetry should resolve on for the default URLs")
	}
	resp, err := c.rawControlRequest(context.Background(), http.MethodGet, "/credits", nil, nil)
	if err != nil {
		t.Fatalf("control request: %v", err)
	}
	drainAndClose(resp.Body)
	if _, err := c.Models(context.Background(), nil); err != nil {
		t.Fatalf("models: %v", err)
	}

	if len(hits) < 3 {
		t.Fatalf("control hits = %d, want the 503, its retry, and /models", len(hits))
	}
	for _, hit := range hits {
		if len(hit.header) != 0 {
			t.Fatalf("control-plane call %s carried x-tr-client %#v", hit.path, hit.header)
		}
	}
}

func TestResolveTelemetryEnabledPrecedence(t *testing.T) {
	cases := []struct {
		name     string
		explicit *bool
		env      map[string]string
		base     string
		control  string
		want     bool
	}{
		{"default on for TrustedRouter hosts", nil, nil, DefaultAPIBaseURL, DefaultControlBaseURL, true},
		{"alias base defaults on", nil, nil, AliasAPIBaseURLs[1], DefaultControlBaseURL, true},
		{"region base defaults on", nil, nil, "https://api-us-east4.quillrouter.com/v1", DefaultControlBaseURL, true},
		{"control subdomain accepted", nil, nil, DefaultAPIBaseURL, "https://eu.trustedrouter.com/v1", true},
		{"custom base defaults off", nil, nil, "https://gateway.example/v1", DefaultControlBaseURL, false},
		{"custom control defaults off", nil, nil, DefaultAPIBaseURL, "https://control.example/v1", false},
		{"non-https control defaults off", nil, nil, DefaultAPIBaseURL, "http://trustedrouter.com/v1", false},
		{"explicit false beats env enable", boolPtr(false), map[string]string{"TRUSTEDROUTER_TELEMETRY": "1"}, DefaultAPIBaseURL, DefaultControlBaseURL, false},
		{"explicit true beats env disable", boolPtr(true), map[string]string{"TRUSTEDROUTER_TELEMETRY": "0"}, DefaultAPIBaseURL, DefaultControlBaseURL, true},
		{"explicit true wins even for custom bases", boolPtr(true), nil, "https://gateway.example/v1", DefaultControlBaseURL, true},
		{"env 0 disables", nil, map[string]string{"TRUSTEDROUTER_TELEMETRY": "0"}, DefaultAPIBaseURL, DefaultControlBaseURL, false},
		{"env off disables case-insensitively", nil, map[string]string{"TRUSTEDROUTER_TELEMETRY": " OFF "}, DefaultAPIBaseURL, DefaultControlBaseURL, false},
		{"env no disables", nil, map[string]string{"TRUSTEDROUTER_TELEMETRY": "no"}, DefaultAPIBaseURL, DefaultControlBaseURL, false},
		{"env enable beats DO_NOT_TRACK", nil, map[string]string{"TRUSTEDROUTER_TELEMETRY": "yes", "DO_NOT_TRACK": "1"}, DefaultAPIBaseURL, DefaultControlBaseURL, true},
		{"DO_NOT_TRACK=1 disables", nil, map[string]string{"DO_NOT_TRACK": "1"}, DefaultAPIBaseURL, DefaultControlBaseURL, false},
		{"DO_NOT_TRACK other values ignored", nil, map[string]string{"DO_NOT_TRACK": "true"}, DefaultAPIBaseURL, DefaultControlBaseURL, true},
		{"unknown env value falls through to default", nil, map[string]string{"TRUSTEDROUTER_TELEMETRY": "maybe"}, DefaultAPIBaseURL, DefaultControlBaseURL, true},
		{"env enable does not force custom bases", nil, map[string]string{"TRUSTEDROUTER_TELEMETRY": "1"}, "https://gateway.example/v1", DefaultControlBaseURL, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			getenv := func(key string) string { return tc.env[key] }
			if got := resolveTelemetryEnabled(tc.explicit, tc.base, tc.control, getenv); got != tc.want {
				t.Fatalf("resolveTelemetryEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTelemetryOptOutSuppressesHeaderOnTheWire(t *testing.T) {
	request := func(t *testing.T, telemetry *bool) http.Header {
		t.Helper()
		var seen http.Header
		sdk, err := NewClient(Options{APIKey: "k", Telemetry: telemetry, HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
			seen = r.Header.Clone()
			return jsonResponse(http.StatusOK, map[string]any{"ok": true}, nil), nil
		})})
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := sdk.Request(context.Background(), http.MethodGet, "/models", nil, &out, nil); err != nil {
			t.Fatal(err)
		}
		return seen
	}

	t.Run("TRUSTEDROUTER_TELEMETRY=0 wins over DO_NOT_TRACK unset", func(t *testing.T) {
		clearTelemetryEnv(t)
		t.Setenv("TRUSTEDROUTER_TELEMETRY", "0")
		if got := request(t, nil).Values("x-tr-client"); len(got) != 0 {
			t.Fatalf("x-tr-client sent despite TRUSTEDROUTER_TELEMETRY=0: %#v", got)
		}
	})
	t.Run("explicit option false beats env enable", func(t *testing.T) {
		clearTelemetryEnv(t)
		t.Setenv("TRUSTEDROUTER_TELEMETRY", "1")
		if got := request(t, boolPtr(false)).Values("x-tr-client"); len(got) != 0 {
			t.Fatalf("x-tr-client sent despite Telemetry=false: %#v", got)
		}
	})
	t.Run("DO_NOT_TRACK=1 disables by default", func(t *testing.T) {
		clearTelemetryEnv(t)
		t.Setenv("DO_NOT_TRACK", "1")
		if got := request(t, nil).Values("x-tr-client"); len(got) != 0 {
			t.Fatalf("x-tr-client sent despite DO_NOT_TRACK=1: %#v", got)
		}
	})
	t.Run("env enable beats DO_NOT_TRACK", func(t *testing.T) {
		clearTelemetryEnv(t)
		t.Setenv("TRUSTEDROUTER_TELEMETRY", "1")
		t.Setenv("DO_NOT_TRACK", "1")
		if got := request(t, nil).Get("x-tr-client"); got != "v=1;a=0;s=0" {
			t.Fatalf("x-tr-client = %q, want %q", got, "v=1;a=0;s=0")
		}
	})
	t.Run("opt-out leaves the User-Agent untouched", func(t *testing.T) {
		clearTelemetryEnv(t)
		t.Setenv("TRUSTEDROUTER_TELEMETRY", "0")
		if got := request(t, nil).Get("user-agent"); got != userAgent() {
			t.Fatalf("user-agent = %q, want %q", got, userAgent())
		}
	})
}

func TestClassifyTransportError(t *testing.T) {
	classify := func(t *testing.T, err error, want string) {
		t.Helper()
		if err == nil {
			t.Fatal("expected an error to classify")
		}
		if got := classifyTransportError(err); got != want {
			t.Fatalf("classifyTransportError(%v) = %q, want %q", err, got, want)
		}
	}

	t.Run("connect refused", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		_, err = http.Get("http://" + address + "/")
		classify(t, err, "connect_refused")
	})

	t.Run("dns failure", func(t *testing.T) {
		// A direct dial rather than http.Get: the plain-TCP path cannot be
		// diverted by HTTP_PROXY-style process configuration, so the
		// failure is a real resolver *net.DNSError on any machine.
		_, err := net.Dial("tcp", "telemetry-probe.invalid:80")
		classify(t, err, "dns")
	})

	t.Run("connect timeout", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		var dialer net.Dialer
		_, err = dialer.DialContext(ctx, "tcp", listener.Addr().String())
		classify(t, err, "connect_timeout")
	})

	t.Run("read timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}))
		defer server.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = server.Client().Do(req)
		classify(t, err, "read_timeout")
	})

	t.Run("tls certificate rejection", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		defer server.Close()
		// Deliberately NOT server.Client(): the default client does not
		// trust the test CA, which is exactly the failure to classify.
		_, err := http.Get(server.URL)
		classify(t, err, "tls")
	})

	t.Run("connection reset", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			reader := bufio.NewReader(conn)
			for {
				line, err := reader.ReadString('\n')
				if err != nil || line == "\r\n" {
					break
				}
			}
			if tcp, ok := conn.(*net.TCPConn); ok {
				_ = tcp.SetLinger(0) // close with RST, not FIN
			}
			_ = conn.Close()
		}()
		_, err = http.Get("http://" + listener.Addr().String() + "/")
		classify(t, err, "reset")
	})

	t.Run("malformed response is protocol_error", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			reader := bufio.NewReader(conn)
			for {
				line, err := reader.ReadString('\n')
				if err != nil || line == "\r\n" {
					break
				}
			}
			_, _ = conn.Write([]byte("bogus\r\n\r\n"))
			_ = conn.Close()
		}()
		_, err = http.Get("http://" + listener.Addr().String() + "/")
		classify(t, err, "protocol_error")
	})

	t.Run("write timeout", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := conn.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		payload := make([]byte, 1<<20)
		var writeErr error
		for i := 0; i < 64 && writeErr == nil; i++ {
			_, writeErr = conn.Write(payload)
		}
		classify(t, writeErr, "write_timeout")
	})

	t.Run("plaintext server on an https url is tls", func(t *testing.T) {
		// net/http REPLACES the tls.RecordHeaderError with the exported
		// ErrSchemeMismatch sentinel here, so the typed TLS error never
		// reaches the SDK and only the sentinel identifies the failure.
		// trusted-router-py gets an ssl.SSLError for the same server.
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		defer server.Close()
		_, err := http.Get("https://" + strings.TrimPrefix(server.URL, "http://") + "/")
		if !errors.Is(err, http.ErrSchemeMismatch) {
			t.Fatalf("err = %v, want net/http's scheme-mismatch sentinel", err)
		}
		classify(t, err, "tls")
	})

	t.Run("http2 stream reset is protocol_error", func(t *testing.T) {
		// A real HTTP/2 stream reset from the peer. Its message —
		// "stream error: stream ID 1; INTERNAL_ERROR; received from peer" —
		// contains neither "http2" nor "PROTOCOL_ERROR", which is why the
		// commonest real HTTP/2 failure used to classify as "unknown".
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic(http.ErrAbortHandler)
		}))
		server.EnableHTTP2 = true
		server.Config.ErrorLog = log.New(io.Discard, "", 0)
		server.StartTLS()
		defer server.Close()
		_, err := server.Client().Get(server.URL)
		if err == nil {
			t.Fatal("expected the reset stream to surface an error")
		}
		if !strings.Contains(err.Error(), "stream error") {
			t.Fatalf("err = %v, want an http2 stream error", err)
		}
		classify(t, err, "protocol_error")
	})

	t.Run("unexpected eof is io_error", func(t *testing.T) {
		classify(t, fmt.Errorf("read body: %w", io.ErrUnexpectedEOF), "io_error")
	})

	t.Run("unrecognized errors are unknown", func(t *testing.T) {
		classify(t, errors.New("mystery"), "unknown")
	})
}

func TestTelemetryHeaderBoundsAndGrammar(t *testing.T) {
	worstCase := func() *requestRecorder {
		start := time.Now()
		return &requestRecorder{
			streaming: true,
			lastAttempt: telemetryAttempt{
				// The previous attempt's index must be currentIndex-1: the
				// po/pc/ph/pm keys are defined as THAT attempt's facts, and
				// headerValue refuses to describe any other attempt under
				// this attempt's number.
				index:      98,
				host:       "europe_west4",
				outcome:    "transport_error",
				errorClass: "connect_timeout",
				elapsedMS:  3_600_000,
			},
			hasLastAttempt: true,
			failoverUsed:   true,
			firstStarted:   start,
			attemptStart:   start.Add(2 * time.Hour), // clamped to 3600000
			currentHost:    "ally",
			currentIndex:   99,
			begun:          true,
		}
	}

	t.Run("worst case stays within 160 bytes", func(t *testing.T) {
		want := "v=1;a=99;po=transport_error;pc=connect_timeout;ph=europe_west4;pm=3600000;sm=3600000;s=1;fo=1"
		got := worstCase().headerValue()
		if got != want {
			t.Fatalf("headerValue() = %q, want %q", got, want)
		}
		if len(got) > 160 {
			t.Fatalf("header is %d bytes, contract caps it at 160", len(got))
		}
		valueRe := regexp.MustCompile(`^[a-z0-9_]{1,24}$`)
		for _, part := range strings.Split(got, ";") {
			_, value, ok := strings.Cut(part, "=")
			if !ok || !valueRe.MatchString(value) {
				t.Fatalf("segment %q violates the value grammar", part)
			}
		}
	})

	t.Run("attempt index above 99 sends nothing", func(t *testing.T) {
		recorder := worstCase()
		recorder.currentIndex = 100
		if got := recorder.headerValue(); got != "" {
			t.Fatalf("headerValue() = %q, want suppression above a=99", got)
		}
	})

	t.Run("out-of-grammar value sends nothing", func(t *testing.T) {
		recorder := worstCase()
		recorder.lastAttempt.errorClass = "Not Valid!"
		if got := recorder.headerValue(); got != "" {
			t.Fatalf("headerValue() = %q, want suppression", got)
		}
	})

	t.Run("oversized header sends nothing", func(t *testing.T) {
		recorder := worstCase()
		long := strings.Repeat("a", 60)
		recorder.lastAttempt.outcome = long
		recorder.lastAttempt.errorClass = long
		recorder.lastAttempt.host = long
		if got := recorder.headerValue(); got != "" {
			t.Fatalf("headerValue() = %q, want suppression", got)
		}
	})

	t.Run("a gap in the attempt records sends nothing", func(t *testing.T) {
		// The immediately preceding attempt lost its record (a recovered
		// callback panic), so its facts are gone. Reporting the attempt
		// before it under this attempt's index would be a false report.
		recorder := worstCase()
		recorder.lastAttempt.index = 97
		if got := recorder.headerValue(); got != "" {
			t.Fatalf("headerValue() = %q, want suppression when the previous attempt has no record", got)
		}
	})

	t.Run("durations clamp to 0..3600000", func(t *testing.T) {
		if got := clampDurationMS(-time.Second); got != 0 {
			t.Fatalf("clampDurationMS(-1s) = %d, want 0", got)
		}
		if got := clampDurationMS(48 * time.Hour); got != 3_600_000 {
			t.Fatalf("clampDurationMS(48h) = %d, want 3600000", got)
		}
	})
}

// TestRequestRecorderHistoryStaysBounded is the memory-bound regression for
// Options.MaxRetries, which is intentionally uncapped. The header for an
// attempt reads only its immediate predecessor, and the beacon event may
// carry at most 16 attempts (§5.3), so even a pathological retry count must
// leave exactly one scalar record plus a 16-entry history reachable from the
// recorder — while the exact counters (§5.4) still count every attempt
// through the folded overflow.
func TestRequestRecorderHistoryStaysBounded(t *testing.T) {
	const attemptCount = 10_000
	sink := &recordingTelemetrySink{}
	recorder := newRequestRecorder(sink, telemetryRequestFacts{endpoint: "models", method: http.MethodGet}, false, 0, false)
	for i := 0; i < attemptCount; i++ {
		recorder.beginAttempt(DefaultAPIBaseURL)
		recorder.onResponse(http.StatusServiceUnavailable, nil)
	}
	if recorder.nextIndex != attemptCount {
		t.Fatalf("nextIndex = %d, want %d", recorder.nextIndex, attemptCount)
	}
	if !recorder.hasLastAttempt || recorder.lastAttempt.index != attemptCount-1 {
		t.Fatalf("retained attempt = (%t, %d), want (true, %d)", recorder.hasLastAttempt, recorder.lastAttempt.index, attemptCount-1)
	}
	if len(recorder.attempts) != telemetryMaxEventAttempts {
		t.Fatalf("event history holds %d attempts, want the §5.3 cap of %d", len(recorder.attempts), telemetryMaxEventAttempts)
	}
	if len(recorder.overflow) != 1 {
		t.Fatalf("overflow holds %d keys, want 1 (every attempt shares one counter key)", len(recorder.overflow))
	}

	recorderType := reflect.TypeOf(recorder).Elem()
	attemptType := reflect.TypeOf(telemetryAttempt{})
	attemptFields := 0
	for i := 0; i < recorderType.NumField(); i++ {
		field := recorderType.Field(i)
		if field.Type == attemptType {
			attemptFields++
		}
		if field.Type == reflect.SliceOf(attemptType) && field.Name != "attempts" {
			t.Fatalf("requestRecorder.%s retains a second attempt history; recorder state must stay bounded", field.Name)
		}
	}
	if attemptFields != 1 {
		t.Fatalf("requestRecorder retains %d scalar attempt records, want exactly 1", attemptFields)
	}

	// The counters are still exact: the request row counts every attempt,
	// and the attempt rows sum to the same total.
	recorder.finish()
	if len(sink.events) != 1 {
		t.Fatalf("events = %d, want 1", len(sink.events))
	}
	if got := len(sink.events[0].attempts); got != telemetryMaxEventAttempts {
		t.Fatalf("event carries %d attempts, want %d", got, telemetryMaxEventAttempts)
	}
	if got := sink.counters[0][0].attempts; got != attemptCount {
		t.Fatalf("request row attempts = %d, want %d", got, attemptCount)
	}
	attemptRows := 0
	for _, increment := range sink.counters[0][1:] {
		if increment.key.level != "attempt" {
			t.Fatalf("unexpected counter level %q", increment.key.level)
		}
		attemptRows += increment.attempts
	}
	if attemptRows != attemptCount {
		t.Fatalf("attempt rows count %d attempts, want %d", attemptRows, attemptCount)
	}
}

func TestHostEnumMapping(t *testing.T) {
	cases := map[string]string{
		DefaultAPIBaseURL:                                        "apex",
		"https://api.trustedrouter.com":                          "apex",
		"https://api.trustedrouter.com:8443/v1":                  "apex", // ports are ignored, as in trusted-router-py
		AliasAPIBaseURLs[0]:                                      "ally",
		AliasAPIBaseURLs[1]:                                      "uptime",
		"https://api-us-central1.quillrouter.com/v1":             "us_central1",
		"https://api-us-east4.quillrouter.com/v1":                "us_east4",
		"https://api-europe-west4.quillrouter.com/v1":            "europe_west4",
		DefaultControlBaseURL:                                    "control",
		"https://trust.trustedrouter.com/trust/gcp-release.json": "control",
		"http://api.trustedrouter.com/v1":                        "custom", // scheme matters
		"https://gateway.example/v1":                             "custom",
		"http://127.0.0.1:8080":                                  "custom",
		"":                                                       "custom",
		"not a url":                                              "custom",
	}
	for input, want := range cases {
		if got := hostEnum(input); got != want {
			t.Errorf("hostEnum(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestTelemetryParityConstants(t *testing.T) {
	// §6.4: every SDK pins the beacon path, the schema version, and the
	// closed enum vocabulary, so the later beacon PR cannot drift from the
	// server-side contract.
	if telemetrySchemaVersion != 1 {
		t.Fatalf("telemetrySchemaVersion = %d, want 1", telemetrySchemaVersion)
	}
	if telemetryEventsPath != "/client-events" {
		t.Fatalf("telemetryEventsPath = %q, want %q", telemetryEventsPath, "/client-events")
	}
	wantHosts := []string{"apex", "ally", "uptime", "us_central1", "us_east4", "europe_west4", "control", "custom"}
	if !reflect.DeepEqual(telemetryHosts, wantHosts) {
		t.Errorf("telemetryHosts = %#v, want %#v", telemetryHosts, wantHosts)
	}
	wantEndpoints := []string{"chat_completions", "messages", "responses", "embeddings", "images", "videos", "models", "fusion", "control_other", "inference_other"}
	if !reflect.DeepEqual(telemetryEndpoints, wantEndpoints) {
		t.Errorf("telemetryEndpoints = %#v, want %#v", telemetryEndpoints, wantEndpoints)
	}
	wantOutcomes := []string{"ok", "http_error", "transport_error", "timeout", "stream_broken", "aborted"}
	if !reflect.DeepEqual(telemetryOutcomes, wantOutcomes) {
		t.Errorf("telemetryOutcomes = %#v, want %#v", telemetryOutcomes, wantOutcomes)
	}
	wantErrorClasses := []string{"dns", "tls", "connect_refused", "connect_timeout", "connect_error", "read_timeout", "write_timeout", "pool_timeout", "protocol_error", "reset", "io_error", "proxy_error", "stream_stalled", "unknown"}
	if !reflect.DeepEqual(telemetryErrorClasses, wantErrorClasses) {
		t.Errorf("telemetryErrorClasses = %#v, want %#v", telemetryErrorClasses, wantErrorClasses)
	}
}

func TestUserAgentMatchesTelemetryContractGrammar(t *testing.T) {
	// §3.1: `trusted-router-go/SEMVER( runtime/ver)?`. The enclave derives
	// sdk, sdk_version, and runtime from this exact shape; an extra token
	// (the old trailing GOOS) makes the whole identity unparseable.
	grammar := regexp.MustCompile(
		`^trusted-router-go/(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)` +
			`(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?` +
			`( [a-z]{1,10}/[0-9A-Za-z.+-]{1,24})?$`)
	got := userAgent()
	if !grammar.MatchString(got) {
		t.Fatalf("userAgent() = %q does not match the §3.1 grammar", got)
	}
	if !strings.HasPrefix(got, "trusted-router-go/"+Version) {
		t.Fatalf("userAgent() = %q does not carry Version %q", got, Version)
	}
}

// TestTelemetryHostAllowlistMatchesSDKConstants keeps telemetry's own
// hostname list honest against the SDK's base-URL constants. Telemetry
// deliberately does not read the exported AliasAPIBaseURLs var (see
// TestMutatedAliasListCannotAttractTelemetry), which means a genuine alias
// or region change would otherwise silently stop being named — so the
// agreement between the two is asserted here instead of assumed.
func TestTelemetryHostAllowlistMatchesSDKConstants(t *testing.T) {
	if len(AliasAPIBaseURLs) != 2 {
		t.Fatalf("AliasAPIBaseURLs has %d entries; telemetry's host vocabulary (ally, uptime) must be updated with it", len(AliasAPIBaseURLs))
	}
	// The exact key set, not just the expected entries: a test that only
	// checks the hosts it knows about would pass with an extra
	// "gateway.attacker.example": "apex" sitting in the map, which is the
	// whole exposure this list exists to close.
	wantHostnames := map[string]string{
		"api.trustedrouter.com":            "apex",
		"api.allyrouter.com":               "ally",
		"api.uptimerouter.com":             "uptime",
		"api-us-central1.quillrouter.com":  "us_central1",
		"api-us-east4.quillrouter.com":     "us_east4",
		"api-europe-west4.quillrouter.com": "europe_west4",
	}
	if !reflect.DeepEqual(telemetryHostnames, wantHostnames) {
		t.Errorf("telemetryHostnames = %#v, want exactly %#v", telemetryHostnames, wantHostnames)
	}
	for _, tc := range []struct{ url, want string }{
		{DefaultAPIBaseURL, "apex"},
		{AliasAPIBaseURLs[0], "ally"},
		{AliasAPIBaseURLs[1], "uptime"},
	} {
		_, host, ok := telemetrySchemeHost(tc.url)
		if !ok {
			t.Fatalf("%q is not a parseable base URL", tc.url)
		}
		if got := telemetryHostnames[host]; got != tc.want {
			t.Errorf("telemetryHostnames[%q] = %q, want %q — update telemetryHostnames alongside the SDK's base-URL constants", host, got, tc.want)
		}
	}
	// The control base is named by suffix rather than by the list.
	if got := hostEnum(DefaultControlBaseURL); got != "control" {
		t.Errorf("hostEnum(DefaultControlBaseURL) = %q, want %q", got, "control")
	}
	// Every name telemetry can produce must be in the closed §5.2 vocabulary.
	allowed := map[string]bool{}
	for _, host := range telemetryHosts {
		allowed[host] = true
	}
	for host, name := range telemetryHostnames {
		if !allowed[name] {
			t.Errorf("telemetryHostnames[%q] = %q, which is outside the closed Host vocabulary", host, name)
		}
	}
}

// TestMutatedAliasListCannotAttractTelemetry is the privacy test for the
// host vocabulary. AliasAPIBaseURLs is an exported var, so a consumer can
// point an entry at their own gateway. Telemetry must not follow it there:
// naming a caller-supplied host "ally" would resolve telemetry ON for it and
// send x-tr-client to a host that is not TrustedRouter's to measure (§3.2).
func TestMutatedAliasListCannotAttractTelemetry(t *testing.T) {
	clearTelemetryEnv(t)
	const selfHosted = "https://gateway.self-hosted.example/v1"
	original := append([]string(nil), AliasAPIBaseURLs...)
	t.Cleanup(func() { AliasAPIBaseURLs = original })
	AliasAPIBaseURLs = []string{selfHosted, "https://second.self-hosted.example/v1"}

	if got := hostEnum(selfHosted); got != "custom" {
		t.Fatalf("hostEnum(%q) = %q, want %q — a mutated alias slice must not name a caller's host", selfHosted, got, "custom")
	}
	// The genuine aliases are still named, because telemetry reads its own list.
	if got := hostEnum(original[0]); got != "ally" {
		t.Fatalf("hostEnum(%q) = %q, want %q", original[0], got, "ally")
	}

	// ...and on the wire: a client pointed at that host sends no header.
	var seen http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	sdk, err := NewClient(Options{APIKey: "k", BaseURL: selfHosted, HTTPClient: &http.Client{
		Transport: newHostRoutingTransport(map[string]string{"gateway.self-hosted.example": server.URL}),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if sdk.telemetry {
		t.Error("telemetry resolved ON for a caller's self-hosted gateway")
	}
	var out map[string]any
	if err := sdk.Request(context.Background(), http.MethodGet, "/models", nil, &out, nil); err != nil {
		t.Fatal(err)
	}
	if got := seen.Values("x-tr-client"); len(got) != 0 {
		t.Fatalf("x-tr-client sent to a mutated-alias host: %#v", got)
	}
}

// innerHostileError and nestedHostileError together defeat fmt's own panic
// recovery: fmt renders a panicking Error() as a "%!s(PANIC=...)" marker, but
// re-panics when the value the Error() method panics WITH also has a
// panicking Error(). That is the shape that makes telemetry classification
// panic for real, since http.Client.Do's *url.Error wrapper renders the
// inner value through fmt.
type innerHostileError struct{}

func (innerHostileError) Error() string { panic("inner hostile Error method") }

type nestedHostileError struct{}

func (nestedHostileError) Error() string { panic(innerHostileError{}) }

// TestLostAttemptRecordDoesNotRewindTheAttemptIndex pins what a recovered
// telemetry panic may and may not cost. It may cost that attempt's record.
// It may not corrupt the attempts that follow: when the index was derived
// from the number of stored records, a dropped record rewound the counter and
// every later attempt re-sent a=0 — a valid-looking header claiming to be the
// first attempt of the call. §2.2 permits missing telemetry, never false
// telemetry.
func TestLostAttemptRecordDoesNotRewindTheAttemptIndex(t *testing.T) {
	clearTelemetryEnv(t)
	defer stubSleep(func(context.Context, time.Duration) error { return nil })()

	var headers []string
	calls := 0
	sdk, err := NewClient(Options{APIKey: "k", MaxRetries: intPtr(3), HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
		headers = append(headers, r.Header.Get("x-tr-client"))
		calls++
		if calls <= 2 {
			return nil, nestedHostileError{}
		}
		return jsonResponse(http.StatusOK, map[string]any{"ok": true}, nil), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	// §2.2 first: the hostile value must not fail the request.
	if err := sdk.Request(context.Background(), http.MethodGet, "/models", nil, &out, nil); err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if len(headers) != 3 {
		t.Fatalf("attempts = %d, want 3", len(headers))
	}
	if headers[0] != "v=1;a=0;s=0" {
		t.Fatalf("attempt 0 x-tr-client = %q, want %q", headers[0], "v=1;a=0;s=0")
	}
	// Attempts 1 and 2 lost their predecessor's record, so they have no
	// previous-attempt facts to report and must send NOTHING. What they must
	// never do is re-claim a=0.
	for i, header := range headers[1:] {
		attempt := i + 1
		if header == "" {
			continue
		}
		fields := parseTelemetryHeader(t, header)
		if fields["a"] != strconv.Itoa(attempt) {
			t.Errorf("attempt %d x-tr-client = %q, which reports a=%s: a dropped record must not rewind the attempt index", attempt, header, fields["a"])
		}
	}
}

// selfUnwrappingError is a caller-injected error whose Unwrap returns itself.
// Telemetry must leave it opaque rather than calling the custom hook at all.
type selfUnwrappingError struct{}

func (selfUnwrappingError) Error() string   { return "cyclic transport error" }
func (e selfUnwrappingError) Unwrap() error { return e }

// deepUnwrappingError would build a long chain if its caller-defined Unwrap
// hook were dispatched. Telemetry must retain it as one opaque link.
type deepUnwrappingError struct{ depth int }

func (e deepUnwrappingError) Error() string { return "deep transport error" }
func (e deepUnwrappingError) Unwrap() error {
	if e.depth == 0 {
		return nil
	}
	return deepUnwrappingError{depth: e.depth - 1}
}

func TestErrorChainWalksOnlyKnownStandardLibraryWrappers(t *testing.T) {
	if got := len(telemetryErrorChain(selfUnwrappingError{})); got != 1 {
		t.Fatalf("custom cyclic chain length = %d, want 1 opaque link", got)
	}
	if got := len(telemetryErrorChain(deepUnwrappingError{depth: 100})); got != 1 {
		t.Fatalf("custom deep chain length = %d, want 1 opaque link", got)
	}
	if got := len(telemetryErrorChain(errors.New("flat"))); got != 1 {
		t.Fatalf("flat chain length = %d, want 1", got)
	}
	if got := len(telemetryErrorChain(nil)); got != 0 {
		t.Fatalf("nil chain length = %d, want 0", got)
	}
	// A joined error's branches are followed, and are also bounded.
	joined := errors.Join(errors.New("a"), errors.New("b"))
	if got := len(telemetryErrorChain(joined)); got != 3 {
		t.Fatalf("joined chain length = %d, want 3 (the join plus two branches)", got)
	}
	if got := classifyTransportError(selfUnwrappingError{}); got != "unknown" {
		t.Fatalf("classifyTransportError(cyclic) = %q, want %q", got, "unknown")
	}
}

type telemetryHookProbe struct {
	errorCalls   int
	isCalls      int
	timeoutCalls int
	unwrapCalls  int
}

func (e *telemetryHookProbe) Error() string {
	e.errorCalls++
	return "custom telemetry hook probe"
}

func (e *telemetryHookProbe) Is(error) bool {
	e.isCalls++
	return false
}

func (e *telemetryHookProbe) Timeout() bool {
	e.timeoutCalls++
	return false
}

func (e *telemetryHookProbe) Unwrap() error {
	e.unwrapCalls++
	return syscall.ECONNREFUSED
}

func TestClassificationDoesNotDispatchCustomErrorHooks(t *testing.T) {
	probe := &telemetryHookProbe{}
	if got := classifyTransportError(probe); got != "unknown" {
		t.Fatalf("classifyTransportError(custom hooks) = %q, want %q", got, "unknown")
	}
	if probe.errorCalls != 0 || probe.isCalls != 0 || probe.timeoutCalls != 0 || probe.unwrapCalls != 0 {
		t.Fatalf("telemetry dispatched custom hooks: Error=%d Is=%d Timeout=%d Unwrap=%d", probe.errorCalls, probe.isCalls, probe.timeoutCalls, probe.unwrapCalls)
	}
}

type blockingUnwrapError struct {
	called  chan struct{}
	release chan struct{}
}

func (*blockingUnwrapError) Error() string { return "blocking custom unwrap" }

func (e *blockingUnwrapError) Unwrap() error {
	close(e.called)
	<-e.release
	return nil
}

// TestBlockingCustomUnwrapIsNotCalledByTheEngine is the real retry-engine
// failure-isolation regression. A link-count bound is insufficient because a
// single Unwrap call can block forever; telemetry must make zero such calls,
// record the custom error as unknown, and allow the retry to succeed.
func TestBlockingCustomUnwrapIsNotCalledByTheEngine(t *testing.T) {
	clearTelemetryEnv(t)
	defer stubSleep(func(context.Context, time.Duration) error { return nil })()
	blocking := &blockingUnwrapError{
		called:  make(chan struct{}),
		release: make(chan struct{}),
	}
	defer close(blocking.release)

	var headers []string
	calls := 0
	maxRetries := 1
	sdk, err := NewClient(Options{APIKey: "k", MaxRetries: &maxRetries, HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
		headers = append(headers, r.Header.Get("x-tr-client"))
		calls++
		if calls == 1 {
			return nil, blocking
		}
		return jsonResponse(http.StatusOK, map[string]any{"ok": true}, nil), nil
	})})
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		var out map[string]any
		done <- sdk.Request(context.Background(), http.MethodGet, "/models", nil, &out, nil)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if calls != 2 {
			t.Fatalf("attempts = %d, want 2 (the retry must still happen)", calls)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request never returned: telemetry called the blocking custom Unwrap")
	}
	select {
	case <-blocking.called:
		t.Fatal("telemetry called the custom Unwrap method")
	default:
	}
	if len(headers) != 2 {
		t.Fatalf("captured headers = %d, want 2", len(headers))
	}
	fields := parseTelemetryHeader(t, headers[1])
	if fields["po"] != "transport_error" || fields["pc"] != "unknown" {
		t.Fatalf("retry x-tr-client = %q, want custom error recorded as transport_error/unknown", headers[1])
	}
}

// TestReadOpErrorIsNotStolenByTheProtocolMatch pins the precedence between
// io_error and protocol_error. An outer *net.OpError inherits the message of
// the error it wraps, so a read op wrapping anything that renders like an
// http2 frame error must still be io_error: the op is the more specific fact,
// and the protocol test only recognizes those renderings at the START of a
// link's own message.
func TestReadOpErrorIsNotStolenByTheProtocolMatch(t *testing.T) {
	readOp := &net.OpError{
		Op:     "read",
		Net:    "tcp",
		Source: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
		Err:    errors.New("connection error: INTERNAL_ERROR"),
	}
	if got := classifyTransportError(readOp); got != "io_error" {
		t.Fatalf("classifyTransportError(read op wrapping http2-looking text) = %q, want %q", got, "io_error")
	}
	// The genuine article, on its own link, still classifies as protocol_error.
	if got := classifyTransportError(errors.New("connection error: PROTOCOL_ERROR")); got != "protocol_error" {
		t.Fatalf("classifyTransportError(http2 connection error) = %q, want %q", got, "protocol_error")
	}
}
