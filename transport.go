package trustedrouter

// transport.go is the TRANSPORT ENGINE (L3) plus ATTEMPT ASSEMBLY (L4): the
// ONE retry/failover loop in the SDK. This file is the only place in the
// entire codebase where a base-URL/candidate index advances and the only
// place that sleeps. Every request mode — buffered and streaming-open — runs
// through do(); the plane adapters in planes.go and the stream adapters in
// chat.go only build a requestSpec and delegate. The engine never drains a
// success body (that is what lets streaming share it) and never retries after
// the first surfaced body byte.
//
// INVARIANTS (each line names its enforcing test):
//
// (1) Failover set {502,503,504} ⊂ retry set {429, ≥500, verdict-true} —
// TestPinnedClientStillRetriesInPlace, TestA503AdvancesToTheNextCandidate.
// (2) 500 NEVER moves domains — a server processed the non-idempotent
// inference; re-sending elsewhere risks a second generation —
// TestA500DoesNotAdvanceToAnotherDomain.
// (3) Aliases exist only for the default host; control plane always has
// exactly one candidate; custom bases are never redirected —
// TestACustomBaseURLIsNeverRedirectedToAPublicAlias,
// TestControlRequestsDoNotUseRegionalFailover.
// (4) x-should-retry overrides both predicates in both directions: explicit
// false forbids retry AND failover; explicit true forces retry;
// absent/unparseable keeps status heuristics —
// TestALabelledSpent502IsNotRetried,
// TestALabelledRetryableStatusIsRetriedEvenWhenTheStatusSaysOtherwise,
// TestALabelledSpent502IsNotRetriedOnStreamOpen,
// TestALabelledRetryableStatusIsRetriedOnStreamOpen.
// (5) Idempotency key minted once per logical call before the loop and
// re-sent verbatim across every attempt and domain move — the caller is never
// double-charged (exactly-once settlement) —
// TestRegionalFailoverAndChatIdempotency.
// (6) Retries happen only before any body bytes are surfaced; a broken open
// stream propagates, never reconnects — TestChatStreamMidReadErrorIsWrapped,
// TestResponsesEventsMidReadErrorIsWrapped.
// (7) The failover flag governs WHERE, never WHETHER — a pinned client still
// retries in place — TestPinnedClientStillRetriesInPlace,
// TestPinnedStreamRetriesInPlace.
// (8) Transport errors are ambiguous about whether a server accepted the
// request. They retry and may move hosts only when the method or idempotency
// key makes replay safe; HTTP moves additionally require a failoverable status
// — TestTransportExhaustionWalksAllCandidates,
// TestGenericUnsafeTransportFailureIsNotRetriedWithoutIdempotency.
// (9) Terminal asymmetries are per-SDK contract and survive verbatim:
// exhausted-status RETURNS the response for the caller to classify
// (TestRequestRetryAndErrorBehavior/retries_exhausted_returns_last_error)
// while IO exhaustion THROWS (TestTransportExhaustionWalksAllCandidates);
// buffered vs stream-open raising differs
// (TestChatStreamOpenNon2xxYieldsTypedError).
// (10) The deliberately-unreachable verdict-false guard inside
// regionalFailoverable (retry_policy.go) is a documented surviving mutant —
// moved verbatim, never "fixed", never tested.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	mathrand "math/rand"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	errOpenTimeout              = errors.New("trustedrouter stream open timeout")
	errStreamIdleTimeout        = errors.New("trustedrouter stream idle timeout")
	idempotencyFallbackSequence atomic.Uint64
)

// requestSpec describes one logical call for the transport engine. The
// candidate list is built once by the plane router (planes.go) and never
// mutated here; only the index into it advances.
type requestSpec struct {
	method          string
	path            string
	body            []byte
	hasBody         bool
	opts            *CallOptions
	candidates      []string
	failover        bool
	streamOpen      bool
	autoIdempotency bool
	credentialFree  bool
	// controlPlane marks a control-plane call: client telemetry records
	// nothing and sends no x-tr-client header for those (contract §3.2).
	controlPlane bool
}

// do is THE transport engine: the only loop that advances a candidate index,
// consults the policy kernel, or sleeps.
//
// Buffered attempts get a context.WithTimeout per attempt. Streaming-open
// attempts get a context.WithCancelCause whose open timer fires
// errOpenTimeout and is stopped the moment response headers arrive; after a
// successful open the SAME cancel-cause is handed to the idle-timeout body
// wrapper, so a leaked timer or goroutine trips the -race stream tests.
func (c *Client) do(ctx context.Context, spec requestSpec) (*http.Response, error) {
	if spec.autoIdempotency {
		if spec.opts == nil {
			spec.opts = &CallOptions{}
		}
		if spec.opts.IdempotencyKey == "" {
			// Minted ONCE per logical call, before attempt 1, and replayed
			// verbatim on every retry and every candidate domain (invariant 5).
			spec.opts.IdempotencyKey = newIdempotencyKey()
		}
	}

	// Client-observed reliability telemetry, header channel (contract v1
	// §6.1: do() is the ONE emit point). One recorder per logical call;
	// control-plane calls and opted-out clients record nothing, and the
	// recorder's methods are nil-safe so the wiring stays unconditional.
	var recorder *requestRecorder
	if c.telemetry && !spec.controlPlane {
		recorder = newRequestRecorder(spec.streamOpen)
	}

	attempt := 0
	// baseIndex, not a pinned baseURL. This was `baseURL := baseURLs[0]` set
	// once outside the loop and never reassigned, so every retry re-hit the
	// same host — failover could not move even when candidates existed.
	baseIndex := 0
	timeout, hasTimeout := c.effectiveTimeout(spec.opts)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		var attemptCtx context.Context
		var cancelBuffered context.CancelFunc
		var cancelStream context.CancelCauseFunc
		var openTimer *time.Timer
		if spec.streamOpen {
			attemptCtx, cancelStream = context.WithCancelCause(ctx)
			if hasTimeout {
				timerCancel := cancelStream
				openTimer = time.AfterFunc(timeout, func() {
					timerCancel(errOpenTimeout)
				})
			}
		} else {
			attemptCtx, cancelBuffered = contextWithOptionalTimeout(ctx, timeout, hasTimeout)
		}
		cancelAttempt := func() {
			if spec.streamOpen {
				cancelStream(nil)
			} else {
				cancelBuffered()
			}
		}

		recorder.beginAttempt(spec.candidates[baseIndex])
		req, err := c.newHTTPRequest(attemptCtx, spec.method, joinURL(spec.candidates[baseIndex], spec.path), spec.body, spec.hasBody, spec.opts, recorder, spec.credentialFree)
		if err != nil {
			stopTimer(openTimer)
			cancelAttempt()
			return nil, err
		}

		httpClient := c.httpClient
		if spec.credentialFree {
			httpClient = c.credentialFreeHTTPClient
		}
		resp, err := httpClient.Do(req)
		// The open timer covers exactly the wait for response headers.
		stopTimer(openTimer)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				cancelAttempt()
				return nil, ctxErr
			}
			openTimedOut := spec.streamOpen && errors.Is(context.Cause(attemptCtx), errOpenTimeout)
			// Classify for telemetry BEFORE the transportRetryError flatten
			// below and the errOpenTimeout swap: after either, only a
			// message string remains of the typed error chain (§6.1).
			recorder.onTransportError(err, openTimedOut)
			if openTimedOut {
				err = errOpenTimeout
			}
			if attempt >= c.maxRetries || !requestReplaySafe(spec.method, spec.opts) {
				cancelAttempt()
				return nil, transportRetryError(err)
			}
			cancelAttempt()
			// A transport error may happen before or after a server accepted the
			// body. The replay-safety gate above is therefore mandatory before
			// either retrying or moving. The failover flag governs only WHERE a
			// safe retry goes; a pinned client retries on the named host.
			if spec.failover && baseIndex < len(spec.candidates)-1 {
				baseIndex++
				recorder.onMoved()
			}
			if sleepErr := sleepForRetry(ctx, attempt, nil); sleepErr != nil {
				return nil, sleepErr
			}
			attempt++
			continue
		}

		recorder.onResponse(resp.StatusCode)
		if attempt >= c.maxRetries || !retryable(resp.StatusCode, resp.Header) || !requestReplaySafe(spec.method, spec.opts) {
			if spec.streamOpen {
				if hasTimeout {
					resp.Body = newStreamIdleTimeoutReadCloser(resp.Body, attemptCtx, cancelStream, timeout)
				} else {
					resp.Body = cancelCauseOnCloseReadCloser{ReadCloser: resp.Body, cancel: cancelStream}
				}
			} else if hasTimeout {
				resp.Body = cancelOnCloseReadCloser{ReadCloser: resp.Body, cancel: cancelBuffered}
			}
			return resp, nil
		}
		retryAfter := retryAfterSeconds(resp.Header)
		drainAndClose(resp.Body)
		cancelAttempt()
		// Only the gateway-level statuses. A 500 means a server received and
		// processed the request, and inference is not idempotent, so retrying
		// it on another domain would run the work again: not a double charge
		// to the caller, but a second upstream generation we pay for.
		if spec.failover && regionalFailoverable(resp.StatusCode, resp.Header) && baseIndex < len(spec.candidates)-1 {
			baseIndex++
			recorder.onMoved()
		}
		if sleepErr := sleepForRetry(ctx, attempt, retryAfter); sleepErr != nil {
			return nil, sleepErr
		}
		attempt++
	}
}

// absoluteRequest is a documented ONE-SHOT (retries=0) path for credential-
// free metadata fetches at absolute URLs outside either /v1 plane (Status,
// Attestation, TrustRelease). It deliberately does not enter do(): there is
// no candidate list, no retry, and no credential attached.
func (c *Client) absoluteRequest(ctx context.Context, method, requestURL string) (*http.Response, error) {
	timeout, hasTimeout := c.effectiveTimeout(nil)
	attemptCtx, cancel := contextWithOptionalTimeout(ctx, timeout, hasTimeout)
	req, err := http.NewRequestWithContext(attemptCtx, method, requestURL, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	for key, value := range c.headers {
		req.Header.Set(key, value)
	}
	req.Header.Set("user-agent", userAgent())
	// Public metadata is credential-free even when the caller configured
	// credential-shaped default headers on the SDK client.
	stripCredentialHeaders(req.Header)
	resp, err := c.credentialFreeHTTPClient.Do(req)
	if err != nil {
		cancel()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, transportRetryError(err)
	}
	if hasTimeout {
		resp.Body = cancelOnCloseReadCloser{ReadCloser: resp.Body, cancel: cancel}
	}
	return resp, nil
}

func contextWithOptionalTimeout(ctx context.Context, timeout time.Duration, enabled bool) (context.Context, context.CancelFunc) {
	if !enabled {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

func marshalRequestBody(body any) ([]byte, bool, error) {
	if body == nil {
		return nil, false, nil
	}
	switch value := body.(type) {
	case json.RawMessage:
		return value, true, nil
	case []byte:
		return value, true, nil
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func (c *Client) newHTTPRequest(ctx context.Context, method, url string, bodyBytes []byte, hasBody bool, opts *CallOptions, recorder *requestRecorder, credentialFree bool) (*http.Request, error) {
	var body io.Reader
	if hasBody {
		body = bytes.NewReader(bodyBytes)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	for key, value := range c.headers {
		req.Header.Set(key, value)
	}
	req.Header.Set("user-agent", userAgent())
	if hasBody {
		req.Header.Set("content-type", "application/json")
	}
	if opts != nil {
		for key, value := range opts.ExtraHeaders {
			req.Header.Set(key, value)
		}
	}
	if opts != nil && opts.IdempotencyKey != "" {
		req.Header.Set("idempotency-key", opts.IdempotencyKey)
	}

	workspaceID := c.workspaceID
	if opts != nil && opts.WorkspaceID != nil {
		workspaceID = *opts.WorkspaceID
	}
	if workspaceID != "" {
		req.Header.Set("x-trustedrouter-workspace", workspaceID)
	}

	// Authorization is SDK-owned. Delete any default/per-call raw value first
	// so an empty APIKey override really suppresses it (notably for OAuth).
	req.Header.Del("authorization")
	apiKey := c.apiKey
	if opts != nil && opts.APIKey != nil {
		apiKey = *opts.APIKey
	}
	if opts != nil && opts.APIKey != nil && *opts.APIKey == "" {
		stripAuthenticationHeaders(req.Header)
	}
	if apiKey != "" {
		req.Header.Set("authorization", "Bearer "+apiKey)
	}

	// x-tr-client is assembled here and only here (contract §6.1), and the
	// header name is SDK-reserved across all six TrustedRouter SDKs: any
	// caller-supplied value is removed on EVERY path — opt-out, custom
	// bases, and control-plane calls included — and the SDK's own value is
	// set only while telemetry is actively recording (§3.2, §6.3).
	req.Header.Del("x-tr-client")
	if recorder != nil {
		if value := recorder.headerValue(); value != "" {
			req.Header.Set("x-tr-client", value)
		}
	}
	if credentialFree {
		stripCredentialHeaders(req.Header)
	}
	return req, nil
}

func joinURL(baseURL, path string) string {
	return strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(path, "/")
}

// userAgent is the SDK's static telemetry identity (contract §3.1): it must
// parse as `trusted-router-go/SEMVER( runtime/ver)?` for the enclave to
// derive sdk/sdk_version/runtime from it. The former trailing GOOS token
// broke that grammar and made the whole User-Agent unparseable, so the OS
// no longer rides the UA. A runtime token outside the §5.1 grammar (e.g. a
// devel toolchain version with spaces) is omitted rather than sent.
func userAgent() string {
	value := "trusted-router-go/" + Version
	if runtimeToken := "go/" + runtime.Version(); telemetryRuntimeTokenRe.MatchString(runtimeToken) {
		value += " " + runtimeToken
	}
	return value
}

// newIdempotencyKey is the single key-generator helper (invariant 5): every
// endpoint that mints does so through this function, exactly once per logical
// call, before the transport loop starts.
func newIdempotencyKey() string {
	return newIdempotencyKeyWithEntropy(rand.Reader)
}

func newIdempotencyKeyWithEntropy(entropy io.Reader) string {
	var b [24]byte
	if _, err := io.ReadFull(entropy, b[:]); err == nil {
		return "tr-req-" + base64.RawURLEncoding.EncodeToString(b[:])
	}
	// rand.Reader failures must not make request construction fail. The
	// process ID, nanosecond timestamp, and atomic sequence make this fallback
	// unique for concurrent calls in one process and collision-resistant across
	// independently started clients.
	binary.BigEndian.PutUint64(b[0:8], uint64(time.Now().UnixNano()))
	binary.BigEndian.PutUint64(b[8:16], uint64(os.Getpid()))
	binary.BigEndian.PutUint64(b[16:24], idempotencyFallbackSequence.Add(1))
	return "tr-req-" + base64.RawURLEncoding.EncodeToString(b[:])
}

func ensureIdempotencyKey(opts CallOptions) CallOptions {
	if opts.IdempotencyKey == "" {
		opts.IdempotencyKey = newIdempotencyKey()
	}
	return opts
}

func ensureIdempotencyOptions(opts *CallOptions) *CallOptions {
	var copy CallOptions
	if opts != nil {
		copy = *opts
	}
	copy = ensureIdempotencyKey(copy)
	return &copy
}

func requestReplaySafe(method string, opts *CallOptions) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return opts != nil && opts.IdempotencyKey != ""
	}
}

func cloneHTTPClientWithRedirectProtection(client *http.Client) *http.Client {
	var protected http.Client
	if client != nil {
		// A shallow copy preserves the caller's Transport, Jar, Timeout, and
		// other configuration without mutating shared client state.
		protected = *client
	}
	// The retry engine, not net/http, owns every physical attempt. Returning
	// the 3xx response also prevents prompt bodies and SDK headers from being
	// replayed to a Location on another origin.
	protected.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &protected
}

func cloneCredentialFreeHTTPClient(client *http.Client) *http.Client {
	credentialFree := *client
	// A standard-library cookie Jar mutates outgoing requests inside Client.Do,
	// after SDK header assembly. Removing it on this private clone keeps public
	// metadata and OAuth exchange credential-free without changing the caller's
	// client or the Jar used for ordinary API requests.
	credentialFree.Jar = nil
	return &credentialFree
}

func stripCredentialHeaders(headers http.Header) {
	for _, name := range []string{
		"authorization",
		"proxy-authorization",
		"cookie",
		"cookie2",
		"x-api-key",
		"x-trustedrouter-workspace",
		"idempotency-key",
		"x-tr-client",
	} {
		headers.Del(name)
	}
}

func stripAuthenticationHeaders(headers http.Header) {
	for _, name := range []string{
		"authorization",
		"proxy-authorization",
		"cookie",
		"cookie2",
		"x-api-key",
	} {
		headers.Del(name)
	}
}

func retrySleepDuration(attempt int, retryAfter *float64) time.Duration {
	if attempt > 6 {
		attempt = 6
	}
	base := 500 * time.Millisecond * time.Duration(1<<attempt)
	if base > 30*time.Second {
		base = 30 * time.Second
	}
	delay := time.Duration(mathrand.Float64() * float64(base))
	if retryAfter != nil {
		// Re-clamp rather than trusting the caller: retrySleepDuration is
		// reachable independently of the parser, and float64->time.Duration
		// SATURATES rather than erroring, so an unbounded value lands as a
		// 292-year timer instead of anything diagnosable.
		if bounded := boundedRetryAfter(*retryAfter); bounded != nil {
			floor := time.Duration(*bounded * float64(time.Second))
			if floor > delay {
				delay = floor
			}
		}
	}
	if ceiling := time.Duration(MaxRetryAfterSeconds * float64(time.Second)); delay > ceiling {
		delay = ceiling
	}
	return delay
}

var sleepContext = func(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func sleepForRetry(ctx context.Context, attempt int, retryAfter *float64) error {
	return sleepContext(ctx, retrySleepDuration(attempt, retryAfter))
}

func drainAndClose(body io.ReadCloser) {
	// Divergence from trusted-router-py: drain errors on failoverable bodies are ignored and retried.
	_, _ = io.Copy(io.Discard, body)
	_ = body.Close()
}

type cancelOnCloseReadCloser struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (r cancelOnCloseReadCloser) Close() error {
	err := r.ReadCloser.Close()
	r.cancel()
	return err
}

type cancelCauseOnCloseReadCloser struct {
	io.ReadCloser
	cancel context.CancelCauseFunc
}

func (r cancelCauseOnCloseReadCloser) Close() error {
	err := r.ReadCloser.Close()
	r.cancel(nil)
	return err
}

type streamIdleTimeoutReadCloser struct {
	body    io.ReadCloser
	ctx     context.Context
	cancel  context.CancelCauseFunc
	timeout time.Duration
	timer   *time.Timer
	mu      sync.Mutex
	closed  bool
}

func newStreamIdleTimeoutReadCloser(body io.ReadCloser, ctx context.Context, cancel context.CancelCauseFunc, timeout time.Duration) io.ReadCloser {
	r := &streamIdleTimeoutReadCloser{
		body:    body,
		ctx:     ctx,
		cancel:  cancel,
		timeout: timeout,
	}
	r.timer = time.AfterFunc(timeout, func() {
		cancel(errStreamIdleTimeout)
	})
	return r
}

func (r *streamIdleTimeoutReadCloser) Read(p []byte) (int, error) {
	n, err := r.body.Read(p)
	if n > 0 {
		r.reset()
	}
	if err != nil {
		r.stop()
		if errors.Is(context.Cause(r.ctx), errStreamIdleTimeout) {
			err = errStreamIdleTimeout
		}
	}
	return n, err
}

func (r *streamIdleTimeoutReadCloser) Close() error {
	r.stop()
	err := r.body.Close()
	r.cancel(nil)
	return err
}

func (r *streamIdleTimeoutReadCloser) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.timer.Reset(r.timeout)
	}
}

func (r *streamIdleTimeoutReadCloser) stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		r.timer.Stop()
	}
}

func stopTimer(timer *time.Timer) {
	if timer != nil {
		timer.Stop()
	}
}
