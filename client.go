package trustedrouter

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand"
	"net/http"
	"runtime"
	"strings"
	"time"
)

const defaultMaxRetries = 2

// Options configures a TrustedRouter Client.
type Options struct {
	// APIKey is the bearer token used for requests.
	APIKey string
	// BaseURL is a custom OpenAI-compatible API base URL.
	BaseURL string
	// Region pins the client to a known TrustedRouter region.
	Region string
	// HTTPClient is the HTTP client used for network requests.
	// When HTTPClient is provided, it is used verbatim; SDK timeouts are still
	// applied with request contexts and any timeout on the supplied client remains
	// the caller's responsibility.
	HTTPClient *http.Client
	// Timeout configures the default per-attempt request timeout. Nil uses
	// DefaultRequestTimeout. A pointer to 0 disables SDK timeouts by default.
	// Non-streaming calls apply this timeout to each retry attempt, not to the
	// whole operation. Streaming calls apply it to opening response headers and,
	// after open, to the idle gap between chunks rather than total stream time.
	Timeout *time.Duration
	// Headers are default headers sent with every request.
	Headers map[string]string
	// WorkspaceID is the default TrustedRouter workspace selector.
	WorkspaceID string
	// MaxRetries controls automatic retries; nil uses the reference default.
	MaxRetries *int
	// RegionalFailover enables or disables regional failover; nil mirrors the reference default.
	RegionalFailover *bool
	// FailoverRegions is the ordered regional failover list.
	FailoverRegions []string
}

// CallOptions configures a single TrustedRouter API call.
type CallOptions struct {
	// APIKey overrides the client API key for this call. Nil inherits; a pointer to "" suppresses Authorization.
	APIKey *string
	// ExtraHeaders are merged into the request headers for this call.
	ExtraHeaders map[string]string
	// WorkspaceID overrides the client workspace selector for this call. Nil inherits; a pointer to "" suppresses the workspace header.
	WorkspaceID *string
	// IdempotencyKey sets the idempotency-key header for this call.
	IdempotencyKey string
	// Timeout overrides Options.Timeout for this call. A pointer to 0 disables
	// the SDK timeout for this call. Non-streaming calls apply this timeout per
	// retry attempt, matching trusted-router-py's per-request behavior. Streaming
	// calls use it as an open timeout until response headers arrive, then as an
	// idle-read timeout between chunks, not as a whole-stream deadline.
	Timeout *time.Duration
}

// Client is a TrustedRouter API client.
type Client struct {
	apiKey      string
	baseURL     string
	region      string
	httpClient  *http.Client
	timeout     *time.Duration
	headers     map[string]string
	workspaceID string
	maxRetries  int
	baseURLs    []string
}

// NewClient constructs a TrustedRouter client.
func NewClient(opts Options) (*Client, error) {
	explicitEndpoint := opts.Region != "" || opts.BaseURL != ""
	if opts.Region != "" && opts.BaseURL != "" {
		return nil, &Error{Message: "pass region= OR base_url=, not both"}
	}

	baseURL := opts.BaseURL
	if opts.Region != "" {
		var err error
		baseURL, err = RegionBaseURL(opts.Region)
		if err != nil {
			return nil, err
		}
	}
	if baseURL == "" {
		baseURL = DefaultAPIBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")

	maxRetries := defaultMaxRetries
	if opts.MaxRetries != nil {
		maxRetries = *opts.MaxRetries
	}
	if maxRetries < 0 {
		maxRetries = 0
	}

	failoverEnabled := !explicitEndpoint
	if opts.RegionalFailover != nil {
		failoverEnabled = *opts.RegionalFailover
	}
	baseURLs, err := regionalBaseURLs(baseURL, failoverEnabled, opts.FailoverRegions)
	if err != nil {
		return nil, err
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	defaultTimeout := defaultTimeoutFromOptions(opts.Timeout)

	headers := map[string]string{}
	for key, value := range opts.Headers {
		headers[key] = value
	}

	return &Client{
		apiKey:      opts.APIKey,
		baseURL:     baseURL,
		region:      opts.Region,
		httpClient:  httpClient,
		timeout:     defaultTimeout,
		headers:     headers,
		workspaceID: opts.WorkspaceID,
		maxRetries:  maxRetries,
		baseURLs:    baseURLs,
	}, nil
}

// APIKey returns the configured default API key.
func (c *Client) APIKey() string {
	return c.apiKey
}

// WorkspaceID returns the configured default workspace selector.
func (c *Client) WorkspaceID() string {
	return c.workspaceID
}

// MaxRetries returns the configured retry count.
func (c *Client) MaxRetries() int {
	return c.maxRetries
}

// DefaultHeaders returns a copy of the configured default headers.
func (c *Client) DefaultHeaders() map[string]string {
	out := make(map[string]string, len(c.headers))
	for key, value := range c.headers {
		out[key] = value
	}
	return out
}

// BaseURL returns the normalized primary API base URL.
func (c *Client) BaseURL() string {
	return c.baseURL
}

// Region returns the configured region, if any.
func (c *Client) Region() string {
	return c.region
}

// BaseURLs returns the ordered primary and failover API base URLs.
func (c *Client) BaseURLs() []string {
	out := make([]string, len(c.baseURLs))
	copy(out, c.baseURLs)
	return out
}

// Request sends an API request, retries reference retryable responses, and decodes JSON into out.
func (c *Client) Request(ctx context.Context, method, path string, body any, out any, opts *CallOptions) error {
	resp, err := c.rawRequest(ctx, method, path, body, opts)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeResponse(ctx, resp, out)
}

// RawRequest sends an API request and returns the final raw HTTP response after retry handling.
// The caller must close the returned response body.
func (c *Client) RawRequest(ctx context.Context, method, path string, body any, opts *CallOptions) (*http.Response, error) {
	return c.rawRequest(ctx, method, path, body, opts)
}

func (c *Client) rawRequest(ctx context.Context, method, path string, body any, opts *CallOptions) (*http.Response, error) {
	bodyBytes, hasBody, err := marshalRequestBody(body)
	if err != nil {
		return nil, err
	}

	attempt := 0
	baseIndex := 0
	timeout, hasTimeout := c.effectiveTimeout(opts)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		attemptCtx, cancel := contextWithOptionalTimeout(ctx, timeout, hasTimeout)

		req, err := c.newHTTPRequest(attemptCtx, method, joinURL(c.baseURLs[baseIndex], path), bodyBytes, hasBody, opts)
		if err != nil {
			cancel()
			return nil, err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				cancel()
				return nil, ctxErr
			}
			if attempt >= c.maxRetries {
				cancel()
				return nil, transportRetryError(err)
			}
			if baseIndex < len(c.baseURLs)-1 {
				baseIndex++
			}
			cancel()
			if sleepErr := sleepForRetry(ctx, attempt, nil); sleepErr != nil {
				return nil, sleepErr
			}
			attempt++
			continue
		}

		if attempt >= c.maxRetries || !retryable(resp.StatusCode) {
			if hasTimeout {
				resp.Body = cancelOnCloseReadCloser{ReadCloser: resp.Body, cancel: cancel}
			}
			return resp, nil
		}
		if regionalFailoverable(resp.StatusCode) && baseIndex < len(c.baseURLs)-1 {
			baseIndex++
		}
		retryAfter := retryAfterSeconds(resp.Header)
		drainAndClose(resp.Body)
		cancel()
		if sleepErr := sleepForRetry(ctx, attempt, retryAfter); sleepErr != nil {
			return nil, sleepErr
		}
		attempt++
	}
}

func defaultTimeoutFromOptions(timeout *time.Duration) *time.Duration {
	if timeout == nil {
		value := DefaultRequestTimeout
		return &value
	}
	if *timeout == 0 {
		return nil
	}
	value := *timeout
	return &value
}

func (c *Client) effectiveTimeout(opts *CallOptions) (time.Duration, bool) {
	if opts != nil && opts.Timeout != nil {
		if *opts.Timeout == 0 {
			return 0, false
		}
		return *opts.Timeout, true
	}
	if c.timeout == nil {
		return 0, false
	}
	return *c.timeout, true
}

func contextWithOptionalTimeout(ctx context.Context, timeout time.Duration, enabled bool) (context.Context, context.CancelFunc) {
	if !enabled {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
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

func regionalBaseURLs(primaryBaseURL string, enabled bool, failoverRegions []string) ([]string, error) {
	urls := []string{strings.TrimRight(primaryBaseURL, "/")}
	if !enabled {
		return urls, nil
	}
	regions := failoverRegions
	if len(regions) == 0 {
		regions = DefaultFailoverRegions
	}
	for _, region := range regions {
		candidate, err := RegionBaseURL(region)
		if err != nil {
			return nil, err
		}
		candidate = strings.TrimRight(candidate, "/")
		if !stringInSlice(candidate, urls) {
			urls = append(urls, candidate)
		}
	}
	return urls, nil
}

func stringInSlice(needle string, haystack []string) bool {
	for _, value := range haystack {
		if value == needle {
			return true
		}
	}
	return false
}

func marshalRequestBody(body any) ([]byte, bool, error) {
	if body == nil {
		return nil, false, nil
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func (c *Client) newHTTPRequest(ctx context.Context, method, url string, bodyBytes []byte, hasBody bool, opts *CallOptions) (*http.Request, error) {
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

	apiKey := c.apiKey
	if opts != nil && opts.APIKey != nil {
		apiKey = *opts.APIKey
	}
	if apiKey != "" {
		req.Header.Set("authorization", "Bearer "+apiKey)
	}
	return req, nil
}

func decodeResponse(ctx context.Context, resp *http.Response, out any) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return transportRetryError(err)
		}
		return err
	}
	if resp.StatusCode >= 400 {
		payload, ok := parseJSONPayload(body)
		if !ok {
			return classifyError(resp.StatusCode, truncateString(string(body), 240), nil, resp.Header)
		}
		return classifyError(resp.StatusCode, errorMessage(payload), payload, resp.Header)
	}
	if out == nil {
		return nil
	}
	if len(body) == 0 {
		return io.ErrUnexpectedEOF
	}
	return json.Unmarshal(body, out)
}

func parseJSONPayload(body []byte) (any, bool) {
	if len(body) == 0 {
		return nil, false
	}
	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, false
	}
	return payload, true
}

func errorMessage(payload any) string {
	obj, ok := payload.(map[string]any)
	if !ok {
		return "TrustedRouter error"
	}
	errRaw, hasError := obj["error"]
	if hasError {
		errValue, ok := errRaw.(map[string]any)
		if ok {
			if message, ok := errValue["message"]; ok && truthy(message) {
				return fmt.Sprint(message)
			}
			if typ, ok := errValue["type"]; ok && truthy(typ) {
				return fmt.Sprint(typ)
			}
			return "TrustedRouter error"
		}
	}
	if message, ok := obj["message"]; ok && truthy(message) {
		return fmt.Sprint(message)
	}
	return "TrustedRouter error"
}

func truthy(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		return v != ""
	case int:
		return v != 0
	case int8:
		return v != 0
	case int16:
		return v != 0
	case int32:
		return v != 0
	case int64:
		return v != 0
	case uint:
		return v != 0
	case uint8:
		return v != 0
	case uint16:
		return v != 0
	case uint32:
		return v != 0
	case uint64:
		return v != 0
	case float32:
		return v != 0
	case float64:
		return v != 0
	default:
		return true
	}
}

func joinURL(baseURL, path string) string {
	return strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(path, "/")
}

func userAgent() string {
	return "trusted-router-go/" + Version + " go/" + runtime.Version() + " " + runtime.GOOS
}

func newIdempotencyKey() string {
	var b [24]byte
	if _, err := rand.Read(b[:]); err == nil {
		return "tr-req-" + base64.RawURLEncoding.EncodeToString(b[:])
	}
	return "tr-req-" + base64.RawURLEncoding.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))
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
		floor := time.Duration(*retryAfter * float64(time.Second))
		if floor > delay {
			delay = floor
		}
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

func truncateString(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
