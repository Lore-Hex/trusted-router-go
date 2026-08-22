package trustedrouter

// client.go is the CLIENT FACADE root (L8): construction, configuration, and
// introspection only. Nothing in this file loops, sleeps, or references a
// candidate index — plane selection lives in planes.go and the single
// retry/failover loop lives in transport.go.

import (
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const defaultMaxRetries = 2

// Options configures a TrustedRouter Client.
type Options struct {
	// APIKey is the bearer token used for requests.
	APIKey string
	// BaseURL is a custom OpenAI-compatible inference API base URL.
	BaseURL string
	// ControlBaseURL is a custom TrustedRouter control-plane base URL.
	ControlBaseURL string
	// HTTPClient is the HTTP client used for network requests.
	// When HTTPClient is provided, the SDK shallow-clones it and overrides only
	// CheckRedirect so API requests cannot carry credentials or bodies to a
	// redirect target. Transport, Jar, Timeout, and other settings are preserved,
	// and the caller's client is not mutated. SDK timeouts are still applied with
	// request contexts; any timeout on the supplied client remains the caller's
	// responsibility.
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
	// RegionalFailover enables or disables regional failover; nil defaults to on.
	// The apex is a global load balancer; failover is handled server-side, so the
	// SDK re-requests the apex rather than pinning per-region hosts.
	RegionalFailover *bool
	// Telemetry enables or disables client-observed reliability telemetry
	// (contract v1): the per-attempt `x-tr-client` request header and the
	// beacon — a bounded, content-free batch of reliability events and exact
	// per-minute counters POSTed to the control plane's /client-events by a
	// background goroutine outside the retry engine. Everything on the wire
	// is a closed enum or a bounded integer: no prompt text, no hostnames,
	// no ids beyond SDK-minted batch ids. Nothing is recorded for custom
	// base URLs or control-plane calls. Nil resolves from the environment:
	// TRUSTEDROUTER_TELEMETRY ({0,false,off,no} disables, {1,true,on,yes}
	// enables), then DO_NOT_TRACK=1 disables, then default on only when both
	// the inference base and the control base are TrustedRouter hosts.
	// Opting out disables the header AND the beacon (no goroutine is ever
	// started) and does not change the User-Agent. Set
	// TRUSTEDROUTER_TELEMETRY_DEBUG=1 to echo each batch to stderr before it
	// is sent. Call Close to flush buffered telemetry (at most 2 seconds)
	// when the process is about to exit.
	Telemetry *bool
	// TelemetrySampleRate is the fraction of healthy, fast, first-attempt
	// successes the beacon reports (failures, retried or failed-over calls,
	// and calls slower than 30 s are always reported). Nil uses the
	// contract default of 0.01; a pointer to 0 reports no sampled
	// successes. The control plane may lower it, never raise it.
	TelemetrySampleRate *float64
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
	apiKey                   string
	baseURL                  string
	controlBaseURL           string
	httpClient               *http.Client
	credentialFreeHTTPClient *http.Client
	timeout                  *time.Duration
	headers                  map[string]string
	workspaceID              string
	maxRetries               int
	regionalFailover         bool
	telemetry                bool
	telemetrySampleRate      float64
	baseURLs                 []string

	// telemetryMu guards the lazily created beacon reporter. telemetrySink
	// is the reporter in production; tests inject a recording sink.
	telemetryMu       sync.Mutex
	telemetrySink     telemetrySink
	telemetryReporter *telemetryReporter
}

// NewClient constructs a TrustedRouter client.
func NewClient(opts Options) (*Client, error) {
	baseURL := opts.BaseURL
	if baseURL == "" {
		baseURL = DefaultAPIBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")

	controlBaseURL := opts.ControlBaseURL
	if controlBaseURL == "" {
		controlBaseURL = DefaultControlBaseURL
	}
	controlBaseURL = strings.TrimRight(controlBaseURL, "/")

	maxRetries := defaultMaxRetries
	if opts.MaxRetries != nil {
		maxRetries = *opts.MaxRetries
	}
	if maxRetries < 0 {
		maxRetries = 0
	}

	failoverEnabled := true
	if opts.RegionalFailover != nil {
		failoverEnabled = *opts.RegionalFailover
	}

	httpClient := cloneHTTPClientWithRedirectProtection(opts.HTTPClient)
	credentialFreeHTTPClient := cloneCredentialFreeHTTPClient(httpClient)
	defaultTimeout := defaultTimeoutFromOptions(opts.Timeout)

	headers := map[string]string{}
	for key, value := range opts.Headers {
		headers[key] = value
	}

	telemetrySampleRate := telemetryDefaultSampleRate
	if opts.TelemetrySampleRate != nil {
		telemetrySampleRate = telemetrySampleRateValue(*opts.TelemetrySampleRate)
	}

	return &Client{
		apiKey:                   opts.APIKey,
		baseURL:                  baseURL,
		controlBaseURL:           controlBaseURL,
		httpClient:               httpClient,
		credentialFreeHTTPClient: credentialFreeHTTPClient,
		timeout:                  defaultTimeout,
		headers:                  headers,
		workspaceID:              opts.WorkspaceID,
		maxRetries:               maxRetries,
		regionalFailover:         failoverEnabled,
		telemetry:                resolveTelemetryEnabled(opts.Telemetry, baseURL, controlBaseURL, os.Getenv),
		telemetrySampleRate:      telemetrySampleRate,
		baseURLs:                 inferenceBaseURLs(baseURL),
	}, nil
}

// Close flushes buffered client telemetry to the control plane — one
// attempt, at most 2 seconds — and stops the beacon's background goroutine.
// It never fails; the error return satisfies io.Closer. The client remains
// usable afterwards, but records no further telemetry. Clients with
// telemetry disabled have nothing to flush and return immediately.
func (c *Client) Close() error {
	c.telemetryMu.Lock()
	reporter := c.telemetryReporter
	c.telemetryMu.Unlock()
	if reporter != nil {
		reporter.close(telemetryCloseTimeout)
	}
	return nil
}

// telemetrySinkFor returns the beacon sink, creating the reporter on the
// first recorded inference call (contract §6.2: lazily, never at
// construction). Its worker goroutine starts on the first record.
func (c *Client) telemetrySinkFor() telemetrySink {
	c.telemetryMu.Lock()
	defer c.telemetryMu.Unlock()
	if c.telemetrySink == nil {
		c.telemetryReporter = newTelemetryReporter(c.controlBaseURL, c.apiKey, c.workspaceID, telemetrySDKIdentity(), c.telemetrySampleRate)
		c.telemetrySink = c.telemetryReporter
	}
	return c.telemetrySink
}

// newRequestRecorder builds the recorder for one inference-plane call
// (transport.go do() is the one emit point).
func (c *Client) newRequestRecorder(spec requestSpec) *requestRecorder {
	timeout, hasTimeout := c.effectiveTimeout(spec.opts)
	return newRequestRecorder(c.telemetrySinkFor(), spec.telemetry, spec.streamOpen, timeout, hasTimeout)
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

// ControlBaseURL returns the normalized primary control-plane base URL.
func (c *Client) ControlBaseURL() string {
	return c.controlBaseURL
}

// BaseURLs returns the normalized inference API base URL.
// Regional failover re-requests this apex/global-load-balancer URL.
func (c *Client) BaseURLs() []string {
	out := make([]string, len(c.baseURLs))
	copy(out, c.baseURLs)
	return out
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
