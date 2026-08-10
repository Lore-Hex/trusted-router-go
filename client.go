package trustedrouter

// client.go is the CLIENT FACADE root (L8): construction, configuration, and
// introspection only. Nothing in this file loops, sleeps, or references a
// candidate index — plane selection lives in planes.go and the single
// retry/failover loop lives in transport.go.

import (
	"net/http"
	"strings"
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
	// RegionalFailover enables or disables regional failover; nil defaults to on.
	// The apex is a global load balancer; failover is handled server-side, so the
	// SDK re-requests the apex rather than pinning per-region hosts.
	RegionalFailover *bool
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
	apiKey           string
	baseURL          string
	controlBaseURL   string
	httpClient       *http.Client
	timeout          *time.Duration
	headers          map[string]string
	workspaceID      string
	maxRetries       int
	regionalFailover bool
	baseURLs         []string
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
		apiKey:           opts.APIKey,
		baseURL:          baseURL,
		controlBaseURL:   controlBaseURL,
		httpClient:       httpClient,
		timeout:          defaultTimeout,
		headers:          headers,
		workspaceID:      opts.WorkspaceID,
		maxRetries:       maxRetries,
		regionalFailover: failoverEnabled,
		baseURLs:         inferenceBaseURLs(baseURL),
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
