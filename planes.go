package trustedrouter

// planes.go is the PLANE ROUTER / CANDIDATE SET (L2): it builds the ordered
// base-URL candidate list once per logical call and hands it to the transport
// engine (transport.go). Inference plane: primary first, alias domains
// appended ONLY when the configured base equals the default host. Control
// plane: a ONE-ENTRY list, so failover is structurally impossible — the list
// length is the gate, not a second flag
// (TestControlRequestsDoNotUseRegionalFailover pins it).
//
// No function in this file loops, sleeps, or references a candidate index.

import (
	"context"
	"net/http"
	"strings"
)

// Request sends an API request, retries reference retryable responses, and decodes JSON into out.
// json.RawMessage and []byte bodies are sent verbatim.
func (c *Client) Request(ctx context.Context, method, path string, body any, out any, opts *CallOptions) error {
	resp, err := c.rawRequest(ctx, method, path, body, opts)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeResponse(ctx, resp, out)
}

// RawRequest sends an API request and returns the final raw HTTP response after retry handling.
// json.RawMessage and []byte bodies are sent verbatim.
// The caller must close the returned response body.
func (c *Client) RawRequest(ctx context.Context, method, path string, body any, opts *CallOptions) (*http.Response, error) {
	return c.rawRequest(ctx, method, path, body, opts)
}

func (c *Client) rawRequest(ctx context.Context, method, path string, body any, opts *CallOptions) (*http.Response, error) {
	return c.rawRequestWithBaseURLs(ctx, method, path, body, opts, c.baseURLs, c.regionalFailover)
}

func (c *Client) controlRequest(ctx context.Context, method, path string, body any, out any, opts *CallOptions) error {
	resp, err := c.rawControlRequest(ctx, method, path, body, opts)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeResponse(ctx, resp, out)
}

func (c *Client) credentialFreeControlRequest(ctx context.Context, method, path string, body any, out any, opts *CallOptions) error {
	resp, err := c.rawControlRequestWithBoundary(ctx, method, path, body, opts, true)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeResponse(ctx, resp, out)
}

func (c *Client) rawControlRequest(ctx context.Context, method, path string, body any, opts *CallOptions) (*http.Response, error) {
	return c.rawControlRequestWithBoundary(ctx, method, path, body, opts, false)
}

func (c *Client) rawControlRequestWithBoundary(ctx context.Context, method, path string, body any, opts *CallOptions, credentialFree bool) (*http.Response, error) {
	// The one-entry candidate list IS the control-plane failover mechanism:
	// every advance in the engine is guarded by baseIndex < len(candidates)-1,
	// so a singleton list makes a domain move structurally impossible. Do not
	// add a second flag.
	//
	// controlPlane marks the spec so client telemetry records nothing and
	// sends no x-tr-client header on this plane (contract §3.2).
	return c.dispatchRequest(ctx, method, path, body, opts, []string{c.controlBaseURL}, true, true, credentialFree)
}

// rawRequestWithBaseURLs is a thin delegate into the transport engine. It is
// kept (unexported) because the alias-failover tests drive it directly with
// an injected candidate pair to prove the ADVANCE half of failover.
func (c *Client) rawRequestWithBaseURLs(ctx context.Context, method, path string, body any, opts *CallOptions, baseURLs []string, regionalFailover bool) (*http.Response, error) {
	return c.dispatchRequest(ctx, method, path, body, opts, baseURLs, regionalFailover, false, false)
}

func (c *Client) dispatchRequest(ctx context.Context, method, path string, body any, opts *CallOptions, baseURLs []string, regionalFailover, controlPlane, credentialFree bool) (*http.Response, error) {
	bodyBytes, hasBody, err := marshalRequestBody(body)
	if err != nil {
		return nil, err
	}
	return c.do(ctx, requestSpec{
		method:         method,
		path:           path,
		body:           bodyBytes,
		hasBody:        hasBody,
		opts:           opts,
		candidates:     baseURLs,
		failover:       regionalFailover,
		controlPlane:   controlPlane,
		credentialFree: credentialFree,
	})
}

// inferenceBaseURLs returns the primary followed by the alias domains.
//
// The list must have MORE THAN ONE entry or failover cannot engage: every
// advance is guarded by `baseIndex < len(baseURLs)-1`.
//
// Aliases are added ONLY for the default host. A caller who passed their own
// base URL — a private deployment, a test server, a regional pin — gets exactly
// that; silently redirecting their traffic to a public alias would be worse
// than failing.
func inferenceBaseURLs(primary string) []string {
	trimmed := strings.TrimRight(primary, "/")
	if trimmed != strings.TrimRight(DefaultAPIBaseURL, "/") {
		return []string{primary}
	}
	out := []string{trimmed}
	for _, alias := range AliasAPIBaseURLs {
		out = append(out, strings.TrimRight(alias, "/"))
	}
	return out
}
