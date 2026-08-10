package trustedrouter

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Error is the base error type returned by the TrustedRouter SDK.
type Error struct {
	// StatusCode is the HTTP status code returned by the gateway.
	StatusCode int
	// Message is the human-readable error message.
	Message string
	// Payload is the parsed error payload when the gateway returned JSON.
	Payload any
	// Layer identifies whether routing, gateway, billing, or provider code failed.
	Layer string
	// Source is the actionable error source supplied by the API.
	Source string
	// Provider identifies the attempted provider when supplied.
	Provider string
	// RequestID correlates the error with TrustedRouter metadata logs.
	RequestID string
}

// Error returns the TrustedRouter error message.
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

type embeddedError = Error

// BadRequestError represents 400-class request errors other than the more specific subclasses.
type BadRequestError struct {
	*embeddedError
}

// Unwrap returns the base TrustedRouter error.
func (e *BadRequestError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.embeddedError
}

// AuthenticationError represents a 401 authentication failure.
type AuthenticationError struct {
	*embeddedError
}

// Unwrap returns the base TrustedRouter error.
func (e *AuthenticationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.embeddedError
}

// PermissionDeniedError represents a 403 authorization failure.
type PermissionDeniedError struct {
	*embeddedError
}

// Unwrap returns the base TrustedRouter error.
func (e *PermissionDeniedError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.embeddedError
}

// NotFoundError represents a 404 missing-resource response.
type NotFoundError struct {
	*embeddedError
}

// Unwrap returns the base TrustedRouter error.
func (e *NotFoundError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.embeddedError
}

// EndpointNotSupportedError represents a 501 intentionally unsupported endpoint.
type EndpointNotSupportedError struct {
	*embeddedError
}

// Unwrap returns the base TrustedRouter error.
func (e *EndpointNotSupportedError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.embeddedError
}

// RateLimitError represents a 429 rate-limit response.
type RateLimitError struct {
	*embeddedError
	// RetryAfter is the Retry-After header value in seconds when present and numeric.
	RetryAfter *float64
}

// Unwrap returns the base TrustedRouter error.
func (e *RateLimitError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.embeddedError
}

// InternalError represents a 5xx gateway or upstream failure.
type InternalError struct {
	*embeddedError
}

// Unwrap returns the base TrustedRouter error.
func (e *InternalError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.embeddedError
}

func classifyError(status int, message string, payload any, headers http.Header) error {
	if message == "" {
		message = "TrustedRouter error"
	}
	base := &Error{StatusCode: status, Message: message, Payload: payload}
	base.Layer = errorString(payload, "layer")
	base.Source = errorString(payload, "source")
	base.Provider = errorString(payload, "provider")
	base.RequestID = errorString(payload, "request_id")
	switch {
	case status == http.StatusUnauthorized:
		return &AuthenticationError{embeddedError: base}
	case status == http.StatusForbidden:
		return &PermissionDeniedError{embeddedError: base}
	case status == http.StatusNotFound:
		return &NotFoundError{embeddedError: base}
	case status == http.StatusTooManyRequests:
		return &RateLimitError{embeddedError: base, RetryAfter: retryAfterSeconds(headers)}
	case status == http.StatusNotImplemented:
		return &EndpointNotSupportedError{embeddedError: base}
	case status >= 400 && status < 500:
		return &BadRequestError{embeddedError: base}
	case status >= 500:
		return &InternalError{embeddedError: base}
	default:
		return base
	}
}

func errorString(payload any, key string) string {
	root, ok := payload.(map[string]any)
	if !ok {
		return ""
	}
	detail := root
	if nested, ok := root["error"].(map[string]any); ok {
		detail = nested
	}
	value, _ := detail[key].(string)
	return value
}

func transportRetryError(err error) error {
	return &InternalError{embeddedError: &Error{
		StatusCode: http.StatusServiceUnavailable,
		Message:    fmt.Sprintf("TrustedRouter endpoint unavailable: %s", err),
	}}
}

// shouldRetryVerdict reads the gateway's explicit x-should-retry instruction,
// which overrides every heuristic below it.
//
// A status code cannot say whether a provider already ran. A 502 from "could
// not reach the provider" and a 502 from "the generation succeeded and then
// settlement failed" are indistinguishable here, and only the second is
// dangerous to re-send. The gateway knows and now says so. Same header
// OpenAI's clients honour.
//
// Returns nil when the server did not say, which leaves existing behaviour
// untouched for older gateways and for paths deliberately left unlabelled.
func shouldRetryVerdict(headers http.Header) *bool {
	raw := strings.ToLower(strings.TrimSpace(headers.Get("X-Should-Retry")))
	switch raw {
	case "true":
		yes := true
		return &yes
	case "false":
		no := false
		return &no
	default:
		return nil
	}
}

func retryAfterSeconds(headers http.Header) *float64 {
	// retry-after-ms wins when both are present: it is the more precise of the
	// two, and a server that sends it means the sub-second value.
	if rawMS := strings.TrimSpace(headers.Get("Retry-After-Ms")); rawMS != "" {
		if millis, err := strconv.ParseFloat(rawMS, 64); err == nil && millis >= 0 {
			seconds := millis / 1000
			return &seconds
		}
	}
	raw := headers.Get("Retry-After")
	if raw == "" {
		return nil
	}
	parsed, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		// Python intentionally ignores HTTP-date Retry-After values; keep Go identical.
		return nil
	}
	if parsed < 0 {
		parsed = 0
	}
	return &parsed
}

// retryable answers "may we send this again", independent of WHERE. It used to
// take regionalFailover and return it for 502/503/504, which conflated two
// separate questions: pinning to one host also silently stopped retrying the
// gateway statuses entirely. Now the flag governs only the destination.
func retryable(status int, headers http.Header) bool {
	if verdict := shouldRetryVerdict(headers); verdict != nil {
		return *verdict
	}
	return status == http.StatusTooManyRequests || status >= 500
}

// regionalFailoverable answers "may this move to a DIFFERENT domain".
//
// An explicit x-should-retry: false forbids it outright — that is the gateway
// telling us a provider already ran, which is exactly when re-sending anywhere
// costs a second generation.
func regionalFailoverable(status int, headers http.Header) bool {
	if verdict := shouldRetryVerdict(headers); verdict != nil && !*verdict {
		return false
	}
	return status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}
