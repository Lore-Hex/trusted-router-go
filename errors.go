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

func transportRetryError(err error) error {
	return &InternalError{embeddedError: &Error{
		StatusCode: http.StatusServiceUnavailable,
		Message:    fmt.Sprintf("TrustedRouter regional endpoint unavailable: %s", err),
	}}
}

func retryAfterSeconds(headers http.Header) *float64 {
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

func retryable(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

func regionalFailoverable(status int) bool {
	return status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}
