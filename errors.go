package trustedrouter

// errors.go is the ERROR TAXONOMY (L6): the typed error hierarchy,
// status→error classification, response decode/raise helpers, and attribution
// fields with the raw payload preserved. Retry/failover DECISIONS live in
// retry_policy.go (L1); this file only names what went wrong.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"unicode/utf8"
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

// transportErrorMessageMaxBytes bounds the WHOLE typed transport-error
// message, prefix included — not just the flattened detail — so
// len(Message) <= transportErrorMessageMaxBytes is the invariant a caller
// can rely on (TestTransportErrorMessageIsBoundedIncludingPrefix).
const transportErrorMessageMaxBytes = 2048

const transportErrorMessagePrefix = "TrustedRouter endpoint unavailable: "

func transportRetryError(err error) error {
	return &InternalError{embeddedError: &Error{
		StatusCode: http.StatusServiceUnavailable,
		Message:    truncateString(transportErrorMessagePrefix+safeErrorMessage(err), transportErrorMessageMaxBytes),
	}}
}

// safeErrorMessage flattens a transport error into a bounded string. It is
// the SDK's single flattening point for a transport error.
//
// The value is arbitrary code whenever the caller injects an http.Client
// (Options.HTTPClient is used verbatim), so flattening it is a call into
// code the SDK does not control, at the exact moment the SDK is trying to
// report a failure.
//
// Rendering goes through fmt with the "%s" verb, not a direct err.Error()
// call and not fmt.Sprint, so an error that implements fmt.Formatter renders
// exactly as it did before this helper existed — including any redaction it
// performs there. Both alternatives are leaks waiting to happen: a direct
// .Error() call bypasses the Format method entirely, and fmt.Sprint (or
// "%v") hands it the VERBOSE verb, which a formatter may legitimately answer
// with the diagnostics it withholds from "%s". The verb is part of the
// contract with the caller's error, so it is pinned by
// TestFormatterRenderingIsPreserved.
//
// The recover guard covers what fmt cannot. fmt recovers a panicking Error
// method and renders a "%!s(PANIC=...)" marker, but it re-panics when the
// value the Error method panics WITH itself has a panicking Error method —
// and that shape reaches this SDK unwrapped on the mid-stream body path
// (TestNestedHostileMidStreamErrorSurfacesPlaceholder). So the SDK no
// longer depends on fmt's recovery for its own safety; it keeps fmt only
// for rendering fidelity.
//
// The guarantee is deliberately narrow: this is one flattening point, not a
// general shield around hostile caller-injected error values. Two shapes
// still bypass it, both out of this function's reach. net/http calls a
// RoundTripper error's Error method itself when it builds its own
// Client.Timeout error, so a panic there happens inside http.Client.Do
// before the SDK sees a value at all; and a panicking or cyclic
// Is/Unwrap method breaks the errors.Is traversal in decodeResponse below.
func safeErrorMessage(err error) (message string) {
	defer func() {
		if recover() != nil {
			message = "unprintable transport error"
		}
	}()
	if err == nil {
		return "unknown transport error"
	}
	return truncateString(fmt.Sprintf("%s", err), transportErrorMessageMaxBytes)
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

// truncateString bounds a string to limit BYTES without splitting a
// multi-byte rune at the cut. It walks back at most utf8.UTFMax-1 bytes to
// find the rune that straddles the limit and drops that rune whole; bytes
// that were already invalid UTF-8 in the source are left exactly as they
// were, so a message that arrives as arbitrary bytes is never mangled
// further than the cut itself.
func truncateString(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	for start := limit - 1; start >= 0 && limit-start < utf8.UTFMax; start-- {
		if !utf8.RuneStart(value[start]) {
			continue
		}
		if _, size := utf8.DecodeRuneInString(value[start:]); start+size > limit {
			return value[:start]
		}
		break
	}
	return value[:limit]
}
