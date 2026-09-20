package trustedrouter

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// ResponseShapeError reports a malformed consumed field in an auth response.
// Optional metadata is not required by these guards.
type ResponseShapeError struct {
	// Err is the underlying response decoding or shape error.
	Err error
}

// Error returns the response-shape failure message.
func (e *ResponseShapeError) Error() string { return "invalid auth response: " + e.Err.Error() }

// Unwrap returns the underlying error for errors.Is and errors.As.
func (e *ResponseShapeError) Unwrap() error { return e.Err }

func requireJSONField(data []byte, field string, kind byte) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return &ResponseShapeError{Err: err}
	}
	raw := bytes.TrimSpace(object[field])
	if len(raw) == 0 || raw[0] != kind {
		return &ResponseShapeError{Err: fmt.Errorf("%s has missing or invalid shape", field)}
	}
	return nil
}
