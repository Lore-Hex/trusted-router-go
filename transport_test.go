package trustedrouter

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// panickingTransportError is the shape of an instrumentation wrapper's bug
// arriving through a caller-injected http.Client: an error value whose
// Error method is arbitrary code that panics.
//
// Reachability note, established while writing this test: fmt.Sprintf
// RECOVERS panics raised by an operand's Error method and renders a
// "%!s(PANIC=...)" marker instead, so the old
// fmt.Sprintf-based transportRetryError never crashed — it silently leaned
// on that fmt implementation detail and produced marker garbage in the
// message. The hazard becomes a real process crash the moment the raw
// value is flattened with a direct .Error() call (as the telemetry branch
// does during error classification, guarded there). safeErrorMessage makes
// the SDK's single flattening point immune either way and bounds the
// message.
type panickingTransportError struct{}

func (panickingTransportError) Error() string { panic("hostile Error method") }

// TestHostileErrorAtExhaustionSurfacesSDKError drives the real engine loop
// to retry exhaustion on an error whose Error() panics. The caller must
// receive the SDK's typed, bounded error — never a panic — regardless of
// how the flattening is implemented. The telemetry branch's
// TestHostileErrorValuesCannotFailTheRequest covers the same hostile value
// on the retry path; this test covers exhaustion.
func TestHostileErrorAtExhaustionSurfacesSDKError(t *testing.T) {
	defer stubSleep(func(context.Context, time.Duration) error { return nil })()

	calls := 0
	sdk, err := NewClient(Options{APIKey: "k", MaxRetries: intPtr(2), HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
		calls++
		return nil, panickingTransportError{}
	})})
	if err != nil {
		t.Fatal(err)
	}

	var out map[string]any
	err = sdk.Request(context.Background(), http.MethodGet, "/models", nil, &out, nil)
	if err == nil {
		t.Fatal("expected an error at retry exhaustion")
	}
	var internal *InternalError
	if !errors.As(err, &internal) {
		t.Fatalf("err = %T, want *InternalError", err)
	}
	if internal.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", internal.StatusCode, http.StatusServiceUnavailable)
	}
	if !strings.HasPrefix(internal.Message, "TrustedRouter endpoint unavailable: ") {
		t.Fatalf("message = %q, want the endpoint-unavailable prefix", internal.Message)
	}
	// http.Client wraps the transport error in *url.Error, whose own Error
	// method formats the hostile value through fmt — so the flattened text
	// may carry fmt's PANIC marker — but it must always be bounded.
	if len(internal.Message) > len("TrustedRouter endpoint unavailable: ")+2048 {
		t.Fatalf("message is %d bytes, want bounded", len(internal.Message))
	}
	if calls != 3 {
		t.Fatalf("attempts = %d, want 3 (initial + MaxRetries 2)", calls)
	}
}

// hostileBody is a response body whose Read fails with the hostile error.
// Mid-stream body errors reach transportRetryError UNWRAPPED — no
// url.Error, no fmt shielding on the direct flattening path — so this is
// where the recover guard itself is load-bearing.
type hostileBody struct{}

func (hostileBody) Read([]byte) (int, error) { return 0, panickingTransportError{} }
func (hostileBody) Close() error             { return nil }

func TestHostileMidStreamErrorSurfacesBoundedSDKError(t *testing.T) {
	sdk, err := NewClient(Options{APIKey: "k", HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
		resp := textResponse(http.StatusOK, "", nil)
		resp.Header.Set("Content-Type", "text/event-stream")
		resp.Body = io.NopCloser(hostileBody{})
		return resp, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	var streamErr error
	for _, err := range sdk.ChatCompletionsChunks(context.Background(), ChatRequest{
		Messages: []map[string]any{{"role": "user", "content": "hi"}},
	}) {
		if err != nil {
			streamErr = err
			break
		}
	}
	if streamErr == nil {
		t.Fatal("expected the broken stream to surface an error")
	}
	var internal *InternalError
	if !errors.As(streamErr, &internal) {
		t.Fatalf("err = %T, want *InternalError", streamErr)
	}
	if !strings.Contains(internal.Message, "unprintable transport error") {
		t.Fatalf("message = %q, want the bounded placeholder", internal.Message)
	}
}

func TestSafeErrorMessageBoundsAndFallbacks(t *testing.T) {
	if got := safeErrorMessage(nil); got != "unknown transport error" {
		t.Fatalf("safeErrorMessage(nil) = %q", got)
	}
	// The direct .Error() call is exactly the shape fmt does NOT shield;
	// only the recover guard stands between this value and a crash.
	if got := safeErrorMessage(panickingTransportError{}); got != "unprintable transport error" {
		t.Fatalf("safeErrorMessage(panicking) = %q", got)
	}
	if got := safeErrorMessage(errors.New(strings.Repeat("x", 10_000))); len(got) != 2048 {
		t.Fatalf("len(safeErrorMessage(long)) = %d, want 2048", len(got))
	}
	if got := safeErrorMessage(errors.New("plain")); got != "plain" {
		t.Fatalf("safeErrorMessage(plain) = %q", got)
	}
}
