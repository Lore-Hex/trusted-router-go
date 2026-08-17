package trustedrouter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// The hostile values below are the shape of an instrumentation wrapper's bug
// arriving through a caller-injected http.Client: an error value whose
// rendering is arbitrary code.
//
// Reachability, established empirically rather than assumed (the numbers
// each test asserts follow from it):
//
//   - fmt RECOVERS a panic raised by an operand's Error method and renders a
//     "%!s(PANIC=...)" marker. So a plain panicking Error method never
//     crashed the pre-fix fmt.Sprintf implementation, and it does not crash
//     the current one either.
//   - fmt does NOT survive a panic whose VALUE is itself an error with a
//     panicking Error method: catchPanic formats the panic value, hits the
//     second panic while already panicking, and re-panics out of
//     fmt.Sprintf. That is a real process crash, and it reaches the SDK
//     unwrapped on the mid-stream body path — see
//     TestNestedHostileMidStreamErrorSurfacesPlaceholder, which is the test
//     that fails (crashes) without safeErrorMessage's recover guard.
//   - http.Client.Do wraps a RoundTripper error in *url.Error, whose own
//     Error method renders the inner value through fmt. That extra fmt
//     frame is why the exhaustion path sees a marker string rather than a
//     panic for the plain hostile value.
type panickingTransportError struct{}

func (panickingTransportError) Error() string { panic("hostile Error method") }

// nestedPanickingTransportError panics WITH an error whose Error method
// panics in turn — the shape fmt cannot recover from.
type nestedPanickingTransportError struct{}

func (nestedPanickingTransportError) Error() string { panic(panickingTransportError{}) }

// redactingError renders three different ways: redacted under the "%s" verb,
// verbose under "%v", and unredacted from Error(). That is the real shape of
// a diagnostics-aware error type, and it makes the rendering path a privacy
// decision rather than a formatting detail — a direct .Error() call and a
// fmt.Sprint/"%v" call each publish something "%s" withholds.
type redactingError struct{}

func (redactingError) Error() string { return "authorization=Bearer sk-live-SECRET" }

func (redactingError) Format(f fmt.State, verb rune) {
	if verb == 's' {
		_, _ = io.WriteString(f, "authorization=[redacted]")
		return
	}
	_, _ = io.WriteString(f, "authorization=Bearer sk-live-SECRET (verbose diagnostics)")
}

// hostileBody is a response body whose Read fails with the supplied error.
// Mid-stream body errors reach transportRetryError UNWRAPPED — no url.Error
// frame, no extra fmt shielding — so this is the path where the guard and
// the bound are load-bearing.
type hostileBody struct{ err error }

func (b hostileBody) Read([]byte) (int, error) { return 0, b.err }
func (b hostileBody) Close() error             { return nil }

func streamErrorFor(t *testing.T, bodyErr error) *InternalError {
	t.Helper()
	sdk, err := NewClient(Options{APIKey: "k", HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
		resp := textResponse(http.StatusOK, "", nil)
		resp.Header.Set("Content-Type", "text/event-stream")
		resp.Body = io.NopCloser(hostileBody{err: bodyErr})
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
	return internal
}

// TestHostileErrorAtExhaustionSurfacesSDKError drives the real engine loop to
// retry exhaustion on an error whose Error method panics. This one is
// REGRESSION coverage, not the proof of the fix: because http.Client.Do's
// *url.Error wrapper renders the value through fmt, this case passed on the
// pre-fix implementation too. It is kept because it pins the engine
// behaviour around the flattening point — typed error, status, attempt
// count, bounded message — for every future refactor of it. The proof that
// the guard does something lives in
// TestNestedHostileMidStreamErrorSurfacesPlaceholder.
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
	if !strings.HasPrefix(internal.Message, transportErrorMessagePrefix) {
		t.Fatalf("message = %q, want the endpoint-unavailable prefix", internal.Message)
	}
	if len(internal.Message) > transportErrorMessageMaxBytes {
		t.Fatalf("message is %d bytes, want <= %d", len(internal.Message), transportErrorMessageMaxBytes)
	}
	if calls != 3 {
		t.Fatalf("attempts = %d, want 3 (initial + MaxRetries 2)", calls)
	}
}

// TestNestedHostileMidStreamErrorSurfacesPlaceholder is the load-bearing
// test for the recover guard. The body error's Error method panics WITH a
// value whose own Error method panics, which fmt re-panics on, and it
// arrives at the single flattening point unwrapped. Without the guard this
// test does not merely fail — it crashes the test binary.
func TestNestedHostileMidStreamErrorSurfacesPlaceholder(t *testing.T) {
	internal := streamErrorFor(t, nestedPanickingTransportError{})
	if !strings.Contains(internal.Message, "unprintable transport error") {
		t.Fatalf("message = %q, want the bounded placeholder", internal.Message)
	}
	if len(internal.Message) > transportErrorMessageMaxBytes {
		t.Fatalf("message is %d bytes, want <= %d", len(internal.Message), transportErrorMessageMaxBytes)
	}
}

// TestHostileMidStreamErrorSurfacesBoundedSDKError covers the plain hostile
// value on the same unwrapped path: fmt renders its marker, the SDK stays up,
// and the message stays typed and bounded.
func TestHostileMidStreamErrorSurfacesBoundedSDKError(t *testing.T) {
	internal := streamErrorFor(t, panickingTransportError{})
	if !strings.HasPrefix(internal.Message, transportErrorMessagePrefix) {
		t.Fatalf("message = %q, want the endpoint-unavailable prefix", internal.Message)
	}
	if len(internal.Message) > transportErrorMessageMaxBytes {
		t.Fatalf("message is %d bytes, want <= %d", len(internal.Message), transportErrorMessageMaxBytes)
	}
}

// TestTransportErrorMessageIsBoundedIncludingPrefix pins the bound as a
// property of the WHOLE message. Bounding only the flattened detail leaves
// the prefix on top of it, which is how a "2048-byte cap" turns into 2084
// bytes on the wire to the caller's logs.
func TestTransportErrorMessageIsBoundedIncludingPrefix(t *testing.T) {
	internal := streamErrorFor(t, errors.New(strings.Repeat("x", 10_000)))
	if len(internal.Message) != transportErrorMessageMaxBytes {
		t.Fatalf("message is %d bytes, want exactly %d (prefix included)", len(internal.Message), transportErrorMessageMaxBytes)
	}
}

// TestFormatterRenderingIsPreserved pins the rendering path down to the
// VERB. The SDK flattens with "%s", which is what the code did before the
// helper existed, so an error that redacts under "%s" keeps redacting. Both
// nearby alternatives fail this test, which is the point of it: a direct
// err.Error() call bypasses Format and publishes the credential, and
// fmt.Sprint (or "%v") asks the same formatter for its verbose rendering and
// publishes it too. Either way the secret ends up in InternalError.Message
// and from there in the caller's logs.
func TestFormatterRenderingIsPreserved(t *testing.T) {
	internal := streamErrorFor(t, redactingError{})
	if strings.Contains(internal.Message, "sk-live-SECRET") {
		t.Fatalf("message = %q leaked what the caller's %%s rendering withholds", internal.Message)
	}
	if !strings.Contains(internal.Message, "authorization=[redacted]") {
		t.Fatalf("message = %q, want the Format method's %%s rendering", internal.Message)
	}
	// Guard the helper directly too, so the pin does not depend on the
	// stream path staying the way in.
	if got := safeErrorMessage(redactingError{}); got != "authorization=[redacted]" {
		t.Fatalf("safeErrorMessage(redacting) = %q, want the %%s rendering", got)
	}
}

func TestSafeErrorMessageBoundsAndFallbacks(t *testing.T) {
	if got := safeErrorMessage(nil); got != "unknown transport error" {
		t.Fatalf("safeErrorMessage(nil) = %q", got)
	}
	if got := safeErrorMessage(errors.New("plain")); got != "plain" {
		t.Fatalf("safeErrorMessage(plain) = %q", got)
	}
	// fmt survives a plain panicking Error method; the SDK must not crash
	// and must not exceed the bound either way.
	if got := safeErrorMessage(panickingTransportError{}); got == "" || len(got) > transportErrorMessageMaxBytes {
		t.Fatalf("safeErrorMessage(panicking) = %q", got)
	}
	// fmt does NOT survive this one; only the recover guard does.
	if got := safeErrorMessage(nestedPanickingTransportError{}); got != "unprintable transport error" {
		t.Fatalf("safeErrorMessage(nested panicking) = %q, want the placeholder", got)
	}
	if got := safeErrorMessage(errors.New(strings.Repeat("x", 10_000))); len(got) != transportErrorMessageMaxBytes {
		t.Fatalf("len(safeErrorMessage(long)) = %d, want %d", len(got), transportErrorMessageMaxBytes)
	}
}

// TestTruncateStringKeepsRunesWhole pins the cut: a multi-byte rune
// straddling the limit is dropped whole rather than sliced into replacement
// characters, and bytes that were already invalid are left alone.
func TestTruncateStringKeepsRunesWhole(t *testing.T) {
	straddling := strings.Repeat("a", transportErrorMessageMaxBytes-1) + "€" + "tail"
	got := truncateString(straddling, transportErrorMessageMaxBytes)
	if len(got) != transportErrorMessageMaxBytes-1 {
		t.Fatalf("len = %d, want %d (the straddling rune dropped whole)", len(got), transportErrorMessageMaxBytes-1)
	}
	if !utf8.ValidString(got) {
		t.Fatalf("truncated value %q is not valid UTF-8", got[len(got)-8:])
	}
	if got := truncateString("abcdef", 3); got != "abc" {
		t.Fatalf("ascii truncation = %q, want %q", got, "abc")
	}
	if got := truncateString("abc", 10); got != "abc" {
		t.Fatalf("under-limit truncation = %q, want %q", got, "abc")
	}
	// Already-invalid bytes are not walked past: the cut lands where asked.
	invalid := "ab\xff\xff\xff\xff\xffcd"
	if got := truncateString(invalid, 6); len(got) != 6 {
		t.Fatalf("len = %d, want 6 (invalid bytes left as-is)", len(got))
	}
}
