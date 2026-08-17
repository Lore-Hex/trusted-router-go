package trustedrouter

// telemetry.go is the HEADER CHANNEL of the client-observed reliability
// telemetry contract, v1 (docs/client-telemetry.md in Lore-Hex/quill-router):
// the per-attempt `x-tr-client` request header (§3.2), the closed host and
// error-class vocabulary (§5.2), and the opt-out resolution (§6.3). It
// mirrors trusted-router-py `_telemetry.py` (RequestRecorder, host_enum,
// classify_transport_error, resolve_telemetry_enabled).
//
// The BEACON channel (§4–§5) is deliberately absent: §9 step 7 ships
// header-only PRs in the non-Python SDKs, and §10 forbids beacons in a
// second SDK until the Python contract has been live and calibrated.
// absoluteRequest (transport.go) is the reserved out-of-engine attach point
// for that later beacon sender (§6.1); the parity constants below pin the
// vocabulary it will use.
//
// Telemetry never fails a request (§2.2): every recorder method is
// nil-receiver safe, and an out-of-grammar header value sends NOTHING
// rather than panicking or erroring.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// telemetrySchemaVersion pins the beacon schema version (§5.1) for the
	// later beacon PR; the header grammar pins v=1 independently (§3.2).
	telemetrySchemaVersion = 1
	// telemetryEventsPath pins the beacon POST path (§4) for the later
	// beacon PR.
	telemetryEventsPath = "/client-events"
	// telemetryMaxHeaderBytes bounds the whole x-tr-client header (§3.2).
	telemetryMaxHeaderBytes = 160
	// telemetryMaxDurationMS clamps every duration field (§3.2, §5.3).
	telemetryMaxDurationMS = 3_600_000
)

// Closed enum vocabulary (§5.2), pinned byte-for-byte by
// TestTelemetryParityConstants. Grown server-first (§9); never edit here
// ahead of the contract.
var (
	telemetryHosts = []string{
		"apex",
		"ally",
		"uptime",
		"us_central1",
		"us_east4",
		"europe_west4",
		"control",
		"custom",
	}
	telemetryEndpoints = []string{
		"chat_completions",
		"messages",
		"responses",
		"embeddings",
		"images",
		"videos",
		"models",
		"fusion",
		"control_other",
		"inference_other",
	}
	telemetryOutcomes = []string{
		"ok",
		"http_error",
		"transport_error",
		"timeout",
		"stream_broken",
		"aborted",
	}
	telemetryErrorClasses = []string{
		"dns",
		"tls",
		"connect_refused",
		"connect_timeout",
		"connect_error",
		"read_timeout",
		"write_timeout",
		"pool_timeout",
		"protocol_error",
		"reset",
		"io_error",
		"proxy_error",
		"stream_stalled",
		"unknown",
	}
)

// telemetryHostCustom is the fail-closed host value: a host telemetry cannot
// name is never measured and never carries the header (§3.2).
const telemetryHostCustom = "custom"

// telemetryHostnames is telemetry's OWN list of the hostnames it is allowed
// to name, and the only source hostEnum consults.
//
// It deliberately does NOT read AliasAPIBaseURLs. That is an exported var,
// not a constant: a consumer can reorder it (swapping which host reports
// "ally" and which reports "uptime"), shorten it (turning a real alias into
// "custom"), or point an entry at their own gateway — and a hostEnum that
// read the live slice would then name that gateway "ally", resolve
// telemetry ON for it, and send x-tr-client to a host that is not
// TrustedRouter's to measure. Telemetry's vocabulary must not be
// caller-writable.
//
// The per-region hostnames are not failover candidates in this SDK
// (regional failover re-requests the apex), but the vocabulary still names
// them so a region-pinned base URL reports its region rather than "custom".
// Cross-checked against trusted-router-py _constants.REGION_BASE_URLS.
//
// TestTelemetryHostAllowlistMatchesSDKConstants pins this list against the
// SDK's own base-URL constants, so a genuine alias or region change cannot
// land without updating telemetry alongside it.
var telemetryHostnames = map[string]string{
	"api.trustedrouter.com":            "apex",
	"api.allyrouter.com":               "ally",
	"api.uptimerouter.com":             "uptime",
	"api-us-central1.quillrouter.com":  "us_central1",
	"api-us-east4.quillrouter.com":     "us_east4",
	"api-europe-west4.quillrouter.com": "europe_west4",
}

var (
	// telemetryHeaderValueRe is the §3.2 value grammar: every value on the
	// wire is a closed enum or a bounded integer, nothing else.
	telemetryHeaderValueRe = regexp.MustCompile(`^[a-z0-9_]{1,24}$`)
	// telemetryRuntimeTokenRe is the §5.1 runtime grammar; the User-Agent
	// runtime token (§3.1) must satisfy it or be omitted.
	telemetryRuntimeTokenRe = regexp.MustCompile(`^[a-z]{1,10}/[0-9A-Za-z.+-]{1,24}$`)
)

// telemetrySchemeHost splits a URL into its lowercased scheme and hostname,
// mirroring trusted-router-py _scheme_host (ports are ignored, exactly as
// urlsplit().hostname ignores them).
func telemetrySchemeHost(rawURL string) (scheme, host string, ok bool) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
		return "", "", false
	}
	return strings.ToLower(parsed.Scheme), strings.ToLower(parsed.Hostname()), true
}

// isTelemetryControlHost reports whether the URL is the TrustedRouter
// control plane: https on trustedrouter.com or any subdomain. Mirrors
// trusted-router-py _control_host.
func isTelemetryControlHost(rawURL string) bool {
	scheme, host, ok := telemetrySchemeHost(rawURL)
	if !ok {
		return false
	}
	return scheme == "https" && (host == "trustedrouter.com" || strings.HasSuffix(host, ".trustedrouter.com"))
}

// hostEnum maps a base URL to the closed telemetry host vocabulary (§5.2).
// It matches https scheme + hostname against telemetryHostnames, telemetry's
// own non-writable list, then the control-plane suffix. Anything else is
// "custom": a self-hosted gateway is not TrustedRouter's to measure (§3.2).
func hostEnum(baseURL string) string {
	scheme, host, ok := telemetrySchemeHost(baseURL)
	if !ok || scheme != "https" {
		return telemetryHostCustom
	}
	if name, named := telemetryHostnames[host]; named {
		return name
	}
	if isTelemetryControlHost(baseURL) {
		return "control"
	}
	return telemetryHostCustom
}

// resolveTelemetryEnabled resolves the §6.3 opt-out precedence: explicit
// option > TRUSTEDROUTER_TELEMETRY > DO_NOT_TRACK > default on only when
// both the inference base and the control base are TrustedRouter hosts.
// Mirrors trusted-router-py resolve_telemetry_enabled; getenv is injected
// so the precedence is testable without process state.
func resolveTelemetryEnabled(explicit *bool, baseURL, controlBaseURL string, getenv func(string) string) bool {
	if explicit != nil {
		return *explicit
	}
	switch strings.ToLower(strings.TrimSpace(getenv("TRUSTEDROUTER_TELEMETRY"))) {
	case "0", "false", "off", "no":
		return false
	case "1", "true", "on", "yes":
		return true
	}
	if strings.TrimSpace(getenv("DO_NOT_TRACK")) == "1" {
		return false
	}
	return hostEnum(baseURL) != telemetryHostCustom && isTelemetryControlHost(controlBaseURL)
}

// classifyTransportError maps a transport error surfaced by this SDK's
// http.Client usage to the closed ErrorClass vocabulary (§5.2). It must run
// BEFORE transportRetryError flattens the typed chain into a message string
// (§6.1). Precedence mirrors trusted-router-py classify_transport_error:
// timeouts, then dns/tls/refused/reset, then generic dial, protocol, io.
func classifyTransportError(err error) string {
	if err == nil {
		return "unknown"
	}
	if errors.Is(err, context.DeadlineExceeded) || isNetTimeoutError(err) {
		switch {
		case isDialError(err), isProxyConnectError(err), isTLSHandshakeTimeout(err):
			// TCP dial, proxy CONNECT, and the TLS handshake are all
			// connection establishment: httpx folds them into
			// ConnectTimeout (checked before ProxyError in the py
			// reference), so the Go classes mirror that.
			return "connect_timeout"
		case isWriteOpError(err):
			// trusted-router-py maps httpx.WriteTimeout to write_timeout;
			// the Go equivalent is a timed-out write op in the chain.
			return "write_timeout"
		default:
			return "read_timeout"
		}
	}
	if isProxyConnectError(err) {
		// Checked BEFORE dns/refused/reset: net/http wraps the proxy dial
		// failure around those same errors (*net.OpError{Op:
		// "proxyconnect"}), and a user's broken proxy must not be
		// attributed to TrustedRouter — proxy_error is excluded from the
		// §8 availability denominator while connect_refused counts.
		return "proxy_error"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns"
	}
	if isTLSError(err) {
		return "tls"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connect_refused"
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return "reset"
	}
	if isDialError(err) {
		return "connect_error"
	}
	if isProtocolError(err) {
		return "protocol_error"
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) || isReadWriteError(err) {
		return "io_error"
	}
	return "unknown"
}

func isNetTimeoutError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func isDialError(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial"
}

func isWriteOpError(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "write"
}

// isProxyConnectError recognizes net/http's proxy-dial wrapper
// (*net.OpError{Op: "proxyconnect"}); errors.As surfaces the outermost
// OpError, so the wrapper is seen before the dial error inside it.
func isProxyConnectError(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "proxyconnect"
}

// isTLSHandshakeTimeout recognizes net/http's unexported
// tlsHandshakeTimeoutError, which is reachable only by its message.
func isTLSHandshakeTimeout(err error) bool {
	return strings.Contains(err.Error(), "TLS handshake timeout")
}

func isReadWriteError(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && (opErr.Op == "read" || opErr.Op == "write")
}

func isTLSError(err error) bool {
	// net/http REPLACES the tls.RecordHeaderError with this sentinel when a
	// plaintext server answers an HTTPS client, so the typed TLS error is
	// gone by the time the SDK sees it and only the sentinel identifies the
	// failure. trusted-router-py sees an ssl.SSLError for the same server and
	// classifies it "tls"; without this check the class was "unknown".
	if errors.Is(err, http.ErrSchemeMismatch) {
		return true
	}
	var (
		certVerification *tls.CertificateVerificationError
		recordHeader     tls.RecordHeaderError
		alert            tls.AlertError
		unknownAuthority x509.UnknownAuthorityError
		hostnameErr      x509.HostnameError
		certInvalid      x509.CertificateInvalidError
	)
	return errors.As(err, &certVerification) ||
		errors.As(err, &recordHeader) ||
		errors.As(err, &alert) ||
		errors.As(err, &unknownAuthority) ||
		errors.As(err, &hostnameErr) ||
		errors.As(err, &certInvalid)
}

// isProtocolError sniffs the HTTP-protocol failures net/http surfaces only
// as strings: the bundled http2 transport's errors and HTTP/1.x response
// parse failures have no exported types to errors.As against.
//
// The two "…error: stream ID"/"connection error:" forms are how the bundled
// http2 StreamError and ConnectionError actually render (h2_bundle.go
// formats them as "stream error: stream ID %d; %v" and "connection error:
// %s"). Neither string contains "http2", so a peer resetting a stream — the
// commonest real HTTP/2 failure, e.g. "stream error: stream ID 1;
// INTERNAL_ERROR; received from peer" — used to classify as "unknown".
// trusted-router-py sees httpx.RemoteProtocolError for these and reports
// protocol_error. The reset/io classes are checked before this function, so
// matching on these substrings cannot steal a more specific class.
func isProtocolError(err error) bool {
	message := err.Error()
	return strings.Contains(message, "http2") ||
		strings.Contains(message, "HTTP/2") ||
		strings.Contains(message, "malformed HTTP") ||
		strings.Contains(message, "PROTOCOL_ERROR") ||
		strings.Contains(message, "stream error: stream ID") ||
		strings.Contains(message, "connection error:")
}

func clampDurationMS(d time.Duration) int64 {
	ms := d.Milliseconds()
	if ms < 0 {
		return 0
	}
	if ms > telemetryMaxDurationMS {
		return telemetryMaxDurationMS
	}
	return ms
}

// telemetryAttempt is the header-channel subset of the per-attempt facts
// (§3.2): index, host enum, outcome, error class, elapsed, and whether the
// candidate index advanced after it. The beacon-only fields (http_status,
// ttfb, request_id, retry_after, should_retry) arrive with the beacon PR.
type telemetryAttempt struct {
	index      int
	host       string
	outcome    string
	errorClass string // "" renders as pc=none
	elapsedMS  int64
	moved      bool
}

// requestRecorder records ONE logical inference call as the engine loop
// (transport.go do()) runs, and assembles the x-tr-client value for the
// attempt in flight. It mirrors trusted-router-py RequestRecorder's
// begin_attempt / on_response / on_transport_error / on_moved /
// header_value flow. All methods are nil-receiver safe so the engine wiring
// stays unconditional (§2.2).
type requestRecorder struct {
	streaming bool
	attempts  []telemetryAttempt
	// nextIndex counts attempts STARTED, independently of attempts
	// successfully recorded. Deriving the index from len(attempts) instead
	// meant a recovered callback panic — which loses that attempt's record —
	// silently rewound the count, so the retry re-sent a=0 and claimed to be
	// the first attempt of the call. A dropped record must cost a record, not
	// corrupt the numbering of the ones that follow.
	nextIndex    int
	failoverUsed bool
	firstStarted time.Time
	attemptStart time.Time
	currentHost  string
	currentIndex int
	begun        bool
}

func newRequestRecorder(streaming bool) *requestRecorder {
	return &requestRecorder{streaming: streaming}
}

// recoverTelemetryPanic is deferred by every recorder callback: telemetry
// runs synchronously on the money path, and a hostile error value — an
// Error(), Unwrap(), or As() that panics, reachable through a
// caller-injected http.Client — must cost at most a missing telemetry
// record, never the user's request (§2.2).
func recoverTelemetryPanic() {
	_ = recover()
}

// beginAttempt marks the start of the attempt about to be sent to baseURL.
func (r *requestRecorder) beginAttempt(baseURL string) {
	if r == nil {
		return
	}
	defer recoverTelemetryPanic()
	// Order matters, and both of these come before anything that can panic.
	// The index advances first so a panic below cannot make the next attempt
	// reuse this one's number, and the host is reset to the fail-closed value
	// first so a panic cannot leave the PREVIOUS attempt's host in place and
	// let a header ride to a host this attempt was not cleared for.
	r.currentIndex = r.nextIndex
	r.nextIndex++
	r.currentHost = telemetryHostCustom
	now := time.Now()
	if !r.begun {
		r.firstStarted = now
		r.begun = true
	}
	r.attemptStart = now
	r.currentHost = hostEnum(baseURL)
}

// onResponse records an attempt that produced an HTTP response.
func (r *requestRecorder) onResponse(statusCode int) {
	if r == nil || !r.begun {
		return
	}
	defer recoverTelemetryPanic()
	outcome := "http_error"
	if statusCode < 400 {
		outcome = "ok"
	}
	r.storeAttempt(telemetryAttempt{
		index:     r.currentIndex,
		host:      r.currentHost,
		outcome:   outcome,
		elapsedMS: clampDurationMS(time.Since(r.attemptStart)),
	})
}

// onTransportError records an attempt that died in transport. openTimedOut
// reports that the stream-open timer fired, which the surfaced error chain
// alone cannot say (the cancel cause arrives as a plain cancellation).
func (r *requestRecorder) onTransportError(err error, openTimedOut bool) {
	if r == nil || !r.begun {
		return
	}
	defer recoverTelemetryPanic()
	var outcome, errorClass string
	if openTimedOut {
		outcome = "timeout"
		if isDialError(err) {
			errorClass = "connect_timeout"
		} else {
			errorClass = "read_timeout"
		}
	} else {
		errorClass = classifyTransportError(err)
		switch errorClass {
		case "connect_timeout", "read_timeout", "write_timeout":
			// trusted-router-py maps every httpx.TimeoutException to the
			// "timeout" outcome; mirror that for the Go timeout classes.
			outcome = "timeout"
		default:
			outcome = "transport_error"
		}
	}
	r.storeAttempt(telemetryAttempt{
		index:      r.currentIndex,
		host:       r.currentHost,
		outcome:    outcome,
		errorClass: errorClass,
		elapsedMS:  clampDurationMS(time.Since(r.attemptStart)),
	})
}

// onMoved marks that the candidate index advanced after the last recorded
// attempt (§3.2 fo). failoverUsed is a fact about the CALL, so it is set even
// when the attempt that moved lost its record: fo describes whether this call
// ever left its first host, and answering "no" because a record was dropped
// would be a false report.
func (r *requestRecorder) onMoved() {
	if r == nil {
		return
	}
	defer recoverTelemetryPanic()
	r.failoverUsed = true
	if last := len(r.attempts) - 1; last >= 0 {
		r.attempts[last].moved = true
	}
}

// storeAttempt appends the record for the attempt in flight, replacing it if
// that attempt is re-recorded. Records are keyed by their own index rather
// than by slice position: a dropped record leaves a GAP in the indices, and
// position-based storage would then file later attempts under earlier
// attempts' numbers.
func (r *requestRecorder) storeAttempt(attempt telemetryAttempt) {
	if last := len(r.attempts) - 1; last >= 0 && r.attempts[last].index == attempt.index {
		r.attempts[last] = attempt
		return
	}
	r.attempts = append(r.attempts, attempt)
}

// headerValue assembles the §3.2 grammar for the attempt in flight, in the
// exact key order v,a[,po,pc,ph,pm,sm],s[,fo]. It returns "" — send
// nothing — when the current host is custom, when no attempt has begun, or
// when any value falls outside the grammar or the 160-byte bound: telemetry
// may never fail a request (§2.2), so an out-of-grammar header is dropped
// here, not surfaced.
func (r *requestRecorder) headerValue() (value string) {
	defer func() {
		// Belt and braces for §2.2: even a recorder bug must cost the
		// caller nothing but a missing telemetry header.
		if recover() != nil {
			value = ""
		}
	}()
	if r == nil || !r.begun || r.currentHost == telemetryHostCustom {
		return ""
	}
	if r.currentIndex > 99 {
		// §3.2 bounds a to 0..99, so past attempt 99 there is no valid
		// header to send. (trusted-router-py currently emits a=100 and the
		// enclave drops it — an upstream bug deliberately not replicated.)
		return ""
	}
	parts := []string{"v=1", "a=" + strconv.Itoa(r.currentIndex)}
	if r.currentIndex > 0 {
		if len(r.attempts) == 0 {
			return ""
		}
		previous := r.attempts[len(r.attempts)-1]
		if previous.index != r.currentIndex-1 {
			// The immediately preceding attempt has no record — it was lost
			// to a recovered callback panic. po/pc/ph/pm are defined as the
			// PREVIOUS attempt's facts, so describing an older attempt under
			// this attempt's index would be a false report: send nothing.
			return ""
		}
		outcome := previous.outcome
		errorClass := previous.errorClass
		if errorClass == "" {
			errorClass = "none"
		}
		switch outcome {
		case "http_error", "transport_error", "timeout", "stream_broken":
		default:
			// §3.2's po vocabulary is none|http_error|transport_error|
			// timeout|stream_broken. A forced x-should-retry retry of a
			// sub-400 response records outcome "ok", which is outside it —
			// sending it would get the whole header dropped by the
			// enclave. Cross-SDK ruling: report po=none;pc=none and keep
			// the remaining keys. (trusted-router-py currently emits
			// po=ok here — an upstream bug deliberately not replicated.)
			outcome = "none"
			errorClass = "none"
		}
		parts = append(parts,
			"po="+outcome,
			"pc="+errorClass,
			"ph="+previous.host,
			"pm="+strconv.FormatInt(previous.elapsedMS, 10),
			"sm="+strconv.FormatInt(clampDurationMS(r.attemptStart.Sub(r.firstStarted)), 10),
		)
	}
	if r.streaming {
		parts = append(parts, "s=1")
	} else {
		parts = append(parts, "s=0")
	}
	if r.currentIndex > 0 {
		if r.failoverUsed {
			parts = append(parts, "fo=1")
		} else {
			parts = append(parts, "fo=0")
		}
	}
	header := strings.Join(parts, ";")
	if len(header) > telemetryMaxHeaderBytes {
		return ""
	}
	for _, part := range parts {
		if !telemetryHeaderValueRe.MatchString(part[strings.IndexByte(part, '=')+1:]) {
			return ""
		}
	}
	return header
}
