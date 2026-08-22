package trustedrouter

// telemetry.go is the RECORDING side of the client-observed reliability
// telemetry contract, v1 (docs/client-telemetry.md in Lore-Hex/quill-router):
// the per-attempt `x-tr-client` request header (§3.2), the closed vocabulary
// (§5.2), the opt-out resolution (§6.3), and the per-call recorder that
// derives the §5.3 event and the exact §5.4 counter increments from the real
// attempt history. It mirrors trusted-router-py `_telemetry.py`
// (RequestRecorder, host_enum, endpoint_enum, classify_transport_error,
// resolve_telemetry_enabled, sdk_identity).
//
// The BEACON channel (§4–§5, §6.2) — buffering, sampling, minute windows and
// the out-of-engine POST to /client-events — lives in telemetry_reporter.go
// (TelemetryReporter in the reference). The owner's decision of 2026-08-21
// ships beacons in every SDK now, superseding the §9 step 7 / §10 "Python
// first" ordering.
//
// Telemetry never fails a request (§2.2): every recorder method is
// nil-receiver safe and recovers its own panics, and an out-of-grammar header
// value sends NOTHING rather than panicking or erroring.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// telemetrySchemaVersion is the beacon schema version (§5.1); the
	// header grammar pins v=1 independently (§3.2).
	telemetrySchemaVersion = 1
	// telemetryEventsPath is the beacon POST path under the control base
	// (§4): POST {control_base}/client-events.
	telemetryEventsPath = "/client-events"
	// telemetryMaxHeaderBytes bounds the whole x-tr-client header (§3.2).
	telemetryMaxHeaderBytes = 160
	// telemetryMaxDurationMS clamps every duration field (§3.2, §5.3).
	telemetryMaxDurationMS = 3_600_000
	// telemetryMaxAgeMS clamps age_ms and window_start_age_ms (§5.3, §5.4).
	telemetryMaxAgeMS = 86_400_000
	// telemetryMaxEventAttempts caps the attempts carried by one event
	// (§5.3: 1..16).
	telemetryMaxEventAttempts = 16
	// telemetryMaxCount bounds every counter count (§5.4: ≤10 000 000).
	telemetryMaxCount = 10_000_000

	// Reporter bounds (§6.2), pinned by TestTelemetryParityConstants
	// against trusted-router-py _constants.py.
	telemetryFlushInterval     = 30 * time.Second
	telemetryMaxEvents         = 1000
	telemetryMaxBatchEvents    = 100
	telemetryMaxBatchCounters  = 200
	telemetryMaxWindowKeys     = 256
	telemetryRetentionSeconds  = 86_400
	telemetryRetentionBytes    = 524_288
	telemetryBackoffMin        = 60 * time.Second
	telemetryBackoffMax        = 600 * time.Second
	telemetryBatchTriggerBytes = 60 * 1024
	telemetryMaxBatchBytes     = 65_536
	telemetryMaxRetryAfter     = 600 * time.Second
	telemetryMaxPause          = 86_400 * time.Second
	telemetryURGENTEvents      = 50
	// telemetryHTTPTimeout bounds one beacon POST (py: httpx.Client(timeout=5.0)).
	telemetryHTTPTimeout = 5 * time.Second
	// telemetryCloseTimeout bounds the final flush on Close (§6.2: ≤2 s).
	telemetryCloseTimeout = 2 * time.Second
	// telemetrySlowMS is the §5.3 sampling threshold for slow successes.
	telemetrySlowMS = 30_000
	// telemetryDefaultSampleRate is the §5.3 default success_sample_rate.
	telemetryDefaultSampleRate = 0.01
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
	telemetryFinalOutcomes = append(append([]string(nil), telemetryOutcomes...), "exhausted")
	telemetryTimeoutPhases = []string{
		"none",
		"connect",
		"first_byte",
		"idle",
		"total",
	}
	telemetryLatencyBuckets = []string{
		"lt100",
		"lt200",
		"lt400",
		"lt800",
		"lt1600",
		"lt3200",
		"lt6400",
		"lt12800",
		"lt25600",
		"lt51200",
		"lt102400",
		"ge102400",
	}
	// telemetryLatencyUpperBounds are the exclusive upper bounds of the
	// lt* buckets, in order.
	telemetryLatencyUpperBounds = []int64{100, 200, 400, 800, 1600, 3200, 6400, 12800, 25600, 51200, 102400}
	telemetryHTTPStatusClasses  = []string{"none", "2xx", "4xx", "429", "5xx"}
	telemetryErrorSources       = []string{"router", "provider", "unknown"}
	telemetrySampleReasons      = []string{"failure", "retried", "slow", "random"}
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
	// telemetryModelRe is the §5.3 model grammar: anything else is null,
	// so free text can never ride the model field.
	telemetryModelRe = regexp.MustCompile(`^[A-Za-z0-9._:/~@-]{1,128}$`)
	// telemetryRequestIDRe is the §3.3 enclave audit id shape.
	telemetryRequestIDRe = regexp.MustCompile(`^rlog_[0-9a-f]{32}$`)
	// telemetrySemverRe bounds the SDK version in the batch identity (§5.1).
	telemetrySemverRe = regexp.MustCompile(`^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)` +
		`(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
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

// telemetryMaxErrorChainLinks bounds the error-chain walk, mirroring
// trusted-router-py _exception_chain's own limit of 6. Every real chain this
// SDK produces is far shorter: the deepest is connect-refused at four links
// (*url.Error, *net.OpError, *os.SyscallError, syscall.Errno).
const telemetryMaxErrorChainLinks = 6

// telemetryErrorChain flattens an error into at most
// telemetryMaxErrorChainLinks links, but only through known standard-library
// wrappers. Exported wrappers are unwrapped through their fields. A short
// allowlist covers standard-library wrappers whose fields are private; their
// concrete package path and type name are checked before an Unwrap method is
// called.
//
// Classification must not call arbitrary Error, Is, Timeout, or Unwrap
// methods. Options.HTTPClient accepts a caller-supplied RoundTripper, so any
// of those methods may block forever. A link bound limits the number of
// callbacks, not the time spent in one callback, and neither recover nor
// context cancellation can interrupt a synchronous method that never
// returns. Unknown and caller-defined wrappers therefore remain opaque and
// classify as unknown unless their concrete outer type supplies a safe fact.
// This deliberately trades classification of custom middleware wrappers for
// the §2.2 guarantee that telemetry never delays the request.
func telemetryErrorChain(err error) []error {
	chain := make([]error, 0, telemetryMaxErrorChainLinks)
	queue := []error{err}
	for len(queue) > 0 && len(chain) < telemetryMaxErrorChainLinks {
		link := queue[0]
		queue = queue[1:]
		if link == nil {
			continue
		}
		chain = append(chain, link)
		children := telemetryStandardErrorChildren(link)
		remaining := telemetryMaxErrorChainLinks - len(chain)
		if len(children) > remaining {
			children = children[:remaining]
		}
		queue = append(queue, children...)
	}
	return chain
}

// telemetryStandardErrorChildren unwraps only concrete wrappers owned by the
// standard library. The exported cases use fields, so even a user-constructed
// wrapper containing a hostile error cannot dispatch to that error's code.
//
// fmt/errors and a few net/http/TLS wrappers have private fields. Package path
// plus concrete type name is compiler-owned identity that caller code cannot
// impersonate. Invoking Unwrap only after that check preserves common %w,
// errors.Join, and net/http chains without opening a callback boundary to an
// arbitrary error implementation. Unknown wrappers are intentionally opaque.
func telemetryStandardErrorChildren(err error) []error {
	switch typed := err.(type) {
	case *url.Error:
		if typed != nil {
			return []error{typed.Err}
		}
	case *net.OpError:
		if typed != nil {
			return []error{typed.Err}
		}
	case *net.DNSError:
		if typed != nil {
			return []error{typed.UnwrapErr}
		}
	case *net.DNSConfigError:
		if typed != nil {
			return []error{typed.Err}
		}
	case *os.PathError:
		if typed != nil {
			return []error{typed.Err}
		}
	case *os.LinkError:
		if typed != nil {
			return []error{typed.Err}
		}
	case *os.SyscallError:
		if typed != nil {
			return []error{typed.Err}
		}
	case *tls.CertificateVerificationError:
		if typed != nil {
			return []error{typed.Err}
		}
	}

	packagePath, typeName := telemetryConcreteErrorType(err)
	switch {
	case packagePath == "fmt" && typeName == "wrapError",
		packagePath == "net/http" && typeName == "transportReadFromServerError",
		packagePath == "net/http" && typeName == "nothingWrittenError",
		packagePath == "crypto/tls" && typeName == "permanentError":
		if unwrapper, ok := err.(interface{ Unwrap() error }); ok {
			return []error{unwrapper.Unwrap()}
		}
	case packagePath == "fmt" && typeName == "wrapErrors",
		packagePath == "errors" && typeName == "joinError":
		if unwrapper, ok := err.(interface{ Unwrap() []error }); ok {
			return unwrapper.Unwrap()
		}
	}
	return nil
}

func telemetryConcreteErrorType(err error) (packagePath, typeName string) {
	if err == nil {
		return "", ""
	}
	typeOf := reflect.TypeOf(err)
	for typeOf.Kind() == reflect.Pointer {
		if reflect.ValueOf(err).IsNil() {
			return "", ""
		}
		typeOf = typeOf.Elem()
	}
	return typeOf.PkgPath(), typeOf.Name()
}

func chainHas(chain []error, predicate func(error) bool) bool {
	for _, link := range chain {
		if predicate(link) {
			return true
		}
	}
	return false
}

// linkIs compares ONE link against a sentinel without traversing anything or
// consulting a caller-defined Is method. The == comparison cannot panic here:
// interface comparison only compares values when their dynamic types are
// identical, and every sentinel passed here has a comparable concrete type.
func linkIs(link, sentinel error) bool {
	return link == sentinel
}

// classifyTransportError maps a transport error surfaced by this SDK's
// http.Client usage to the closed ErrorClass vocabulary (§5.2). It must run
// BEFORE transportRetryError flattens the typed chain into a message string
// (§6.1). Precedence mirrors trusted-router-py classify_transport_error:
// timeouts, then dns/tls/refused/reset, then generic dial, protocol, io — and
// like the reference it asks "does ANY link in the bounded chain look like
// this?", link by link.
func classifyTransportError(err error) string {
	if err == nil {
		return "unknown"
	}
	chain := telemetryErrorChain(err)
	if chainHas(chain, isDeadlineExceededLink) || chainHas(chain, isTimeoutLink) {
		switch {
		case chainHas(chain, isDialOpLink), chainHas(chain, isProxyConnectLink), chainHas(chain, isTLSHandshakeTimeoutLink):
			// TCP dial, proxy CONNECT, and the TLS handshake are all
			// connection establishment: httpx folds them into
			// ConnectTimeout (checked before ProxyError in the py
			// reference), so the Go classes mirror that.
			return "connect_timeout"
		case chainHas(chain, isWriteOpLink):
			// trusted-router-py maps httpx.WriteTimeout to write_timeout;
			// the Go equivalent is a timed-out write op in the chain.
			return "write_timeout"
		default:
			return "read_timeout"
		}
	}
	if chainHas(chain, isProxyConnectLink) {
		// Checked BEFORE dns/refused/reset: net/http wraps the proxy dial
		// failure around those same errors (*net.OpError{Op:
		// "proxyconnect"}), and a user's broken proxy must not be
		// attributed to TrustedRouter — proxy_error is excluded from the
		// §8 availability denominator while connect_refused counts.
		return "proxy_error"
	}
	if chainHas(chain, isDNSLink) {
		return "dns"
	}
	if chainHas(chain, isTLSLink) {
		return "tls"
	}
	if chainHas(chain, func(link error) bool { return linkIs(link, syscall.ECONNREFUSED) }) {
		return "connect_refused"
	}
	if chainHas(chain, func(link error) bool { return linkIs(link, syscall.ECONNRESET) }) {
		return "reset"
	}
	if chainHas(chain, isDialOpLink) {
		return "connect_error"
	}
	if chainHas(chain, isIOLink) {
		// Checked BEFORE protocol: a read/write op error is the more
		// specific fact, and the protocol test below matches on message
		// text, which an OpError's message can contain by inheritance
		// from the error it wraps.
		return "io_error"
	}
	if chainHas(chain, isProtocolLink) {
		return "protocol_error"
	}
	return "unknown"
}

func isDeadlineExceededLink(link error) bool {
	return linkIs(link, context.DeadlineExceeded)
}

func isTimeoutLink(link error) bool {
	if linkIs(link, context.DeadlineExceeded) || linkIs(link, os.ErrDeadlineExceeded) {
		return true
	}
	switch typed := link.(type) {
	case *net.DNSError:
		return typed != nil && typed.IsTimeout
	case syscall.Errno:
		// Invoke no interface hook: this is the concrete standard-library
		// integer type, whose Timeout method is a fixed errno comparison.
		return typed.Timeout()
	}
	packagePath, typeName := telemetryConcreteErrorType(link)
	return (packagePath == "net" && typeName == "timeoutError") ||
		(packagePath == "net/http" && (typeName == "timeoutError" || typeName == "tlsHandshakeTimeoutError")) ||
		(packagePath == "crypto/tls" && typeName == "timeoutError") ||
		(packagePath == "internal/poll" && typeName == "DeadlineExceededError")
}

func opLink(link error, op string) bool {
	opErr, ok := link.(*net.OpError)
	return ok && opErr.Op == op
}

func isDialOpLink(link error) bool { return opLink(link, "dial") }

func isWriteOpLink(link error) bool { return opLink(link, "write") }

// isProxyConnectLink recognizes net/http's proxy-dial wrapper
// (*net.OpError{Op: "proxyconnect"}), which sits OUTSIDE the dial error it
// wraps — so proxy_error is decided before the classes that dial error would
// otherwise claim.
func isProxyConnectLink(link error) bool { return opLink(link, "proxyconnect") }

// isTLSHandshakeTimeoutLink recognizes net/http's unexported concrete type
// without calling its Error or Timeout methods.
func isTLSHandshakeTimeoutLink(link error) bool {
	packagePath, typeName := telemetryConcreteErrorType(link)
	return packagePath == "net/http" && typeName == "tlsHandshakeTimeoutError"
}

func isDNSLink(link error) bool {
	_, ok := link.(*net.DNSError)
	return ok
}

func isIOLink(link error) bool {
	if linkIs(link, io.ErrUnexpectedEOF) || linkIs(link, io.EOF) {
		return true
	}
	return opLink(link, "read") || opLink(link, "write")
}

func isTLSLink(link error) bool {
	// net/http REPLACES the tls.RecordHeaderError with this sentinel when a
	// plaintext server answers an HTTPS client, so the typed TLS error is
	// gone by the time the SDK sees it and only the sentinel identifies the
	// failure. trusted-router-py sees an ssl.SSLError for the same server and
	// classifies it "tls"; without this check the class was "unknown".
	if linkIs(link, http.ErrSchemeMismatch) {
		return true
	}
	switch link.(type) {
	case *tls.CertificateVerificationError,
		tls.RecordHeaderError,
		tls.AlertError,
		x509.UnknownAuthorityError,
		x509.HostnameError,
		x509.CertificateInvalidError:
		return true
	}
	return false
}

// isProtocolLink recognizes the HTTP-protocol failures net/http surfaces as
// private concrete types or as safe standard-library strings. It never calls
// Error on a caller-defined value.
//
// The stream/connection forms are how the bundled http2 StreamError and
// ConnectionError actually render (h2_bundle.go formats them as "stream
// error: stream ID %d; %v" and "connection error: %s"). Neither string
// contains "http2", so a peer resetting a stream — the commonest real HTTP/2
// failure, "stream error: stream ID 1; INTERNAL_ERROR; received from peer" —
// classified as "unknown" before they were added. trusted-router-py sees
// httpx.RemoteProtocolError for these and reports protocol_error.
func isProtocolLink(link error) bool {
	packagePath, typeName := telemetryConcreteErrorType(link)
	if packagePath == "net/http" && (typeName == "ProtocolError" || strings.HasPrefix(typeName, "http2")) {
		return true
	}
	message, ok := telemetrySafeStandardErrorText(link)
	if !ok {
		return false
	}
	return strings.Contains(message, "http2") ||
		strings.Contains(message, "HTTP/2") ||
		strings.Contains(message, "malformed HTTP") ||
		strings.Contains(message, "PROTOCOL_ERROR") ||
		strings.HasPrefix(message, "stream error: stream ID ") ||
		strings.HasPrefix(message, "connection error: ")
}

// telemetrySafeStandardErrorText returns text only for standard-library
// concrete types whose Error method simply returns already-stored text. In
// particular it excludes wrappers such as *url.Error and errors.joinError,
// whose Error methods dispatch to their children.
func telemetrySafeStandardErrorText(err error) (string, bool) {
	packagePath, typeName := telemetryConcreteErrorType(err)
	if (packagePath == "errors" && typeName == "errorString") ||
		(packagePath == "fmt" && (typeName == "wrapError" || typeName == "wrapErrors")) {
		return err.Error(), true
	}
	return "", false
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

// endpointEnum maps an inference-plane path to the closed Endpoint
// vocabulary (§5.2), mirroring trusted-router-py endpoint_enum: four exact
// matches, four prefix families, everything else inference_other. The query
// string and fragment are ignored and a trailing slash is trimmed.
func endpointEnum(path string) string {
	clean := path
	if cut := strings.IndexAny(clean, "?#"); cut >= 0 {
		clean = clean[:cut]
	}
	clean = strings.TrimRight(clean, "/")
	if clean == "" {
		clean = "/"
	}
	switch clean {
	case "/chat/completions":
		return "chat_completions"
	case "/messages":
		return "messages"
	case "/responses":
		return "responses"
	case "/embeddings":
		return "embeddings"
	}
	for _, family := range []struct{ prefix, endpoint string }{
		{"/images", "images"},
		{"/videos", "videos"},
		{"/models", "models"},
		{"/fusion", "fusion"},
	} {
		if clean == family.prefix || strings.HasPrefix(clean, family.prefix+"/") {
			return family.endpoint
		}
	}
	return "inference_other"
}

// latencyBucket maps milliseconds to the upper-bound-exclusive LatencyBucket
// enum (§5.2).
func latencyBucket(ms int64) string {
	if ms < 0 {
		ms = 0
	}
	for i, upper := range telemetryLatencyUpperBounds {
		if ms < upper {
			return telemetryLatencyBuckets[i]
		}
	}
	return telemetryLatencyBuckets[len(telemetryLatencyBuckets)-1]
}

// statusClass maps an HTTP status (0 = no response) to HttpStatusClass (§5.2).
func statusClass(status int) string {
	switch {
	case status >= 200 && status <= 299:
		return "2xx"
	case status == 429:
		return "429"
	case status >= 400 && status <= 499:
		return "4xx"
	case status >= 500 && status <= 599:
		return "5xx"
	default:
		return "none"
	}
}

// timeoutFloorMet reports whether the configured timeout for the phase meets
// the §5.4 floor (connect ≥10 s, first_byte ≥60 s, idle ≥30 s).
func timeoutFloorMet(phase string, configuredMS int64, hasConfigured bool) bool {
	if !hasConfigured {
		return false
	}
	switch phase {
	case "connect":
		return configuredMS >= 10_000
	case "first_byte":
		return configuredMS >= 60_000
	case "idle":
		return configuredMS >= 30_000
	default:
		return false
	}
}

func clampInt64(value, minimum, maximum int64) int64 {
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}

func telemetryInSlice(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

// telemetryAttempt carries the per-attempt facts of §5.3 ClientAttempt plus
// the attempt's timeout phase (used by the §5.4 attempt-level counter). The
// header channel reads index/host/outcome/errorClass/elapsedMS; the beacon
// reads everything. Optional fields use a has* flag or the empty string so
// the struct stays comparable-by-value and copies cheaply.
type telemetryAttempt struct {
	index         int
	host          string
	outcome       string
	httpStatus    int    // 0 renders as null
	errorClass    string // "" renders as pc=none / null
	errorSource   string // "" renders as null
	shouldRetry   string // "true" | "false" | "absent" ("" is absent)
	retryAfterMS  int64
	hasRetryAfter bool
	elapsedMS     int64
	ttfbMS        int64
	hasTTFB       bool
	requestID     string // "" renders as null
	moved         bool
	phase         string // TimeoutPhase of this attempt; "" is none
}

// telemetryRequestFacts are the bounded, content-free facts about ONE logical
// call that the recorder needs before the first attempt: the endpoint enum,
// the method, the model id (regex-bounded; anything else is dropped) and
// whether the request pinned a provider. Mirrors what trusted-router-py
// _recorder derives from the path and the JSON body.
type telemetryRequestFacts struct {
	endpoint       string
	method         string
	model          string
	providerPinned bool
}

// telemetryRequestFactsFor derives the request facts from the path and the
// not-yet-marshaled body. Only the "model" and "provider" keys of a map body
// are consulted; raw (json.RawMessage / []byte) bodies are not parsed, so
// they report no model and no pin — exactly as trusted-router-py, whose
// request() only sees a Mapping.
func telemetryRequestFactsFor(method, path string, body any) telemetryRequestFacts {
	facts := telemetryRequestFacts{
		endpoint: endpointEnum(path),
		method:   strings.ToUpper(method),
	}
	fields, ok := body.(map[string]any)
	if !ok {
		return facts
	}
	if model, ok := fields["model"].(string); ok && telemetryModelRe.MatchString(model) {
		facts.model = model
	}
	facts.providerPinned = telemetryProviderPinned(fields["provider"])
	return facts
}

// telemetryProviderPinned mirrors trusted-router-py's
// `provider.get("allow_fallbacks") is False`: only an explicit false pins.
func telemetryProviderPinned(provider any) bool {
	switch typed := provider.(type) {
	case *ProviderPreferences:
		return typed != nil && typed.AllowFallbacks != nil && !*typed.AllowFallbacks
	case ProviderPreferences:
		return typed.AllowFallbacks != nil && !*typed.AllowFallbacks
	case map[string]any:
		allow, ok := typed["allow_fallbacks"].(bool)
		return ok && !allow
	default:
		return false
	}
}

// telemetryRequestEvent is the recorder's account of one finished logical
// call (§5.3 ClientRequestEvent before sampling and wire bounding).
type telemetryRequestEvent struct {
	endpoint             string
	method               string
	streaming            bool
	providerPinned       bool
	model                string // "" renders as null
	attempts             []telemetryAttempt
	finalOutcome         string
	finalHTTPStatus      int // 0 renders as null
	totalMS              int64
	ttftMS               int64
	hasTTFT              bool
	failoverUsed         bool
	timeoutPhase         string
	configuredTimeoutMS  int64
	hasConfiguredTimeout bool
}

// telemetryCounterKey is the exact 10-field §5.4 counter key (the fields
// minus the counts and histograms; model is deliberately not part of it).
// Its outcome is Outcome, never FinalOutcome: "exhausted" belongs only to
// sampled request events (the executable schema wins over the prose typo).
// errorClass "" is the null error class.
type telemetryCounterKey struct {
	level           string
	endpoint        string
	streaming       bool
	host            string
	outcome         string
	errorClass      string
	httpStatusClass string
	timeoutPhase    string
	timeoutFloorMet bool
	providerPinned  bool
}

// telemetryCounterIncrement is one (key, counts) contribution to a minute
// window; the reporter merges increments with equal keys.
type telemetryCounterIncrement struct {
	key                 telemetryCounterKey
	requests            int
	attempts            int
	failoverUsed        int
	firstAttemptSuccess int
	totalMSHist         map[string]int
	firstEventMSHist    map[string]int
}

// telemetrySink receives one finished logical call: the event and its exact
// counter increments. The production sink is telemetryReporter; tests inject
// a recording sink.
type telemetrySink interface {
	onRequest(event telemetryRequestEvent, counters []telemetryCounterIncrement)
}

// telemetryOverflowEntry folds the attempt-level counter contribution of an
// attempt whose record fell past the 16-attempt event cap (§5.3), so the
// counters stay exact (§5.4) while recorder memory stays bounded under the
// uncapped MaxRetries option.
type telemetryOverflowEntry struct {
	key      telemetryCounterKey
	attempts int
	moved    int
}

// requestRecorder records ONE logical inference call as the engine loop
// (transport.go do()) runs and the caller drains the body, assembles the
// x-tr-client value for the attempt in flight, and on finish derives the
// §5.3 event and the exact §5.4 counter increments (mirroring
// trusted-router-py RequestRecorder's begin_attempt / on_response /
// on_transport_error / on_moved / on_first_event / on_aborted / header_value
// / _finish flow). All methods are nil-receiver safe so the engine wiring
// stays unconditional (§2.2), and every method takes the recorder's own
// mutex: the body wrapper may be read and closed from different goroutines.
type requestRecorder struct {
	mu sync.Mutex

	sink                 telemetrySink
	endpoint             string
	method               string
	streaming            bool
	providerPinned       bool
	model                string
	configuredTimeoutMS  int64
	hasConfiguredTimeout bool
	recordable           bool

	// attempts holds the first telemetryMaxEventAttempts records by index —
	// exactly what the wire event may carry. Records past that cap live only
	// in lastAttempt until superseded, then fold into overflow as counter
	// contributions, so memory stays bounded under the uncapped MaxRetries
	// option while the counters still count every attempt.
	attempts        []telemetryAttempt
	overflow        []telemetryOverflowEntry
	foldedIndex     int
	recorded        int
	firstErrorClass string

	lastAttempt    telemetryAttempt
	hasLastAttempt bool
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
	ttftMS       int64
	hasTTFT      bool
	exhausted    bool
	finished     bool
}

// newRequestRecorder builds the recorder for one logical call. A nil sink
// records nothing beyond the header channel. Only GET and POST calls to a
// known inference endpoint are recordable: the beacon schema admits no
// other method (the contract's executable module, not its prose, wins).
func newRequestRecorder(sink telemetrySink, facts telemetryRequestFacts, streaming bool, timeout time.Duration, hasTimeout bool) *requestRecorder {
	r := &requestRecorder{
		sink:           sink,
		endpoint:       facts.endpoint,
		method:         strings.ToUpper(facts.method),
		streaming:      streaming,
		providerPinned: facts.providerPinned,
		foldedIndex:    -1,
	}
	if telemetryModelRe.MatchString(facts.model) {
		r.model = facts.model
	}
	if hasTimeout && timeout > 0 {
		r.configuredTimeoutMS = clampInt64(timeout.Milliseconds(), 1, telemetryMaxDurationMS)
		r.hasConfiguredTimeout = true
	}
	r.recordable = telemetryInSlice(telemetryEndpoints, r.endpoint) &&
		(r.method == http.MethodGet || r.method == http.MethodPost)
	return r
}

// recoverTelemetryPanic is deferred by every recorder callback: telemetry
// runs synchronously on the money path, and an unexpected bug or malformed
// standard-library wrapper must cost at most a missing telemetry record,
// never the user's request (§2.2).
func recoverTelemetryPanic() {
	_ = recover()
}

// beginAttempt marks the start of the attempt about to be sent to baseURL.
func (r *requestRecorder) beginAttempt(baseURL string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	defer recoverTelemetryPanic()
	// Order matters, and both of these come before anything that can panic.
	// The index advances first so a panic below cannot make the next attempt
	// reuse this one's number, and the host is reset to the fail-closed value
	// first so a panic cannot leave the PREVIOUS attempt's host in place and
	// let a header ride to a host this attempt was not cleared for.
	r.currentIndex = r.nextIndex
	r.nextIndex++
	r.currentHost = telemetryHostCustom
	r.foldOverflowLocked()
	now := time.Now()
	if !r.begun {
		r.firstStarted = now
		r.begun = true
	}
	r.attemptStart = now
	r.currentHost = hostEnum(baseURL)
}

// telemetryShouldRetry reads x-should-retry as observed: "true", "false", or
// "absent" for anything else.
func telemetryShouldRetry(headers http.Header) string {
	switch strings.ToLower(strings.TrimSpace(headers.Get("X-Should-Retry"))) {
	case "true":
		return "true"
	case "false":
		return "false"
	default:
		return "absent"
	}
}

// telemetryRequestID reads x-request-id when it is an enclave audit id
// (§3.3); anything else is dropped, never forwarded.
func telemetryRequestID(headers http.Header) string {
	value := strings.TrimSpace(headers.Get("X-Request-Id"))
	if telemetryRequestIDRe.MatchString(value) {
		return value
	}
	return ""
}

// onResponse records an attempt that produced an HTTP response.
func (r *requestRecorder) onResponse(statusCode int, headers http.Header) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	defer recoverTelemetryPanic()
	if !r.begun {
		return
	}
	outcome := "http_error"
	if statusCode < 400 {
		outcome = "ok"
	}
	elapsed := clampDurationMS(time.Since(r.attemptStart))
	attempt := telemetryAttempt{
		index:       r.currentIndex,
		host:        r.currentHost,
		outcome:     outcome,
		httpStatus:  statusCode,
		shouldRetry: telemetryShouldRetry(headers),
		elapsedMS:   elapsed,
		ttfbMS:      elapsed,
		hasTTFB:     true,
		requestID:   telemetryRequestID(headers),
		phase:       "none",
	}
	if seconds := retryAfterSeconds(headers); seconds != nil {
		attempt.retryAfterMS = clampInt64(int64(*seconds*1000), 0, telemetryMaxDurationMS)
		attempt.hasRetryAfter = true
	}
	r.storeAttempt(attempt)
}

// onTransportError records an attempt that died in transport. openTimedOut
// reports that the stream-open timer fired, which the surfaced error chain
// alone cannot say (the cancel cause arrives as a plain cancellation).
// responseOpened and bodyStarted describe how far the attempt got, exactly
// as trusted-router-py's drivers report them: a failure after the first
// body event is stream_broken (or an idle stall), and a failure after the
// headers keeps the status and ttfb already recorded for this attempt.
func (r *requestRecorder) onTransportError(err error, openTimedOut, responseOpened, bodyStarted bool) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	defer recoverTelemetryPanic()
	if !r.begun {
		return
	}
	var errorClass, phase string
	timedOut := false
	switch {
	case openTimedOut:
		timedOut = true
		// Bounded chain here too: this runs on the same caller-supplied
		// error value as classifyTransportError, so it must not traverse
		// with errors.As either.
		if chainHas(telemetryErrorChain(err), isDialOpLink) {
			errorClass, phase = "connect_timeout", "connect"
		} else {
			errorClass, phase = "read_timeout", "first_byte"
		}
	case linkIs(err, errStreamIdleTimeout):
		// The SDK's own idle-timeout sentinel: a read that stalled after
		// the stream opened.
		timedOut = true
		errorClass, phase = "read_timeout", "first_byte"
	default:
		errorClass = classifyTransportError(err)
		switch errorClass {
		case "connect_timeout":
			timedOut, phase = true, "connect"
		case "read_timeout", "write_timeout":
			// trusted-router-py maps every httpx.TimeoutException to the
			// "timeout" outcome; mirror that for the Go timeout classes.
			timedOut, phase = true, "first_byte"
		default:
			phase = "none"
		}
	}
	var outcome string
	switch {
	case timedOut:
		outcome = "timeout"
		if bodyStarted {
			phase = "idle"
			if errorClass == "read_timeout" {
				errorClass = "stream_stalled"
			}
		}
	case bodyStarted:
		outcome = "stream_broken"
	default:
		outcome = "transport_error"
	}
	attempt := telemetryAttempt{
		index:      r.currentIndex,
		host:       r.currentHost,
		outcome:    outcome,
		errorClass: errorClass,
		elapsedMS:  clampDurationMS(time.Since(r.attemptStart)),
		phase:      phase,
	}
	if previous := r.currentRecordLocked(); previous != nil {
		if responseOpened {
			attempt.httpStatus = previous.httpStatus
			attempt.ttfbMS, attempt.hasTTFB = previous.ttfbMS, previous.hasTTFB
		}
		attempt.errorSource = previous.errorSource
		attempt.shouldRetry = previous.shouldRetry
		attempt.retryAfterMS, attempt.hasRetryAfter = previous.retryAfterMS, previous.hasRetryAfter
		attempt.requestID = previous.requestID
	}
	r.storeAttempt(attempt)
}

// onMoved marks that the candidate index advanced after the last recorded
// attempt (§3.2 fo, §5.3 moved). failoverUsed is a fact about the CALL, so it
// is set even when the attempt that moved lost its record: fo describes
// whether this call ever left its first host, and answering "no" because a
// record was dropped would be a false report. The per-attempt moved flag is
// set only on this attempt's own record.
func (r *requestRecorder) onMoved() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	defer recoverTelemetryPanic()
	r.failoverUsed = true
	if previous := r.currentRecordLocked(); previous != nil {
		previous.moved = true
		for i := range r.attempts {
			if r.attempts[i].index == previous.index {
				r.attempts[i].moved = true
			}
		}
	}
}

// onFirstEvent records time-to-first-token: the first SSE event of the
// stream, measured from the start of the FIRST attempt (§5.3 ttft_ms). Only
// the SSE decoder (sse.go) can observe it (§6.1).
func (r *requestRecorder) onFirstEvent() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	defer recoverTelemetryPanic()
	if !r.begun || r.hasTTFT {
		return
	}
	r.ttftMS = clampDurationMS(time.Since(r.firstStarted))
	r.hasTTFT = true
}

// onAborted records that the caller abandoned the call — its context ended,
// or it stopped consuming the stream — replacing the in-flight attempt's
// outcome with "aborted" while keeping every fact already observed for it.
func (r *requestRecorder) onAborted() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	defer recoverTelemetryPanic()
	if !r.begun {
		return
	}
	attempt := telemetryAttempt{
		index:     r.currentIndex,
		host:      r.currentHost,
		outcome:   "aborted",
		elapsedMS: clampDurationMS(time.Since(r.attemptStart)),
		phase:     "none",
	}
	if previous := r.currentRecordLocked(); previous != nil {
		attempt.httpStatus = previous.httpStatus
		attempt.errorClass = previous.errorClass
		attempt.errorSource = previous.errorSource
		attempt.shouldRetry = previous.shouldRetry
		attempt.retryAfterMS, attempt.hasRetryAfter = previous.retryAfterMS, previous.hasRetryAfter
		attempt.ttfbMS, attempt.hasTTFB = previous.ttfbMS, previous.hasTTFB
		attempt.requestID = previous.requestID
		attempt.moved = previous.moved
		attempt.phase = previous.phase
	}
	r.storeAttempt(attempt)
}

// markExhausted records that the engine gave up on a retryable failure
// after more than one attempt (§5.3 final_outcome exhausted).
func (r *requestRecorder) markExhausted(exhausted bool) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.exhausted = exhausted
}

// currentRecordLocked returns the record of the attempt in flight, or nil
// when that attempt has no record yet (or lost it to a recovered panic).
func (r *requestRecorder) currentRecordLocked() *telemetryAttempt {
	if r.hasLastAttempt && r.lastAttempt.index == r.currentIndex {
		return &r.lastAttempt
	}
	return nil
}

// storeAttempt stores or replaces the record for attempt.index. The record
// carries its own index so a callback panic still leaves a detectable gap
// rather than causing an older attempt to be misreported.
func (r *requestRecorder) storeAttempt(attempt telemetryAttempt) {
	if attempt.phase == "" {
		attempt.phase = "none"
	}
	if attempt.shouldRetry == "" {
		attempt.shouldRetry = "absent"
	}
	replaced := r.hasLastAttempt && r.lastAttempt.index == attempt.index
	stored := false
	for i := range r.attempts {
		if r.attempts[i].index == attempt.index {
			r.attempts[i] = attempt
			stored = true
		}
	}
	if !stored && !replaced && len(r.attempts) < telemetryMaxEventAttempts {
		r.attempts = append(r.attempts, attempt)
	}
	if !replaced {
		r.recorded++
	}
	if r.firstErrorClass == "" && attempt.errorClass != "" {
		r.firstErrorClass = attempt.errorClass
	}
	r.lastAttempt = attempt
	r.hasLastAttempt = true
}

// foldOverflowLocked folds the last record into the overflow counters when
// it fell past the event cap and has not been folded yet.
func (r *requestRecorder) foldOverflowLocked() {
	if !r.hasLastAttempt || r.lastAttempt.index == r.foldedIndex {
		return
	}
	for _, attempt := range r.attempts {
		if attempt.index == r.lastAttempt.index {
			return
		}
	}
	key := r.attemptCounterKeyLocked(r.lastAttempt)
	r.foldedIndex = r.lastAttempt.index
	for i := range r.overflow {
		if r.overflow[i].key == key {
			r.overflow[i].attempts++
			if r.lastAttempt.moved {
				r.overflow[i].moved++
			}
			return
		}
	}
	entry := telemetryOverflowEntry{key: key, attempts: 1}
	if r.lastAttempt.moved {
		entry.moved = 1
	}
	r.overflow = append(r.overflow, entry)
}

// configuredTimeoutForLocked mirrors trusted-router-py _configured_timeout_ms
// for an httpx.Timeout: the connect phase reports the connect timeout and
// the first_byte/idle phases the read timeout; other phases report nothing.
// This SDK has ONE per-attempt timeout, which bounds connection
// establishment, the wait for headers, and (for streams) the idle gap, so
// it is the configured value for every timed phase.
func (r *requestRecorder) configuredTimeoutForLocked(phase string) (int64, bool) {
	switch phase {
	case "connect", "first_byte", "idle":
		if r.hasConfiguredTimeout {
			return r.configuredTimeoutMS, true
		}
	}
	return 0, false
}

func (r *requestRecorder) attemptCounterKeyLocked(attempt telemetryAttempt) telemetryCounterKey {
	phase := attempt.phase
	if phase == "" {
		phase = "none"
	}
	configuredMS, hasConfigured := r.configuredTimeoutForLocked(phase)
	return telemetryCounterKey{
		level:           "attempt",
		endpoint:        r.endpoint,
		streaming:       r.streaming,
		host:            attempt.host,
		outcome:         attempt.outcome,
		errorClass:      attempt.errorClass,
		httpStatusClass: statusClass(attempt.httpStatus),
		timeoutPhase:    phase,
		timeoutFloorMet: timeoutFloorMet(phase, configuredMS, hasConfigured),
		providerPinned:  r.providerPinned,
	}
}

// finish closes the logical call: it derives the §5.3 event and the exact
// §5.4 counter increments from the real attempt history and hands them to
// the sink, exactly once. Mirrors trusted-router-py RequestRecorder._finish.
func (r *requestRecorder) finish() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	defer recoverTelemetryPanic()
	if r.finished {
		return
	}
	r.finished = true
	if !r.recordable || r.sink == nil || !r.begun || !r.hasLastAttempt {
		return
	}
	r.foldOverflowLocked()
	final := r.lastAttempt
	finalOutcome := final.outcome
	if r.exhausted && r.recorded > 1 && final.outcome != "ok" {
		finalOutcome = "exhausted"
	}
	timeoutPhase := final.phase
	if timeoutPhase == "" {
		timeoutPhase = "none"
	}
	configuredMS, hasConfigured := r.configuredTimeoutForLocked(timeoutPhase)
	totalMS := clampDurationMS(time.Since(r.firstStarted))
	event := telemetryRequestEvent{
		endpoint:             r.endpoint,
		method:               r.method,
		streaming:            r.streaming,
		providerPinned:       r.providerPinned,
		model:                r.model,
		attempts:             append([]telemetryAttempt(nil), r.attempts...),
		finalOutcome:         finalOutcome,
		finalHTTPStatus:      final.httpStatus,
		totalMS:              totalMS,
		ttftMS:               r.ttftMS,
		hasTTFT:              r.hasTTFT,
		failoverUsed:         r.failoverUsed,
		timeoutPhase:         timeoutPhase,
		configuredTimeoutMS:  configuredMS,
		hasConfiguredTimeout: hasConfigured,
	}
	first := final
	if len(r.attempts) > 0 {
		first = r.attempts[0]
	}
	request := telemetryCounterIncrement{
		key: telemetryCounterKey{
			level:           "request",
			endpoint:        r.endpoint,
			streaming:       r.streaming,
			host:            final.host,
			outcome:         final.outcome,
			errorClass:      r.firstErrorClass,
			httpStatusClass: statusClass(final.httpStatus),
			timeoutPhase:    timeoutPhase,
			timeoutFloorMet: timeoutFloorMet(timeoutPhase, configuredMS, hasConfigured),
			providerPinned:  r.providerPinned,
		},
		requests:    1,
		attempts:    r.recorded,
		totalMSHist: map[string]int{latencyBucket(totalMS): 1},
	}
	if r.failoverUsed {
		request.failoverUsed = 1
	}
	if first.outcome == "ok" {
		request.firstAttemptSuccess = 1
	}
	switch {
	case r.hasTTFT:
		request.firstEventMSHist = map[string]int{latencyBucket(r.ttftMS): 1}
	case final.hasTTFB:
		request.firstEventMSHist = map[string]int{latencyBucket(final.ttfbMS): 1}
	}
	counters := make([]telemetryCounterIncrement, 0, 1+len(r.attempts)+len(r.overflow))
	counters = append(counters, request)
	for _, attempt := range r.attempts {
		increment := telemetryCounterIncrement{key: r.attemptCounterKeyLocked(attempt), requests: 1, attempts: 1}
		if attempt.moved {
			increment.failoverUsed = 1
		}
		counters = append(counters, increment)
	}
	for _, entry := range r.overflow {
		counters = append(counters, telemetryCounterIncrement{
			key:          entry.key,
			requests:     entry.attempts,
			attempts:     entry.attempts,
			failoverUsed: entry.moved,
		})
	}
	r.sink.onRequest(event, counters)
}

// headerValue assembles the §3.2 grammar for the attempt in flight, in the
// exact key order v,a[,po,pc,ph,pm,sm],s[,fo]. It returns "" — send
// nothing — when the current host is custom, when no attempt has begun, or
// when any value falls outside the grammar or the 160-byte bound: telemetry
// may never fail a request (§2.2), so an out-of-grammar header is dropped
// here, not surfaced.
func (r *requestRecorder) headerValue() (value string) {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	defer func() {
		// Belt and braces for §2.2: even a recorder bug must cost the
		// caller nothing but a missing telemetry header.
		if recover() != nil {
			value = ""
		}
	}()
	if !r.begun || r.currentHost == telemetryHostCustom {
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
		if !r.hasLastAttempt {
			return ""
		}
		previous := r.lastAttempt
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

// telemetryBody is the outermost wrapper around a response body returned by
// the engine when a recorder is active. The logical call is not over when
// do() returns — the caller still drains the body — so this is where the
// recorder learns about mid-body failures (§5.3 stream_broken, idle
// stalls), caller aborts, and the moment the call is finished. It also
// carries the SSE decoder's hooks: sse.go finds it by type assertion on the
// reader it was handed and reports the first event (ttft) and an early stop.
type telemetryBody struct {
	io.ReadCloser
	recorder *requestRecorder
	ctx      context.Context

	mu          sync.Mutex
	bodyStarted bool
	sawEOF      bool
	done        bool
}

func newTelemetryBody(ctx context.Context, body io.ReadCloser, recorder *requestRecorder) io.ReadCloser {
	return &telemetryBody{ReadCloser: body, recorder: recorder, ctx: ctx}
}

func (b *telemetryBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.observeReadError(err)
	}
	return n, err
}

func (b *telemetryBody) observeReadError(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err == io.EOF {
		b.sawEOF = true
		return
	}
	if b.done {
		return
	}
	b.done = true
	if b.ctx.Err() != nil {
		b.recorder.onAborted()
	} else {
		b.recorder.onTransportError(err, false, true, b.bodyStarted)
	}
	b.recorder.finish()
}

// Close finishes the logical call. A close while the caller's context has
// ended and the body had not been drained is a caller abort.
func (b *telemetryBody) Close() error {
	err := b.ReadCloser.Close()
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.done {
		b.done = true
		if b.ctx.Err() != nil && !b.sawEOF {
			b.recorder.onAborted()
		}
	}
	b.recorder.finish()
	return err
}

// onFirstEvent is the SSE decoder's hook for the first event of the stream.
func (b *telemetryBody) onFirstEvent() {
	b.mu.Lock()
	b.bodyStarted = true
	b.mu.Unlock()
	b.recorder.onFirstEvent()
}

// onAborted is the SSE decoder's hook for a consumer that stopped iterating
// before the stream ended (the Go shape of a closed generator).
func (b *telemetryBody) onAborted() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done {
		return
	}
	b.done = true
	b.recorder.onAborted()
}

// telemetrySDKIdentity builds the bounded SDK identity of §5.1 for this
// process, mirroring trusted-router-py sdk_identity: every field is a closed
// enum or an anchored, length-bounded token, with the same fallbacks.
func telemetrySDKIdentity() telemetryWireSDK {
	version := Version
	if len(version) > 32 || !telemetrySemverRe.MatchString(version) {
		version = "0.0.0"
	}
	runtimeToken := "go/" + strings.TrimPrefix(runtime.Version(), "go")
	if !telemetryRuntimeTokenRe.MatchString(runtimeToken) {
		runtimeToken = "go/0.0.0"
	}
	return telemetryWireSDK{
		Name:    "tr-go",
		Version: version,
		Lang:    "go",
		Runtime: runtimeToken,
		OS:      telemetryOSEnum(runtime.GOOS),
		Arch:    telemetryArchEnum(runtime.GOARCH),
	}
}

func telemetryOSEnum(goos string) string {
	switch goos {
	case "darwin":
		return "macos"
	case "linux", "windows", "ios", "android", "freebsd":
		return goos
	default:
		return "other"
	}
}

func telemetryArchEnum(goarch string) string {
	switch goarch {
	case "amd64":
		return "x64"
	case "386":
		return "x32"
	case "arm":
		return "arm"
	case "arm64":
		return "arm64"
	case "wasm":
		return "wasm"
	default:
		return "other"
	}
}
