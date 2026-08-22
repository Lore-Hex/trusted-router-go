package trustedrouter

// telemetry_reporter.go is the BEACON CHANNEL of the client-observed
// reliability telemetry contract, v1 (§4, §5, §6.2): the bounded,
// fire-and-forget delivery of the recorder's events and exact per-minute
// counters to POST {control_base}/client-events. It mirrors
// trusted-router-py `_telemetry.py` TelemetryReporter method for method
// (on_request, _select_batch_locked, _counter_target_locked, _flush_once,
// _handle_response, _apply_policy_locked, close).
//
// It deliberately lives OUTSIDE the transport engine (§2.2, §6.2): it owns
// its own *http.Client, never touches the client's engine or the user's
// injected client, never enters do(), carries no x-tr-client header, and
// makes exactly one attempt per flush. Its worker is one goroutine, started
// lazily on the first record and never at construction; Client.Close runs
// the bounded final flush.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Wire shapes (§5.1, §5.3, §5.4). Field order mirrors the reference's
// dict order; optional fields serialise as null exactly as the reference
// does, except should_retry, which is absent rather than null when the
// gateway sent no verdict.

type telemetryWireSDK struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Lang    string `json:"lang"`
	Runtime string `json:"runtime"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

type telemetryWireAttempt struct {
	Index        int     `json:"index"`
	Host         string  `json:"host"`
	Outcome      string  `json:"outcome"`
	HTTPStatus   *int    `json:"http_status"`
	ErrorClass   *string `json:"error_class"`
	ErrorSource  *string `json:"error_source"`
	RetryAfterMS *int64  `json:"retry_after_ms"`
	ElapsedMS    int64   `json:"elapsed_ms"`
	TTFBMS       *int64  `json:"ttfb_ms"`
	RequestID    *string `json:"request_id"`
	Moved        bool    `json:"moved"`
	ShouldRetry  *bool   `json:"should_retry,omitempty"`
}

type telemetryWireEvent struct {
	AgeMS               int64                  `json:"age_ms"`
	Plane               string                 `json:"plane"`
	Endpoint            string                 `json:"endpoint"`
	Method              string                 `json:"method"`
	Streaming           bool                   `json:"streaming"`
	ProviderPinned      bool                   `json:"provider_pinned"`
	Model               *string                `json:"model"`
	Attempts            []telemetryWireAttempt `json:"attempts"`
	FinalOutcome        string                 `json:"final_outcome"`
	FinalHTTPStatus     *int                   `json:"final_http_status"`
	TotalMS             int64                  `json:"total_ms"`
	TTFTMS              *int64                 `json:"ttft_ms"`
	FailoverUsed        bool                   `json:"failover_used"`
	TimeoutPhase        string                 `json:"timeout_phase"`
	ConfiguredTimeoutMS *int64                 `json:"configured_timeout_ms"`
	SampleRate          float64                `json:"sample_rate"`
	SampleReason        string                 `json:"sample_reason"`
}

type telemetryWireCounter struct {
	WindowStartAgeMS    int64          `json:"window_start_age_ms"`
	Level               string         `json:"level"`
	Endpoint            string         `json:"endpoint"`
	Streaming           bool           `json:"streaming"`
	Host                string         `json:"host"`
	Outcome             string         `json:"outcome"`
	ErrorClass          *string        `json:"error_class"`
	HTTPStatusClass     string         `json:"http_status_class"`
	TimeoutPhase        string         `json:"timeout_phase"`
	TimeoutFloorMet     bool           `json:"timeout_floor_met"`
	ProviderPinned      bool           `json:"provider_pinned"`
	Requests            int            `json:"requests"`
	Attempts            int            `json:"attempts"`
	FailoverUsed        int            `json:"failover_used"`
	FirstAttemptSuccess int            `json:"first_attempt_success"`
	TotalMSHist         map[string]int `json:"total_ms_hist"`
	FirstEventMSHist    map[string]int `json:"first_event_ms_hist"`
}

// telemetryWireBatch is the §5.1 batch: NOTHING else rides it — no ids
// beyond the SDK-minted batch/instance ids, no hostnames, no prompt text,
// no idempotency keys.
type telemetryWireBatch struct {
	SchemaVersion    int                    `json:"schema_version"`
	BatchID          string                 `json:"batch_id"`
	InstanceID       string                 `json:"instance_id"`
	Seq              int                    `json:"seq"`
	SentAtMS         int64                  `json:"sent_at_ms"`
	SDK              telemetryWireSDK       `json:"sdk"`
	Synthetic        bool                   `json:"synthetic"`
	DroppedSinceLast int                    `json:"dropped_since_last"`
	Events           []telemetryWireEvent   `json:"events"`
	Counters         []telemetryWireCounter `json:"counters"`
}

func telemetryOptionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func telemetryBoundedOptionalInt(value int, minimum, maximum int) *int {
	if value < minimum || value > maximum {
		return nil
	}
	return &value
}

func telemetryBoundedOptionalInt64(value int64, present bool, minimum, maximum int64) *int64 {
	if !present || value < minimum || value > maximum {
		return nil
	}
	return &value
}

func telemetryBoundedCount(value int) int {
	return int(clampInt64(int64(value), 0, telemetryMaxCount))
}

// telemetryWireAttemptFrom bounds one attempt for the wire, mirroring
// trusted-router-py _wire_attempt: every enum falls back to a closed value,
// every integer is clamped or nulled, and the request id must match the
// enclave's audit-id shape.
func telemetryWireAttemptFrom(attempt telemetryAttempt) telemetryWireAttempt {
	host := attempt.host
	if !telemetryInSlice(telemetryHosts, host) {
		host = telemetryHostCustom
	}
	outcome := attempt.outcome
	if !telemetryInSlice(telemetryOutcomes, outcome) {
		outcome = "transport_error"
	}
	errorClass := attempt.errorClass
	if !telemetryInSlice(telemetryErrorClasses, errorClass) {
		errorClass = ""
	}
	errorSource := attempt.errorSource
	if !telemetryInSlice(telemetryErrorSources, errorSource) {
		errorSource = ""
	}
	requestID := attempt.requestID
	if !telemetryRequestIDRe.MatchString(requestID) {
		requestID = ""
	}
	wire := telemetryWireAttempt{
		Index:        int(clampInt64(int64(attempt.index), 0, 99)),
		Host:         host,
		Outcome:      outcome,
		HTTPStatus:   telemetryBoundedOptionalInt(attempt.httpStatus, 100, 599),
		ErrorClass:   telemetryOptionalString(errorClass),
		ErrorSource:  telemetryOptionalString(errorSource),
		RetryAfterMS: telemetryBoundedOptionalInt64(attempt.retryAfterMS, attempt.hasRetryAfter, 0, telemetryMaxDurationMS),
		ElapsedMS:    clampInt64(attempt.elapsedMS, 0, telemetryMaxDurationMS),
		TTFBMS:       telemetryBoundedOptionalInt64(attempt.ttfbMS, attempt.hasTTFB, 0, telemetryMaxDurationMS),
		RequestID:    telemetryOptionalString(requestID),
		Moved:        attempt.moved,
	}
	switch attempt.shouldRetry {
	case "true":
		yes := true
		wire.ShouldRetry = &yes
	case "false":
		no := false
		wire.ShouldRetry = &no
	}
	return wire
}

// telemetryWireEventFrom bounds one event for the wire, mirroring
// trusted-router-py _wire_event. It reports false when the event cannot be
// expressed at all (no attempts, unusable sampling facts).
func telemetryWireEventFrom(event telemetryRequestEvent, sampleRate float64, sampleReason string, ageMS int64) (telemetryWireEvent, bool) {
	if len(event.attempts) == 0 {
		return telemetryWireEvent{}, false
	}
	attempts := event.attempts
	if len(attempts) > telemetryMaxEventAttempts {
		attempts = attempts[:telemetryMaxEventAttempts]
	}
	wireAttempts := make([]telemetryWireAttempt, 0, len(attempts))
	for _, attempt := range attempts {
		wireAttempts = append(wireAttempts, telemetryWireAttemptFrom(attempt))
	}
	endpoint := event.endpoint
	if !telemetryInSlice(telemetryEndpoints, endpoint) {
		endpoint = "inference_other"
	}
	method := event.method
	switch method {
	case http.MethodGet, http.MethodPost:
	default:
		method = http.MethodPost
	}
	model := event.model
	if !telemetryModelRe.MatchString(model) {
		model = ""
	}
	finalOutcome := event.finalOutcome
	if !telemetryInSlice(telemetryFinalOutcomes, finalOutcome) {
		finalOutcome = wireAttempts[len(wireAttempts)-1].Outcome
	}
	timeoutPhase := event.timeoutPhase
	if !telemetryInSlice(telemetryTimeoutPhases, timeoutPhase) {
		timeoutPhase = "none"
	}
	if !telemetryInSlice(telemetrySampleReasons, sampleReason) {
		return telemetryWireEvent{}, false
	}
	if math.IsNaN(sampleRate) || math.IsInf(sampleRate, 0) || sampleRate <= 0 || sampleRate > 1 {
		return telemetryWireEvent{}, false
	}
	return telemetryWireEvent{
		AgeMS:               clampInt64(ageMS, 0, telemetryMaxAgeMS),
		Plane:               "inference",
		Endpoint:            endpoint,
		Method:              method,
		Streaming:           event.streaming,
		ProviderPinned:      event.providerPinned,
		Model:               telemetryOptionalString(model),
		Attempts:            wireAttempts,
		FinalOutcome:        finalOutcome,
		FinalHTTPStatus:     telemetryBoundedOptionalInt(event.finalHTTPStatus, 100, 599),
		TotalMS:             clampInt64(event.totalMS, 0, telemetryMaxDurationMS),
		TTFTMS:              telemetryBoundedOptionalInt64(event.ttftMS, event.hasTTFT, 0, telemetryMaxDurationMS),
		FailoverUsed:        event.failoverUsed,
		TimeoutPhase:        timeoutPhase,
		ConfiguredTimeoutMS: telemetryBoundedOptionalInt64(event.configuredTimeoutMS, event.hasConfiguredTimeout, 1, telemetryMaxDurationMS),
		SampleRate:          sampleRate,
		SampleReason:        sampleReason,
	}, true
}

// telemetryCounterValue is the counts half of a §5.4 counter row.
type telemetryCounterValue struct {
	requests            int
	attempts            int
	failoverUsed        int
	firstAttemptSuccess int
	totalMSHist         map[string]int
	firstEventMSHist    map[string]int
}

func telemetryMergeHistogram(target map[string]int, source map[string]int) {
	for bucket, count := range source {
		if !telemetryInSlice(telemetryLatencyBuckets, bucket) {
			continue
		}
		target[bucket] += telemetryBoundedCount(count)
	}
}

// mergeIncrement mirrors trusted-router-py _merge_counter_increment: every
// count is bounded before it is added, and histogram buckets outside the
// enum are ignored.
func (v *telemetryCounterValue) mergeIncrement(increment telemetryCounterIncrement) {
	v.requests += telemetryBoundedCount(increment.requests)
	v.attempts += telemetryBoundedCount(increment.attempts)
	v.failoverUsed += telemetryBoundedCount(increment.failoverUsed)
	v.firstAttemptSuccess += telemetryBoundedCount(increment.firstAttemptSuccess)
	if v.totalMSHist == nil {
		v.totalMSHist = map[string]int{}
	}
	if v.firstEventMSHist == nil {
		v.firstEventMSHist = map[string]int{}
	}
	telemetryMergeHistogram(v.totalMSHist, increment.totalMSHist)
	telemetryMergeHistogram(v.firstEventMSHist, increment.firstEventMSHist)
}

func (v *telemetryCounterValue) asIncrement(key telemetryCounterKey) telemetryCounterIncrement {
	return telemetryCounterIncrement{
		key:                 key,
		requests:            v.requests,
		attempts:            v.attempts,
		failoverUsed:        v.failoverUsed,
		firstAttemptSuccess: v.firstAttemptSuccess,
		totalMSHist:         v.totalMSHist,
		firstEventMSHist:    v.firstEventMSHist,
	}
}

func telemetryCopyHistogram(source map[string]int) map[string]int {
	out := make(map[string]int, len(source))
	for bucket, count := range source {
		out[bucket] = count
	}
	return out
}

// telemetryWireCounterFrom renders one row, mirroring trusted-router-py
// _counter_row (requests ≥1, every count ≤10 000 000).
func telemetryWireCounterFrom(key telemetryCounterKey, value *telemetryCounterValue, windowAgeMS int64) telemetryWireCounter {
	return telemetryWireCounter{
		WindowStartAgeMS:    clampInt64(windowAgeMS, 0, telemetryMaxAgeMS),
		Level:               key.level,
		Endpoint:            key.endpoint,
		Streaming:           key.streaming,
		Host:                key.host,
		Outcome:             key.outcome,
		ErrorClass:          telemetryOptionalString(key.errorClass),
		HTTPStatusClass:     key.httpStatusClass,
		TimeoutPhase:        key.timeoutPhase,
		TimeoutFloorMet:     key.timeoutFloorMet,
		ProviderPinned:      key.providerPinned,
		Requests:            int(clampInt64(int64(value.requests), 1, telemetryMaxCount)),
		Attempts:            telemetryBoundedCount(value.attempts),
		FailoverUsed:        telemetryBoundedCount(value.failoverUsed),
		FirstAttemptSuccess: telemetryBoundedCount(value.firstAttemptSuccess),
		TotalMSHist:         telemetryCopyHistogram(value.totalMSHist),
		FirstEventMSHist:    telemetryCopyHistogram(value.firstEventMSHist),
	}
}

// telemetryCounterTable is an insertion-ordered map of counter rows. The
// order matters: the §5.4 fold ladder's last resort is "any existing key",
// which the reference resolves as the FIRST inserted, and the batch lists
// rows in insertion order.
type telemetryCounterTable struct {
	keys []telemetryCounterKey
	rows map[telemetryCounterKey]*telemetryCounterValue
}

func newTelemetryCounterTable() *telemetryCounterTable {
	return &telemetryCounterTable{rows: map[telemetryCounterKey]*telemetryCounterValue{}}
}

func (t *telemetryCounterTable) size() int { return len(t.keys) }

func (t *telemetryCounterTable) get(key telemetryCounterKey) (*telemetryCounterValue, bool) {
	value, ok := t.rows[key]
	return value, ok
}

func (t *telemetryCounterTable) put(key telemetryCounterKey, value *telemetryCounterValue) {
	if _, exists := t.rows[key]; !exists {
		t.keys = append(t.keys, key)
	}
	t.rows[key] = value
}

func (t *telemetryCounterTable) remove(key telemetryCounterKey) (*telemetryCounterValue, bool) {
	value, ok := t.rows[key]
	if !ok {
		return nil, false
	}
	delete(t.rows, key)
	for i := range t.keys {
		if t.keys[i] == key {
			t.keys = append(t.keys[:i], t.keys[i+1:]...)
			break
		}
	}
	return value, true
}

func (t *telemetryCounterTable) first() telemetryCounterKey { return t.keys[0] }

// telemetryCounterWindow is one closed client minute (§5.4) awaiting
// delivery, retained ≤24 h under the byte cap.
type telemetryCounterWindow struct {
	start     time.Time
	rows      *telemetryCounterTable
	sizeBytes int
}

// telemetryBufferedEvent is a sampled, wire-bounded event awaiting delivery;
// age_ms is recomputed at flush time from completedAt.
type telemetryBufferedEvent struct {
	wire           telemetryWireEvent
	completedAt    time.Time
	estimatedBytes int
}

type telemetryCounterRef struct {
	window *telemetryCounterWindow
	key    telemetryCounterKey
}

type telemetrySelectedBatch struct {
	payload  []byte
	events   []*telemetryBufferedEvent
	counters []telemetryCounterRef
	dropped  int
}

// telemetryReporter is the beacon sender (§6.2). See the file comment.
type telemetryReporter struct {
	mu      sync.Mutex
	flushMu sync.Mutex

	controlBaseURL    string
	apiKey            string
	workspaceID       string
	sdk               telemetryWireSDK
	successSampleRate float64
	flushInterval     time.Duration
	newHTTPClient     func() *http.Client
	httpClient        *http.Client
	clock             func() time.Time
	random            func() float64
	debug             bool
	debugOut          io.Writer

	wake       chan struct{}
	stop       chan struct{}
	stopped    bool
	workerDone chan struct{}

	events              []*telemetryBufferedEvent
	eventsSizeBytes     int
	windowStart         time.Time
	hasWindow           bool
	current             *telemetryCounterTable
	closedWindows       []*telemetryCounterWindow
	retainedWindowBytes int
	droppedSinceLast    int
	instanceID          string
	seq                 int
	backoff             time.Duration
	backoffUntil        time.Time
	pausedUntil         time.Time
	nextFlushAt         time.Time
	urgentFlush         bool
	disabled            bool
	closed              bool
}

// newTelemetryReporter constructs a reporter. Nothing starts here: the
// worker goroutine and the HTTP client are created lazily on first use.
func newTelemetryReporter(controlBaseURL, apiKey, workspaceID string, identity telemetryWireSDK, successSampleRate float64) *telemetryReporter {
	return &telemetryReporter{
		controlBaseURL:    strings.TrimRight(controlBaseURL, "/"),
		apiKey:            apiKey,
		workspaceID:       workspaceID,
		sdk:               normaliseTelemetrySDKIdentity(identity),
		successSampleRate: telemetrySampleRateValue(successSampleRate),
		flushInterval:     telemetryFlushInterval,
		newHTTPClient:     newTelemetryHTTPClient,
		clock:             time.Now,
		random:            telemetryRandomUnit,
		debug:             os.Getenv("TRUSTEDROUTER_TELEMETRY_DEBUG") == "1",
		debugOut:          os.Stderr,
		wake:              make(chan struct{}, 1),
		stop:              make(chan struct{}),
		current:           newTelemetryCounterTable(),
		instanceID:        telemetryHex(8),
		backoff:           telemetryBackoffMin,
	}
}

// newTelemetryHTTPClient is the reporter's OWN client (§6.2): a private
// redirect-refusing client on a private clone of the default transport, so
// the beacon shares neither the engine's client nor the user's injected one.
func newTelemetryHTTPClient() *http.Client {
	client := &http.Client{Timeout: telemetryHTTPTimeout}
	if transport, ok := http.DefaultTransport.(*http.Transport); ok {
		client.Transport = transport.Clone()
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return client
}

// telemetrySampleRateValue mirrors TelemetryReporter._sample_rate: anything
// unusable is the default, and usable values are clamped into [0, 1].
func telemetrySampleRateValue(value float64) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return telemetryDefaultSampleRate
	}
	return math.Min(1, math.Max(0, value))
}

// normaliseTelemetrySDKIdentity mirrors _normalise_sdk_identity: each field
// outside its closed vocabulary falls back to this process's own identity.
func normaliseTelemetrySDKIdentity(identity telemetryWireSDK) telemetryWireSDK {
	fallback := telemetrySDKIdentity()
	if !telemetryInSlice([]string{"tr-py", "tr-js", "tr-go", "tr-rust", "tr-java", "tr-swift"}, identity.Name) {
		identity.Name = fallback.Name
	}
	if len(identity.Version) > 32 || !telemetrySemverRe.MatchString(identity.Version) {
		identity.Version = fallback.Version
	}
	if !telemetryInSlice([]string{"python", "js", "go", "rust", "java", "swift"}, identity.Lang) {
		identity.Lang = fallback.Lang
	}
	if !telemetryRuntimeTokenRe.MatchString(identity.Runtime) {
		identity.Runtime = fallback.Runtime
	}
	if !telemetryInSlice([]string{"linux", "macos", "windows", "ios", "android", "freebsd", "other"}, identity.OS) {
		identity.OS = fallback.OS
	}
	if !telemetryInSlice([]string{"x64", "x32", "arm", "arm64", "wasm", "other"}, identity.Arch) {
		identity.Arch = fallback.Arch
	}
	return identity
}

// telemetryHex mints n random bytes as lowercase hex (batch and instance
// ids, §5.1). A failing entropy source falls back to time and a counter so
// the id is still well-formed and unique within the process.
func telemetryHex(n int) string {
	buf := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		var fallback [16]byte
		binary.BigEndian.PutUint64(fallback[0:8], uint64(time.Now().UnixNano()))
		binary.BigEndian.PutUint64(fallback[8:16], idempotencyFallbackSequence.Add(1))
		for i := range buf {
			buf[i] = fallback[i%len(fallback)]
		}
	}
	return hex.EncodeToString(buf)
}

// telemetryRandomUnit draws a uniform float in [0, 1) from the system
// entropy source (py: secrets.randbits(53) / 2**53). On failure it returns
// 1, which never samples.
func telemetryRandomUnit() float64 {
	var buf [8]byte
	if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
		return 1
	}
	return float64(binary.BigEndian.Uint64(buf[:])>>11) / float64(1<<53)
}

func telemetryLatest(times ...time.Time) time.Time {
	var latest time.Time
	for _, candidate := range times {
		if candidate.After(latest) {
			latest = candidate
		}
	}
	return latest
}

func (r *telemetryReporter) wakeLocked() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *telemetryReporter) stopLocked() {
	if !r.stopped {
		r.stopped = true
		close(r.stop)
	}
	r.wakeLocked()
}

// startWorkerLocked starts the single background goroutine on the first
// record (§6.2: never at construction).
func (r *telemetryReporter) startWorkerLocked(now time.Time) {
	if r.workerDone != nil || r.disabled || r.closed {
		return
	}
	r.nextFlushAt = now.Add(r.flushInterval)
	r.workerDone = make(chan struct{})
	go r.worker(r.workerDone)
}

// worker mirrors TelemetryReporter._worker: sleep until the earliest of the
// next flush, the pause, and the backoff deadline unless an urgent flush is
// due, then flush once and reschedule.
func (r *telemetryReporter) worker(done chan struct{}) {
	defer close(done)
	for {
		select {
		case <-r.stop:
			return
		default:
		}
		now := r.clock()
		r.mu.Lock()
		deadline := telemetryLatest(r.nextFlushAt, r.pausedUntil, r.backoffUntil)
		urgent := r.urgentFlush && !now.Before(telemetryLatest(r.pausedUntil, r.backoffUntil))
		if urgent {
			r.urgentFlush = false
		}
		r.mu.Unlock()
		if !urgent && now.Before(deadline) {
			timer := time.NewTimer(deadline.Sub(now))
			select {
			case <-timer.C:
			case <-r.wake:
				timer.Stop()
			case <-r.stop:
				timer.Stop()
				return
			}
			continue
		}
		r.flushOnce(context.Background())
		r.mu.Lock()
		r.nextFlushAt = r.clock().Add(r.flushInterval)
		r.mu.Unlock()
	}
}

// sampleReason mirrors TelemetryReporter._sample_reason (§5.3 sampling):
// every failure, every retried or failed-over success, every slow success,
// and success_sample_rate of the rest.
func (r *telemetryReporter) sampleReason(event telemetryRequestEvent) (string, float64, bool) {
	if event.finalOutcome != "ok" {
		return "failure", 1, true
	}
	if len(event.attempts) > 1 || event.failoverUsed {
		return "retried", 1, true
	}
	if clampInt64(event.totalMS, 0, telemetryMaxDurationMS) > telemetrySlowMS {
		return "slow", 1, true
	}
	r.mu.Lock()
	rate := r.successSampleRate
	r.mu.Unlock()
	draw := r.random()
	if rate <= 0 || draw >= rate {
		return "", 0, false
	}
	return "random", rate, true
}

// onRequest is the telemetrySink entry point: sample the event, bound it for
// the wire, merge the exact counters into the current minute, buffer, and
// trigger an urgent flush when the batch thresholds are met. It never
// returns an error and never panics out (§2.2).
func (r *telemetryReporter) onRequest(event telemetryRequestEvent, counters []telemetryCounterIncrement) {
	defer recoverTelemetryPanic()
	now := r.clock()
	reason, rate, sampled := r.sampleReason(event)
	var buffered *telemetryBufferedEvent
	invalid := false
	if sampled {
		wire, ok := telemetryWireEventFrom(event, rate, reason, 0)
		if !ok {
			invalid = true
		} else {
			estimated := 600
			if encoded, err := json.Marshal(wire); err == nil {
				estimated = len(encoded)
			}
			buffered = &telemetryBufferedEvent{wire: wire, completedAt: now, estimatedBytes: estimated}
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.disabled || r.closed {
		return
	}
	r.rollWindowLocked(now)
	r.mergeCountersLocked(counters)
	if invalid {
		r.droppedSinceLast++
	}
	if buffered != nil {
		r.appendEventLocked(buffered)
	}
	r.startWorkerLocked(now)
	if len(r.events) >= telemetryURGENTEvents ||
		r.eventsSizeBytes+r.retainedWindowBytes+r.current.size()*400 >= telemetryBatchTriggerBytes {
		r.urgentFlush = true
		r.wakeLocked()
	}
}

// dropBufferedEventLocked drops the oldest success, or the oldest event of
// any kind when no success is buffered, counting the drop (§6.2).
func (r *telemetryReporter) dropBufferedEventLocked() {
	index := 0
	for i, buffered := range r.events {
		if buffered.wire.FinalOutcome == "ok" {
			index = i
			break
		}
	}
	dropped := r.events[index]
	r.events = append(r.events[:index], r.events[index+1:]...)
	r.eventsSizeBytes -= dropped.estimatedBytes
	r.droppedSinceLast++
}

func (r *telemetryReporter) appendEventLocked(buffered *telemetryBufferedEvent) {
	if len(r.events) >= telemetryMaxEvents {
		r.dropBufferedEventLocked()
	}
	r.events = append(r.events, buffered)
	r.eventsSizeBytes += buffered.estimatedBytes
}

func telemetryMinuteStart(now time.Time) time.Time {
	return now.Truncate(time.Minute)
}

func (r *telemetryReporter) rollWindowLocked(now time.Time) {
	minuteStart := telemetryMinuteStart(now)
	if !r.hasWindow {
		r.windowStart = minuteStart
		r.hasWindow = true
		return
	}
	if minuteStart.After(r.windowStart) {
		r.closeCurrentWindowLocked(now)
		r.windowStart = minuteStart
	}
}

func telemetryFoldedCounterKey(key telemetryCounterKey, endpoint bool) telemetryCounterKey {
	key.errorClass = "unknown"
	if endpoint {
		key.endpoint = "inference_other"
	}
	return key
}

func telemetryKeysMatchExceptErrorClass(a, b telemetryCounterKey) bool {
	a.errorClass, b.errorClass = "", ""
	return a == b
}

func telemetryKeysMatchExceptEndpointAndErrorClass(a, b telemetryCounterKey) bool {
	a.errorClass, b.errorClass = "", ""
	a.endpoint, b.endpoint = "", ""
	return a == b
}

// counterTargetLocked is the §5.4 fold ladder, mirroring
// _counter_target_locked exactly: past 256 keys a new key folds its error
// class to unknown (re-keying a compatible existing row if needed), then its
// endpoint to inference_other, and as a last resort lands on the first
// existing key — so the counts stay exact, only coarser, and no record is
// ever dropped by folding.
func (r *telemetryReporter) counterTargetLocked(key telemetryCounterKey) telemetryCounterKey {
	if _, exists := r.current.get(key); exists || r.current.size() < telemetryMaxWindowKeys {
		return key
	}
	errorFolded := telemetryFoldedCounterKey(key, false)
	if _, exists := r.current.get(errorFolded); exists {
		return errorFolded
	}
	for _, existing := range r.current.keys {
		if telemetryKeysMatchExceptErrorClass(existing, key) {
			previous, _ := r.current.remove(existing)
			target := telemetryFoldedCounterKey(existing, false)
			merged := &telemetryCounterValue{}
			merged.mergeIncrement(previous.asIncrement(existing))
			r.current.put(target, merged)
			return target
		}
	}
	endpointFolded := telemetryFoldedCounterKey(key, true)
	if _, exists := r.current.get(endpointFolded); exists {
		return endpointFolded
	}
	for _, existing := range r.current.keys {
		if telemetryKeysMatchExceptEndpointAndErrorClass(existing, key) {
			previous, _ := r.current.remove(existing)
			target := telemetryFoldedCounterKey(existing, true)
			merged := &telemetryCounterValue{}
			merged.mergeIncrement(previous.asIncrement(existing))
			r.current.put(target, merged)
			return target
		}
	}
	return r.current.first()
}

// normaliseTelemetryCounterKey mirrors _normalise_counter_key: unknown
// levels and outcomes drop the increment; other fields fall back to a
// closed value.
func normaliseTelemetryCounterKey(key telemetryCounterKey) (telemetryCounterKey, bool) {
	if key.level != "attempt" && key.level != "request" {
		return key, false
	}
	if !telemetryInSlice(telemetryEndpoints, key.endpoint) {
		key.endpoint = "inference_other"
	}
	if !telemetryInSlice(telemetryHosts, key.host) {
		key.host = telemetryHostCustom
	}
	// The schema module types counter outcome as Outcome, not FinalOutcome.
	// In particular, "exhausted" is event-only; request counters carry the
	// final attempt's ordinary outcome.
	if !telemetryInSlice(telemetryOutcomes, key.outcome) {
		return key, false
	}
	if key.errorClass != "" && !telemetryInSlice(telemetryErrorClasses, key.errorClass) {
		key.errorClass = "unknown"
	}
	if !telemetryInSlice(telemetryHTTPStatusClasses, key.httpStatusClass) {
		key.httpStatusClass = "none"
	}
	if !telemetryInSlice(telemetryTimeoutPhases, key.timeoutPhase) {
		key.timeoutPhase = "none"
	}
	return key, true
}

func (r *telemetryReporter) mergeCountersLocked(counters []telemetryCounterIncrement) {
	for _, increment := range counters {
		key, ok := normaliseTelemetryCounterKey(increment.key)
		if !ok {
			r.droppedSinceLast++
			continue
		}
		target := r.counterTargetLocked(key)
		value, exists := r.current.get(target)
		if !exists {
			value = &telemetryCounterValue{}
			r.current.put(target, value)
		}
		value.mergeIncrement(increment)
	}
}

func telemetryWindowSize(window *telemetryCounterWindow) int {
	rows := make([]telemetryWireCounter, 0, window.rows.size())
	for _, key := range window.rows.keys {
		rows = append(rows, telemetryWireCounterFrom(key, window.rows.rows[key], 0))
	}
	encoded, err := json.Marshal(rows)
	if err != nil {
		return 0
	}
	return len(encoded)
}

func (r *telemetryReporter) closeCurrentWindowLocked(now time.Time) {
	if r.current.size() == 0 || !r.hasWindow {
		return
	}
	window := &telemetryCounterWindow{start: r.windowStart, rows: r.current}
	window.sizeBytes = telemetryWindowSize(window)
	r.closedWindows = append(r.closedWindows, window)
	r.retainedWindowBytes += window.sizeBytes
	r.current = newTelemetryCounterTable()
	r.windowStart = telemetryMinuteStart(now)
	r.pruneWindowsLocked(now)
}

func (r *telemetryReporter) dropWindowLocked(window *telemetryCounterWindow) {
	r.retainedWindowBytes -= window.sizeBytes
	r.droppedSinceLast += window.rows.size()
}

// pruneWindowsLocked enforces the §6.2 retention: closed windows older than
// 24 h go first, then the oldest until the byte cap holds.
func (r *telemetryReporter) pruneWindowsLocked(now time.Time) {
	for len(r.closedWindows) > 0 && now.Sub(r.closedWindows[0].start) > telemetryRetentionSeconds*time.Second {
		r.dropWindowLocked(r.closedWindows[0])
		r.closedWindows = r.closedWindows[1:]
	}
	for len(r.closedWindows) > 0 && r.retainedWindowBytes > telemetryRetentionBytes {
		r.dropWindowLocked(r.closedWindows[0])
		r.closedWindows = r.closedWindows[1:]
	}
}

// selectBatchLocked mirrors _select_batch_locked: close the current minute,
// take up to 100 events (ages recomputed now) and up to 200 counter rows
// (oldest windows first, ages from the window start), mint the batch, and
// trim from the tail until it fits in 65 536 bytes.
func (r *telemetryReporter) selectBatchLocked(now time.Time) *telemetrySelectedBatch {
	r.rollWindowLocked(now)
	r.closeCurrentWindowLocked(now)
	r.pruneWindowsLocked(now)
	var eventRefs []*telemetryBufferedEvent
	wireEvents := []telemetryWireEvent{}
	for _, buffered := range r.events {
		wire := buffered.wire
		wire.AgeMS = clampInt64(now.Sub(buffered.completedAt).Milliseconds(), 0, telemetryMaxAgeMS)
		eventRefs = append(eventRefs, buffered)
		wireEvents = append(wireEvents, wire)
		if len(wireEvents) >= telemetryMaxBatchEvents {
			break
		}
	}
	var counterRefs []telemetryCounterRef
	wireCounters := []telemetryWireCounter{}
windows:
	for _, window := range r.closedWindows {
		ageMS := now.Sub(window.start).Milliseconds()
		for _, key := range window.rows.keys {
			counterRefs = append(counterRefs, telemetryCounterRef{window: window, key: key})
			wireCounters = append(wireCounters, telemetryWireCounterFrom(key, window.rows.rows[key], ageMS))
			if len(wireCounters) >= telemetryMaxBatchCounters {
				break windows
			}
		}
	}
	if len(wireEvents) == 0 && len(wireCounters) == 0 {
		return nil
	}
	dropped := r.droppedSinceLast
	batch := telemetryWireBatch{
		SchemaVersion:    telemetrySchemaVersion,
		BatchID:          telemetryHex(16),
		InstanceID:       r.instanceID,
		Seq:              r.seq,
		SentAtMS:         time.Now().UnixMilli(),
		SDK:              r.sdk,
		Synthetic:        false,
		DroppedSinceLast: dropped,
		Events:           wireEvents,
		Counters:         wireCounters,
	}
	r.seq++
	for {
		payload, err := json.Marshal(batch)
		if err != nil {
			return nil
		}
		if len(payload) <= telemetryMaxBatchBytes {
			return &telemetrySelectedBatch{payload: payload, events: eventRefs, counters: counterRefs, dropped: dropped}
		}
		switch {
		case len(batch.Events) > 0:
			batch.Events = batch.Events[:len(batch.Events)-1]
			eventRefs = eventRefs[:len(eventRefs)-1]
		case len(batch.Counters) > 0:
			batch.Counters = batch.Counters[:len(batch.Counters)-1]
			counterRefs = counterRefs[:len(counterRefs)-1]
		default:
			return nil
		}
	}
}

func (r *telemetryReporter) client() *http.Client {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.httpClient == nil {
		r.httpClient = r.newHTTPClient()
	}
	return r.httpClient
}

// telemetryRetryAfter parses the beacon endpoint's Retry-After as seconds,
// honouring it only within the §6.2 bound of 600 s.
func telemetryRetryAfter(headers http.Header) (time.Duration, bool) {
	raw := strings.TrimSpace(headers.Get("Retry-After"))
	if raw == "" {
		return 0, false
	}
	seconds, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 {
		return 0, false
	}
	delay := time.Duration(seconds * float64(time.Second))
	if delay > telemetryMaxRetryAfter {
		return 0, false
	}
	return delay, true
}

// setBackoffLocked mirrors _set_backoff_locked: exponential 60 s → 10 min,
// floored by a bounded Retry-After.
func (r *telemetryReporter) setBackoffLocked(now time.Time, retryAfter time.Duration, hasRetryAfter bool) {
	delay := r.backoff
	if hasRetryAfter && retryAfter > delay {
		delay = retryAfter
	}
	if delay > telemetryBackoffMax {
		delay = telemetryBackoffMax
	}
	r.backoffUntil = now.Add(delay)
	next := r.backoff * 2
	if next < telemetryBackoffMin {
		next = telemetryBackoffMin
	}
	if next > telemetryBackoffMax {
		next = telemetryBackoffMax
	}
	r.backoff = next
	r.wakeLocked()
}

func (r *telemetryReporter) removeSelectedLocked(selected *telemetrySelectedBatch) {
	sent := make(map[*telemetryBufferedEvent]bool, len(selected.events))
	for _, buffered := range selected.events {
		sent[buffered] = true
	}
	kept := r.events[:0]
	size := 0
	for _, buffered := range r.events {
		if sent[buffered] {
			continue
		}
		kept = append(kept, buffered)
		size += buffered.estimatedBytes
	}
	for i := len(kept); i < len(r.events); i++ {
		r.events[i] = nil
	}
	r.events = kept
	r.eventsSizeBytes = size
	changed := map[*telemetryCounterWindow]bool{}
	for _, ref := range selected.counters {
		if _, ok := ref.window.rows.remove(ref.key); ok {
			changed[ref.window] = true
		}
	}
	for window := range changed {
		r.retainedWindowBytes -= window.sizeBytes
		window.sizeBytes = 0
		if window.rows.size() > 0 {
			window.sizeBytes = telemetryWindowSize(window)
		}
		r.retainedWindowBytes += window.sizeBytes
	}
	remaining := r.closedWindows[:0]
	for _, window := range r.closedWindows {
		if window.rows.size() > 0 {
			remaining = append(remaining, window)
		}
	}
	for i := len(remaining); i < len(r.closedWindows); i++ {
		r.closedWindows[i] = nil
	}
	r.closedWindows = remaining
}

func telemetryFloatValue(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return 0, false
		}
		return typed, true
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
			return 0, false
		}
		return parsed, true
	default:
		return 0, false
	}
}

// applyPolicyLocked mirrors _apply_policy_locked: a 202's policy is applied
// ONLY where it reduces volume — a lower success_sample_rate, a longer
// flush interval (capped at 10 min), a pause in [0, 86 400] s.
func (r *telemetryReporter) applyPolicyLocked(body []byte, now time.Time) {
	var payload struct {
		Policy map[string]any `json:"policy"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.Policy == nil {
		return
	}
	if raw, present := payload.Policy["success_sample_rate"]; present {
		if rate, ok := telemetryFloatValue(raw); ok && rate >= 0 && rate < r.successSampleRate {
			r.successSampleRate = rate
		}
	}
	if raw, present := payload.Policy["flush_seconds"]; present {
		if seconds, ok := telemetryFloatValue(raw); ok && seconds > r.flushInterval.Seconds() {
			interval := time.Duration(math.Min(seconds, telemetryBackoffMax.Seconds()) * float64(time.Second))
			r.flushInterval = interval
		}
	}
	if seconds, ok := telemetryFloatValue(payload.Policy["pause_seconds"]); ok && seconds >= 0 && seconds <= telemetryMaxPause.Seconds() {
		until := now.Add(time.Duration(seconds * float64(time.Second)))
		if until.After(r.pausedUntil) {
			r.pausedUntil = until
		}
	}
}

// disableLocked turns the reporter off for the rest of the process and
// releases every buffer (§6.2: 400/401/403/404/410, x-tr-telemetry: off).
func (r *telemetryReporter) disableLocked() {
	r.disabled = true
	r.events = nil
	r.eventsSizeBytes = 0
	r.current = newTelemetryCounterTable()
	r.closedWindows = nil
	r.retainedWindowBytes = 0
	r.droppedSinceLast = 0
	r.stopLocked()
}

// handleResponse mirrors _handle_response (§4, §6.2).
func (r *telemetryReporter) handleResponse(status int, headers http.Header, body []byte, now time.Time, selected *telemetrySelectedBatch) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if strings.EqualFold(strings.TrimSpace(headers.Get("X-TR-Telemetry")), "off") {
		r.disableLocked()
		return
	}
	switch status {
	case http.StatusAccepted:
		r.removeSelectedLocked(selected)
		r.droppedSinceLast -= selected.dropped
		if r.droppedSinceLast < 0 {
			r.droppedSinceLast = 0
		}
		r.backoff = telemetryBackoffMin
		r.backoffUntil = time.Time{}
		r.applyPolicyLocked(body, now)
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusGone:
		r.disableLocked()
	case http.StatusRequestEntityTooLarge:
		r.removeSelectedLocked(selected)
		r.droppedSinceLast += len(selected.events) + len(selected.counters)
	default:
		retryAfter, hasRetryAfter := telemetryRetryAfter(headers)
		r.setBackoffLocked(now, retryAfter, hasRetryAfter)
	}
}

// flushOnce mirrors _flush_once: one POST, no retries. It reports whether
// the batch was accepted. ctx bounds the attempt (Close passes its deadline).
func (r *telemetryReporter) flushOnce(ctx context.Context) bool {
	r.flushMu.Lock()
	defer r.flushMu.Unlock()
	now := r.clock()
	r.mu.Lock()
	if r.disabled || now.Before(r.pausedUntil) || now.Before(r.backoffUntil) {
		r.mu.Unlock()
		return false
	}
	apiKey := r.apiKey
	r.mu.Unlock()
	if apiKey == "" {
		return false
	}
	r.mu.Lock()
	selected := r.selectBatchLocked(now)
	r.mu.Unlock()
	if selected == nil {
		return false
	}
	if r.debug {
		// A trust feature (§6.3): the exact bytes about to leave, on
		// stderr, before they leave.
		fmt.Fprintln(r.debugOut, "trustedrouter telemetry batch: "+string(selected.payload))
	}
	status, headers, body, err := r.post(ctx, apiKey, selected.payload)
	if err != nil {
		r.mu.Lock()
		r.setBackoffLocked(r.clock(), 0, false)
		r.mu.Unlock()
		return false
	}
	r.handleResponse(status, headers, body, r.clock(), selected)
	return status == http.StatusAccepted
}

// post is the beacon's single-shot sender. It follows the shape of
// absoluteRequest (transport.go) — one request, no candidate list, no retry,
// no recorder — but on the reporter's OWN client, and it is never traced:
// no x-tr-client, no idempotency key, nothing the engine adds.
func (r *telemetryReporter) post(ctx context.Context, apiKey string, payload []byte) (int, http.Header, []byte, error) {
	if len(payload) > telemetryMaxBatchBytes {
		return 0, nil, nil, fmt.Errorf("telemetry batch is %d bytes; maximum is %d", len(payload), telemetryMaxBatchBytes)
	}
	ctx, cancel := context.WithTimeout(ctx, telemetryHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.controlBaseURL+telemetryEventsPath, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("authorization", "Bearer "+apiKey)
	req.Header.Set("user-agent", userAgent())
	req.Header.Set("content-type", "application/json")
	if r.workspaceID != "" {
		req.Header.Set("x-trustedrouter-workspace", r.workspaceID)
	}
	resp, err := r.client().Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, telemetryMaxBatchBytes))
	return resp.StatusCode, resp.Header, body, nil
}

// flushNow synchronously attempts one flush; for deterministic tests.
func (r *telemetryReporter) flushNow() bool {
	return r.flushOnce(context.Background())
}

func (r *telemetryReporter) closeHTTPClient() {
	r.mu.Lock()
	client := r.httpClient
	r.httpClient = nil
	r.mu.Unlock()
	if client == nil {
		return
	}
	if closer, ok := client.Transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

// close mirrors TelemetryReporter.close: stop the worker, make one final
// flush attempt bounded by timeout, and wait for the worker no longer than
// the remaining budget. It returns within timeout even if a flush is still
// in flight.
func (r *telemetryReporter) close(timeout time.Duration) {
	if timeout < 0 {
		timeout = 0
	}
	started := time.Now()
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	workerDone := r.workerDone
	r.stopLocked()
	r.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	finalDone := make(chan struct{})
	go func() {
		defer close(finalDone)
		r.flushOnce(ctx)
		r.closeHTTPClient()
	}()
	select {
	case <-finalDone:
	case <-ctx.Done():
	}
	if workerDone == nil {
		return
	}
	remaining := timeout - time.Since(started)
	if remaining <= 0 {
		return
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case <-workerDone:
	case <-timer.C:
	}
}
