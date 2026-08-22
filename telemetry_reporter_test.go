package trustedrouter

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recordingTelemetrySink captures recorder output without starting a
// reporter worker. Recorder tests use snapshots so assertions remain safe
// when a response body is read or closed from another goroutine.
type recordingTelemetrySink struct {
	mu       sync.Mutex
	events   []telemetryRequestEvent
	counters [][]telemetryCounterIncrement
}

func (s *recordingTelemetrySink) onRequest(event telemetryRequestEvent, counters []telemetryCounterIncrement) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	s.counters = append(s.counters, counters)
}

func (s *recordingTelemetrySink) snapshot() ([]telemetryRequestEvent, [][]telemetryCounterIncrement) {
	s.mu.Lock()
	defer s.mu.Unlock()
	events := append([]telemetryRequestEvent(nil), s.events...)
	counters := make([][]telemetryCounterIncrement, len(s.counters))
	for i := range s.counters {
		counters[i] = append([]telemetryCounterIncrement(nil), s.counters[i]...)
	}
	return events, counters
}

func telemetryBool(value bool) *bool { return &value }

func telemetryInt(value int) *int { return &value }

func newEngineTelemetryClient(t *testing.T, engineURL string, sink telemetrySink) *Client {
	t.Helper()
	client, err := NewClient(Options{
		APIKey:         "sk-test",
		BaseURL:        engineURL,
		Telemetry:      telemetryBool(true),
		MaxRetries:     telemetryInt(0),
		ControlBaseURL: "http://127.0.0.1.invalid",
	})
	if err != nil {
		t.Fatal(err)
	}
	client.telemetrySink = sink
	return client
}

func writeChatSSE(w http.ResponseWriter, frames ...string) {
	w.Header().Set("content-type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	for _, frame := range frames {
		_, _ = io.WriteString(w, "data: "+frame+"\n\n")
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}
}

func oneChatChunkRequest() ChatRequest {
	return ChatRequest{
		Model:    "trustedrouter/auto",
		Messages: []map[string]any{{"role": "user", "content": "not telemetry"}},
	}
}

func TestTelemetryStreamFirstItemRecordsTTFT(t *testing.T) {
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeChatSSE(w, `{"id":"chunk-1","choices":[]}`, "[DONE]")
	}))
	defer engine.Close()

	sink := &recordingTelemetrySink{}
	client := newEngineTelemetryClient(t, engine.URL, sink)
	for _, err := range client.ChatCompletionsChunks(context.Background(), oneChatChunkRequest()) {
		if err != nil {
			t.Fatal(err)
		}
	}
	events, _ := sink.snapshot()
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if !events[0].hasTTFT {
		t.Fatal("first SSE item did not record ttft_ms")
	}
	if events[0].ttftMS < 0 || events[0].ttftMS > events[0].totalMS {
		t.Fatalf("ttft_ms = %d, total_ms = %d", events[0].ttftMS, events[0].totalMS)
	}
	if events[0].finalOutcome != "ok" {
		t.Fatalf("final_outcome = %q, want ok", events[0].finalOutcome)
	}
}

func TestTelemetryStreamMidBodyErrorRecordsStreamBroken(t *testing.T) {
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "text/event-stream")
		w.Header().Set("content-length", "4096")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "data: {\"id\":\"chunk-1\",\"choices\":[]}\n\n")
		w.(http.Flusher).Flush()
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("httptest response writer cannot hijack")
			return
		}
		conn, _, err := hijacker.Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = conn.Close()
	}))
	defer engine.Close()

	sink := &recordingTelemetrySink{}
	client := newEngineTelemetryClient(t, engine.URL, sink)
	var streamErr error
	for _, err := range client.ChatCompletionsChunks(context.Background(), oneChatChunkRequest()) {
		if err != nil {
			streamErr = err
			break
		}
	}
	if streamErr == nil {
		t.Fatal("truncated response did not surface a stream error")
	}
	events, _ := sink.snapshot()
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if events[0].finalOutcome != "stream_broken" {
		t.Fatalf("final_outcome = %q, want stream_broken", events[0].finalOutcome)
	}
	if got := events[0].attempts[len(events[0].attempts)-1].outcome; got != "stream_broken" {
		t.Fatalf("attempt outcome = %q, want stream_broken", got)
	}
}

func TestTelemetryStreamCallerStopRecordsAborted(t *testing.T) {
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeChatSSE(w,
			`{"id":"chunk-1","choices":[]}`,
			`{"id":"chunk-2","choices":[]}`,
			"[DONE]",
		)
	}))
	defer engine.Close()

	sink := &recordingTelemetrySink{}
	client := newEngineTelemetryClient(t, engine.URL, sink)
	for _, err := range client.ChatCompletionsChunks(context.Background(), oneChatChunkRequest()) {
		if err != nil {
			t.Fatal(err)
		}
		break
	}
	events, _ := sink.snapshot()
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if events[0].finalOutcome != "aborted" {
		t.Fatalf("final_outcome = %q, want aborted", events[0].finalOutcome)
	}
}

func TestTelemetryRecorderCountersMatchRetrySequence(t *testing.T) {
	var calls atomic.Int32
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.Header().Set("x-request-id", "rlog_0123456789abcdef0123456789abcdef")
		if calls.Add(1) == 1 {
			w.Header().Set("x-should-retry", "true")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"error":{"message":"retry"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":[]}`)
	}))
	defer engine.Close()

	sink := &recordingTelemetrySink{}
	client := newEngineTelemetryClient(t, engine.URL, sink)
	client.maxRetries = 1
	var out map[string]any
	if err := client.Request(context.Background(), http.MethodGet, "/models", nil, &out, nil); err != nil {
		t.Fatal(err)
	}
	events, batches := sink.snapshot()
	if len(events) != 1 || len(batches) != 1 {
		t.Fatalf("events/counter batches = %d/%d, want 1/1", len(events), len(batches))
	}
	if len(events[0].attempts) != 2 || events[0].finalOutcome != "ok" {
		t.Fatalf("event attempts/final = %d/%q, want 2/ok", len(events[0].attempts), events[0].finalOutcome)
	}
	wantKeys := []telemetryCounterKey{
		{level: "request", endpoint: "models", host: "custom", outcome: "ok", httpStatusClass: "2xx", timeoutPhase: "none"},
		{level: "attempt", endpoint: "models", host: "custom", outcome: "http_error", httpStatusClass: "5xx", timeoutPhase: "none"},
		{level: "attempt", endpoint: "models", host: "custom", outcome: "ok", httpStatusClass: "2xx", timeoutPhase: "none"},
	}
	if len(batches[0]) != len(wantKeys) {
		t.Fatalf("counter rows = %d, want %d", len(batches[0]), len(wantKeys))
	}
	for i, want := range wantKeys {
		if got := batches[0][i].key; got != want {
			t.Errorf("counter[%d] key = %#v, want %#v", i, got, want)
		}
	}
	request := batches[0][0]
	if request.requests != 1 || request.attempts != 2 || request.failoverUsed != 0 || request.firstAttemptSuccess != 0 {
		t.Errorf("request counts = (%d,%d,%d,%d), want (1,2,0,0)", request.requests, request.attempts, request.failoverUsed, request.firstAttemptSuccess)
	}
	for i, increment := range batches[0][1:] {
		if increment.requests != 1 || increment.attempts != 1 || increment.failoverUsed != 0 || increment.firstAttemptSuccess != 0 {
			t.Errorf("attempt counter[%d] counts = (%d,%d,%d,%d), want (1,1,0,0)", i, increment.requests, increment.attempts, increment.failoverUsed, increment.firstAttemptSuccess)
		}
	}
	if len(request.totalMSHist) != 1 {
		t.Fatalf("total_ms_hist = %#v, want one observation", request.totalMSHist)
	}
}

func TestTelemetryRecorderRejectsNonSchemaMethods(t *testing.T) {
	sink := &recordingTelemetrySink{}
	recorder := newRequestRecorder(sink, telemetryRequestFacts{endpoint: "models", method: http.MethodPut}, false, 0, false)
	recorder.beginAttempt(DefaultAPIBaseURL)
	recorder.onResponse(http.StatusOK, nil)
	recorder.finish()
	events, counters := sink.snapshot()
	if len(events) != 0 || len(counters) != 0 {
		t.Fatalf("PUT emitted %d events and %d counter batches; schema permits only GET/POST", len(events), len(counters))
	}
}

type atomicTelemetryClock struct {
	nanos atomic.Int64
}

func newAtomicTelemetryClock(now time.Time) *atomicTelemetryClock {
	clock := &atomicTelemetryClock{}
	clock.Set(now)
	return clock
}

func (c *atomicTelemetryClock) Now() time.Time {
	return time.Unix(0, c.nanos.Load())
}

func (c *atomicTelemetryClock) Set(now time.Time) {
	c.nanos.Store(now.UnixNano())
}

func (c *atomicTelemetryClock) Advance(duration time.Duration) {
	c.nanos.Add(int64(duration))
}

func validTelemetryEvent(outcome string) telemetryRequestEvent {
	status := http.StatusServiceUnavailable
	errorClass := "connect_error"
	if outcome == "ok" {
		status = http.StatusOK
		errorClass = ""
	}
	return telemetryRequestEvent{
		endpoint:        "models",
		method:          http.MethodGet,
		attempts:        []telemetryAttempt{{index: 0, host: "apex", outcome: outcome, httpStatus: status, errorClass: errorClass, elapsedMS: 10, phase: "none"}},
		finalOutcome:    outcome,
		finalHTTPStatus: status,
		totalMS:         10,
		timeoutPhase:    "none",
	}
}

func validTelemetryCounter(outcome string) telemetryCounterIncrement {
	status := "5xx"
	if outcome == "ok" {
		status = "2xx"
	}
	return telemetryCounterIncrement{
		key: telemetryCounterKey{
			level:           "request",
			endpoint:        "models",
			host:            "apex",
			outcome:         outcome,
			httpStatusClass: status,
			timeoutPhase:    "none",
		},
		requests:    1,
		attempts:    1,
		totalMSHist: map[string]int{"lt100": 1},
	}
}

func newReporterForTest(controlURL string, clock *atomicTelemetryClock) *telemetryReporter {
	reporter := newTelemetryReporter(controlURL, "sk-test", "workspace-test", telemetrySDKIdentity(), 0.5)
	reporter.flushInterval = time.Hour
	if clock != nil {
		reporter.clock = clock.Now
	}
	return reporter
}

func stopReporterForTest(t *testing.T, reporter *telemetryReporter) {
	t.Helper()
	reporter.mu.Lock()
	reporter.closed = true
	reporter.stopLocked()
	done := reporter.workerDone
	reporter.mu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("telemetry worker did not stop")
		}
	}
	reporter.closeHTTPClient()
}

func TestTelemetryReporterSamplesSuccessesButAlwaysKeepsFailures(t *testing.T) {
	reporter := newReporterForTest("http://127.0.0.1.invalid", nil)
	defer stopReporterForTest(t, reporter)
	draws := []float64{0.75, 0.25}
	var drawIndex int
	reporter.random = func() float64 {
		draw := draws[drawIndex]
		drawIndex++
		return draw
	}

	reporter.onRequest(validTelemetryEvent("ok"), []telemetryCounterIncrement{validTelemetryCounter("ok")})
	reporter.onRequest(validTelemetryEvent("http_error"), []telemetryCounterIncrement{validTelemetryCounter("http_error")})
	reporter.onRequest(validTelemetryEvent("ok"), []telemetryCounterIncrement{validTelemetryCounter("ok")})

	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.events) != 2 {
		t.Fatalf("sampled events = %d, want failure plus one sampled success", len(reporter.events))
	}
	if reporter.events[0].wire.SampleReason != "failure" || reporter.events[0].wire.SampleRate != 1 {
		t.Errorf("failure sampling = %q/%v, want failure/1", reporter.events[0].wire.SampleReason, reporter.events[0].wire.SampleRate)
	}
	if reporter.events[1].wire.SampleReason != "random" || reporter.events[1].wire.SampleRate != 0.5 {
		t.Errorf("success sampling = %q/%v, want random/0.5", reporter.events[1].wire.SampleReason, reporter.events[1].wire.SampleRate)
	}
	rows := reporter.current.rows
	if rows[validTelemetryCounter("ok").key].requests != 2 || rows[validTelemetryCounter("http_error").key].requests != 1 {
		t.Fatal("exact counters were sampled with the diagnostic events")
	}
}

func TestTelemetryReporterDropsOldestSuccessAtEventBound(t *testing.T) {
	reporter := newReporterForTest("http://127.0.0.1.invalid", nil)
	failure, _ := telemetryWireEventFrom(validTelemetryEvent("http_error"), 1, "failure", 0)
	success, _ := telemetryWireEventFrom(validTelemetryEvent("ok"), 1, "random", 0)
	reporter.mu.Lock()
	reporter.appendEventLocked(&telemetryBufferedEvent{wire: failure, estimatedBytes: 10})
	reporter.appendEventLocked(&telemetryBufferedEvent{wire: success, estimatedBytes: 10})
	for i := 2; i < telemetryMaxEvents; i++ {
		reporter.appendEventLocked(&telemetryBufferedEvent{wire: failure, estimatedBytes: 10})
	}
	reporter.appendEventLocked(&telemetryBufferedEvent{wire: failure, estimatedBytes: 10})
	defer reporter.mu.Unlock()
	if len(reporter.events) != telemetryMaxEvents {
		t.Fatalf("events = %d, want %d", len(reporter.events), telemetryMaxEvents)
	}
	if reporter.droppedSinceLast != 1 {
		t.Fatalf("dropped_since_last = %d, want 1", reporter.droppedSinceLast)
	}
	for _, event := range reporter.events {
		if event.wire.FinalOutcome == "ok" {
			t.Fatal("oldest success was not preferred for eviction")
		}
	}
}

func TestTelemetryReporterCounterFoldLadderKeepsExactCounts(t *testing.T) {
	reporter := newReporterForTest("http://127.0.0.1.invalid", nil)
	errorBase := telemetryCounterKey{level: "request", endpoint: "models", host: "apex", outcome: "http_error", errorClass: "dns", httpStatusClass: "5xx", timeoutPhase: "none"}
	endpointBase := telemetryCounterKey{level: "request", endpoint: "models", streaming: true, host: "ally", outcome: "http_error", errorClass: "dns", httpStatusClass: "4xx", timeoutPhase: "none"}
	newError := errorBase
	newError.errorClass = "tls"
	newEndpoint := endpointBase
	newEndpoint.endpoint = "responses"
	newEndpoint.errorClass = "tls"
	arbitrary := telemetryCounterKey{level: "attempt", endpoint: "fusion", streaming: true, host: "control", outcome: "aborted", errorClass: "reset", httpStatusClass: "none", timeoutPhase: "total", timeoutFloorMet: true, providerPinned: true}

	reporter.mu.Lock()
	reporter.mergeCountersLocked([]telemetryCounterIncrement{{key: errorBase, requests: 3}, {key: endpointBase, requests: 5}})
	levels := []string{"attempt", "request"}
	endpoints := telemetryEndpoints
	hosts := telemetryHosts
	outcomes := telemetryOutcomes
	errorClasses := append([]string{""}, telemetryErrorClasses...)
	statuses := telemetryHTTPStatusClasses
	phases := telemetryTimeoutPhases
fill:
	for _, level := range levels {
		for _, endpoint := range endpoints {
			for _, host := range hosts {
				for _, outcome := range outcomes {
					for _, errorClass := range errorClasses {
						for _, status := range statuses {
							for _, phase := range phases {
								candidate := telemetryCounterKey{level: level, endpoint: endpoint, host: host, outcome: outcome, errorClass: errorClass, httpStatusClass: status, timeoutPhase: phase}
								if telemetryKeysMatchExceptErrorClass(candidate, newError) || telemetryKeysMatchExceptEndpointAndErrorClass(candidate, newEndpoint) || telemetryKeysMatchExceptErrorClass(candidate, arbitrary) || telemetryKeysMatchExceptEndpointAndErrorClass(candidate, arbitrary) {
									continue
								}
								if _, exists := reporter.current.get(candidate); exists {
									continue
								}
								reporter.mergeCountersLocked([]telemetryCounterIncrement{{key: candidate, requests: 1}})
								if reporter.current.size() == telemetryMaxWindowKeys {
									break fill
								}
							}
						}
					}
				}
			}
		}
	}
	if reporter.current.size() != telemetryMaxWindowKeys {
		reporter.mu.Unlock()
		t.Fatalf("filled %d counter keys, want %d", reporter.current.size(), telemetryMaxWindowKeys)
	}
	reporter.mergeCountersLocked([]telemetryCounterIncrement{{key: newError, requests: 7}})
	errorFolded := telemetryFoldedCounterKey(errorBase, false)
	if value, ok := reporter.current.get(errorFolded); !ok || value.requests != 10 {
		reporter.mu.Unlock()
		t.Fatalf("error fold requests = %v/%v, want 10/true", value, ok)
	}
	reporter.mergeCountersLocked([]telemetryCounterIncrement{{key: newEndpoint, requests: 11}})
	endpointFolded := telemetryFoldedCounterKey(endpointBase, true)
	if value, ok := reporter.current.get(endpointFolded); !ok || value.requests != 16 {
		reporter.mu.Unlock()
		t.Fatalf("endpoint fold requests = %v/%v, want 16/true", value, ok)
	}
	first := reporter.current.first()
	before := reporter.current.rows[first].requests
	reporter.mergeCountersLocked([]telemetryCounterIncrement{{key: arbitrary, requests: 13}})
	after := reporter.current.rows[first].requests
	dropped := reporter.droppedSinceLast
	size := reporter.current.size()
	reporter.mu.Unlock()
	if after != before+13 {
		t.Fatalf("arbitrary fallback requests = %d, want %d", after, before+13)
	}
	if size != telemetryMaxWindowKeys || dropped != 0 {
		t.Fatalf("folded size/dropped = %d/%d, want %d/0", size, dropped, telemetryMaxWindowKeys)
	}
}

func TestTelemetryReporterRetainsWindowAcrossFailedFlush(t *testing.T) {
	var posts atomic.Int32
	beacon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer beacon.Close()
	clock := newAtomicTelemetryClock(time.Now().Truncate(time.Minute))
	reporter := newReporterForTest(beacon.URL, clock)
	defer stopReporterForTest(t, reporter)
	reporter.onRequest(validTelemetryEvent("http_error"), []telemetryCounterIncrement{validTelemetryCounter("http_error")})
	if reporter.flushNow() {
		t.Fatal("503 flush reported success")
	}
	clock.Advance(23*time.Hour + 59*time.Minute)
	reporter.mu.Lock()
	reporter.pruneWindowsLocked(clock.Now())
	windows := len(reporter.closedWindows)
	rows := 0
	if windows != 0 {
		rows = reporter.closedWindows[0].rows.size()
	}
	reporter.mu.Unlock()
	if posts.Load() != 1 {
		t.Fatalf("posts = %d, want one single-shot attempt", posts.Load())
	}
	if windows != 1 || rows != 1 {
		t.Fatalf("retained windows/rows = %d/%d, want 1/1", windows, rows)
	}
}

func TestTelemetryReporter429BackoffHonorsRetryAfter(t *testing.T) {
	var posts atomic.Int32
	beacon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if posts.Add(1) == 1 {
			w.Header().Set("retry-after", "120")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer beacon.Close()
	start := time.Now().Truncate(time.Second)
	clock := newAtomicTelemetryClock(start)
	reporter := newReporterForTest(beacon.URL, clock)
	defer stopReporterForTest(t, reporter)
	reporter.onRequest(validTelemetryEvent("http_error"), []telemetryCounterIncrement{validTelemetryCounter("http_error")})
	if reporter.flushNow() {
		t.Fatal("429 flush reported success")
	}
	reporter.mu.Lock()
	backoffUntil := reporter.backoffUntil
	nextBackoff := reporter.backoff
	reporter.mu.Unlock()
	if !backoffUntil.Equal(start.Add(120 * time.Second)) {
		t.Fatalf("backoff_until = %v, want %v", backoffUntil, start.Add(120*time.Second))
	}
	if nextBackoff != 120*time.Second {
		t.Fatalf("next exponential backoff = %v, want 2m", nextBackoff)
	}
	if reporter.flushNow() || posts.Load() != 1 {
		t.Fatalf("flush during backoff sent a request; posts = %d", posts.Load())
	}
	clock.Advance(120 * time.Second)
	if !reporter.flushNow() {
		t.Fatal("flush after Retry-After was not accepted")
	}
	if posts.Load() != 2 {
		t.Fatalf("posts = %d, want 2", posts.Load())
	}
}

func TestTelemetryReporterBadRequestDisablesProcess(t *testing.T) {
	beacon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer beacon.Close()
	reporter := newReporterForTest(beacon.URL, nil)
	defer stopReporterForTest(t, reporter)
	reporter.onRequest(validTelemetryEvent("http_error"), []telemetryCounterIncrement{validTelemetryCounter("http_error")})
	reporter.flushNow()
	reporter.mu.Lock()
	disabled := reporter.disabled
	empty := len(reporter.events) == 0 && reporter.current.size() == 0 && len(reporter.closedWindows) == 0
	reporter.mu.Unlock()
	if !disabled || !empty {
		t.Fatalf("disabled/empty = %t/%t, want true/true", disabled, empty)
	}
}

func TestTelemetryReporterKillSwitchDisablesProcess(t *testing.T) {
	beacon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("x-tr-telemetry", " off ")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer beacon.Close()
	reporter := newReporterForTest(beacon.URL, nil)
	defer stopReporterForTest(t, reporter)
	reporter.onRequest(validTelemetryEvent("http_error"), []telemetryCounterIncrement{validTelemetryCounter("http_error")})
	reporter.flushNow()
	reporter.mu.Lock()
	disabled := reporter.disabled
	reporter.mu.Unlock()
	if !disabled {
		t.Fatal("x-tr-telemetry: off did not disable the reporter")
	}
}

func TestTelemetryReporterPolicyOnlyReducesVolume(t *testing.T) {
	var posts atomic.Int32
	beacon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		if posts.Add(1) == 1 {
			_, _ = io.WriteString(w, `{"policy":{"success_sample_rate":0.9,"flush_seconds":10,"pause_seconds":5}}`)
			return
		}
		_, _ = io.WriteString(w, `{"policy":{"success_sample_rate":0.1,"flush_seconds":60,"pause_seconds":90000}}`)
	}))
	defer beacon.Close()
	start := time.Now().Truncate(time.Second)
	clock := newAtomicTelemetryClock(start)
	reporter := newReporterForTest(beacon.URL, clock)
	reporter.flushInterval = 30 * time.Second
	defer stopReporterForTest(t, reporter)
	reporter.onRequest(validTelemetryEvent("http_error"), []telemetryCounterIncrement{validTelemetryCounter("http_error")})
	if !reporter.flushNow() {
		t.Fatal("first policy response was not accepted")
	}
	reporter.mu.Lock()
	firstRate, firstInterval, pausedUntil := reporter.successSampleRate, reporter.flushInterval, reporter.pausedUntil
	reporter.mu.Unlock()
	if firstRate != 0.5 || firstInterval != 30*time.Second || !pausedUntil.Equal(start.Add(5*time.Second)) {
		t.Fatalf("expansive policy changed rate/interval/pause to %v/%v/%v", firstRate, firstInterval, pausedUntil)
	}
	clock.Advance(5 * time.Second)
	reporter.onRequest(validTelemetryEvent("http_error"), []telemetryCounterIncrement{validTelemetryCounter("http_error")})
	if !reporter.flushNow() {
		t.Fatal("second policy response was not accepted")
	}
	reporter.mu.Lock()
	secondRate, secondInterval, secondPause := reporter.successSampleRate, reporter.flushInterval, reporter.pausedUntil
	reporter.mu.Unlock()
	if secondRate != 0.1 || secondInterval != 60*time.Second {
		t.Fatalf("reducing policy produced rate/interval %v/%v, want 0.1/1m", secondRate, secondInterval)
	}
	if !secondPause.Equal(pausedUntil) {
		t.Fatalf("out-of-range pause changed paused_until to %v, want %v", secondPause, pausedUntil)
	}
}

func TestTelemetryReporterCloseFlushIsDeadlineBounded(t *testing.T) {
	requestStarted := make(chan struct{}, 1)
	release := make(chan struct{})
	beacon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestStarted <- struct{}{}
		<-release
	}))
	defer beacon.Close()
	reporter := newReporterForTest(beacon.URL, nil)
	reporter.onRequest(validTelemetryEvent("http_error"), []telemetryCounterIncrement{validTelemetryCounter("http_error")})
	started := time.Now()
	reporter.close(100 * time.Millisecond)
	elapsed := time.Since(started)
	close(release)
	if elapsed > 500*time.Millisecond {
		t.Fatalf("close took %v, want a 100ms-bounded flush", elapsed)
	}
	select {
	case <-requestStarted:
	default:
		t.Fatal("close did not attempt a final flush")
	}
}

func TestTelemetryReporterRefusesOversizePayloadBeforeNetwork(t *testing.T) {
	var posts atomic.Int32
	beacon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer beacon.Close()
	reporter := newReporterForTest(beacon.URL, nil)
	defer stopReporterForTest(t, reporter)
	payload := make([]byte, telemetryMaxBatchBytes+1)
	_, _, _, err := reporter.post(context.Background(), "sk-test", payload)
	if err == nil {
		t.Fatal("65,537-byte payload was accepted by sender")
	}
	if posts.Load() != 0 {
		t.Fatalf("oversize payload reached network %d times", posts.Load())
	}
}

type trackingRoundTripper struct {
	base  http.RoundTripper
	mu    sync.Mutex
	paths []string
}

func (t *trackingRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.paths = append(t.paths, request.URL.Path)
	t.mu.Unlock()
	return t.base.RoundTrip(request)
}

func (t *trackingRoundTripper) snapshot() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.paths...)
}

type capturedBeacon struct {
	path    string
	headers http.Header
	body    []byte
}

func sortedJSONKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func assertJSONKeys(t *testing.T, object map[string]any, want ...string) {
	t.Helper()
	sort.Strings(want)
	if got := sortedJSONKeys(object); !reflect.DeepEqual(got, want) {
		t.Fatalf("JSON keys = %v, want %v", got, want)
	}
}

func jsonObjects(t *testing.T, value any) []map[string]any {
	t.Helper()
	items, ok := value.([]any)
	if !ok {
		t.Fatalf("JSON value has type %T, want array", value)
	}
	objects := make([]map[string]any, 0, len(items))
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("JSON array item has type %T, want object", item)
		}
		objects = append(objects, object)
	}
	return objects
}

func TestTelemetryBeaconUsesOwnClientAndSerializesOnlySchemaFields(t *testing.T) {
	const promptSecret = "PROMPT_MUST_NEVER_ENTER_TELEMETRY_7f31"
	captured := make(chan capturedBeacon, 1)
	beacon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		captured <- capturedBeacon{path: r.URL.Path, headers: r.Header.Clone(), body: body}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer beacon.Close()
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.Header().Set("x-request-id", "rlog_0123456789abcdef0123456789abcdef")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":{"message":"invalid key","source":"router"}}`)
	}))
	defer engine.Close()

	tracking := &trackingRoundTripper{base: http.DefaultTransport}
	client, err := NewClient(Options{
		APIKey:         "sk-integration",
		WorkspaceID:    "workspace-integration",
		BaseURL:        engine.URL,
		ControlBaseURL: beacon.URL,
		HTTPClient:     &http.Client{Transport: tracking},
		Telemetry:      telemetryBool(true),
		MaxRetries:     telemetryInt(0),
	})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	err = client.Request(context.Background(), http.MethodPost, "/chat/completions", map[string]any{
		"model":    "trustedrouter/auto",
		"messages": []map[string]any{{"role": "user", "content": promptSecret}},
	}, &out, nil)
	if err == nil {
		t.Fatal("engine 401 was not surfaced")
	}
	if closeErr := client.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	var sent capturedBeacon
	select {
	case sent = <-captured:
	case <-time.After(time.Second):
		t.Fatal("Close did not flush telemetry")
	}
	if sent.path != "/client-events" {
		t.Fatalf("beacon path = %q, want /client-events", sent.path)
	}
	if sent.headers.Get("authorization") != "Bearer sk-integration" || sent.headers.Get("x-trustedrouter-workspace") != "workspace-integration" {
		t.Fatalf("beacon auth/workspace headers = %q/%q", sent.headers.Get("authorization"), sent.headers.Get("x-trustedrouter-workspace"))
	}
	if sent.headers.Get("content-type") != "application/json" || sent.headers.Get("user-agent") != userAgent() {
		t.Fatalf("beacon content-type/user-agent = %q/%q", sent.headers.Get("content-type"), sent.headers.Get("user-agent"))
	}
	if len(sent.body) > telemetryMaxBatchBytes {
		t.Fatalf("batch bytes = %d, exceeds %d", len(sent.body), telemetryMaxBatchBytes)
	}
	for _, forbidden := range []string{promptSecret, engine.URL, strings.TrimPrefix(engine.URL, "http://"), "idempotency"} {
		if strings.Contains(string(sent.body), forbidden) {
			t.Fatalf("batch contains forbidden value %q: %s", forbidden, sent.body)
		}
	}
	paths := tracking.snapshot()
	if !reflect.DeepEqual(paths, []string{"/chat/completions"}) {
		t.Fatalf("user transport paths = %v; beacon must use its own client", paths)
	}

	var batch map[string]any
	if err := json.Unmarshal(sent.body, &batch); err != nil {
		t.Fatal(err)
	}
	assertJSONKeys(t, batch, "schema_version", "batch_id", "instance_id", "seq", "sent_at_ms", "sdk", "synthetic", "dropped_since_last", "events", "counters")
	sdk, ok := batch["sdk"].(map[string]any)
	if !ok {
		t.Fatalf("sdk has type %T", batch["sdk"])
	}
	assertJSONKeys(t, sdk, "name", "version", "lang", "runtime", "os", "arch")
	events := jsonObjects(t, batch["events"])
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	assertJSONKeys(t, events[0], "age_ms", "plane", "endpoint", "method", "streaming", "provider_pinned", "model", "attempts", "final_outcome", "final_http_status", "total_ms", "ttft_ms", "failover_used", "timeout_phase", "configured_timeout_ms", "sample_rate", "sample_reason")
	attempts := jsonObjects(t, events[0]["attempts"])
	if len(attempts) != 1 {
		t.Fatalf("attempts = %d, want 1", len(attempts))
	}
	assertJSONKeys(t, attempts[0], "index", "host", "outcome", "http_status", "error_class", "error_source", "retry_after_ms", "elapsed_ms", "ttfb_ms", "request_id", "moved")
	if attempts[0]["host"] != "custom" || attempts[0]["request_id"] != "rlog_0123456789abcdef0123456789abcdef" {
		t.Fatalf("attempt host/request_id = %v/%v", attempts[0]["host"], attempts[0]["request_id"])
	}
	if events[0]["final_outcome"] != "http_error" || events[0]["sample_reason"] != "failure" {
		t.Fatalf("event final/sample = %v/%v", events[0]["final_outcome"], events[0]["sample_reason"])
	}
	counters := jsonObjects(t, batch["counters"])
	if len(counters) != 2 {
		t.Fatalf("counters = %d, want request + attempt", len(counters))
	}
	for _, counter := range counters {
		assertJSONKeys(t, counter, "window_start_age_ms", "level", "endpoint", "streaming", "host", "outcome", "error_class", "http_status_class", "timeout_phase", "timeout_floor_met", "provider_pinned", "requests", "attempts", "failover_used", "first_attempt_success", "total_ms_hist", "first_event_ms_hist")
	}
}

func TestTelemetryOptOutCreatesNoReporterOrWorker(t *testing.T) {
	var beaconPosts atomic.Int32
	beacon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		beaconPosts.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer beacon.Close()
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = io.WriteString(w, `{"data":[]}`)
	}))
	defer engine.Close()
	client, err := NewClient(Options{APIKey: "sk-test", BaseURL: engine.URL, ControlBaseURL: beacon.URL, Telemetry: telemetryBool(false)})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := client.Request(context.Background(), http.MethodGet, "/models", nil, &out, nil); err != nil {
		t.Fatal(err)
	}
	if client.telemetryReporter != nil || client.telemetrySink != nil {
		t.Fatal("opted-out request created a reporter or sink")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if beaconPosts.Load() != 0 {
		t.Fatalf("opted-out client sent %d beacons", beaconPosts.Load())
	}
}

func TestTelemetryBatchSelectionCapsItemsAndBytes(t *testing.T) {
	now := time.Now().Truncate(time.Minute)
	wire, ok := telemetryWireEventFrom(validTelemetryEvent("http_error"), 1, "failure", 0)
	if !ok {
		t.Fatal("valid event did not serialize")
	}
	eventReporter := newReporterForTest("http://127.0.0.1.invalid", nil)
	eventReporter.mu.Lock()
	for i := 0; i < 150; i++ {
		eventReporter.appendEventLocked(&telemetryBufferedEvent{wire: wire, completedAt: now, estimatedBytes: 600})
	}
	eventSelection := eventReporter.selectBatchLocked(now.Add(time.Second))
	eventReporter.mu.Unlock()
	if eventSelection == nil {
		t.Fatal("event-only reporter selected no batch")
	}
	var eventBatch telemetryWireBatch
	if err := json.Unmarshal(eventSelection.payload, &eventBatch); err != nil {
		t.Fatal(err)
	}
	if len(eventBatch.Events) != 100 || len(eventBatch.Counters) != 0 || len(eventSelection.payload) > 65_536 {
		t.Fatalf("event batch events/counters/bytes = %d/%d/%d, want 100/0/<=65536", len(eventBatch.Events), len(eventBatch.Counters), len(eventSelection.payload))
	}

	counterReporter := newReporterForTest("http://127.0.0.1.invalid", nil)
	counterReporter.mu.Lock()
	counterReporter.windowStart = now
	counterReporter.hasWindow = true
	for i := 0; i < 250; i++ {
		key := telemetryCounterKey{
			level:           "attempt",
			endpoint:        telemetryEndpoints[i%len(telemetryEndpoints)],
			streaming:       i%2 == 0,
			host:            telemetryHosts[(i/2)%len(telemetryHosts)],
			outcome:         telemetryOutcomes[(i/16)%len(telemetryOutcomes)],
			errorClass:      telemetryErrorClasses[(i/96)%len(telemetryErrorClasses)],
			httpStatusClass: telemetryHTTPStatusClasses[(i/7)%len(telemetryHTTPStatusClasses)],
			timeoutPhase:    telemetryTimeoutPhases[(i/11)%len(telemetryTimeoutPhases)],
			providerPinned:  i%3 == 0,
		}
		counterReporter.mergeCountersLocked([]telemetryCounterIncrement{{key: key, requests: 1, attempts: 1}})
	}
	counterSelection := counterReporter.selectBatchLocked(now.Add(time.Second))
	counterReporter.mu.Unlock()
	if counterSelection == nil {
		t.Fatal("counter-only reporter selected no batch")
	}
	var counterBatch telemetryWireBatch
	if err := json.Unmarshal(counterSelection.payload, &counterBatch); err != nil {
		t.Fatal(err)
	}
	if len(counterBatch.Events) != 0 || len(counterBatch.Counters) == 0 || len(counterBatch.Counters) > 200 || len(counterSelection.payload) > 65_536 {
		t.Fatalf("counter batch events/counters/bytes = %d/%d/%d, want 0/1..200/<=65536", len(counterBatch.Events), len(counterBatch.Counters), len(counterSelection.payload))
	}
}

func TestTelemetryReporter413DropsSelectedBatch(t *testing.T) {
	beacon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	}))
	defer beacon.Close()
	reporter := newReporterForTest(beacon.URL, nil)
	defer stopReporterForTest(t, reporter)
	reporter.onRequest(validTelemetryEvent("http_error"), []telemetryCounterIncrement{validTelemetryCounter("http_error")})
	reporter.flushNow()
	reporter.mu.Lock()
	events, windows, dropped := len(reporter.events), len(reporter.closedWindows), reporter.droppedSinceLast
	reporter.mu.Unlock()
	if events != 0 || windows != 0 || dropped != 2 {
		t.Fatalf("after 413 events/windows/dropped = %d/%d/%d, want 0/0/2", events, windows, dropped)
	}
}
