package trustedrouter

import (
	"math"
	"net/http"
	"testing"
	"time"
)

// Property tests for the Retry-After bound.
//
// Retry-After arrives from whatever answered the socket — the gateway, a proxy,
// an alias domain — so it is untrusted input, and it was applied as an
// *uncapped* floor on the backoff sleep. The law:
//
//	for every attempt a and every header set H over arbitrary strings,
//	    retryAfterSeconds(H)      is nil, or finite and in [0, MaxRetryAfterSeconds]
//	    retrySleepDuration(a, ..) is finite and in [0, MaxRetryAfterSeconds]
//
// Two Go-specific facts make this worse here than the same defect was in
// Python, and both were measured on go1.23.4 rather than assumed:
//
//	strconv.ParseFloat accepts far more than the RFC 7231 grammar — "inf",
//	"Inf", "infinity", "nan", and hex-float forms like "0x1p1000" all parse
//	with err == nil.
//
//	float64 -> time.Duration SATURATES rather than erroring. "inf" and "1e300"
//	both produced 2562047h47m16.854775807s — the maximum int64 nanosecond
//	count, a 292-year timer. There is no panic and no error to notice; the
//	client simply never retries again.
//
// A plain "100000" needed no exotic behaviour at all: it parked the caller for
// 27h46m40s per attempt.
//
// Mirrors tests/test_retry_after_bounds.py and test/retry-after-bounds.test.js.

const sleepCeiling = time.Duration(MaxRetryAfterSeconds * float64(time.Second))

func headersWith(name, value string) http.Header {
	h := http.Header{}
	h.Set(name, value)
	return h
}

// FuzzParsedHintIsAlwaysFiniteAndBounded is the parser half of the law.
func FuzzParsedHintIsAlwaysFiniteAndBounded(f *testing.F) {
	for _, seed := range []string{
		"inf", "Inf", "+Inf", "-inf", "infinity", "INFINITY", "nan", "NaN",
		"1e300", "1e309", "0x1p1000", "100000", "86400", "-5", "0", "30",
		"1_0", "", "   ", "30s", "Wed, 21 Oct 2015 07:28:00 GMT",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		for _, header := range []string{"Retry-After", "Retry-After-Ms"} {
			parsed := retryAfterSeconds(headersWith(header, raw))
			if parsed == nil {
				continue
			}
			if math.IsNaN(*parsed) || math.IsInf(*parsed, 0) {
				t.Fatalf("%s: %q produced a non-finite hint %v", header, raw, *parsed)
			}
			if *parsed < 0 || *parsed > MaxRetryAfterSeconds {
				t.Fatalf("%s: %q produced an unbounded hint %v", header, raw, *parsed)
			}
		}
	})
}

// FuzzSleepIsAlwaysBounded is the half that matters operationally: the value
// that actually reaches time.NewTimer. Quantifies over the attempt counter too,
// since the jitter base is exponential in it.
func FuzzSleepIsAlwaysBounded(f *testing.F) {
	f.Add("inf", 0)
	f.Add("1e300", 3)
	f.Add("100000", 0)
	f.Add("30", 10)
	f.Add("", 1000)

	f.Fuzz(func(t *testing.T, raw string, attempt int) {
		if attempt < 0 {
			attempt = -attempt
		}
		delay := retrySleepDuration(attempt, retryAfterSeconds(headersWith("Retry-After", raw)))
		if delay < 0 || delay > sleepCeiling {
			t.Fatalf("Retry-After %q at attempt %d produced sleep %v (ceiling %v)",
				raw, attempt, delay, sleepCeiling)
		}
	})
}

// TestTheHeadersThatUsedToParkOrStallACaller pins the concrete measured values
// alongside the general property.
func TestTheHeadersThatUsedToParkOrStallACaller(t *testing.T) {
	for _, raw := range []string{"inf", "Inf", "infinity", "nan", "-5"} {
		if got := retryAfterSeconds(headersWith("Retry-After", raw)); got != nil {
			t.Fatalf("Retry-After %q should be rejected, got %v", raw, *got)
		}
	}
	for _, tc := range []struct {
		raw  string
		want float64
	}{
		{"1e300", MaxRetryAfterSeconds},
		{"100000", MaxRetryAfterSeconds},
		{"86400", MaxRetryAfterSeconds},
		{"30", 30},
		{"0", 0},
	} {
		got := retryAfterSeconds(headersWith("Retry-After", tc.raw))
		if got == nil || *got != tc.want {
			t.Fatalf("Retry-After %q: got %v want %v", tc.raw, got, tc.want)
		}
	}
}

func TestSleepStaysBoundedForTheWorstHeaders(t *testing.T) {
	for _, raw := range []string{"inf", "1e300", "100000", "0x1p1000"} {
		delay := retrySleepDuration(0, retryAfterSeconds(headersWith("Retry-After", raw)))
		if delay > sleepCeiling {
			t.Fatalf("Retry-After %q produced %v, above the %v ceiling", raw, delay, sleepCeiling)
		}
	}
}

// TestRetrySleepDurationReclampsADirectHint covers the path that does not go
// through the parser at all.
func TestRetrySleepDurationReclampsADirectHint(t *testing.T) {
	for _, seconds := range []float64{
		math.Inf(1), math.Inf(-1), math.NaN(), 1e300, 1e9, 100000, -5, 0, 30,
	} {
		value := seconds
		delay := retrySleepDuration(0, &value)
		if delay < 0 || delay > sleepCeiling {
			t.Fatalf("direct hint %v produced sleep %v", seconds, delay)
		}
	}
}

// TestHintsWithinTheBoundAreHonouredExactly: the bound must not disturb the
// values it was not aimed at.
func TestHintsWithinTheBoundAreHonouredExactly(t *testing.T) {
	for _, seconds := range []float64{0, 0.25, 1, 30, MaxRetryAfterSeconds} {
		value := seconds
		bounded := boundedRetryAfter(value)
		if bounded == nil || *bounded != seconds {
			t.Fatalf("boundedRetryAfter(%v) = %v, want %v", seconds, bounded, seconds)
		}
		if delay := retrySleepDuration(0, &value); delay < time.Duration(seconds*float64(time.Second)) {
			t.Fatalf("hint %v was not honoured as a floor: got %v", seconds, delay)
		}
	}
}

// TestJunkMillisecondHeaderFallsThroughToSeconds preserves the original
// fall-through, now for non-finite values as well as negatives.
func TestJunkMillisecondHeaderFallsThroughToSeconds(t *testing.T) {
	for _, junk := range []string{"inf", "nan", "-5", "abc"} {
		h := http.Header{}
		h.Set("Retry-After-Ms", junk)
		h.Set("Retry-After", "7")
		got := retryAfterSeconds(h)
		if got == nil || *got != 7 {
			t.Fatalf("retry-after-ms %q should fall through to retry-after, got %v", junk, got)
		}
	}
}

func TestMillisecondHeaderStillWinsWhenUsable(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After-Ms", "1500")
	h.Set("Retry-After", "7")
	got := retryAfterSeconds(h)
	if got == nil || *got != 1.5 {
		t.Fatalf("retry-after-ms should win, got %v", got)
	}
}

// TestSleepCeilingStaysWellInsideDurationRange documents why saturation cannot
// resurface: the ceiling is nowhere near the int64 nanosecond limit.
func TestSleepCeilingStaysWellInsideDurationRange(t *testing.T) {
	if sleepCeiling >= time.Duration(math.MaxInt64) {
		t.Fatalf("ceiling %v is not comfortably inside time.Duration range", sleepCeiling)
	}
}
