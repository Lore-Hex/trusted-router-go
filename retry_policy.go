package trustedrouter

// retry_policy.go is the POLICY KERNEL (L1): pure decision functions with no
// I/O and no clock. Everything here answers a question about a status code and
// a header set; nothing here sends a request, advances a candidate, or sleeps
// (that is transport.go, the only place either happens).
//
// Invariants enforced by this file (each line names its enforcing test):
//
// (1) Failover set {502,503,504} ⊂ retry set {429, ≥500, verdict-true} —
// TestPinnedClientStillRetriesInPlace, TestA503AdvancesToTheNextCandidate.
// (2) 500 NEVER moves domains — a server processed the non-idempotent
// inference; re-sending elsewhere risks a second generation —
// TestA500DoesNotAdvanceToAnotherDomain.
// (4) x-should-retry overrides both predicates in both directions: explicit
// false forbids retry AND failover; explicit true forces retry;
// absent/unparseable keeps status heuristics —
// TestALabelledSpent502IsNotRetried,
// TestALabelledRetryableStatusIsRetriedEvenWhenTheStatusSaysOtherwise,
// TestShouldRetryVerdictOnlySpeaksWhenTheServerDid.
// (10) The verdict-false guard inside regionalFailoverable is deliberately
// unreachable from the transport engine (retryable() already returned false)
// — a documented surviving mutant, mirrored in trusted-router-py/swift; never
// "fixed", never tested.

import (
	"net/http"
	"strconv"
	"strings"
)

// shouldRetryVerdict reads the gateway's explicit x-should-retry instruction,
// which overrides every heuristic below it.
//
// A status code cannot say whether a provider already ran. A 502 from "could
// not reach the provider" and a 502 from "the generation succeeded and then
// settlement failed" are indistinguishable here, and only the second is
// dangerous to re-send. The gateway knows and now says so. Same header
// OpenAI's clients honour.
//
// Returns nil when the server did not say, which leaves existing behaviour
// untouched for older gateways and for paths deliberately left unlabelled.
func shouldRetryVerdict(headers http.Header) *bool {
	raw := strings.ToLower(strings.TrimSpace(headers.Get("X-Should-Retry")))
	switch raw {
	case "true":
		yes := true
		return &yes
	case "false":
		no := false
		return &no
	default:
		return nil
	}
}

func retryAfterSeconds(headers http.Header) *float64 {
	// retry-after-ms wins when both are present: it is the more precise of the
	// two, and a server that sends it means the sub-second value.
	if rawMS := strings.TrimSpace(headers.Get("Retry-After-Ms")); rawMS != "" {
		if millis, err := strconv.ParseFloat(rawMS, 64); err == nil && millis >= 0 {
			seconds := millis / 1000
			return &seconds
		}
	}
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

// retryable answers "may we send this again", independent of WHERE. It used to
// take regionalFailover and return it for 502/503/504, which conflated two
// separate questions: pinning to one host also silently stopped retrying the
// gateway statuses entirely. Now the flag governs only the destination.
func retryable(status int, headers http.Header) bool {
	if verdict := shouldRetryVerdict(headers); verdict != nil {
		return *verdict
	}
	return status == http.StatusTooManyRequests || status >= 500
}

// regionalFailoverable answers "may this move to a DIFFERENT domain".
//
// Only the gateway-level statuses {502, 503, 504}. A 500 means a server
// received and processed the request, and inference is not idempotent, so
// retrying it on another domain would run the work again: not a double charge
// to the caller, but a second upstream generation we pay for.
//
// An explicit x-should-retry: false forbids it outright — that is the gateway
// telling us a provider already ran, which is exactly when re-sending anywhere
// costs a second generation. (The transport engine consults this predicate
// only after retryable() said yes, so this guard is unreachable there; it is
// kept deliberately — see invariant 10 above.)
func regionalFailoverable(status int, headers http.Header) bool {
	if verdict := shouldRetryVerdict(headers); verdict != nil && !*verdict {
		return false
	}
	return status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}
