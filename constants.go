package trustedrouter

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// DefaultAPIBaseURL is the default OpenAI-compatible TrustedRouter API base URL.
const DefaultAPIBaseURL = "https://api.quillrouter.com/v1"

// DefaultTrustReleaseURL is the default public trust-release metadata URL.
const DefaultTrustReleaseURL = "https://trust.trustedrouter.com/trust/gcp-release.json"

// DefaultStatusURL is the default TrustedRouter status document URL.
const DefaultStatusURL = "https://status.trustedrouter.com/status.json"

// DefaultRequestTimeout is the default timeout for SDK-owned HTTP clients.
const DefaultRequestTimeout = 120 * time.Second

// DefaultFusionTimeout is the default timeout for Fusion requests.
const DefaultFusionTimeout = 600 * time.Second

// AutoModel is the default automatic TrustedRouter model selector.
const AutoModel = "trustedrouter/auto"

// FastModel is the low-latency TrustedRouter model selector.
const FastModel = "trustedrouter/fast"

// FusionModel is the TrustedRouter Fusion orchestration model.
const FusionModel = "trustedrouter/fusion"

// AdvisorModel is the TrustedRouter Advisor orchestration model.
const AdvisorModel = "trustedrouter/advisor"

// FusionFreedomPanel is the recommended Fusion panel for maximum willingness to answer.
var FusionFreedomPanel = []string{
	"minimax/minimax-m3",
	"~kimi/latest",
	"~zai/glm-latest",
	"google/gemma-4-31b-it",
	"deepseek/deepseek-v4-flash",
}

// FusionFreedomFallbackJudges is the recommended Fusion fallback judge chain.
var FusionFreedomFallbackJudges = []string{
	"minimax/minimax-m3",
	"~zai/glm-latest",
	"~kimi/latest",
	"deepseek/deepseek-v4-flash",
	"google/gemma-4-31b-it",
}

// FusionFreedomFallbackFinals is the recommended Fusion fallback final-model chain.
var FusionFreedomFallbackFinals = []string{
	"minimax/minimax-m3",
	"~zai/glm-latest",
	"~kimi/latest",
	"deepseek/deepseek-v4-flash",
	"google/gemma-4-31b-it",
}

// Fusion selection strategies.
const (
	SelectionStrategySynthesize            = "synthesize"
	SelectionStrategySynthesizeNonRefusals = "synthesize_non_refusals"
	SelectionStrategyFirstSuccess          = "first_success"
	SelectionStrategyFirstNonRefusal       = "first_non_refusal"
)

// RegionHosts maps supported TrustedRouter region IDs to their gateway hosts.
var RegionHosts = map[string]string{
	"us-central1":  "api.quillrouter.com",
	"us-east4":     "api-us-east4.quillrouter.com",
	"europe-west4": "api-europe-west4.quillrouter.com",
}

// DefaultFailoverRegions is the default regional failover chain.
var DefaultFailoverRegions = []string{"us-central1", "us-east4", "europe-west4"}

// RegionBaseURL returns the OpenAI-compatible /v1 base URL for a TrustedRouter region.
func RegionBaseURL(region string) (string, error) {
	host, ok := RegionHosts[region]
	if !ok {
		known := make([]string, 0, len(RegionHosts))
		for key := range RegionHosts {
			known = append(known, key)
		}
		sort.Strings(known)
		return "", fmt.Errorf("unknown TrustedRouter region %q; known: %s", region, strings.Join(known, ", "))
	}
	return "https://" + host + "/v1", nil
}
