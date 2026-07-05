package trustedrouter

import "time"

// DefaultAPIBaseURL is the default OpenAI-compatible TrustedRouter inference base URL.
const DefaultAPIBaseURL = "https://api.trustedrouter.com/v1"

// DefaultControlBaseURL is the default TrustedRouter control-plane base URL.
const DefaultControlBaseURL = "https://trustedrouter.com/v1"

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
