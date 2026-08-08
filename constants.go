package trustedrouter

import "time"

// DefaultAPIBaseURL is the default OpenAI-compatible TrustedRouter inference base URL.
const DefaultAPIBaseURL = "https://api.trustedrouter.com/v1"

// AliasAPIBaseURLs are exact aliases of DefaultAPIBaseURL, on separate domains
// served by separate DNS providers (trustedrouter.com from Google Cloud DNS,
// these two from Route 53). They resolve to the same attested enclaves.
//
// The domain is a single point of failure sitting above the whole deployment:
// a zone that stops answering, a registrar lock, or a resolver handing out a
// stale record takes the API down however many clouds are behind it.
var AliasAPIBaseURLs = []string{
	"https://api.allyrouter.com/v1",
	"https://api.uptimerouter.com/v1",
}

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

// ZDRModel routes only through zero-data-retention providers.
const ZDRModel = "trustedrouter/zdr"

// E2EModel routes only through provider-side confidential compute and E2EE.
const E2EModel = "trustedrouter/e2e"

// ConfidentialModel is an alias for E2EModel.
const ConfidentialModel = "trustedrouter/confidential"

// EUModel routes through EU-focused providers.
const EUModel = "trustedrouter/eu"

// USModel routes through US-jurisdiction providers.
const USModel = "trustedrouter/us"

// FusionModel is the TrustedRouter Fusion orchestration model.
const FusionModel = "trustedrouter/fusion"

// SynthModel is the preferred Synth orchestration alias.
const SynthModel = "trustedrouter/synth"

// AdvisorModel is the TrustedRouter Advisor orchestration model.
const AdvisorModel = "trustedrouter/advisor"

// SelectorModel is the Selector orchestration primitive.
const SelectorModel = "trustedrouter/selector"

// MapReduceModel is the MapReduce orchestration primitive.
const MapReduceModel = "trustedrouter/mapreduce"

// SubagentModel is the Subagent orchestration primitive.
const SubagentModel = "trustedrouter/subagent"

// Stable named orchestration aliases.
const (
	SocratesModel   = "trustedrouter/socrates-1.1"
	PrometheusModel = "trustedrouter/prometheus-2.0"
	ZeusModel       = "trustedrouter/zeus-1.0"
	AthenaModel     = "trustedrouter/athena"
)

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
