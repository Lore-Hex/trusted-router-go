package trustedrouter

// ProviderPreferences configures typed provider routing, privacy, and pricing.
type ProviderPreferences struct {
	Order             []string       `json:"order,omitempty"`
	Only              []string       `json:"only,omitempty"`
	Ignore            []string       `json:"ignore,omitempty"`
	Sort              string         `json:"sort,omitempty"`
	AllowFallbacks    *bool          `json:"allow_fallbacks,omitempty"`
	RequireParameters *bool          `json:"require_parameters,omitempty"`
	DataCollection    string         `json:"data_collection,omitempty"`
	MinPrivacy        string         `json:"min_privacy,omitempty"`
	Jurisdiction      string         `json:"jurisdiction,omitempty"`
	Usage             string         `json:"usage,omitempty"`
	Quantizations     []string       `json:"quantizations,omitempty"`
	MaxPrice          map[string]any `json:"max_price,omitempty"`
}

// ZDRProvider requires zero data retention and denies provider data collection.
func ZDRProvider() ProviderPreferences {
	return ProviderPreferences{MinPrivacy: "zdr", DataCollection: "deny"}
}

// ConfidentialProvider requires provider-side confidential compute and E2EE.
func ConfidentialProvider() ProviderPreferences {
	return ProviderPreferences{MinPrivacy: "confidential", DataCollection: "deny"}
}

// USProvider requires US-jurisdiction providers.
func USProvider() ProviderPreferences {
	return ProviderPreferences{Jurisdiction: "us"}
}
