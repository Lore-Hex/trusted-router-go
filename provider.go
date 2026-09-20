package trustedrouter

// ProviderPreferences configures typed provider routing, privacy, and pricing.
type ProviderPreferences struct {
	// Order lists providers in routing preference order.
	Order []string `json:"order,omitempty"`
	// Only restricts routing to these providers.
	Only []string `json:"only,omitempty"`
	// Ignore excludes these providers from routing.
	Ignore []string `json:"ignore,omitempty"`
	// Sort selects the provider sorting strategy.
	Sort string `json:"sort,omitempty"`
	// AllowFallbacks controls fallback routing when non-nil.
	AllowFallbacks *bool `json:"allow_fallbacks,omitempty"`
	// RequireParameters requires support for all request parameters when non-nil.
	RequireParameters *bool `json:"require_parameters,omitempty"`
	// DataCollection selects the provider data-collection policy.
	DataCollection string `json:"data_collection,omitempty"`
	// MinPrivacy sets the minimum required provider privacy tier.
	MinPrivacy string `json:"min_privacy,omitempty"`
	// Jurisdiction restricts the provider jurisdiction.
	Jurisdiction string `json:"jurisdiction,omitempty"`
	// Usage selects the provider usage category.
	Usage string `json:"usage,omitempty"`
	// Quantizations restricts acceptable model quantizations.
	Quantizations []string `json:"quantizations,omitempty"`
	// MaxPrice sets maximum prices by pricing category.
	MaxPrice map[string]any `json:"max_price,omitempty"`
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
