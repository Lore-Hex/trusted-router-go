package trustedrouter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

// ModelListOptions filters the TrustedRouter model catalog request.
type ModelListOptions struct {
	// OpenWeights filters for open-weight models when non-nil.
	OpenWeights *bool
	// ProviderJurisdiction filters providers by jurisdiction.
	ProviderJurisdiction string
	// ProviderRegion filters providers by region.
	ProviderRegion string
}

// ModelList is the response returned by the models endpoint.
type ModelList struct {
	// Data is the catalog page of models.
	Data []ModelInfo `json:"data"`
	// Extra contains unknown top-level response fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes a model list and preserves unknown fields in Extra.
func (m *ModelList) UnmarshalJSON(data []byte) error {
	type alias ModelList
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*m = ModelList(out)
	m.Extra = extraFields(data, "data")
	return nil
}

// ByID returns the model with the supplied ID, if present.
func (m *ModelList) ByID(modelID string) *ModelInfo {
	if m == nil {
		return nil
	}
	for i := range m.Data {
		if m.Data[i].ID == modelID {
			return &m.Data[i]
		}
	}
	return nil
}

// ModelInfo is one TrustedRouter model catalog entry.
type ModelInfo struct {
	// ID is the model identifier.
	ID string `json:"id"`
	// Object is the optional OpenAI/OpenRouter object type.
	Object string `json:"object,omitempty"`
	// Created is the model creation timestamp when provided.
	Created int `json:"created,omitempty"`
	// OwnedBy is the owner identifier when provided.
	OwnedBy string `json:"owned_by,omitempty"`
	// Name is the display name.
	Name string `json:"name,omitempty"`
	// Description is the model description.
	Description string `json:"description,omitempty"`
	// ContextLength is the context window length.
	ContextLength *int `json:"context_length,omitempty"`
	// Architecture describes model architecture metadata.
	Architecture ModelArchitecture `json:"architecture,omitempty"`
	// Pricing describes model token pricing metadata.
	Pricing ModelPricing `json:"pricing,omitempty"`
	// TopProvider describes provider-level limits.
	TopProvider ModelTopProvider `json:"top_provider,omitempty"`
	// PerRequestLimits contains OpenRouter-compatible per-request limits.
	PerRequestLimits map[string]any `json:"per_request_limits,omitempty"`
	// TrustedRouter contains TrustedRouter-specific model metadata.
	TrustedRouter *ModelTrustedRouterMetadata `json:"trustedrouter,omitempty"`
	// Extra contains unknown model fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes a model entry and preserves unknown fields in Extra.
func (m *ModelInfo) UnmarshalJSON(data []byte) error {
	type alias ModelInfo
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*m = ModelInfo(out)
	m.Extra = extraFields(data, "id", "object", "created", "owned_by", "name", "description", "context_length", "architecture", "pricing", "top_provider", "per_request_limits", "trustedrouter")
	return nil
}

// OpenWeights reports whether this model is marked as open weights.
func (m ModelInfo) OpenWeights() bool {
	return m.TrustedRouter != nil && m.TrustedRouter.OpenWeights != nil && *m.TrustedRouter.OpenWeights
}

// USProviderAvailable reports whether a US provider is available.
func (m ModelInfo) USProviderAvailable() bool {
	return m.TrustedRouter != nil && m.TrustedRouter.USProviderAvailable != nil && *m.TrustedRouter.USProviderAvailable
}

// EUFocusedProviderAvailable reports whether an EU-focused provider is available.
func (m ModelInfo) EUFocusedProviderAvailable() bool {
	return m.TrustedRouter != nil && m.TrustedRouter.EUFocusedProviderAvailable != nil && *m.TrustedRouter.EUFocusedProviderAvailable
}

// ModelTrustedRouterMetadata contains TrustedRouter-specific model metadata.
type ModelTrustedRouterMetadata struct {
	// OpenWeights indicates whether the model weights are open.
	OpenWeights *bool `json:"open_weights,omitempty"`
	// USProviderAvailable indicates whether a US provider is available.
	USProviderAvailable *bool `json:"us_provider_available,omitempty"`
	// EUFocusedProviderAvailable indicates whether an EU-focused provider is available.
	EUFocusedProviderAvailable *bool `json:"eu_focused_provider_available,omitempty"`
	// Extra contains unknown TrustedRouter metadata fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes TrustedRouter model metadata and preserves unknown fields in Extra.
func (m *ModelTrustedRouterMetadata) UnmarshalJSON(data []byte) error {
	type alias ModelTrustedRouterMetadata
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*m = ModelTrustedRouterMetadata(out)
	m.Extra = extraFields(data, "open_weights", "us_provider_available", "eu_focused_provider_available")
	return nil
}

// ModelPricing contains OpenRouter-compatible token pricing strings.
type ModelPricing struct {
	// Prompt is the prompt-token price.
	Prompt *string `json:"prompt,omitempty"`
	// Completion is the completion-token price.
	Completion *string `json:"completion,omitempty"`
	// PromptMax is the max prompt-token price for automatic model selectors.
	PromptMax *string `json:"prompt_max,omitempty"`
	// CompletionMax is the max completion-token price for automatic model selectors.
	CompletionMax *string `json:"completion_max,omitempty"`
	// Extra contains unknown pricing fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes pricing metadata and preserves unknown fields in Extra.
func (m *ModelPricing) UnmarshalJSON(data []byte) error {
	type alias ModelPricing
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*m = ModelPricing(out)
	m.Extra = extraFields(data, "prompt", "completion", "prompt_max", "completion_max")
	return nil
}

// ModelArchitecture contains OpenRouter-compatible architecture metadata.
type ModelArchitecture struct {
	// Modality is the input/output modality.
	Modality string `json:"modality,omitempty"`
	// Tokenizer is the tokenizer identifier.
	Tokenizer string `json:"tokenizer,omitempty"`
	// InstructType is the instruction-tuning style.
	InstructType *string `json:"instruct_type,omitempty"`
	// Extra contains unknown architecture fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes architecture metadata and preserves unknown fields in Extra.
func (m *ModelArchitecture) UnmarshalJSON(data []byte) error {
	type alias ModelArchitecture
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*m = ModelArchitecture(out)
	m.Extra = extraFields(data, "modality", "tokenizer", "instruct_type")
	return nil
}

// ModelTopProvider contains OpenRouter-compatible top-provider metadata.
type ModelTopProvider struct {
	// ContextLength is the provider-specific context length.
	ContextLength *int `json:"context_length,omitempty"`
	// MaxCompletionTokens is the provider-specific completion limit.
	MaxCompletionTokens *int `json:"max_completion_tokens,omitempty"`
	// IsModerated indicates whether the provider moderates requests.
	IsModerated bool `json:"is_moderated,omitempty"`
	// Extra contains unknown top-provider fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes top-provider metadata and preserves unknown fields in Extra.
func (m *ModelTopProvider) UnmarshalJSON(data []byte) error {
	type alias ModelTopProvider
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*m = ModelTopProvider(out)
	m.Extra = extraFields(data, "context_length", "max_completion_tokens", "is_moderated")
	return nil
}

// Models fetches the TrustedRouter model catalog.
func (c *Client) Models(ctx context.Context, opts *ModelListOptions) (*ModelList, error) {
	var out ModelList
	if err := c.Request(ctx, http.MethodGet, modelsPath(opts), nil, &out, nil); err != nil {
		return nil, err
	}
	return &out, nil
}

func modelsPath(opts *ModelListOptions) string {
	if opts == nil {
		return "/models"
	}
	params := url.Values{}
	if opts.OpenWeights != nil {
		if *opts.OpenWeights {
			params.Set("open_weights", "true")
		} else {
			params.Set("open_weights", "false")
		}
	}
	if opts.ProviderJurisdiction != "" {
		params.Set("provider[jurisdiction]", opts.ProviderJurisdiction)
	}
	if opts.ProviderRegion != "" {
		params.Set("provider[region]", opts.ProviderRegion)
	}
	encoded := params.Encode()
	if encoded == "" {
		return "/models"
	}
	return "/models?" + encoded
}

func extraFields(data []byte, known ...string) map[string]any {
	var all map[string]any
	if err := json.Unmarshal(data, &all); err != nil || len(all) == 0 {
		return nil
	}
	for _, key := range known {
		delete(all, key)
	}
	if len(all) == 0 {
		return nil
	}
	return all
}
