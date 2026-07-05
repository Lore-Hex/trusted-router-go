package trustedrouter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// EmbeddingsRequest configures an OpenAI-compatible embeddings request.
type EmbeddingsRequest struct {
	// Model is the embedding model ID.
	Model string
	// Input is a string, string slice, token slice, or batch of token slices.
	Input any
	// EncodingFormat requests the embedding encoding format.
	EncodingFormat *string
	// Dimensions requests a reduced embedding dimension count.
	Dimensions *int
	// User is an end-user identifier forwarded to the provider.
	User *string
	// Extra contains additional JSON body fields to forward to TrustedRouter.
	Extra map[string]any
	// CallOptions configures per-call headers, auth, workspace, idempotency, and timeout.
	CallOptions
}

// MarshalJSON encodes the request body sent to the embeddings endpoint.
func (r EmbeddingsRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(buildEmbeddingsBody(r))
}

// EmbeddingsResponse is an OpenAI-compatible embeddings response.
type EmbeddingsResponse struct {
	// Object is the response object type.
	Object *string `json:"object,omitempty"`
	// Data contains the returned embeddings.
	Data []Embedding `json:"data"`
	// Model is the model that produced the embeddings.
	Model string `json:"model"`
	// Usage contains token usage when present.
	Usage *ChatUsage `json:"usage,omitempty"`
	// Extra contains unknown response fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes an embeddings response and preserves unknown fields in Extra.
func (e *EmbeddingsResponse) UnmarshalJSON(data []byte) error {
	type alias EmbeddingsResponse
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*e = EmbeddingsResponse(out)
	e.Extra = extraFields(data, "object", "data", "model", "usage")
	return nil
}

// MarshalJSON encodes an embeddings response and includes unknown Extra fields.
func (e EmbeddingsResponse) MarshalJSON() ([]byte, error) {
	fields := map[string]any{
		"data":  e.Data,
		"model": e.Model,
	}
	if e.Object != nil {
		fields["object"] = *e.Object
	}
	if e.Usage != nil {
		fields["usage"] = e.Usage
	}
	return marshalObject(fields, e.Extra)
}

// Embedding is one embedding vector in an embeddings response.
type Embedding struct {
	// Index is the embedding index.
	Index int `json:"index"`
	// Object is the embedding object type.
	Object *string `json:"object,omitempty"`
	// Embedding is the embedding value, returned either as floats or as base64.
	Embedding EmbeddingValue `json:"embedding"`
	// Extra contains unknown embedding fields.
	Extra map[string]any `json:"-"`
}

// EmbeddingValue is an embedding vector in either float-list or base64 wire form.
type EmbeddingValue struct {
	// Floats contains the embedding when the provider returns JSON numbers.
	Floats []float64
	// Base64 contains the embedding when encoding_format requests base64.
	Base64 string

	base64Encoded bool
}

// UnmarshalJSON accepts the embedding field as either a JSON float array or a base64 string.
func (e *EmbeddingValue) UnmarshalJSON(data []byte) error {
	var floats []float64
	if err := json.Unmarshal(data, &floats); err == nil {
		e.Floats = floats
		e.Base64 = ""
		e.base64Encoded = false
		return nil
	}

	var base64Value string
	if err := json.Unmarshal(data, &base64Value); err == nil {
		e.Floats = nil
		e.Base64 = base64Value
		e.base64Encoded = true
		return nil
	}

	return fmt.Errorf("trustedrouter: embedding must be a float array or base64 string")
}

// MarshalJSON emits the embedding in the same union shape: base64 string when set, otherwise float array.
func (e EmbeddingValue) MarshalJSON() ([]byte, error) {
	if e.base64Encoded || e.Base64 != "" {
		return json.Marshal(e.Base64)
	}
	if e.Floats == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(e.Floats)
}

// Float64s returns a copy of the float embedding and false when this value is base64 encoded.
func (e EmbeddingValue) Float64s() ([]float64, bool) {
	if e.IsBase64() {
		return nil, false
	}
	return append([]float64(nil), e.Floats...), true
}

// Base64String returns the base64 embedding and whether this value uses base64 encoding.
func (e EmbeddingValue) Base64String() (string, bool) {
	if !e.IsBase64() {
		return "", false
	}
	return e.Base64, true
}

// IsBase64 reports whether this embedding value represents the base64 wire form.
func (e EmbeddingValue) IsBase64() bool {
	return e.base64Encoded || e.Base64 != ""
}

// UnmarshalJSON decodes an embedding and preserves unknown fields in Extra.
func (e *Embedding) UnmarshalJSON(data []byte) error {
	type alias Embedding
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*e = Embedding(out)
	e.Extra = extraFields(data, "index", "object", "embedding")
	return nil
}

// MarshalJSON encodes an embedding and includes unknown Extra fields.
func (e Embedding) MarshalJSON() ([]byte, error) {
	fields := map[string]any{
		"index":     e.Index,
		"embedding": e.Embedding,
	}
	if e.Object != nil {
		fields["object"] = *e.Object
	}
	return marshalObject(fields, e.Extra)
}

// Embeddings sends an OpenAI-compatible embeddings request.
func (c *Client) Embeddings(ctx context.Context, req EmbeddingsRequest) (*EmbeddingsResponse, error) {
	var out EmbeddingsResponse
	callOpts := req.CallOptions
	if err := c.Request(ctx, http.MethodPost, "/embeddings", buildEmbeddingsBody(req), &out, &callOpts); err != nil {
		return nil, err
	}
	return &out, nil
}

func buildEmbeddingsBody(req EmbeddingsRequest) map[string]any {
	body := map[string]any{
		"model": req.Model,
		"input": req.Input,
	}
	if req.EncodingFormat != nil {
		body["encoding_format"] = *req.EncodingFormat
	}
	if req.Dimensions != nil {
		body["dimensions"] = *req.Dimensions
	}
	if req.User != nil {
		body["user"] = *req.User
	}
	for key, value := range req.Extra {
		body[key] = value
	}
	return body
}
