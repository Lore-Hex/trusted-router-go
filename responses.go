package trustedrouter

import (
	"context"
	"encoding/json"
	"io"
	"iter"
	"net/http"
)

// ResponsesRequest configures an OpenAI Responses API request.
type ResponsesRequest struct {
	// Model is the model ID. Empty uses AutoModel.
	Model string
	// Input is a string or Responses-compatible input item array.
	Input any
	// Instructions are optional system or developer instructions.
	Instructions *string
	// Extra contains additional JSON body fields to forward to TrustedRouter.
	Extra map[string]any
	// CallOptions configures per-call headers, auth, workspace, idempotency, and timeout.
	CallOptions
}

// MarshalJSON encodes the non-streaming request body sent to the responses endpoint.
func (r ResponsesRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(buildResponsesBody(r, false))
}

// ResponseObject is an OpenAI Responses API response object.
type ResponseObject struct {
	// ID is the response ID.
	ID string `json:"id"`
	// Object is the response object type.
	Object string `json:"object"`
	// CreatedAt is the response creation timestamp.
	CreatedAt *int `json:"created_at,omitempty"`
	// Status is the response status.
	Status *string `json:"status,omitempty"`
	// Model is the model that produced the response.
	Model *string `json:"model,omitempty"`
	// Output contains response output items.
	Output []map[string]any `json:"output,omitempty"`
	// Usage contains token usage when present.
	Usage map[string]any `json:"usage,omitempty"`
	// Extra contains unknown response fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes a response object and preserves unknown fields in Extra.
func (r *ResponseObject) UnmarshalJSON(data []byte) error {
	type alias ResponseObject
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*r = ResponseObject(out)
	r.Extra = extraFields(data, "id", "object", "created_at", "status", "model", "output", "usage")
	return nil
}

// MarshalJSON encodes a response object and includes unknown Extra fields.
func (r ResponseObject) MarshalJSON() ([]byte, error) {
	fields := map[string]any{
		"id":     r.ID,
		"object": r.Object,
	}
	if r.CreatedAt != nil {
		fields["created_at"] = *r.CreatedAt
	}
	if r.Status != nil {
		fields["status"] = *r.Status
	}
	if r.Model != nil {
		fields["model"] = *r.Model
	}
	if r.Output != nil {
		fields["output"] = r.Output
	}
	if r.Usage != nil {
		fields["usage"] = r.Usage
	}
	return marshalObject(fields, r.Extra)
}

// ResponseInputTokens is the /responses/input_tokens result.
type ResponseInputTokens struct {
	// InputTokens is the counted input-token total.
	InputTokens int `json:"input_tokens"`
	// TotalTokens is the total token count when returned.
	TotalTokens *int `json:"total_tokens,omitempty"`
	// Extra contains unknown response fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes a response input-token count and preserves unknown fields in Extra.
func (r *ResponseInputTokens) UnmarshalJSON(data []byte) error {
	type alias ResponseInputTokens
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*r = ResponseInputTokens(out)
	r.Extra = extraFields(data, "input_tokens", "total_tokens")
	return nil
}

// MarshalJSON encodes a response input-token count and includes unknown Extra fields.
func (r ResponseInputTokens) MarshalJSON() ([]byte, error) {
	fields := map[string]any{"input_tokens": r.InputTokens}
	if r.TotalTokens != nil {
		fields["total_tokens"] = *r.TotalTokens
	}
	return marshalObject(fields, r.Extra)
}

// Responses creates a stateless OpenAI Responses API request.
func (c *Client) Responses(ctx context.Context, req ResponsesRequest) (*ResponseObject, error) {
	var out ResponseObject
	callOpts := responsesCallOptions(req, true)
	if callOpts.IdempotencyKey == "" {
		callOpts.IdempotencyKey = newIdempotencyKey()
	}
	if err := c.Request(ctx, http.MethodPost, "/responses", buildResponsesBody(req, false), &out, &callOpts); err != nil {
		return nil, err
	}
	return &out, nil
}

// ResponsesEvents streams parsed OpenAI Responses API SSE events.
func (c *Client) ResponsesEvents(ctx context.Context, req ResponsesRequest) iter.Seq2[map[string]any, error] {
	return func(yield func(map[string]any, error) bool) {
		resp, err := c.openResponsesStream(ctx, req)
		if err != nil {
			yield(nil, err)
			return
		}
		defer resp.Body.Close()

		for event, err := range iterSSEEvents(resp.Body) {
			if err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					yield(nil, ctxErr)
					return
				}
				yield(nil, transportRetryError(err))
				return
			}
			if !yield(event, nil) {
				return
			}
		}
	}
}

// ResponsesRawStream opens a raw Responses API SSE stream.
// The caller must close the returned stream.
func (c *Client) ResponsesRawStream(ctx context.Context, req ResponsesRequest) (io.ReadCloser, error) {
	resp, err := c.openResponsesStream(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// ResponsesInputTokens counts input tokens for a Responses API request.
func (c *Client) ResponsesInputTokens(ctx context.Context, req ResponsesRequest) (*ResponseInputTokens, error) {
	var out ResponseInputTokens
	callOpts := responsesCallOptions(req, false)
	if err := c.Request(ctx, http.MethodPost, "/responses/input_tokens", buildResponsesBody(req, false), &out, &callOpts); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) openResponsesStream(ctx context.Context, req ResponsesRequest) (*http.Response, error) {
	return c.openEventStream(ctx, http.MethodPost, "/responses", buildResponsesBody(req, true), responsesCallOptions(req, true))
}

func buildResponsesBody(req ResponsesRequest, stream bool) map[string]any {
	model := req.Model
	if model == "" {
		model = AutoModel
	}
	params := cloneMap(req.Extra)
	for _, reserved := range []string{
		"api_key",
		"extra_headers",
		"idempotency_key",
		"timeout",
		"workspace_id",
		"stream",
	} {
		delete(params, reserved)
	}

	body := map[string]any{
		"model":  model,
		"input":  req.Input,
		"stream": stream,
	}
	for key, value := range params {
		body[key] = value
	}
	if req.Instructions != nil {
		body["instructions"] = *req.Instructions
	}
	return body
}

func responsesCallOptions(req ResponsesRequest, routeAllReserved bool) CallOptions {
	callOpts := req.CallOptions
	extra := req.Extra
	if routeAllReserved && callOpts.APIKey == nil {
		if value, ok := stringExtra(extra, "api_key"); ok {
			callOpts.APIKey = &value
		}
	}
	if callOpts.WorkspaceID == nil {
		if value, ok := stringExtra(extra, "workspace_id"); ok {
			callOpts.WorkspaceID = &value
		}
	}
	if routeAllReserved && callOpts.IdempotencyKey == "" {
		if value, ok := stringExtra(extra, "idempotency_key"); ok {
			callOpts.IdempotencyKey = value
		}
	}
	if routeAllReserved && callOpts.Timeout == nil {
		if timeout, ok := timeoutExtra(extra, "timeout"); ok {
			callOpts.Timeout = &timeout
		}
	}
	if routeAllReserved {
		if headers := headersExtra(extra, "extra_headers"); len(headers) > 0 {
			merged := make(map[string]string, len(headers)+len(callOpts.ExtraHeaders))
			for key, value := range headers {
				merged[key] = value
			}
			for key, value := range callOpts.ExtraHeaders {
				merged[key] = value
			}
			callOpts.ExtraHeaders = merged
		}
	}
	return callOpts
}
