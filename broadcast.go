package trustedrouter

import (
	"context"
	"encoding/json"
	"net/http"
)

// BroadcastDestinationOptions configures broadcast destination read/delete/test requests.
type BroadcastDestinationOptions struct {
	// WorkspaceID overrides the client workspace selector. Nil inherits the client default; a pointer to "" suppresses the workspace header.
	WorkspaceID *string
	// CallOptions configures per-call headers, auth, workspace, idempotency, and timeout.
	CallOptions
}

// BroadcastDestinationRequest configures a broadcast destination create request.
type BroadcastDestinationRequest struct {
	// Type is the broadcast destination backend type, such as "posthog" or "webhook".
	Type string
	// Name defaults to "Broadcast destination" when empty.
	Name string
	// Endpoint is the destination URL. Nil omits the field.
	Endpoint *string
	// Enabled defaults to true when nil.
	Enabled *bool
	// IncludeContent defaults to false when nil.
	IncludeContent *bool
	// Method defaults to "POST" when empty.
	Method string
	// Headers are destination-specific headers. Nil omits the field.
	Headers map[string]string
	// APIKey is the destination-specific API key. Nil omits the field.
	APIKey *string
	// WorkspaceID routes the request to a workspace without including it in the body.
	WorkspaceID *string
	// CallOptions configures per-call headers, auth, workspace, idempotency, and timeout.
	CallOptions
}

// MarshalJSON encodes the create body sent to the broadcast destinations endpoint.
func (r BroadcastDestinationRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(broadcastDestinationBody(r))
}

// BroadcastDestinationList is the response returned by the broadcast destinations endpoint.
type BroadcastDestinationList struct {
	// Data contains the destinations.
	Data []BroadcastDestination `json:"data"`
	// Extra contains unknown top-level response fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes a broadcast destination list and preserves unknown fields in Extra.
func (b *BroadcastDestinationList) UnmarshalJSON(data []byte) error {
	type alias BroadcastDestinationList
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*b = BroadcastDestinationList(out)
	b.Extra = extraFields(data, "data")
	return nil
}

// BroadcastDestination is one TrustedRouter broadcast destination.
type BroadcastDestination struct {
	// ID is the destination identifier.
	ID string `json:"id"`
	// Type is the destination backend type.
	Type string `json:"type"`
	// Name is the display name.
	Name *string `json:"name,omitempty"`
	// Endpoint is the destination URL.
	Endpoint *string `json:"endpoint,omitempty"`
	// Enabled indicates whether the destination is active.
	Enabled *bool `json:"enabled,omitempty"`
	// IncludeContent indicates whether generation content is included.
	IncludeContent *bool `json:"include_content,omitempty"`
	// Method is the HTTP method used for webhook-style destinations.
	Method *string `json:"method,omitempty"`
	// Extra contains unknown destination fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes a broadcast destination and preserves unknown fields in Extra.
func (b *BroadcastDestination) UnmarshalJSON(data []byte) error {
	type alias BroadcastDestination
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*b = BroadcastDestination(out)
	b.Extra = extraFields(data, "id", "type", "name", "endpoint", "enabled", "include_content", "method")
	return nil
}

// BroadcastDestinations fetches configured broadcast destinations.
func (c *Client) BroadcastDestinations(ctx context.Context, opts *BroadcastDestinationOptions) (*BroadcastDestinationList, error) {
	var out BroadcastDestinationList
	if err := c.Request(ctx, http.MethodGet, "/broadcast/destinations", nil, &out, broadcastDestinationCallOptions(opts)); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateBroadcastDestination creates a broadcast destination.
func (c *Client) CreateBroadcastDestination(ctx context.Context, req BroadcastDestinationRequest) (*BroadcastDestination, error) {
	var out BroadcastDestination
	callOpts := req.CallOptions
	if callOpts.WorkspaceID == nil {
		callOpts.WorkspaceID = req.WorkspaceID
	}
	if err := c.Request(ctx, http.MethodPost, "/broadcast/destinations", broadcastDestinationBody(req), &out, &callOpts); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetBroadcastDestination fetches a broadcast destination by ID.
func (c *Client) GetBroadcastDestination(ctx context.Context, id string, opts *BroadcastDestinationOptions) (*BroadcastDestination, error) {
	var out BroadcastDestination
	if err := c.Request(ctx, http.MethodGet, "/broadcast/destinations/"+id, nil, &out, broadcastDestinationCallOptions(opts)); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateBroadcastDestination patches a broadcast destination by ID.
func (c *Client) UpdateBroadcastDestination(ctx context.Context, id string, patch map[string]any) (*BroadcastDestination, error) {
	var out BroadcastDestination
	body, callOpts := broadcastDestinationPatchBodyAndOptions(patch)
	if err := c.Request(ctx, http.MethodPatch, "/broadcast/destinations/"+id, body, &out, callOpts); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteBroadcastDestination deletes a broadcast destination by ID.
func (c *Client) DeleteBroadcastDestination(ctx context.Context, id string, opts *BroadcastDestinationOptions) (map[string]any, error) {
	var out map[string]any
	if err := c.Request(ctx, http.MethodDelete, "/broadcast/destinations/"+id, nil, &out, broadcastDestinationCallOptions(opts)); err != nil {
		return nil, err
	}
	return out, nil
}

// TestBroadcastDestination sends a test event through a broadcast destination.
func (c *Client) TestBroadcastDestination(ctx context.Context, id string, opts *BroadcastDestinationOptions) (map[string]any, error) {
	var out map[string]any
	if err := c.Request(ctx, http.MethodPost, "/broadcast/destinations/"+id+"/test", nil, &out, broadcastDestinationCallOptions(opts)); err != nil {
		return nil, err
	}
	return out, nil
}

func broadcastDestinationBody(req BroadcastDestinationRequest) map[string]any {
	name := req.Name
	if name == "" {
		name = "Broadcast destination"
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	includeContent := false
	if req.IncludeContent != nil {
		includeContent = *req.IncludeContent
	}
	method := req.Method
	if method == "" {
		method = "POST"
	}

	body := map[string]any{
		"type":            req.Type,
		"name":            name,
		"enabled":         enabled,
		"include_content": includeContent,
		"method":          method,
	}
	if req.Endpoint != nil {
		body["endpoint"] = *req.Endpoint
	}
	if req.Headers != nil {
		headers := make(map[string]string, len(req.Headers))
		for key, value := range req.Headers {
			headers[key] = value
		}
		body["headers"] = headers
	}
	if req.APIKey != nil {
		body["api_key"] = *req.APIKey
	}
	return body
}

func broadcastDestinationCallOptions(opts *BroadcastDestinationOptions) *CallOptions {
	if opts == nil {
		return nil
	}
	callOpts := opts.CallOptions
	if callOpts.WorkspaceID == nil {
		callOpts.WorkspaceID = opts.WorkspaceID
	}
	return &callOpts
}

func broadcastDestinationPatchBodyAndOptions(patch map[string]any) (map[string]any, *CallOptions) {
	body := map[string]any{}
	var workspaceID *string
	for key, value := range patch {
		switch key {
		case "workspace_id", "workspaceId":
			if s, ok := value.(string); ok {
				workspaceID = &s
			}
			continue
		}
		if value != nil {
			body[key] = value
		}
	}
	if workspaceID == nil {
		return body, nil
	}
	return body, &CallOptions{WorkspaceID: workspaceID}
}
