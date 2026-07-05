package trustedrouter

import (
	"context"
	"encoding/json"
	"net/http"
)

// MessagesRequest configures an Anthropic-compatible /messages request.
type MessagesRequest struct {
	// Model is the model ID to route to.
	Model string
	// Messages is the Anthropic-compatible messages array.
	Messages []map[string]any
	// MaxTokens is the maximum number of output tokens. Nil uses the reference default of 1024.
	MaxTokens *int
	// Extra contains additional JSON body fields to forward to TrustedRouter.
	Extra map[string]any
	// CallOptions configures per-call headers, auth, workspace, idempotency, and timeout.
	CallOptions
}

// MarshalJSON encodes the request body sent to the messages endpoint.
func (r MessagesRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(buildMessagesBody(r))
}

// MessageResponse is an Anthropic-compatible message response.
type MessageResponse struct {
	// ID is the message ID.
	ID string `json:"id"`
	// Type is the response object type.
	Type *string `json:"type,omitempty"`
	// Role is the message role.
	Role string `json:"role"`
	// Content contains message content blocks.
	Content []MessageContentBlock `json:"content"`
	// Model is the model that produced the message.
	Model string `json:"model"`
	// StopReason is the provider stop reason.
	StopReason *string `json:"stop_reason,omitempty"`
	// StopSequence is the provider stop sequence, when supplied.
	StopSequence *string `json:"stop_sequence,omitempty"`
	// Usage contains token usage when present.
	Usage *MessagesUsage `json:"usage,omitempty"`
	// Extra contains unknown response fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes a message response and preserves unknown fields in Extra.
func (m *MessageResponse) UnmarshalJSON(data []byte) error {
	type alias MessageResponse
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*m = MessageResponse(out)
	m.Extra = extraFields(data, "id", "type", "role", "content", "model", "stop_reason", "stop_sequence", "usage")
	return nil
}

// MarshalJSON encodes a message response and includes unknown Extra fields.
func (m MessageResponse) MarshalJSON() ([]byte, error) {
	fields := map[string]any{
		"id":      m.ID,
		"role":    m.Role,
		"content": m.Content,
		"model":   m.Model,
	}
	if m.Type != nil {
		fields["type"] = *m.Type
	}
	if m.StopReason != nil {
		fields["stop_reason"] = *m.StopReason
	}
	if m.StopSequence != nil {
		fields["stop_sequence"] = *m.StopSequence
	}
	if m.Usage != nil {
		fields["usage"] = m.Usage
	}
	return marshalObject(fields, m.Extra)
}

// MessageContentBlock is one Anthropic-compatible message content block.
type MessageContentBlock struct {
	// Type is the content block type.
	Type string `json:"type"`
	// Text is the text content for text blocks.
	Text *string `json:"text,omitempty"`
	// Extra contains unknown content-block fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes a message content block and preserves unknown fields in Extra.
func (b *MessageContentBlock) UnmarshalJSON(data []byte) error {
	type alias MessageContentBlock
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*b = MessageContentBlock(out)
	b.Extra = extraFields(data, "type", "text")
	return nil
}

// MarshalJSON encodes a message content block and includes unknown Extra fields.
func (b MessageContentBlock) MarshalJSON() ([]byte, error) {
	fields := map[string]any{"type": b.Type}
	if b.Text != nil {
		fields["text"] = *b.Text
	}
	return marshalObject(fields, b.Extra)
}

// MessagesUsage contains Anthropic-compatible message token usage.
type MessagesUsage struct {
	// InputTokens is the number of input tokens.
	InputTokens int `json:"input_tokens"`
	// OutputTokens is the number of output tokens.
	OutputTokens int `json:"output_tokens"`
	// Extra contains unknown usage fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes message usage and preserves unknown fields in Extra.
func (u *MessagesUsage) UnmarshalJSON(data []byte) error {
	type alias MessagesUsage
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*u = MessagesUsage(out)
	u.Extra = extraFields(data, "input_tokens", "output_tokens")
	return nil
}

// MarshalJSON encodes message usage and includes unknown Extra fields.
func (u MessagesUsage) MarshalJSON() ([]byte, error) {
	return marshalObject(map[string]any{
		"input_tokens":  u.InputTokens,
		"output_tokens": u.OutputTokens,
	}, u.Extra)
}

// Messages sends an Anthropic-compatible /messages request.
func (c *Client) Messages(ctx context.Context, req MessagesRequest) (*MessageResponse, error) {
	var out MessageResponse
	callOpts := req.CallOptions
	if err := c.Request(ctx, http.MethodPost, "/messages", buildMessagesBody(req), &out, &callOpts); err != nil {
		return nil, err
	}
	return &out, nil
}

func buildMessagesBody(req MessagesRequest) map[string]any {
	maxTokens := 1024
	if req.MaxTokens != nil {
		maxTokens = *req.MaxTokens
	}
	body := map[string]any{
		"model":      req.Model,
		"messages":   req.Messages,
		"max_tokens": maxTokens,
	}
	for key, value := range req.Extra {
		body[key] = value
	}
	return body
}
