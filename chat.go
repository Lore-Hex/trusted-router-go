package trustedrouter

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"iter"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

var advisorModels = map[string]struct{}{
	AdvisorModel: {},
}

var fusionPrimitiveModels = map[string]struct{}{
	"trustedrouter/fusion":      {},
	"trustedrouter/fusion-code": {},
	"trustedrouter/synth":       {},
	"trustedrouter/synth-code":  {},
	"trustedrouter/selector":    {},
	"trustedrouter/mapreduce":   {},
}

var (
	errOpenTimeout       = errors.New("trustedrouter stream open timeout")
	errStreamIdleTimeout = errors.New("trustedrouter stream idle timeout")
)

// FusionToolOptions configures a trustedrouter:fusion tool.
type FusionToolOptions struct {
	// AnalysisModels is the panel of models to ask.
	AnalysisModels []string
	// Model is the judge or synthesis model.
	Model *string
	// SelectionStrategy configures how the gateway selects or synthesizes the final answer.
	SelectionStrategy *string
	// FallbackJudges configures fallback judge models.
	FallbackJudges []string
	// FallbackFinalModels configures fallback final models.
	FallbackFinalModels []string
	// MaxCompletionTokens configures the maximum completion tokens.
	MaxCompletionTokens *int
	// MaxToolCalls configures the maximum Fusion tool calls.
	MaxToolCalls *int
	// Preset configures a Fusion preset.
	Preset *string
}

// FusionTool builds a trustedrouter:fusion tool spec.
func FusionTool(opts FusionToolOptions) map[string]any {
	parameters := map[string]any{}
	setPtr(parameters, "preset", opts.Preset)
	setSlice(parameters, "analysis_models", opts.AnalysisModels)
	setPtr(parameters, "model", opts.Model)
	setPtr(parameters, "selection_strategy", opts.SelectionStrategy)
	setSlice(parameters, "fallback_judges", opts.FallbackJudges)
	setSlice(parameters, "fallback_final_models", opts.FallbackFinalModels)
	setPtr(parameters, "max_completion_tokens", opts.MaxCompletionTokens)
	setPtr(parameters, "max_tool_calls", opts.MaxToolCalls)
	return map[string]any{"type": "trustedrouter:fusion", "parameters": parameters}
}

// AdvisorToolOptions configures a trustedrouter:advisor tool.
type AdvisorToolOptions struct {
	// Depth configures Advisor depth.
	Depth *int
	// WorkerModels configures worker models.
	WorkerModels []string
	// AdvisorModels configures advisor models.
	AdvisorModels []string
	// MaxGetAdviceCalls configures the internal advice-call limit.
	MaxGetAdviceCalls *int
	// AdvisorMaxTokens configures the advisor token limit.
	AdvisorMaxTokens *int
	// AdvisorTimeoutMs configures the advisor timeout in milliseconds.
	AdvisorTimeoutMs *int
}

// AdvisorTool builds a trustedrouter:advisor tool spec.
func AdvisorTool(opts AdvisorToolOptions) map[string]any {
	parameters := map[string]any{}
	setPtr(parameters, "depth", opts.Depth)
	setSlice(parameters, "worker_models", opts.WorkerModels)
	setSlice(parameters, "advisor_models", opts.AdvisorModels)
	setPtr(parameters, "max_get_advice_calls", opts.MaxGetAdviceCalls)
	setPtr(parameters, "advisor_max_tokens", opts.AdvisorMaxTokens)
	setPtr(parameters, "advisor_timeout_ms", opts.AdvisorTimeoutMs)
	return map[string]any{"type": "trustedrouter:advisor", "parameters": parameters}
}

// ChatRequest configures a chat completions request.
type ChatRequest struct {
	// Model is the model ID; empty defaults to AutoModel.
	Model string
	// Messages is the OpenAI-compatible chat messages array.
	Messages []map[string]any
	// Tools is an optional OpenAI-compatible tools array.
	Tools []map[string]any
	// Depth configures TrustedRouter Advisor depth.
	Depth *int
	// WorkerModels configures TrustedRouter Advisor worker models.
	WorkerModels []string
	// AdvisorModels configures TrustedRouter Advisor models.
	AdvisorModels []string
	// MaxGetAdviceCalls configures the Advisor internal advice-call limit.
	MaxGetAdviceCalls *int
	// AdvisorMaxTokens configures the Advisor token limit.
	AdvisorMaxTokens *int
	// AdvisorTimeoutMs configures the Advisor timeout in milliseconds.
	AdvisorTimeoutMs *int
	// AnalysisModels configures Fusion analysis models.
	AnalysisModels []string
	// JudgeModel configures the Fusion judge or synthesis model.
	JudgeModel *string
	// SelectionStrategy configures the Fusion selection strategy.
	SelectionStrategy *string
	// FallbackJudges configures Fusion fallback judges.
	FallbackJudges []string
	// FallbackFinalModels configures Fusion fallback final models.
	FallbackFinalModels []string
	// MaxCompletionTokens configures Fusion max completion tokens.
	MaxCompletionTokens *int
	// MaxToolCalls configures Fusion max tool calls.
	MaxToolCalls *int
	// Preset configures a Fusion preset.
	Preset *string
	// PanelPrompt configures the Fusion panel prompt.
	PanelPrompt *string
	// SynthesisPrompt configures the Fusion synthesis prompt.
	SynthesisPrompt *string
	// FinalPrompt configures the Fusion final prompt.
	FinalPrompt *string
	// SelectorModels configures selector orchestration models.
	SelectorModels []string
	// SelectorModel configures the selector orchestration model.
	SelectorModel *string
	// SelectorPrompt configures the selector prompt.
	SelectorPrompt *string
	// MapperModels configures map-reduce mapper models.
	MapperModels []string
	// MapperModel configures the map-reduce mapper model.
	MapperModel *string
	// MapperPrompt configures the map-reduce mapper prompt.
	MapperPrompt *string
	// ParallelModels configures parallel orchestration models.
	ParallelModels []string
	// ParallelModel configures the parallel orchestration model.
	ParallelModel *string
	// ParallelPrompt configures the parallel orchestration prompt.
	ParallelPrompt *string
	// ReducerModels configures reducer orchestration models.
	ReducerModels []string
	// ReducerModel configures the reducer orchestration model.
	ReducerModel *string
	// ReducerPrompt configures the reducer prompt.
	ReducerPrompt *string
	// Extra contains additional JSON body fields to forward to TrustedRouter.
	Extra map[string]any
	// CallOptions configures per-call headers, auth, workspace, and idempotency.
	CallOptions
}

// FusionRequest configures a TrustedRouter Fusion request.
type FusionRequest struct {
	// Messages is the OpenAI-compatible chat messages array.
	Messages []map[string]any
	// Tools is an optional OpenAI-compatible tools array to send before the Fusion tool.
	Tools []map[string]any
	// AnalysisModels is the Fusion analysis panel.
	AnalysisModels []string
	// Model is the judge or synthesis model.
	Model *string
	// SelectionStrategy configures Fusion selection.
	SelectionStrategy *string
	// FallbackJudges configures fallback judges.
	FallbackJudges []string
	// FallbackFinalModels configures fallback final models.
	FallbackFinalModels []string
	// MaxCompletionTokens configures Fusion max completion tokens.
	MaxCompletionTokens *int
	// MaxToolCalls configures Fusion max tool calls.
	MaxToolCalls *int
	// Preset configures a Fusion preset.
	Preset *string
	// Extra contains additional JSON body fields to forward to TrustedRouter.
	Extra map[string]any
	// CallOptions configures per-call headers, auth, workspace, idempotency, and timeout.
	CallOptions
}

// MarshalJSON encodes the request body sent to the chat completions endpoint.
func (r ChatRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(buildChatBody(r, false))
}

// ChatMessage is an OpenAI-compatible chat completion message.
type ChatMessage struct {
	// Role is the message role.
	Role string `json:"role"`
	// Content is the message content; nil represents JSON null.
	Content *string `json:"content"`
	// Name is the optional participant name.
	Name *string `json:"name,omitempty"`
	// ToolCalls contains assistant tool calls.
	ToolCalls []map[string]any `json:"tool_calls,omitempty"`
	// ToolCallID is the ID of the tool call this message answers.
	ToolCallID *string `json:"tool_call_id,omitempty"`
	// Extra contains unknown message fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes a chat message and preserves unknown fields in Extra.
func (m *ChatMessage) UnmarshalJSON(data []byte) error {
	type alias ChatMessage
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*m = ChatMessage(out)
	m.Extra = extraFields(data, "role", "content", "name", "tool_calls", "tool_call_id")
	return nil
}

// MarshalJSON encodes a chat message and includes unknown Extra fields.
func (m ChatMessage) MarshalJSON() ([]byte, error) {
	fields := map[string]any{"role": m.Role, "content": m.Content}
	if m.Name != nil {
		fields["name"] = *m.Name
	}
	if m.ToolCalls != nil {
		fields["tool_calls"] = m.ToolCalls
	}
	if m.ToolCallID != nil {
		fields["tool_call_id"] = *m.ToolCallID
	}
	return marshalObject(fields, m.Extra)
}

// ChatChoice is one non-streaming chat completion choice.
type ChatChoice struct {
	// Index is the choice index.
	Index int `json:"index"`
	// Message is the assistant message.
	Message ChatMessage `json:"message"`
	// FinishReason is the provider finish reason.
	FinishReason *string `json:"finish_reason,omitempty"`
	// Logprobs contains optional log probability metadata.
	Logprobs map[string]any `json:"logprobs,omitempty"`
	// Extra contains unknown choice fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes a chat choice and preserves unknown fields in Extra.
func (c *ChatChoice) UnmarshalJSON(data []byte) error {
	type alias ChatChoice
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*c = ChatChoice(out)
	c.Extra = extraFields(data, "index", "message", "finish_reason", "logprobs")
	return nil
}

// MarshalJSON encodes a chat choice and includes unknown Extra fields.
func (c ChatChoice) MarshalJSON() ([]byte, error) {
	fields := map[string]any{"index": c.Index, "message": c.Message}
	if c.FinishReason != nil {
		fields["finish_reason"] = *c.FinishReason
	}
	if c.Logprobs != nil {
		fields["logprobs"] = c.Logprobs
	}
	return marshalObject(fields, c.Extra)
}

// ChatUsage is OpenAI-compatible token usage metadata.
type ChatUsage struct {
	// PromptTokens is the prompt token count.
	PromptTokens int `json:"prompt_tokens"`
	// CompletionTokens is the completion token count.
	CompletionTokens int `json:"completion_tokens"`
	// TotalTokens is the total token count.
	TotalTokens int `json:"total_tokens"`
	// Extra contains unknown usage fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes chat usage and preserves unknown fields in Extra.
func (u *ChatUsage) UnmarshalJSON(data []byte) error {
	type alias ChatUsage
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*u = ChatUsage(out)
	u.Extra = extraFields(data, "prompt_tokens", "completion_tokens", "total_tokens")
	return nil
}

// MarshalJSON encodes chat usage and includes unknown Extra fields.
func (u ChatUsage) MarshalJSON() ([]byte, error) {
	return marshalObject(map[string]any{
		"prompt_tokens":     u.PromptTokens,
		"completion_tokens": u.CompletionTokens,
		"total_tokens":      u.TotalTokens,
	}, u.Extra)
}

// ChatCompletion is an OpenAI-compatible chat.completion response.
type ChatCompletion struct {
	// ID is the completion ID.
	ID string `json:"id"`
	// Object is the response object type.
	Object string `json:"object"`
	// Created is the creation timestamp.
	Created int `json:"created,omitempty"`
	// Model is the model that produced the completion.
	Model string `json:"model,omitempty"`
	// Choices contains completion choices.
	Choices []ChatChoice `json:"choices"`
	// Usage contains token usage when the gateway streamed it.
	Usage *ChatUsage `json:"usage,omitempty"`
	// Extra contains unknown response fields, including TrustedRouter metadata.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes a chat completion and preserves unknown fields in Extra.
func (c *ChatCompletion) UnmarshalJSON(data []byte) error {
	type alias ChatCompletion
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*c = ChatCompletion(out)
	c.Extra = extraFields(data, "id", "object", "created", "model", "choices", "usage")
	return nil
}

// MarshalJSON encodes a chat completion and includes unknown Extra fields.
func (c ChatCompletion) MarshalJSON() ([]byte, error) {
	fields := map[string]any{
		"id":      c.ID,
		"object":  c.Object,
		"created": c.Created,
		"model":   c.Model,
		"choices": c.Choices,
	}
	if c.Usage != nil {
		fields["usage"] = c.Usage
	}
	return marshalObject(fields, c.Extra)
}

// ChatChoiceDelta is a streamed chat completion delta.
type ChatChoiceDelta struct {
	// Role is the streamed role when present.
	Role *string `json:"role,omitempty"`
	// Content is the streamed text delta when present.
	Content *string `json:"content,omitempty"`
	// ToolCalls contains streamed tool-call fragments.
	ToolCalls []map[string]any `json:"tool_calls,omitempty"`
	// Extra contains unknown delta fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes a chat delta and preserves unknown fields in Extra.
func (d *ChatChoiceDelta) UnmarshalJSON(data []byte) error {
	type alias ChatChoiceDelta
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*d = ChatChoiceDelta(out)
	d.Extra = extraFields(data, "role", "content", "tool_calls")
	return nil
}

// MarshalJSON encodes a chat delta and includes unknown Extra fields.
func (d ChatChoiceDelta) MarshalJSON() ([]byte, error) {
	fields := map[string]any{}
	if d.Role != nil {
		fields["role"] = *d.Role
	}
	if d.Content != nil {
		fields["content"] = *d.Content
	}
	if d.ToolCalls != nil {
		fields["tool_calls"] = d.ToolCalls
	}
	return marshalObject(fields, d.Extra)
}

// ChatChoiceChunk is one streamed chat completion choice chunk.
type ChatChoiceChunk struct {
	// Index is the choice index.
	Index int `json:"index,omitempty"`
	// Delta is the streamed choice delta.
	Delta ChatChoiceDelta `json:"delta,omitempty"`
	// FinishReason is the provider finish reason when present.
	FinishReason *string `json:"finish_reason,omitempty"`
	// Extra contains unknown choice chunk fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes a choice chunk and preserves unknown fields in Extra.
func (c *ChatChoiceChunk) UnmarshalJSON(data []byte) error {
	type alias ChatChoiceChunk
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*c = ChatChoiceChunk(out)
	c.Extra = extraFields(data, "index", "delta", "finish_reason")
	return nil
}

// MarshalJSON encodes a choice chunk and includes unknown Extra fields.
func (c ChatChoiceChunk) MarshalJSON() ([]byte, error) {
	fields := map[string]any{"index": c.Index, "delta": c.Delta}
	if c.FinishReason != nil {
		fields["finish_reason"] = *c.FinishReason
	}
	return marshalObject(fields, c.Extra)
}

// ChatCompletionChunk is one streamed chat.completion.chunk SSE frame.
type ChatCompletionChunk struct {
	// ID is the chunk ID.
	ID string `json:"id,omitempty"`
	// Object is the streamed object type.
	Object string `json:"object,omitempty"`
	// Created is the creation timestamp.
	Created int `json:"created,omitempty"`
	// Model is the model that produced the chunk.
	Model string `json:"model,omitempty"`
	// Choices contains streamed choices.
	Choices []ChatChoiceChunk `json:"choices"`
	// Usage contains trailing streamed usage when present.
	Usage *ChatUsage `json:"usage,omitempty"`
	// Extra contains unknown chunk fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes a completion chunk and preserves unknown fields in Extra.
func (c *ChatCompletionChunk) UnmarshalJSON(data []byte) error {
	type alias ChatCompletionChunk
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*c = ChatCompletionChunk(out)
	c.Extra = extraFields(data, "id", "object", "created", "model", "choices", "usage")
	return nil
}

// MarshalJSON encodes a completion chunk and includes unknown Extra fields.
func (c ChatCompletionChunk) MarshalJSON() ([]byte, error) {
	fields := map[string]any{
		"id":      c.ID,
		"object":  c.Object,
		"created": c.Created,
		"model":   c.Model,
		"choices": c.Choices,
	}
	if c.Usage != nil {
		fields["usage"] = c.Usage
	}
	return marshalObject(fields, c.Extra)
}

// ChatCompletions collects a streamed TrustedRouter chat response into a chat completion.
func (c *Client) ChatCompletions(ctx context.Context, req ChatRequest) (*ChatCompletion, error) {
	var chunks []ChatCompletionChunk
	for chunk, err := range c.chatCompletionsChunks(ctx, req, true) {
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, chunk)
	}
	return CollectCompletion(chunks), nil
}

// ChatCompletionsChunks streams parsed chat.completion.chunk frames.
func (c *Client) ChatCompletionsChunks(ctx context.Context, req ChatRequest) iter.Seq2[ChatCompletionChunk, error] {
	return c.chatCompletionsChunks(ctx, req, false)
}

// ChatCompletionsText streams assistant text deltas.
func (c *Client) ChatCompletionsText(ctx context.Context, req ChatRequest) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		for chunk, err := range c.ChatCompletionsChunks(ctx, req) {
			if err != nil {
				yield("", err)
				return
			}
			// Divergence from trusted-router-py: ChatCompletionsText tolerates only struct-decodable chunks.
			if len(chunk.Choices) == 0 || chunk.Choices[0].Delta.Content == nil {
				continue
			}
			text := *chunk.Choices[0].Delta.Content
			if text != "" && !yield(text, nil) {
				return
			}
		}
	}
}

// ChatCompletionsRawStream opens a raw SSE stream for a chat completions request.
// The caller must close the returned stream.
func (c *Client) ChatCompletionsRawStream(ctx context.Context, req ChatRequest) (io.ReadCloser, error) {
	resp, err := c.openChatStream(ctx, req, false)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// Fusion runs a request through TrustedRouter Fusion and collects the streamed completion.
func (c *Client) Fusion(ctx context.Context, req FusionRequest) (*ChatCompletion, error) {
	extra := cloneMap(req.Extra)
	tools := make([]any, 0, len(req.Tools)+len(toolsFromValue(extra["tools"]))+1)
	for _, tool := range req.Tools {
		tools = append(tools, tool)
	}
	tools = append(tools, toolsFromValue(extra["tools"])...)
	tools = append(tools, FusionTool(FusionToolOptions{
		AnalysisModels:      req.AnalysisModels,
		Model:               req.Model,
		SelectionStrategy:   req.SelectionStrategy,
		FallbackJudges:      req.FallbackJudges,
		FallbackFinalModels: req.FallbackFinalModels,
		MaxCompletionTokens: req.MaxCompletionTokens,
		MaxToolCalls:        req.MaxToolCalls,
		Preset:              req.Preset,
	}))
	extra["tools"] = tools

	callOpts := req.CallOptions
	if callOpts.Timeout == nil {
		if timeout, ok := timeoutExtra(extra, "timeout"); ok {
			callOpts.Timeout = &timeout
		} else {
			timeout := DefaultFusionTimeout
			callOpts.Timeout = &timeout
		}
	}
	return c.ChatCompletions(ctx, ChatRequest{
		Model:       FusionModel,
		Messages:    req.Messages,
		Extra:       extra,
		CallOptions: callOpts,
	})
}

// CollectCompletion reconstructs a non-streaming chat completion from streamed chunks.
func CollectCompletion(chunks []ChatCompletionChunk) *ChatCompletion {
	if len(chunks) == 0 {
		content := ""
		finish := "stop"
		return &ChatCompletion{
			ID:     "",
			Object: "chat.completion",
			Choices: []ChatChoice{{
				Index:        0,
				Message:      ChatMessage{Role: "assistant", Content: &content},
				FinishReason: &finish,
			}},
		}
	}

	var textParts []string
	var finishReason *string
	role := "assistant"
	var usage *ChatUsage
	trustedrouter := collectTrustedRouterMetadata(chunks)
	toolCalls := map[int]map[string]any{}

	for _, chunk := range chunks {
		if chunk.Usage != nil {
			usage = chunk.Usage
		}
		if len(chunk.Choices) == 0 {
			continue
		}
		choice := chunk.Choices[0]
		if choice.Delta.Role != nil {
			role = *choice.Delta.Role
		}
		if choice.Delta.Content != nil {
			textParts = append(textParts, *choice.Delta.Content)
		}
		for _, tc := range choice.Delta.ToolCalls {
			idx := toolCallIndex(tc)
			slot, ok := toolCalls[idx]
			if !ok {
				slot = map[string]any{
					"index": idx,
					"type":  "function",
					"function": map[string]any{
						"name":      "",
						"arguments": "",
					},
				}
				toolCalls[idx] = slot
			}
			if id, ok := nonEmptyString(tc["id"]); ok {
				slot["id"] = id
			}
			if typ, ok := nonEmptyString(tc["type"]); ok {
				slot["type"] = typ
			}
			if fn, ok := tc["function"].(map[string]any); ok {
				slotFn, _ := slot["function"].(map[string]any)
				if name, ok := nonEmptyString(fn["name"]); ok {
					slotFn["name"] = name
				}
				if args, ok := fn["arguments"].(string); ok {
					existing, _ := slotFn["arguments"].(string)
					slotFn["arguments"] = existing + args
				}
			}
		}
		if choice.FinishReason != nil && *choice.FinishReason != "" {
			value := *choice.FinishReason
			finishReason = &value
		}
	}

	content := strings.Join(textParts, "")
	message := ChatMessage{Role: role}
	if content != "" {
		message.Content = &content
	} else if len(toolCalls) == 0 {
		empty := ""
		message.Content = &empty
	}
	if len(toolCalls) > 0 {
		indexes := make([]int, 0, len(toolCalls))
		for idx := range toolCalls {
			indexes = append(indexes, idx)
		}
		sort.Ints(indexes)
		message.ToolCalls = make([]map[string]any, 0, len(indexes))
		for _, idx := range indexes {
			message.ToolCalls = append(message.ToolCalls, toolCalls[idx])
		}
	}

	if finishReason == nil {
		value := "stop"
		finishReason = &value
	}
	last := chunks[len(chunks)-1]
	result := &ChatCompletion{
		ID:      last.ID,
		Object:  "chat.completion",
		Created: last.Created,
		Model:   last.Model,
		Choices: []ChatChoice{{
			Index:        0,
			Message:      message,
			FinishReason: finishReason,
		}},
		Usage: usage,
	}
	if trustedrouter != nil {
		result.Extra = map[string]any{"trustedrouter": trustedrouter}
	}
	return result
}

func (c *Client) chatCompletionsChunks(ctx context.Context, req ChatRequest, includeUsage bool) iter.Seq2[ChatCompletionChunk, error] {
	return func(yield func(ChatCompletionChunk, error) bool) {
		resp, err := c.openChatStream(ctx, req, includeUsage)
		if err != nil {
			yield(ChatCompletionChunk{}, err)
			return
		}
		defer resp.Body.Close()

		for event, err := range iterSSEChunks(resp.Body) {
			if err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					yield(ChatCompletionChunk{}, ctxErr)
					return
				}
				yield(ChatCompletionChunk{}, transportRetryError(err))
				return
			}
			data, err := json.Marshal(event)
			if err != nil {
				yield(ChatCompletionChunk{}, err)
				return
			}
			var chunk ChatCompletionChunk
			if err := json.Unmarshal(data, &chunk); err != nil {
				yield(ChatCompletionChunk{}, err)
				return
			}
			if !yield(chunk, nil) {
				return
			}
		}
	}
}

func (c *Client) openChatStream(ctx context.Context, req ChatRequest, includeUsage bool) (*http.Response, error) {
	callOpts := chatCallOptions(req)
	timeout, hasTimeout := c.effectiveTimeout(&callOpts)

	body := buildChatBody(req, includeUsage)
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	if callOpts.IdempotencyKey == "" {
		callOpts.IdempotencyKey = newIdempotencyKey()
	}
	headers := map[string]string{"accept": "text/event-stream"}
	for key, value := range callOpts.ExtraHeaders {
		headers[key] = value
	}
	callOpts.ExtraHeaders = headers

	attempt := 0
	baseIndex := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		attemptCtx, cancelAttempt := context.WithCancelCause(ctx)
		var openTimer *time.Timer
		if hasTimeout {
			openTimer = time.AfterFunc(timeout, func() {
				cancelAttempt(errOpenTimeout)
			})
		}
		url := joinURL(c.baseURLs[baseIndex], "/chat/completions")
		httpReq, err := c.newHTTPRequest(attemptCtx, http.MethodPost, url, bodyBytes, true, &callOpts)
		if err != nil {
			stopTimer(openTimer)
			cancelAttempt(nil)
			return nil, err
		}
		resp, err := c.httpClient.Do(httpReq)
		stopTimer(openTimer)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				cancelAttempt(nil)
				return nil, ctxErr
			}
			if errors.Is(context.Cause(attemptCtx), errOpenTimeout) {
				err = errOpenTimeout
			}
			if attempt >= c.maxRetries {
				cancelAttempt(nil)
				return nil, transportRetryError(err)
			}
			if baseIndex < len(c.baseURLs)-1 {
				baseIndex++
			}
			cancelAttempt(nil)
			if sleepErr := sleepForRetry(ctx, attempt, nil); sleepErr != nil {
				return nil, sleepErr
			}
			attempt++
			continue
		}
		if resp.StatusCode >= 400 {
			if attempt < c.maxRetries && regionalFailoverable(resp.StatusCode) && baseIndex < len(c.baseURLs)-1 {
				retryAfter := retryAfterSeconds(resp.Header)
				drainAndClose(resp.Body)
				cancelAttempt(nil)
				baseIndex++
				if sleepErr := sleepForRetry(ctx, attempt, retryAfter); sleepErr != nil {
					return nil, sleepErr
				}
				attempt++
				continue
			}
			err := raiseForStreamResponse(resp)
			cancelAttempt(nil)
			return nil, err
		}
		if hasTimeout {
			resp.Body = newStreamIdleTimeoutReadCloser(resp.Body, attemptCtx, cancelAttempt, timeout)
		} else {
			resp.Body = cancelCauseOnCloseReadCloser{ReadCloser: resp.Body, cancel: cancelAttempt}
		}
		return resp, nil
	}
}

func chatCallOptions(req ChatRequest) CallOptions {
	callOpts := req.CallOptions
	extra := req.Extra
	if callOpts.APIKey == nil {
		if value, ok := stringExtra(extra, "api_key"); ok {
			callOpts.APIKey = &value
		}
	}
	if callOpts.WorkspaceID == nil {
		if value, ok := stringExtra(extra, "workspace_id"); ok {
			callOpts.WorkspaceID = &value
		}
	}
	if callOpts.IdempotencyKey == "" {
		if value, ok := stringExtra(extra, "idempotency_key"); ok {
			callOpts.IdempotencyKey = value
		}
	}
	if callOpts.Timeout == nil {
		if timeout, ok := timeoutExtra(extra, "timeout"); ok {
			callOpts.Timeout = &timeout
		}
	}
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
	return callOpts
}

func timeoutExtra(extra map[string]any, key string) (time.Duration, bool) {
	value, ok := extra[key]
	if !ok {
		return 0, false
	}
	switch v := value.(type) {
	case int:
		return time.Duration(v) * time.Second, true
	case float64:
		return time.Duration(v * float64(time.Second)), true
	default:
		return 0, false
	}
}

func stringExtra(extra map[string]any, key string) (string, bool) {
	value, ok := extra[key]
	if !ok {
		return "", false
	}
	s, ok := value.(string)
	return s, ok
}

func headersExtra(extra map[string]any, key string) map[string]string {
	value, ok := extra[key]
	if !ok {
		return nil
	}
	switch headers := value.(type) {
	case map[string]string:
		out := make(map[string]string, len(headers))
		for key, value := range headers {
			out[key] = value
		}
		return out
	case map[string]any:
		out := make(map[string]string, len(headers))
		for key, value := range headers {
			if s, ok := value.(string); ok {
				out[key] = s
			}
		}
		return out
	default:
		return nil
	}
}

func buildChatBody(req ChatRequest, includeUsage bool) map[string]any {
	model := req.Model
	if model == "" {
		model = AutoModel
	}
	params := chatParams(req)
	if includeUsage {
		params = withUsage(params)
	}
	params = moveOrchestrationOptionsIntoTools(model, params)

	body := map[string]any{
		"model":    model,
		"messages": req.Messages,
		"stream":   true,
	}
	for key, value := range params {
		body[key] = value
	}
	return body
}

func chatParams(req ChatRequest) map[string]any {
	params := map[string]any{}
	tools := make([]any, 0, len(req.Tools)+len(toolsFromValue(req.Extra["tools"])))
	for _, tool := range req.Tools {
		tools = append(tools, tool)
	}
	tools = append(tools, toolsFromValue(req.Extra["tools"])...)
	if len(tools) > 0 || req.Tools != nil {
		params["tools"] = tools
	}
	setSlice(params, "worker_models", req.WorkerModels)
	setSlice(params, "advisor_models", req.AdvisorModels)
	setPtr(params, "depth", req.Depth)
	setPtr(params, "max_get_advice_calls", req.MaxGetAdviceCalls)
	setPtr(params, "advisor_max_tokens", req.AdvisorMaxTokens)
	setPtr(params, "advisor_timeout_ms", req.AdvisorTimeoutMs)
	setSlice(params, "analysis_models", req.AnalysisModels)
	setPtr(params, "judge_model", req.JudgeModel)
	setPtr(params, "selection_strategy", req.SelectionStrategy)
	setSlice(params, "fallback_judges", req.FallbackJudges)
	setSlice(params, "fallback_final_models", req.FallbackFinalModels)
	setPtr(params, "max_completion_tokens", req.MaxCompletionTokens)
	setPtr(params, "max_tool_calls", req.MaxToolCalls)
	setPtr(params, "preset", req.Preset)
	setPtr(params, "panel_prompt", req.PanelPrompt)
	setPtr(params, "synthesis_prompt", req.SynthesisPrompt)
	setPtr(params, "final_prompt", req.FinalPrompt)
	setSlice(params, "selector_models", req.SelectorModels)
	setPtr(params, "selector_model", req.SelectorModel)
	setPtr(params, "selector_prompt", req.SelectorPrompt)
	setSlice(params, "mapper_models", req.MapperModels)
	setPtr(params, "mapper_model", req.MapperModel)
	setPtr(params, "mapper_prompt", req.MapperPrompt)
	setSlice(params, "parallel_models", req.ParallelModels)
	setPtr(params, "parallel_model", req.ParallelModel)
	setPtr(params, "parallel_prompt", req.ParallelPrompt)
	setSlice(params, "reducer_models", req.ReducerModels)
	setPtr(params, "reducer_model", req.ReducerModel)
	setPtr(params, "reducer_prompt", req.ReducerPrompt)

	for key, value := range req.Extra {
		if key == "tools" {
			continue
		}
		params[key] = value
	}
	delete(params, "api_key")
	delete(params, "extra_headers")
	delete(params, "idempotency_key")
	delete(params, "timeout")
	delete(params, "workspace_id")
	return params
}

func setPtr[T any](params map[string]any, key string, value *T) {
	if value != nil {
		params[key] = *value
	}
}

func setSlice(params map[string]any, key string, value []string) {
	if value != nil {
		params[key] = append([]string(nil), value...)
	}
}

func withUsage(params map[string]any) map[string]any {
	merged := cloneMap(params)
	streamOptions := map[string]any{}
	if existing, ok := merged["stream_options"].(map[string]any); ok {
		for key, value := range existing {
			streamOptions[key] = value
		}
	}
	if _, exists := streamOptions["include_usage"]; !exists {
		streamOptions["include_usage"] = true
	}
	merged["stream_options"] = streamOptions
	return merged
}

func moveOrchestrationOptionsIntoTools(model string, params map[string]any) map[string]any {
	out := cloneMap(params)
	tools := toolsFromValue(out["tools"])
	delete(out, "tools")

	advisorKeys := []string{
		"depth",
		"worker_models",
		"advisor_models",
		"max_get_advice_calls",
		"advisor_max_tokens",
		"advisor_timeout_ms",
	}
	advisorValues := map[string]any{}
	for _, key := range advisorKeys {
		value, ok := out[key]
		if !ok {
			continue
		}
		delete(out, key)
		if value != nil {
			advisorValues[key] = value
		}
	}
	if len(advisorValues) > 0 {
		tools = append(tools, map[string]any{"type": "trustedrouter:advisor", "parameters": advisorValues})
	}

	fusionKeyMap := map[string]string{
		"analysis_models":       "analysis_models",
		"judge_model":           "model",
		"selection_strategy":    "selection_strategy",
		"fallback_judges":       "fallback_judges",
		"fallback_final_models": "fallback_final_models",
		"max_completion_tokens": "max_completion_tokens",
		"max_tool_calls":        "max_tool_calls",
		"preset":                "preset",
		"panel_prompt":          "panel_prompt",
		"synthesis_prompt":      "synthesis_prompt",
		"final_prompt":          "final_prompt",
		"selector_models":       "selector_models",
		"selector_model":        "selector_model",
		"selector_prompt":       "selector_prompt",
		"mapper_models":         "mapper_models",
		"mapper_model":          "mapper_model",
		"mapper_prompt":         "mapper_prompt",
		"parallel_models":       "parallel_models",
		"parallel_model":        "parallel_model",
		"parallel_prompt":       "parallel_prompt",
		"reducer_models":        "reducer_models",
		"reducer_model":         "reducer_model",
		"reducer_prompt":        "reducer_prompt",
	}
	fusionValues := map[string]any{}
	for sdkKey, gatewayKey := range fusionKeyMap {
		value, ok := out[sdkKey]
		if !ok {
			continue
		}
		delete(out, sdkKey)
		if value != nil {
			fusionValues[gatewayKey] = value
		}
	}
	if len(fusionValues) > 0 {
		tools = append(tools, map[string]any{"type": "trustedrouter:fusion", "parameters": fusionValues})
	}

	normalized := strings.ToLower(strings.TrimSpace(model))
	_, isAdvisor := advisorModels[normalized]
	_, isFusionPrimitive := fusionPrimitiveModels[normalized]
	if len(tools) > 0 {
		out["tools"] = tools
	} else if isAdvisor || isFusionPrimitive {
		delete(out, "tools")
	}
	return out
}

func toolsFromValue(value any) []any {
	switch v := value.(type) {
	case nil:
		return nil
	case []any:
		return append([]any(nil), v...)
	case []map[string]any:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, item)
		}
		return out
	default:
		return []any{v}
	}
}

type cancelCauseOnCloseReadCloser struct {
	io.ReadCloser
	cancel context.CancelCauseFunc
}

func (r cancelCauseOnCloseReadCloser) Close() error {
	err := r.ReadCloser.Close()
	r.cancel(nil)
	return err
}

type streamIdleTimeoutReadCloser struct {
	body    io.ReadCloser
	ctx     context.Context
	cancel  context.CancelCauseFunc
	timeout time.Duration
	timer   *time.Timer
	mu      sync.Mutex
	closed  bool
}

func newStreamIdleTimeoutReadCloser(body io.ReadCloser, ctx context.Context, cancel context.CancelCauseFunc, timeout time.Duration) io.ReadCloser {
	r := &streamIdleTimeoutReadCloser{
		body:    body,
		ctx:     ctx,
		cancel:  cancel,
		timeout: timeout,
	}
	r.timer = time.AfterFunc(timeout, func() {
		cancel(errStreamIdleTimeout)
	})
	return r
}

func (r *streamIdleTimeoutReadCloser) Read(p []byte) (int, error) {
	n, err := r.body.Read(p)
	if n > 0 {
		r.reset()
	}
	if err != nil {
		r.stop()
		if errors.Is(context.Cause(r.ctx), errStreamIdleTimeout) {
			err = errStreamIdleTimeout
		}
	}
	return n, err
}

func (r *streamIdleTimeoutReadCloser) Close() error {
	r.stop()
	err := r.body.Close()
	r.cancel(nil)
	return err
}

func (r *streamIdleTimeoutReadCloser) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.timer.Reset(r.timeout)
	}
}

func (r *streamIdleTimeoutReadCloser) stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		r.timer.Stop()
	}
}

func stopTimer(timer *time.Timer) {
	if timer != nil {
		timer.Stop()
	}
}

func collectTrustedRouterMetadata(chunks []ChatCompletionChunk) map[string]any {
	var synthEvents []map[string]any
	synthDetails := map[string]any{}

	for _, chunk := range chunks {
		trusted, ok := chunk.Extra["trustedrouter"].(map[string]any)
		if !ok {
			continue
		}
		synth, ok := trusted["synth"].(map[string]any)
		if !ok {
			continue
		}
		synthCopy := cloneMap(synth)
		if _, hasEvent := synthCopy["event"]; hasEvent {
			synthEvents = append(synthEvents, synthCopy)
		} else {
			for key, value := range synthCopy {
				synthDetails[key] = value
			}
		}
	}

	if len(synthEvents) == 0 && len(synthDetails) == 0 {
		return nil
	}

	synthOut := cloneMap(synthDetails)
	if len(synthEvents) > 0 {
		events := make([]any, 0, len(synthEvents))
		for _, event := range synthEvents {
			events = append(events, event)
		}
		synthOut["events"] = events
	}

	var panel []any
	var judgeAttempts []any
	var finalAttempts []any
	for _, event := range synthEvents {
		detail := trustedRouterSynthEventDetail(event)
		if detail == nil {
			continue
		}
		switch event["event"] {
		case "panel.done":
			panel = append(panel, detail)
		case "judge.done":
			judgeAttempts = append(judgeAttempts, detail)
		case "final.done":
			finalAttempts = append(finalAttempts, detail)
		}
	}
	if len(panel) > 0 {
		if _, exists := synthOut["panel"]; !exists {
			synthOut["panel"] = panel
		}
	}
	if len(judgeAttempts) > 0 {
		if _, exists := synthOut["judge_attempts"]; !exists {
			synthOut["judge_attempts"] = judgeAttempts
		}
		if _, exists := synthOut["judge"]; !exists {
			synthOut["judge"] = judgeAttempts[len(judgeAttempts)-1]
		}
	}
	if len(finalAttempts) > 0 {
		if _, exists := synthOut["final_attempts"]; !exists {
			synthOut["final_attempts"] = finalAttempts
		}
	}

	return map[string]any{"synth": synthOut}
}

func trustedRouterSynthEventDetail(event map[string]any) map[string]any {
	detail, ok := event["detail"].(map[string]any)
	if !ok {
		return nil
	}
	out := cloneMap(detail)
	for _, key := range []string{"stage", "index", "model"} {
		if _, exists := out[key]; !exists {
			if value, ok := event[key]; ok {
				out[key] = value
			}
		}
	}
	return out
}

func toolCallIndex(tc map[string]any) int {
	switch value := tc["index"].(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	case json.Number:
		parsed, _ := value.Int64()
		return int(parsed)
	default:
		return 0
	}
}

func nonEmptyString(value any) (string, bool) {
	s, ok := value.(string)
	return s, ok && s != ""
}

func cloneMap(in map[string]any) map[string]any {
	out := map[string]any{}
	for key, value := range in {
		out[key] = value
	}
	return out
}

func marshalObject(fields map[string]any, extra map[string]any) ([]byte, error) {
	out := map[string]any{}
	for key, value := range extra {
		out[key] = value
	}
	for key, value := range fields {
		out[key] = value
	}
	return json.Marshal(out)
}
