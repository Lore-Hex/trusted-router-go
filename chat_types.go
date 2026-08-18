package trustedrouter

// chat_types.go holds the chat wire types (L5/L7 data): request structs,
// Extra-preserving codecs for every chunk/choice/usage shape, and the
// stream→completion collector. Pure data transforms — no retry logic, no I/O.

import (
	"encoding/json"
	"sort"
	"strings"
)

// ChatRequest configures a chat completions request.
type ChatRequest struct {
	// Model is the model ID; empty defaults to AutoModel.
	Model string
	// Messages is the OpenAI-compatible chat messages array.
	Messages []map[string]any
	// Tools is an optional OpenAI-compatible tools array.
	Tools []map[string]any
	// Provider configures typed provider routing and privacy requirements.
	Provider *ProviderPreferences
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
	// WorkerTimeoutMs configures the Advisor worker timeout in milliseconds.
	WorkerTimeoutMs *int
	// AdvisorTimeoutMs configures the Advisor timeout in milliseconds.
	AdvisorTimeoutMs *int
	// AutoInitialAdvice asks advisors before the first worker turn.
	AutoInitialAdvice *bool
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

	var usage *ChatUsage
	trustedrouter := collectTrustedRouterMetadata(chunks)
	states := map[int]*completionChoiceState{}
	result := &ChatCompletion{Object: "chat.completion"}
	resultExtra := map[string]any{}

	for _, chunk := range chunks {
		if chunk.ID != "" {
			result.ID = chunk.ID
		}
		if chunk.Created != 0 {
			result.Created = chunk.Created
		}
		if chunk.Model != "" {
			result.Model = chunk.Model
		}
		if chunk.Usage != nil {
			usage = chunk.Usage
		}
		for key, value := range chunk.Extra {
			resultExtra[key] = value
		}
		for _, choice := range chunk.Choices {
			state, ok := states[choice.Index]
			if !ok {
				state = &completionChoiceState{
					index:        choice.Index,
					role:         "assistant",
					toolCalls:    map[int]map[string]any{},
					messageExtra: map[string]any{},
					choiceExtra:  map[string]any{},
				}
				states[choice.Index] = state
			}
			if choice.Delta.Role != nil {
				state.role = *choice.Delta.Role
			}
			if choice.Delta.Content != nil {
				state.textParts = append(state.textParts, *choice.Delta.Content)
			}
			for key, value := range choice.Delta.Extra {
				mergeCompletionField(state.messageExtra, key, value)
			}
			for key, value := range choice.Extra {
				mergeCompletionField(state.choiceExtra, key, value)
			}
			for _, tc := range choice.Delta.ToolCalls {
				idx := toolCallIndex(tc)
				slot, ok := state.toolCalls[idx]
				if !ok {
					slot = map[string]any{
						"index": idx,
						"type":  "function",
						"function": map[string]any{
							"name":      "",
							"arguments": "",
						},
					}
					state.toolCalls[idx] = slot
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
				state.finishReason = &value
			}
		}
	}

	if len(states) == 0 {
		states[0] = &completionChoiceState{
			index: 0, role: "assistant", toolCalls: map[int]map[string]any{},
			messageExtra: map[string]any{}, choiceExtra: map[string]any{},
		}
	}
	choiceIndexes := make([]int, 0, len(states))
	for index := range states {
		choiceIndexes = append(choiceIndexes, index)
	}
	sort.Ints(choiceIndexes)
	result.Choices = make([]ChatChoice, 0, len(choiceIndexes))
	for _, choiceIndex := range choiceIndexes {
		state := states[choiceIndex]
		content := strings.Join(state.textParts, "")
		message := ChatMessage{Role: state.role, Extra: state.messageExtra}
		if content != "" {
			message.Content = &content
		} else if len(state.toolCalls) == 0 {
			empty := ""
			message.Content = &empty
		}
		if len(state.toolCalls) > 0 {
			toolIndexes := make([]int, 0, len(state.toolCalls))
			for index := range state.toolCalls {
				toolIndexes = append(toolIndexes, index)
			}
			sort.Ints(toolIndexes)
			message.ToolCalls = make([]map[string]any, 0, len(toolIndexes))
			for _, index := range toolIndexes {
				message.ToolCalls = append(message.ToolCalls, state.toolCalls[index])
			}
		}
		if state.finishReason == nil {
			value := "stop"
			state.finishReason = &value
		}
		choice := ChatChoice{
			Index: choiceIndex, Message: message, FinishReason: state.finishReason,
			Extra: state.choiceExtra,
		}
		if logprobs, ok := state.choiceExtra["logprobs"].(map[string]any); ok {
			choice.Logprobs = logprobs
			delete(choice.Extra, "logprobs")
		}
		result.Choices = append(result.Choices, choice)
	}
	result.Usage = usage
	if trustedrouter != nil {
		resultExtra["trustedrouter"] = trustedrouter
	}
	if len(resultExtra) > 0 {
		result.Extra = resultExtra
	}
	return result
}

type completionChoiceState struct {
	index        int
	role         string
	textParts    []string
	finishReason *string
	toolCalls    map[int]map[string]any
	messageExtra map[string]any
	choiceExtra  map[string]any
}

func mergeCompletionField(target map[string]any, key string, value any) {
	if value == nil {
		return
	}
	existing, present := target[key]
	if !present {
		target[key] = value
		return
	}
	switch next := value.(type) {
	case string:
		if prior, ok := existing.(string); ok {
			target[key] = prior + next
			return
		}
	case []any:
		if prior, ok := existing.([]any); ok {
			target[key] = append(prior, next...)
			return
		}
	case map[string]any:
		if prior, ok := existing.(map[string]any); ok {
			for nestedKey, nestedValue := range next {
				mergeCompletionField(prior, nestedKey, nestedValue)
			}
			return
		}
	}
	target[key] = value
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
