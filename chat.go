package trustedrouter

// chat.go is a CLIENT FACADE (L8): chat endpoint wrappers and body builders
// only. The stream adapters openChatStream/openEventStream are THIN — they
// build the request body and headers and delegate to the transport engine
// (transport.go do()), which owns every retry, every candidate advance, and
// every sleep. Zero loops, zero sleeps, zero candidate indexes here.

import (
	"context"
	"encoding/json"
	"io"
	"iter"
	"net/http"
)

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
	body := buildChatBody(req, includeUsage)
	return c.openEventStream(ctx, http.MethodPost, "/chat/completions", body, callOpts)
}

// openEventStream opens an SSE stream through the transport engine. Stream
// opens get the full inference-plane semantics — the candidate walk, the
// retryable()/x-should-retry consult, retry-after honoring, and pinned
// in-place retries — identical to the buffered path, because both are the
// same do() loop. Retries can only happen before the stream is surfaced to
// the caller; once open, a broken stream propagates (invariant 6).
func (c *Client) openEventStream(ctx context.Context, method, path string, body any, callOpts CallOptions) (*http.Response, error) {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	headers := map[string]string{"accept": "text/event-stream"}
	for key, value := range callOpts.ExtraHeaders {
		headers[key] = value
	}
	callOpts.ExtraHeaders = headers

	resp, err := c.do(ctx, requestSpec{
		method:          method,
		path:            path,
		body:            bodyBytes,
		hasBody:         true,
		opts:            &callOpts,
		candidates:      c.baseURLs,
		failover:        c.regionalFailover,
		streamOpen:      true,
		autoIdempotency: true,
		telemetry:       telemetryRequestFactsFor(method, path, body),
	})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, raiseForStreamResponse(resp)
	}
	return resp, nil
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
	if req.Provider != nil {
		params["provider"] = req.Provider
	}
	setSlice(params, "worker_models", req.WorkerModels)
	setSlice(params, "advisor_models", req.AdvisorModels)
	setPtr(params, "depth", req.Depth)
	setPtr(params, "max_get_advice_calls", req.MaxGetAdviceCalls)
	setPtr(params, "advisor_max_tokens", req.AdvisorMaxTokens)
	setPtr(params, "worker_timeout_ms", req.WorkerTimeoutMs)
	setPtr(params, "advisor_timeout_ms", req.AdvisorTimeoutMs)
	setPtr(params, "auto_initial_advice", req.AutoInitialAdvice)
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
