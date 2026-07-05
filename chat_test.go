package trustedrouter

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSSEChatTextAndCollectCompletion(t *testing.T) {
	stream := strings.Join([]string{
		`event: trustedrouter.route`,
		`data: {"id":"r","object":"chat.completion.chunk","created":1,"model":"trustedrouter/synth","choices":[],"trustedrouter":{"synth":{"event":"synth.started","preset":"quality"}}}`,
		`data: not-json`,
		``,
		`event: invisible`,
		`data: {"id":"r","object":"chat.completion.chunk","created":2,"model":"model/a","choices":[{"index":0,"delta":{"role":"assistant","content":"he"}}]}`,
		`data: {"id":"r","object":"chat.completion.chunk","created":2,"model":"model/a","choices":[{"index":0,"delta":{"content":"l"}}]}`,
		``,
		`data: {"id":"r","object":"chat.completion.chunk","created":3,"model":"model/a","choices":[{"index":0,"delta":{"content":"lo ","tool_calls":[{"index":0,"id":"call_a","type":"function","function":{"name":"lookup","arguments":""}}]}}]}`,
		``,
		`data: {"id":"r","object":"chat.completion.chunk","created":4,"model":"model/a","choices":[{"index":0,"delta":{"content":"world","tool_calls":[{"index":0,"function":{"arguments":"{\"q\":"}}]}}]}`,
		``,
		`data: {"id":"r","object":"chat.completion.chunk","created":5,"model":"model/a","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":" \"x\"}"}}]},"finish_reason":"tool_calls"}]}`,
		``,
		`data: {"id":"r","object":"chat.completion.chunk","created":6,"model":"model/a","choices":[],"usage":{"prompt_tokens":11,"completion_tokens":3,"total_tokens":14},"trustedrouter":{"synth":{"event":"panel.done","stage":"panel","index":0,"model":"model/a","detail":{"visible_answer":"hello world"}}}}`,
		``,
		`data: [DONE]`,
		``,
	}, "\n")

	sdk, err := NewClient(Options{HTTPClient: newRoundTripClient(func(*http.Request) (*http.Response, error) {
		return textResponse(200, stream, http.Header{"Content-Type": []string{"text/event-stream"}}), nil
	})})
	if err != nil {
		t.Fatal(err)
	}

	var chunks []ChatCompletionChunk
	for chunk, err := range sdk.ChatCompletionsChunks(context.Background(), ChatRequest{
		Messages: []map[string]any{{"role": "user", "content": "hi"}},
	}) {
		if err != nil {
			t.Fatal(err)
		}
		chunks = append(chunks, chunk)
	}
	if len(chunks) != 7 {
		t.Fatalf("chunks = %d", len(chunks))
	}
	if _, ok := chunks[0].Extra["event"]; ok {
		t.Fatalf("event line leaked into chunk extra: %#v", chunks[0].Extra)
	}

	var tokens []string
	for token, err := range sdk.ChatCompletionsText(context.Background(), ChatRequest{
		Messages: []map[string]any{{"role": "user", "content": "hi"}},
	}) {
		if err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, token)
	}
	if strings.Join(tokens, "") != "hello world" {
		t.Fatalf("tokens = %#v", tokens)
	}

	collected := CollectCompletion(chunks)
	if collected.Object != "chat.completion" || collected.ID != "r" || collected.Model != "model/a" {
		t.Fatalf("collected envelope = %#v", collected)
	}
	if got := *collected.Choices[0].Message.Content; got != "hello world" {
		t.Fatalf("content = %q", got)
	}
	if collected.Usage == nil || collected.Usage.TotalTokens != 14 {
		t.Fatalf("usage = %#v", collected.Usage)
	}
	toolCalls := collected.Choices[0].Message.ToolCalls
	if len(toolCalls) != 1 {
		t.Fatalf("tool calls = %#v", toolCalls)
	}
	fn := toolCalls[0]["function"].(map[string]any)
	if fn["name"] != "lookup" || fn["arguments"] != `{"q": "x"}` {
		t.Fatalf("function = %#v", fn)
	}
	synth := collected.Extra["trustedrouter"].(map[string]any)["synth"].(map[string]any)
	if _, ok := synth["events"]; !ok {
		t.Fatalf("missing synth events: %#v", synth)
	}
	if panel := synth["panel"].([]any); len(panel) != 1 {
		t.Fatalf("panel = %#v", synth["panel"])
	}
}

func TestChatCompletionsIncludesUsageOption(t *testing.T) {
	var seen map[string]any
	sdk, err := NewClient(Options{HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Fatal(err)
		}
		return textResponse(200, `data: {"id":"x","choices":[{"delta":{"content":"ok"},"finish_reason":"stop"}]}`+"\n\n", nil), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	out, err := sdk.ChatCompletions(context.Background(), ChatRequest{
		Messages: []map[string]any{{"role": "user", "content": "hi"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if *out.Choices[0].Message.Content != "ok" {
		t.Fatalf("out = %#v", out)
	}
	streamOptions := seen["stream_options"].(map[string]any)
	if streamOptions["include_usage"] != true {
		t.Fatalf("stream_options = %#v", streamOptions)
	}
}

func TestChatBodyBuildsTrustedRouterTools(t *testing.T) {
	depth := 2
	maxCalls := 3
	judge := "judge/model"
	strategy := "first_success"
	panelPrompt := "panel"
	temp := 0.2
	body := buildChatBody(ChatRequest{
		Model:             FusionModel,
		Messages:          []map[string]any{{"role": "user", "content": "hi"}},
		Tools:             []map[string]any{{"type": "function", "function": map[string]any{"name": "existing"}}},
		Depth:             &depth,
		WorkerModels:      []string{"worker/a"},
		AnalysisModels:    []string{"panel/a", "panel/b"},
		JudgeModel:        &judge,
		SelectionStrategy: &strategy,
		MaxToolCalls:      &maxCalls,
		PanelPrompt:       &panelPrompt,
		Extra: map[string]any{
			"temperature": temp,
		},
	}, false)

	if body["model"] != FusionModel || body["stream"] != true || body["temperature"] != temp {
		t.Fatalf("body = %#v", body)
	}
	if _, ok := body["depth"]; ok {
		t.Fatalf("advisor key leaked top-level: %#v", body)
	}
	tools := body["tools"].([]any)
	if len(tools) != 3 {
		t.Fatalf("tools = %#v", tools)
	}
	advisor := tools[1].(map[string]any)
	if advisor["type"] != "trustedrouter:advisor" {
		t.Fatalf("advisor tool = %#v", advisor)
	}
	fusion := tools[2].(map[string]any)
	params := fusion["parameters"].(map[string]any)
	want := map[string]any{
		"analysis_models":    []string{"panel/a", "panel/b"},
		"model":              "judge/model",
		"selection_strategy": "first_success",
		"max_tool_calls":     3,
		"panel_prompt":       "panel",
	}
	if !reflect.DeepEqual(params, want) {
		t.Fatalf("fusion params = %#v", params)
	}
}

func TestChatExtraWinsAndPrimitiveModelsDoNotSendEmptyTools(t *testing.T) {
	body := buildChatBody(ChatRequest{
		Model:    FusionModel,
		Messages: []map[string]any{{"role": "user", "content": "hi"}},
		Extra: map[string]any{
			"stream": false,
			"tools":  []any{},
		},
	}, false)
	if body["stream"] != false {
		t.Fatalf("extra stream did not win: %#v", body)
	}
	if _, ok := body["tools"]; ok {
		t.Fatalf("empty tools should be omitted for primitive model: %#v", body)
	}
}

func TestChatStreamMidReadErrorIsWrapped(t *testing.T) {
	readErr := errors.New("socket closed")
	body := &scriptedReadCloser{
		chunks: []string{`data: {"id":"x","choices":[{"delta":{"content":"ok"}}]}` + "\n"},
		err:    readErr,
	}
	sdk, err := NewClient(Options{HTTPClient: newRoundTripClient(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body:       body,
		}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}

	var sawChunk bool
	var gotErr error
	for chunk, err := range sdk.ChatCompletionsChunks(context.Background(), ChatRequest{
		Messages: []map[string]any{{"role": "user", "content": "hi"}},
	}) {
		if err != nil {
			gotErr = err
			break
		}
		sawChunk = true
		if *chunk.Choices[0].Delta.Content != "ok" {
			t.Fatalf("chunk = %#v", chunk)
		}
	}
	if !sawChunk {
		t.Fatal("expected first chunk before read error")
	}
	var internal *InternalError
	if !errors.As(gotErr, &internal) || internal.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected wrapped InternalError, got %T %[1]v", gotErr)
	}
	if !strings.Contains(internal.Message, "TrustedRouter regional endpoint unavailable: socket closed") {
		t.Fatalf("message = %q", internal.Message)
	}
}

func TestChatStreamOpenNon2xxYieldsTypedError(t *testing.T) {
	maxRetries := 0
	sdk, err := NewClient(Options{
		MaxRetries: &maxRetries,
		HTTPClient: newRoundTripClient(func(*http.Request) (*http.Response, error) {
			return textResponse(429, "slow down", http.Header{"Retry-After": []string{"2.5"}}), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	var gotErr error
	for _, err := range sdk.ChatCompletionsChunks(context.Background(), ChatRequest{
		Messages: []map[string]any{{"role": "user", "content": "hi"}},
	}) {
		gotErr = err
		break
	}
	var rateLimit *RateLimitError
	if !errors.As(gotErr, &rateLimit) || rateLimit.RetryAfter == nil || *rateLimit.RetryAfter != 2.5 {
		t.Fatalf("expected RateLimitError with RetryAfter, got %T %[1]v", gotErr)
	}
}

func TestRaiseForStreamResponseReadErrorIsTransportError(t *testing.T) {
	readErr := errors.New("read failed")
	err := raiseForStreamResponse(&http.Response{
		StatusCode: 503,
		Header:     http.Header{},
		Body:       &scriptedReadCloser{err: readErr},
	})
	var internal *InternalError
	if !errors.As(err, &internal) || internal.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected transport InternalError, got %T %[1]v", err)
	}
	if !strings.Contains(internal.Message, "read failed") {
		t.Fatalf("message = %q", internal.Message)
	}
}

func TestChatStreamIdleTimeoutYieldsInternalError(t *testing.T) {
	maxRetries := 0
	sdk, err := NewClient(Options{
		MaxRetries: &maxRetries,
		HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body: &timedStreamReadCloser{
					ctx:    r.Context(),
					chunks: []string{`data: {"id":"x","choices":[{"delta":{"content":"a"}}]}` + "\n\n"},
					stall:  true,
				},
			}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	timeout := 50 * time.Millisecond
	var sawChunk bool
	var gotErr error
	for chunk, err := range sdk.ChatCompletionsChunks(context.Background(), ChatRequest{
		Messages: []map[string]any{{"role": "user", "content": "hi"}},
		CallOptions: CallOptions{
			Timeout: &timeout,
		},
	}) {
		if err != nil {
			gotErr = err
			break
		}
		sawChunk = true
		if *chunk.Choices[0].Delta.Content != "a" {
			t.Fatalf("chunk = %#v", chunk)
		}
	}
	if !sawChunk {
		t.Fatal("expected first chunk before idle timeout")
	}
	var internal *InternalError
	if !errors.As(gotErr, &internal) {
		t.Fatalf("expected idle timeout InternalError, got %T %[1]v", gotErr)
	}
}

func TestChatStreamIdleTimeoutResetsBetweenChunks(t *testing.T) {
	maxRetries := 0
	sdk, err := NewClient(Options{
		MaxRetries: &maxRetries,
		HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body: &timedStreamReadCloser{
					ctx: r.Context(),
					chunks: []string{
						`data: {"id":"x","choices":[{"delta":{"content":"a"}}]}` + "\n\n",
						`data: {"id":"x","choices":[{"delta":{"content":"b"}}]}` + "\n\n",
						`data: {"id":"x","choices":[{"delta":{"content":"c"}}]}` + "\n\n",
						`data: {"id":"x","choices":[{"delta":{"content":"d"}}]}` + "\n\n",
						`data: {"id":"x","choices":[{"delta":{"content":"e"}}]}` + "\n\n",
					},
					delays: []time.Duration{
						0,
						30 * time.Millisecond,
						30 * time.Millisecond,
						30 * time.Millisecond,
						30 * time.Millisecond,
					},
				},
			}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	timeout := 50 * time.Millisecond
	var got []string
	for chunk, err := range sdk.ChatCompletionsChunks(context.Background(), ChatRequest{
		Messages: []map[string]any{{"role": "user", "content": "hi"}},
		CallOptions: CallOptions{
			Timeout: &timeout,
		},
	}) {
		if err != nil {
			t.Fatalf("unexpected stream error: %v", err)
		}
		got = append(got, *chunk.Choices[0].Delta.Content)
	}
	if strings.Join(got, "") != "abcde" {
		t.Fatalf("tokens = %#v", got)
	}
}

func TestChatCompletionsChunksEarlyBreakClosesBody(t *testing.T) {
	body := &trackingReadCloser{Reader: strings.NewReader(strings.Join([]string{
		`data: {"id":"x","choices":[{"delta":{"content":"a"}}]}`,
		``,
		`data: {"id":"x","choices":[{"delta":{"content":"b"}}]}`,
		``,
	}, "\n"))}
	sdk, err := NewClient(Options{HTTPClient: newRoundTripClient(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body:       body,
		}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}

	for chunk, err := range sdk.ChatCompletionsChunks(context.Background(), ChatRequest{
		Messages: []map[string]any{{"role": "user", "content": "hi"}},
	}) {
		if err != nil {
			t.Fatal(err)
		}
		if *chunk.Choices[0].Delta.Content != "a" {
			t.Fatalf("chunk = %#v", chunk)
		}
		break
	}
	if !body.closed {
		t.Fatal("body was not closed after early break")
	}
}

func TestChatExtraReservedKeysRouteAndUnknownKeysSurvive(t *testing.T) {
	var seenBody map[string]any
	var seenHeader http.Header
	sdk, err := NewClient(Options{
		APIKey:      "client-key",
		WorkspaceID: "client-workspace",
		HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
			seenHeader = r.Header.Clone()
			if err := json.NewDecoder(r.Body).Decode(&seenBody); err != nil {
				t.Fatal(err)
			}
			return textResponse(200, `data: {"id":"x","choices":[{"delta":{"content":"ok"},"finish_reason":"stop"}]}`+"\n\n", nil), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = sdk.ChatCompletions(context.Background(), ChatRequest{
		Model:    AutoModel,
		Messages: []map[string]any{{"role": "user", "content": "typed"}},
		Extra: map[string]any{
			"api_key":         "",
			"workspace_id":    "extra-workspace",
			"idempotency_key": "extra-idem",
			"extra_headers":   map[string]any{"x-extra": "yes", "authorization": "Bearer header"},
			"temperature":     0.4,
			"stream":          false,
			"model":           "extra-model",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := seenHeader.Get("authorization"); got != "Bearer header" {
		t.Fatalf("authorization = %q", got)
	}
	if got := seenHeader.Get("x-trustedrouter-workspace"); got != "extra-workspace" {
		t.Fatalf("workspace = %q", got)
	}
	if got := seenHeader.Get("idempotency-key"); got != "extra-idem" {
		t.Fatalf("idempotency = %q", got)
	}
	if got := seenHeader.Get("x-extra"); got != "yes" {
		t.Fatalf("extra header = %q", got)
	}
	for _, reserved := range []string{"api_key", "workspace_id", "idempotency_key", "extra_headers", "timeout"} {
		if _, ok := seenBody[reserved]; ok {
			t.Fatalf("reserved key %q leaked into body: %#v", reserved, seenBody)
		}
	}
	if seenBody["temperature"] != 0.4 || seenBody["stream"] != false || seenBody["model"] != "extra-model" {
		t.Fatalf("body precedence/passthrough = %#v", seenBody)
	}
}

func TestFusionToolAdvisorToolAndFusionTools(t *testing.T) {
	judge := "judge/model"
	strategy := SelectionStrategyFirstSuccess
	maxTokens := 128
	fusionTool := FusionTool(FusionToolOptions{
		AnalysisModels:      []string{"panel/a"},
		Model:               &judge,
		SelectionStrategy:   &strategy,
		MaxCompletionTokens: &maxTokens,
	})
	fusionParams := fusionTool["parameters"].(map[string]any)
	if !reflect.DeepEqual(fusionParams, map[string]any{
		"analysis_models":       []string{"panel/a"},
		"model":                 "judge/model",
		"selection_strategy":    SelectionStrategyFirstSuccess,
		"max_completion_tokens": 128,
	}) {
		t.Fatalf("fusion tool = %#v", fusionTool)
	}
	depth := 2
	advisorTool := AdvisorTool(AdvisorToolOptions{Depth: &depth, WorkerModels: []string{"worker/a"}})
	advisorParams := advisorTool["parameters"].(map[string]any)
	if !reflect.DeepEqual(advisorParams, map[string]any{
		"depth":         2,
		"worker_models": []string{"worker/a"},
	}) {
		t.Fatalf("advisor tool = %#v", advisorTool)
	}

	var seenBody map[string]any
	sdk, err := NewClient(Options{HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
		if err := json.NewDecoder(r.Body).Decode(&seenBody); err != nil {
			t.Fatal(err)
		}
		return textResponse(200, `data: {"id":"x","choices":[{"delta":{"content":"ok"},"finish_reason":"stop"}]}`+"\n\n", nil), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	out, err := sdk.Fusion(context.Background(), FusionRequest{
		Messages:       []map[string]any{{"role": "user", "content": "hi"}},
		Tools:          []map[string]any{{"type": "function", "function": map[string]any{"name": "typed"}}},
		AnalysisModels: []string{"panel/a"},
		Model:          &judge,
		Extra: map[string]any{
			"tools": []any{map[string]any{"type": "function", "function": map[string]any{"name": "custom"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if *out.Choices[0].Message.Content != "ok" {
		t.Fatalf("out = %#v", out)
	}
	if seenBody["model"] != FusionModel {
		t.Fatalf("fusion body model = %#v", seenBody)
	}
	tools := seenBody["tools"].([]any)
	if len(tools) != 3 {
		t.Fatalf("tools = %#v", tools)
	}
	first := tools[0].(map[string]any)["function"].(map[string]any)
	if first["name"] != "typed" {
		t.Fatalf("typed tool not preserved first: %#v", tools)
	}
	second := tools[1].(map[string]any)["function"].(map[string]any)
	if second["name"] != "custom" {
		t.Fatalf("extra tool not preserved before fusion: %#v", tools)
	}
	last := tools[len(tools)-1].(map[string]any)
	if last["type"] != "trustedrouter:fusion" {
		t.Fatalf("fusion tool missing: %#v", tools)
	}
	params := last["parameters"].(map[string]any)
	if !reflect.DeepEqual(params["analysis_models"], []any{"panel/a"}) || params["model"] != judge {
		t.Fatalf("fusion params = %#v", params)
	}
}

func TestFusionDefaultTimeoutOverridesClientDefault(t *testing.T) {
	clientTimeout := 10 * time.Millisecond
	maxRetries := 0
	sdk, err := NewClient(Options{
		Timeout:    &clientTimeout,
		MaxRetries: &maxRetries,
		HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
			select {
			case <-time.After(30 * time.Millisecond):
				return textResponse(200, `data: {"id":"x","choices":[{"delta":{"content":"ok"},"finish_reason":"stop"}]}`+"\n\n", nil), nil
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	out, err := sdk.Fusion(context.Background(), FusionRequest{
		Messages: []map[string]any{{"role": "user", "content": "hi"}},
	})
	if err != nil {
		t.Fatalf("fusion default timeout should replace client default: %v", err)
	}
	if *out.Choices[0].Message.Content != "ok" {
		t.Fatalf("out = %#v", out)
	}
}

func TestFusionExtraTimeoutOverridesFusionDefault(t *testing.T) {
	maxRetries := 0
	sdk, err := NewClient(Options{
		MaxRetries: &maxRetries,
		HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
			select {
			case <-time.After(200 * time.Millisecond):
				return textResponse(200, `data: {"id":"x","choices":[{"delta":{"content":"late"},"finish_reason":"stop"}]}`+"\n\n", nil), nil
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = sdk.Fusion(context.Background(), FusionRequest{
		Messages: []map[string]any{{"role": "user", "content": "hi"}},
		Extra:    map[string]any{"timeout": 0.05},
	})
	var internal *InternalError
	if !errors.As(err, &internal) {
		t.Fatalf("expected Extra timeout InternalError, got %T %[1]v", err)
	}
}

type scriptedReadCloser struct {
	chunks []string
	err    error
}

func (r *scriptedReadCloser) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, r.err
	}
	chunk := r.chunks[0]
	r.chunks = r.chunks[1:]
	return copy(p, chunk), nil
}

func (r *scriptedReadCloser) Close() error { return nil }

type trackingReadCloser struct {
	*strings.Reader
	closed bool
}

func (r *trackingReadCloser) Close() error {
	r.closed = true
	return nil
}

var _ io.ReadCloser = (*trackingReadCloser)(nil)

type timedStreamReadCloser struct {
	ctx    context.Context
	chunks []string
	delays []time.Duration
	stall  bool
}

func (r *timedStreamReadCloser) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		if !r.stall {
			return 0, io.EOF
		}
		<-r.ctx.Done()
		return 0, r.ctx.Err()
	}
	delay := time.Duration(0)
	if len(r.delays) > 0 {
		delay = r.delays[0]
		r.delays = r.delays[1:]
	}
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.ctx.Done():
			return 0, r.ctx.Err()
		}
	}
	chunk := r.chunks[0]
	r.chunks = r.chunks[1:]
	return copy(p, chunk), nil
}

func (r *timedStreamReadCloser) Close() error { return nil }
