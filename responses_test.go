package trustedrouter

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"iter"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestResponsesBodyGoldenAndDecode(t *testing.T) {
	instructions := "answer tersely"
	var seenBody map[string]any
	var seenHeader http.Header
	client := newIncrement2TestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/responses" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		seenHeader = r.Header.Clone()
		seenBody = decodeRequestBody(t, r)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":         "resp_1",
			"object":     "response",
			"created_at": 123,
			"status":     "completed",
			"model":      "trustedrouter/auto",
			"output": []map[string]any{{
				"type": "message",
				"content": []map[string]any{{
					"type": "output_text",
					"text": "ok",
				}},
			}},
			"usage":         map[string]any{"input_tokens": 5, "output_tokens": 1, "total_tokens": 6},
			"trustedrouter": map[string]any{"route": "auto"},
		})
	})

	req := ResponsesRequest{
		Input:        "hello",
		Instructions: &instructions,
		Extra: map[string]any{
			"temperature":     0.25,
			"api_key":         "extra-key",
			"workspace_id":    "workspace-1",
			"idempotency_key": "idem-1",
			"extra_headers":   map[string]any{"x-extra": "yes"},
			"stream":          true,
		},
	}
	out, err := client.Responses(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	assertMapEqual(t, seenBody, map[string]any{
		"model":        AutoModel,
		"input":        "hello",
		"stream":       false,
		"instructions": "answer tersely",
		"temperature":  0.25,
	})
	if seenHeader.Get("authorization") != "Bearer extra-key" ||
		seenHeader.Get("x-trustedrouter-workspace") != "workspace-1" ||
		seenHeader.Get("idempotency-key") != "idem-1" ||
		seenHeader.Get("x-extra") != "yes" {
		t.Fatalf("headers = %#v", seenHeader)
	}
	if out.ID != "resp_1" || out.CreatedAt == nil || *out.CreatedAt != 123 || out.Status == nil || *out.Status != "completed" {
		t.Fatalf("response object = %#v", out)
	}
	if out.Extra["trustedrouter"] == nil || out.Usage["total_tokens"] != float64(6) {
		t.Fatalf("response extras/usage = %#v %#v", out.Extra, out.Usage)
	}
	assertRequestMarshalMatchesMap(t, req, seenBody)
}

func TestResponsesEventsParsesEventNamedMultilineFrames(t *testing.T) {
	var seenBody map[string]any
	stream := strings.Join([]string{
		`event: trustedrouter.route`,
		`data: {"detail":`,
		`data: {"stage":"route"}}`,
		``,
		`event: response.output_text.delta`,
		`data: {"delta":"hi"}`,
		``,
		`data: [DONE]`,
		``,
	}, "\n")
	client := newIncrement2TestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/responses" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		seenBody = decodeRequestBody(t, r)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, stream)
	})

	var events []map[string]any
	for event, err := range client.ResponsesEvents(context.Background(), ResponsesRequest{
		Model: "model/a",
		Input: []map[string]any{{"role": "user", "content": "hello"}},
	}) {
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if seenBody["stream"] != true {
		t.Fatalf("stream body = %#v", seenBody)
	}
	if len(events) != 2 {
		t.Fatalf("events = %#v", events)
	}
	if events[0]["event"] != "trustedrouter.route" {
		t.Fatalf("first event = %#v", events[0])
	}
	detail := events[0]["detail"].(map[string]any)
	if detail["stage"] != "route" {
		t.Fatalf("detail = %#v", detail)
	}
	if events[1]["event"] != "response.output_text.delta" || events[1]["delta"] != "hi" {
		t.Fatalf("second event = %#v", events[1])
	}
}

func TestEventFromSSEFrameNamelessEventUsesNil(t *testing.T) {
	event := eventFromSSEFrame([]string{`data: "hello"`})
	if event == nil {
		t.Fatal("event is nil")
	}
	if got, ok := event["event"]; !ok || got != nil {
		t.Fatalf("event value = %#v, present = %t", got, ok)
	}
	if event["data"] != "hello" {
		t.Fatalf("data = %#v", event["data"])
	}

	objectEvent := eventFromSSEFrame([]string{`data: {"delta":"hi"}`})
	if objectEvent == nil {
		t.Fatal("object event is nil")
	}
	if _, ok := objectEvent["event"]; ok {
		t.Fatalf("object event should not synthesize event key: %#v", objectEvent)
	}
}

func TestResponsesMarshalRoundTrips(t *testing.T) {
	t.Run("ResponseObject", func(t *testing.T) {
		assertDecodeMarshalRoundTrip[ResponseObject](t, `{
			"id":"resp_2",
			"object":"response",
			"created_at":123,
			"status":"completed",
			"model":"trustedrouter/auto",
			"output":[{"type":"message","content":[{"type":"output_text","text":"ok"}]}],
			"usage":{"input_tokens":5,"output_tokens":1,"total_tokens":6},
			"trustedrouter":{"route":"auto"}
		}`)
	})
	t.Run("ResponseInputTokens", func(t *testing.T) {
		assertDecodeMarshalRoundTrip[ResponseInputTokens](t, `{
			"input_tokens":7,
			"total_tokens":9,
			"provider":"counter"
		}`)
	})
}

func TestResponsesRawStreamPassthrough(t *testing.T) {
	client := newIncrement2TestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: raw\n\n")
	})

	body, err := client.ResponsesRawStream(context.Background(), ResponsesRequest{Input: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()

	data, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "data: raw\n\n" {
		t.Fatalf("raw stream = %q", data)
	}
}

func TestResponsesInputTokens(t *testing.T) {
	var seenBody map[string]any
	client := newIncrement2TestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/responses/input_tokens" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		seenBody = decodeRequestBody(t, r)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"input_tokens": 7,
			"total_tokens": 9,
			"provider":     "counter",
		})
	})

	out, err := client.ResponsesInputTokens(context.Background(), ResponsesRequest{
		Model: "model/a",
		Input: "hello",
		Extra: map[string]any{
			"workspace_id": "workspace-1",
			"stream":       true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertMapEqual(t, seenBody, map[string]any{
		"model":  "model/a",
		"input":  "hello",
		"stream": false,
	})
	if out.InputTokens != 7 || out.TotalTokens == nil || *out.TotalTokens != 9 || out.Extra["provider"] != "counter" {
		t.Fatalf("input tokens = %#v", out)
	}
}

func TestResponsesStreamIdleTimeoutYieldsInternalError(t *testing.T) {
	maxRetries := 0
	client, err := NewClient(Options{
		MaxRetries: &maxRetries,
		HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body: &timedStreamReadCloser{
					ctx: r.Context(),
					chunks: []string{
						"event: response.created\n" + `data: {"id":"resp_1"}` + "\n\n",
					},
					stall: true,
				},
			}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	timeout := 50 * time.Millisecond
	var sawEvent bool
	var gotErr error
	for event, err := range client.ResponsesEvents(context.Background(), ResponsesRequest{
		Input: "hello",
		CallOptions: CallOptions{
			Timeout: &timeout,
		},
	}) {
		if err != nil {
			gotErr = err
			break
		}
		sawEvent = true
		if event["event"] != "response.created" || event["id"] != "resp_1" {
			t.Fatalf("event = %#v", event)
		}
	}
	if !sawEvent {
		t.Fatal("expected first event before idle timeout")
	}
	var internal *InternalError
	if !errors.As(gotErr, &internal) {
		t.Fatalf("expected idle timeout InternalError, got %T %[1]v", gotErr)
	}
}

func TestResponsesEventsMidReadErrorIsWrapped(t *testing.T) {
	readErr := errors.New("socket closed")
	body := &scriptedReadCloser{
		chunks: []string{"event: response.created\n" + `data: {"id":"resp_1"}` + "\n\n"},
		err:    readErr,
	}
	client, err := NewClient(Options{HTTPClient: newRoundTripClient(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body:       body,
		}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}

	var sawEvent bool
	var gotErr error
	for event, err := range client.ResponsesEvents(context.Background(), ResponsesRequest{Input: "hello"}) {
		if err != nil {
			gotErr = err
			break
		}
		sawEvent = true
		if event["id"] != "resp_1" {
			t.Fatalf("event = %#v", event)
		}
	}
	if !sawEvent {
		t.Fatal("expected first event before read error")
	}
	var internal *InternalError
	if !errors.As(gotErr, &internal) || !strings.Contains(internal.Message, "socket closed") {
		t.Fatalf("expected wrapped InternalError, got %T %[1]v", gotErr)
	}
}

func TestClientIncrementSurfaceParitySmoke(t *testing.T) {
	var _ func(*Client, context.Context, ChatRequest) (*ChatCompletion, error) = (*Client).ChatCompletions
	var _ func(*Client, context.Context, ChatRequest) iter.Seq2[ChatCompletionChunk, error] = (*Client).ChatCompletionsChunks
	var _ func(*Client, context.Context, ChatRequest) iter.Seq2[string, error] = (*Client).ChatCompletionsText
	var _ func(*Client, context.Context, ChatRequest) (io.ReadCloser, error) = (*Client).ChatCompletionsRawStream
	var _ func(*Client, context.Context, FusionRequest) (*ChatCompletion, error) = (*Client).Fusion
	var _ func(*Client, context.Context, *ModelListOptions) (*ModelList, error) = (*Client).Models
	var _ func(*Client, context.Context) (*ProviderList, error) = (*Client).Providers
	var _ func(*Client, context.Context) (*RegionList, error) = (*Client).Regions
	var _ func(*Client, context.Context, *CreditsOptions) (*CreditsBalance, error) = (*Client).Credits
	var _ func(*Client, context.Context, EmbeddingsRequest) (*EmbeddingsResponse, error) = (*Client).Embeddings
	var _ func(*Client, context.Context, MessagesRequest) (*MessageResponse, error) = (*Client).Messages
	var _ func(*Client, context.Context, ResponsesRequest) (*ResponseObject, error) = (*Client).Responses
	var _ func(*Client, context.Context, ResponsesRequest) iter.Seq2[map[string]any, error] = (*Client).ResponsesEvents
	var _ func(*Client, context.Context, ResponsesRequest) (io.ReadCloser, error) = (*Client).ResponsesRawStream
	var _ func(*Client, context.Context, ResponsesRequest) (*ResponseInputTokens, error) = (*Client).ResponsesInputTokens
}
