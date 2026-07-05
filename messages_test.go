package trustedrouter

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func newIncrement2TestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	maxRetries := 0
	client, err := NewClient(Options{
		BaseURL:    "https://example.test",
		MaxRetries: &maxRetries,
		HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
			recorder := httptest.NewRecorder()
			handler(recorder, r)
			return recorder.Result(), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func decodeRequestBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body
}

func assertMapEqual(t *testing.T, got, want map[string]any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("body = %#v, want %#v", got, want)
	}
}

func assertRequestMarshalMatchesMap(t *testing.T, req any, sent map[string]any) {
	t.Helper()
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var marshaled map[string]any
	if err := json.Unmarshal(data, &marshaled); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(marshaled, sent) {
		t.Fatalf("MarshalJSON body = %#v, sent body = %#v", marshaled, sent)
	}
}

func assertDecodeMarshalRoundTrip[T any](t *testing.T, golden string) {
	t.Helper()
	var decoded T
	if err := json.Unmarshal([]byte(golden), &decoded); err != nil {
		t.Fatal(err)
	}
	marshaled, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, marshaled, []byte(golden))
}

func assertJSONEqual(t *testing.T, got, want []byte) {
	t.Helper()
	var gotValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatalf("decode got JSON: %v\n%s", err, got)
	}
	var wantValue any
	if err := json.Unmarshal(want, &wantValue); err != nil {
		t.Fatalf("decode want JSON: %v\n%s", err, want)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("JSON = %#v, want %#v", gotValue, wantValue)
	}
}

func TestMessagesBodyBuildingGolden(t *testing.T) {
	maxTokens := 64
	var seenBody map[string]any
	var seenHeader http.Header
	client := newIncrement2TestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/messages" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		seenHeader = r.Header.Clone()
		seenBody = decodeRequestBody(t, r)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "msg_1",
			"type":    "message",
			"role":    "assistant",
			"content": []map[string]any{{"type": "text", "text": "ok"}},
			"model":   "anthropic/claude",
		})
	})

	apiKey := "typed-key"
	req := MessagesRequest{
		Model:     "anthropic/claude",
		Messages:  []map[string]any{{"role": "user", "content": "hello"}},
		MaxTokens: &maxTokens,
		Extra: map[string]any{
			"system":  "be brief",
			"api_key": "body-key",
		},
		CallOptions: CallOptions{APIKey: &apiKey},
	}
	_, err := client.Messages(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	assertMapEqual(t, seenBody, map[string]any{
		"model":      "anthropic/claude",
		"messages":   []any{map[string]any{"role": "user", "content": "hello"}},
		"max_tokens": float64(64),
		"system":     "be brief",
		"api_key":    "body-key",
	})
	if got := seenHeader.Get("authorization"); got != "Bearer typed-key" {
		t.Fatalf("authorization = %q", got)
	}
	assertRequestMarshalMatchesMap(t, req, seenBody)
}

func TestMessagesResponseDecodeCapturesUnknownFields(t *testing.T) {
	client := newIncrement2TestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":            "msg_2",
			"type":          "message",
			"role":          "assistant",
			"model":         "anthropic/claude",
			"stop_reason":   "end_turn",
			"stop_sequence": nil,
			"content": []map[string]any{{
				"type":          "text",
				"text":          "hi",
				"cache_control": map[string]any{"type": "ephemeral"},
			}},
			"usage": map[string]any{
				"input_tokens":  3,
				"output_tokens": 4,
				"cache_read":    2,
			},
			"trustedrouter": map[string]any{"route": "anthropic"},
		})
	})

	out, err := client.Messages(context.Background(), MessagesRequest{
		Model:    "anthropic/claude",
		Messages: []map[string]any{{"role": "user", "content": "hello"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.ID != "msg_2" || out.Role != "assistant" || out.StopReason == nil || *out.StopReason != "end_turn" {
		t.Fatalf("message response = %#v", out)
	}
	if out.StopSequence != nil {
		t.Fatalf("stop sequence = %q, want nil", *out.StopSequence)
	}
	if _, ok := out.Extra["stop_sequence"]; ok || out.Extra["trustedrouter"] == nil {
		t.Fatalf("top-level extra = %#v", out.Extra)
	}
	if out.Content[0].Extra["cache_control"] == nil {
		t.Fatalf("content extra = %#v", out.Content[0].Extra)
	}
	if out.Usage == nil || out.Usage.Extra["cache_read"] != float64(2) {
		t.Fatalf("usage extra = %#v", out.Usage)
	}
}

func TestMessagesMarshalRoundTrips(t *testing.T) {
	t.Run("MessageResponse", func(t *testing.T) {
		assertDecodeMarshalRoundTrip[MessageResponse](t, `{
			"id":"msg_3",
			"type":"message",
			"role":"assistant",
			"content":[{"type":"text","text":"hi","cache_control":{"type":"ephemeral"}}],
			"model":"anthropic/claude",
			"stop_reason":"stop_sequence",
			"stop_sequence":"\\n\\nHuman:",
			"usage":{"input_tokens":3,"output_tokens":4,"cache_read":2},
			"trustedrouter":{"route":"anthropic"}
		}`)
	})
	t.Run("MessageContentBlock", func(t *testing.T) {
		assertDecodeMarshalRoundTrip[MessageContentBlock](t, `{
			"type":"text",
			"text":"hello",
			"cache_control":{"type":"ephemeral"}
		}`)
	})
	t.Run("MessagesUsage", func(t *testing.T) {
		assertDecodeMarshalRoundTrip[MessagesUsage](t, `{
			"input_tokens":5,
			"output_tokens":7,
			"cache_read":2
		}`)
	})
}

func TestMessagesErrorTyping(t *testing.T) {
	client := newIncrement2TestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "bad message"}})
	})

	_, err := client.Messages(context.Background(), MessagesRequest{
		Model:    "anthropic/claude",
		Messages: []map[string]any{{"role": "user", "content": "hello"}},
	})
	var bad *BadRequestError
	if !errors.As(err, &bad) || bad.Message != "bad message" {
		t.Fatalf("expected BadRequestError, got %T %[1]v", err)
	}
}
