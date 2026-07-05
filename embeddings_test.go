package trustedrouter

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestEmbeddingsBodyGoldenInputVariants(t *testing.T) {
	var bodies []map[string]any
	client := newIncrement2TestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/embeddings" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		bodies = append(bodies, decodeRequestBody(t, r))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object": "list",
			"model":  "embed/model",
			"data": []map[string]any{{
				"object":    "embedding",
				"index":     0,
				"embedding": []float64{0.1, 0.2},
			}},
		})
	})

	encoding := "float"
	dimensions := 2
	user := "user-1"
	req := EmbeddingsRequest{
		Model:          "embed/model",
		Input:          "hello",
		EncodingFormat: &encoding,
		Dimensions:     &dimensions,
		User:           &user,
		Extra:          map[string]any{"truncate": "none"},
	}
	if _, err := client.Embeddings(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	assertRequestMarshalMatchesMap(t, req, bodies[0])

	req = EmbeddingsRequest{
		Model: "embed/model",
		Input: []string{"hello", "world"},
	}
	if _, err := client.Embeddings(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	assertRequestMarshalMatchesMap(t, req, bodies[1])

	assertMapEqual(t, bodies[0], map[string]any{
		"model":           "embed/model",
		"input":           "hello",
		"encoding_format": "float",
		"dimensions":      float64(2),
		"user":            "user-1",
		"truncate":        "none",
	})
	assertMapEqual(t, bodies[1], map[string]any{
		"model": "embed/model",
		"input": []any{"hello", "world"},
	})
}

func TestEmbeddingsDecodeCapturesUnknownFields(t *testing.T) {
	client := newIncrement2TestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object": "list",
			"model":  "embed/model",
			"data": []map[string]any{{
				"object":    "embedding",
				"index":     0,
				"embedding": []float64{0.1, 0.2},
				"provider":  "p",
			}},
			"usage": map[string]any{
				"prompt_tokens":     4,
				"completion_tokens": 0,
				"total_tokens":      4,
				"cache_read":        1,
			},
			"trustedrouter": map[string]any{"route": "local"},
		})
	})

	out, err := client.Embeddings(context.Background(), EmbeddingsRequest{
		Model: "embed/model",
		Input: "hello",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Model != "embed/model" || len(out.Data) != 1 {
		t.Fatalf("embedding response = %#v", out)
	}
	floats, ok := out.Data[0].Embedding.Float64s()
	if !ok || len(floats) != 2 || floats[1] != 0.2 {
		t.Fatalf("embedding response = %#v", out)
	}
	if out.Extra["trustedrouter"] == nil || out.Data[0].Extra["provider"] != "p" {
		t.Fatalf("extra not captured: top=%#v item=%#v", out.Extra, out.Data[0].Extra)
	}
	if out.Usage == nil || out.Usage.Extra["cache_read"] != float64(1) {
		t.Fatalf("usage extra = %#v", out.Usage)
	}
}

func TestEmbeddingsDecodeBase64ResponseWhenRequested(t *testing.T) {
	client := newIncrement2TestClient(t, func(w http.ResponseWriter, r *http.Request) {
		body := decodeRequestBody(t, r)
		if body["encoding_format"] != "base64" {
			t.Fatalf("body = %#v", body)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object": "list",
			"model":  "embed/model",
			"data": []map[string]any{{
				"object":    "embedding",
				"index":     0,
				"embedding": "AQIDBA==",
			}},
		})
	})

	encoding := "base64"
	out, err := client.Embeddings(context.Background(), EmbeddingsRequest{
		Model:          "embed/model",
		Input:          "hello",
		EncodingFormat: &encoding,
	})
	if err != nil {
		t.Fatal(err)
	}
	base64Value, ok := out.Data[0].Embedding.Base64String()
	if !ok || base64Value != "AQIDBA==" {
		t.Fatalf("embedding = %#v", out.Data[0].Embedding)
	}
	if floats, ok := out.Data[0].Embedding.Float64s(); ok || floats != nil {
		t.Fatalf("float getter = %#v, %t", floats, ok)
	}
}

func TestEmbeddingsMarshalRoundTrips(t *testing.T) {
	t.Run("EmbeddingsResponse", func(t *testing.T) {
		assertDecodeMarshalRoundTrip[EmbeddingsResponse](t, `{
			"object":"list",
			"data":[{"object":"embedding","index":0,"embedding":[0.1,0.2],"provider":"p"}],
			"model":"embed/model",
			"usage":{"prompt_tokens":4,"completion_tokens":0,"total_tokens":4,"cache_read":1},
			"trustedrouter":{"route":"local"}
		}`)
	})
	t.Run("EmbeddingFloat", func(t *testing.T) {
		assertDecodeMarshalRoundTrip[Embedding](t, `{
			"object":"embedding",
			"index":0,
			"embedding":[0.1,0.2],
			"provider":"p"
		}`)
	})
	t.Run("EmbeddingBase64", func(t *testing.T) {
		assertDecodeMarshalRoundTrip[Embedding](t, `{
			"object":"embedding",
			"index":0,
			"embedding":"AQIDBA==",
			"provider":"p"
		}`)
	})
}
