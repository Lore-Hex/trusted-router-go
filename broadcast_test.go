package trustedrouter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestBroadcastDestinationEndpointsWireShape(t *testing.T) {
	type seenRequest struct {
		method        string
		path          string
		workspace     string
		authorization string
		body          map[string]any
	}
	var seen []seenRequest
	client := newIncrement3TestClient(t, Options{
		APIKey:      "client-key",
		WorkspaceID: "client-workspace",
	}, func(w http.ResponseWriter, r *http.Request) {
		record := seenRequest{
			method:        r.Method,
			path:          r.URL.Path,
			workspace:     r.Header.Get("x-trustedrouter-workspace"),
			authorization: r.Header.Get("authorization"),
		}
		if r.Body != nil && r.Header.Get("Content-Type") == "application/json" {
			record.body = decodeRequestBody(t, r)
		}
		seen = append(seen, record)

		switch r.URL.Path {
		case "/broadcast/destinations":
			switch r.Method {
			case http.MethodGet:
				_ = json.NewEncoder(w).Encode(map[string]any{
					"data": []map[string]any{{"id": "bd_1", "type": "webhook", "future": "kept"}},
					"next": "cursor",
				})
			case http.MethodPost:
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id":              "bd_2",
					"type":            "webhook",
					"name":            "Deploy hook",
					"endpoint":        "https://example.test/hook",
					"enabled":         true,
					"include_content": false,
					"method":          "PUT",
					"new_field":       "kept",
				})
			default:
				t.Fatalf("unexpected method = %s", r.Method)
			}
		case "/broadcast/destinations/bd_2":
			switch r.Method {
			case http.MethodGet:
				_ = json.NewEncoder(w).Encode(map[string]any{"id": "bd_2", "type": "webhook"})
			case http.MethodPatch:
				_ = json.NewEncoder(w).Encode(map[string]any{"id": "bd_2", "type": "webhook", "name": "Updated"})
			case http.MethodDelete:
				_ = json.NewEncoder(w).Encode(map[string]any{"deleted": true})
			default:
				t.Fatalf("unexpected method = %s", r.Method)
			}
		case "/broadcast/destinations/bd_2/test":
			if r.Method != http.MethodPost {
				t.Fatalf("unexpected method = %s", r.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		default:
			t.Fatalf("unexpected path = %s", r.URL.Path)
		}
	})

	list, err := client.BroadcastDestinations(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "https://example.test/hook"
	apiKey := "posthog-key"
	createWorkspace := "create-workspace"
	method := "PUT"
	created, err := client.CreateBroadcastDestination(context.Background(), BroadcastDestinationRequest{
		Type:           "webhook",
		Name:           "Deploy hook",
		Endpoint:       &endpoint,
		Method:         method,
		Headers:        map[string]string{"x-hook": "yes"},
		APIKey:         &apiKey,
		WorkspaceID:    &createWorkspace,
		CallOptions:    CallOptions{IdempotencyKey: "create-idem"},
		IncludeContent: boolPtr(false),
	})
	if err != nil {
		t.Fatal(err)
	}
	empty := ""
	if _, err := client.GetBroadcastDestination(context.Background(), "bd_2", &BroadcastDestinationOptions{WorkspaceID: &empty}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.UpdateBroadcastDestination(context.Background(), "bd_2", map[string]any{
		"workspaceId": "patch-workspace",
		"name":        "Updated",
		"endpoint":    nil,
	}); err != nil {
		t.Fatal(err)
	}
	deleteWorkspace := "delete-workspace"
	if _, err := client.DeleteBroadcastDestination(context.Background(), "bd_2", &BroadcastDestinationOptions{WorkspaceID: &deleteWorkspace}); err != nil {
		t.Fatal(err)
	}
	testWorkspace := "test-workspace"
	if _, err := client.TestBroadcastDestination(context.Background(), "bd_2", &BroadcastDestinationOptions{WorkspaceID: &testWorkspace}); err != nil {
		t.Fatal(err)
	}

	if len(list.Data) != 1 || list.Data[0].Extra["future"] != "kept" || list.Extra["next"] != "cursor" {
		t.Fatalf("list extra capture failed: %#v", list)
	}
	if created.Extra["new_field"] != "kept" || created.Method == nil || *created.Method != "PUT" {
		t.Fatalf("created = %#v", created)
	}

	want := []seenRequest{
		{method: http.MethodGet, path: "/broadcast/destinations", workspace: "client-workspace", authorization: "Bearer client-key"},
		{
			method:        http.MethodPost,
			path:          "/broadcast/destinations",
			workspace:     "create-workspace",
			authorization: "Bearer client-key",
			body: map[string]any{
				"type":            "webhook",
				"name":            "Deploy hook",
				"endpoint":        "https://example.test/hook",
				"enabled":         true,
				"include_content": false,
				"method":          "PUT",
				"headers":         map[string]any{"x-hook": "yes"},
				"api_key":         "posthog-key",
			},
		},
		{method: http.MethodGet, path: "/broadcast/destinations/bd_2", authorization: "Bearer client-key"},
		{
			method:        http.MethodPatch,
			path:          "/broadcast/destinations/bd_2",
			workspace:     "patch-workspace",
			authorization: "Bearer client-key",
			body:          map[string]any{"name": "Updated"},
		},
		{method: http.MethodDelete, path: "/broadcast/destinations/bd_2", workspace: "delete-workspace", authorization: "Bearer client-key"},
		{method: http.MethodPost, path: "/broadcast/destinations/bd_2/test", workspace: "test-workspace", authorization: "Bearer client-key"},
	}
	if !reflect.DeepEqual(seen, want) {
		t.Fatalf("seen = %#v\nwant = %#v", seen, want)
	}
}

func TestBroadcastDestinationRequestDefaults(t *testing.T) {
	body := broadcastDestinationBody(BroadcastDestinationRequest{Type: "posthog"})
	assertMapEqual(t, body, map[string]any{
		"type":            "posthog",
		"name":            "Broadcast destination",
		"enabled":         true,
		"include_content": false,
		"method":          "POST",
	})
}

func newIncrement3TestClient(t *testing.T, opts Options, handler http.HandlerFunc) *Client {
	t.Helper()
	maxRetries := 0
	opts.BaseURL = "https://example.test"
	opts.MaxRetries = &maxRetries
	opts.HTTPClient = newRoundTripClient(func(r *http.Request) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		handler(recorder, r)
		return recorder.Result(), nil
	})
	client, err := NewClient(opts)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func boolPtr(v bool) *bool {
	return &v
}
