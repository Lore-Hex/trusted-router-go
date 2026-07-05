package trustedrouter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestModelsPath(t *testing.T) {
	open := true
	closed := false
	cases := []struct {
		name string
		opts *ModelListOptions
		want string
	}{
		{"nil", nil, "/models"},
		{"empty", &ModelListOptions{}, "/models"},
		{"open", &ModelListOptions{OpenWeights: &open}, "/models?open_weights=true"},
		{"closed", &ModelListOptions{OpenWeights: &closed}, "/models?open_weights=false"},
		{"all", &ModelListOptions{OpenWeights: &open, ProviderJurisdiction: "us", ProviderRegion: "eu"}, "/models?open_weights=true&provider%5Bjurisdiction%5D=us&provider%5Bregion%5D=eu"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := modelsPath(tc.opts); got != tc.want {
				t.Fatalf("modelsPath() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestModelExtraCapture(t *testing.T) {
	var list ModelList
	data := []byte(`{"data":[{"id":"m","trustedrouter":{"open_weights":true,"new_flag":"x"},"new_model_field":1}],"next":"cursor"}`)
	if err := list.UnmarshalJSON(data); err != nil {
		t.Fatal(err)
	}
	if list.Extra["next"] != "cursor" {
		t.Fatalf("list extra = %#v", list.Extra)
	}
	model := list.ByID("m")
	if model == nil || !model.OpenWeights() {
		t.Fatalf("model = %#v", model)
	}
	if model.Extra["new_model_field"] == nil || model.TrustedRouter.Extra["new_flag"] != "x" {
		t.Fatalf("extra not captured: model=%#v tr=%#v", model.Extra, model.TrustedRouter.Extra)
	}
}

func TestCatalogEndpointWirePaths(t *testing.T) {
	type seenRequest struct {
		method    string
		path      string
		workspace string
	}
	var seen []seenRequest
	client := newCatalogWireClient(t, Options{}, func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, seenRequest{
			method:    r.Method,
			path:      r.URL.Path,
			workspace: r.Header.Get("x-trustedrouter-workspace"),
		})
		switch r.URL.Path {
		case "/providers":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{"id": "openai", "name": "OpenAI"}},
			})
		case "/regions":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{"id": "us-central1"}},
			})
		default:
			t.Fatalf("unexpected request = %s %s", r.Method, r.URL.Path)
		}
	})

	providers, err := client.Providers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	regions, err := client.Regions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(providers.Data) != 1 || providers.Data[0].ID != "openai" || providers.Data[0].Name != "OpenAI" {
		t.Fatalf("providers = %#v", providers)
	}
	if len(regions.Data) != 1 || regions.Data[0].ID != "us-central1" {
		t.Fatalf("regions = %#v", regions)
	}

	want := []seenRequest{
		{method: http.MethodGet, path: "/providers"},
		{method: http.MethodGet, path: "/regions"},
	}
	if len(seen) != len(want) {
		t.Fatalf("seen requests = %#v", seen)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("request %d = %#v, want %#v", i, seen[i], want[i])
		}
	}
}

func TestCreditsEndpointWireWorkspaceRouting(t *testing.T) {
	type seenRequest struct {
		method    string
		path      string
		workspace string
	}
	var seen []seenRequest
	client := newCatalogWireClient(t, Options{WorkspaceID: "client-workspace"}, func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, seenRequest{
			method:    r.Method,
			path:      r.URL.Path,
			workspace: r.Header.Get("x-trustedrouter-workspace"),
		})
		if r.Method != http.MethodGet || r.URL.Path != "/credits" {
			t.Fatalf("unexpected request = %s %s", r.Method, r.URL.Path)
		}
		switch len(seen) {
		case 1:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"workspace_id": "client-workspace", "balance": 12.5},
			})
		case 2:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{"workspace_id": "request-workspace", "balance": 7}},
			})
		case 3:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"balance": 99},
			})
		default:
			t.Fatalf("unexpected credits call %d", len(seen))
		}
	})

	first, err := client.Credits(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	workspace := "request-workspace"
	second, err := client.Credits(context.Background(), &CreditsOptions{WorkspaceID: &workspace})
	if err != nil {
		t.Fatal(err)
	}
	empty := ""
	third, err := client.Credits(context.Background(), &CreditsOptions{WorkspaceID: &empty})
	if err != nil {
		t.Fatal(err)
	}

	firstData, ok := first.Data.(map[string]any)
	if !ok || firstData["workspace_id"] != "client-workspace" {
		t.Fatalf("first credits data = %#v", first.Data)
	}
	secondData, ok := second.Data.([]any)
	if !ok || len(secondData) != 1 {
		t.Fatalf("second credits data = %#v", second.Data)
	}
	thirdData, ok := third.Data.(map[string]any)
	if !ok || thirdData["balance"] != float64(99) {
		t.Fatalf("third credits data = %#v", third.Data)
	}

	want := []seenRequest{
		{method: http.MethodGet, path: "/credits", workspace: "client-workspace"},
		{method: http.MethodGet, path: "/credits", workspace: "request-workspace"},
		{method: http.MethodGet, path: "/credits"},
	}
	if len(seen) != len(want) {
		t.Fatalf("seen requests = %#v", seen)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("request %d = %#v, want %#v", i, seen[i], want[i])
		}
	}
}

func newCatalogWireClient(t *testing.T, opts Options, handler http.HandlerFunc) *Client {
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

func TestCatalogDecodeRoundTrips(t *testing.T) {
	t.Run("ProviderList", func(t *testing.T) {
		assertDecodeMarshalRoundTrip[ProviderList](t, `{"data":[{"id":"openai","name":"OpenAI"}]}`)
	})
	t.Run("RegionList", func(t *testing.T) {
		assertDecodeMarshalRoundTrip[RegionList](t, `{"data":[{"id":"us-central1","name":"US Central"}]}`)
	})
	t.Run("CreditsBalanceDictData", func(t *testing.T) {
		assertDecodeMarshalRoundTrip[CreditsBalance](t, `{"data":{"workspace_id":"w1","balance":12.5}}`)
	})
	t.Run("CreditsBalanceListData", func(t *testing.T) {
		assertDecodeMarshalRoundTrip[CreditsBalance](t, `{"data":[{"workspace_id":"w1","balance":12.5}]}`)
	})
}
