package trustedrouter

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestStableRoutingAndOrchestrationAliases(t *testing.T) {
	want := map[string]string{
		"zdr": ZDRModel, "e2e": E2EModel, "confidential": ConfidentialModel,
		"eu": EUModel, "us": USModel, "synth": SynthModel, "selector": SelectorModel,
		"mapreduce": MapReduceModel, "subagent": SubagentModel,
	}
	if !reflect.DeepEqual(want, map[string]string{
		"zdr": "trustedrouter/zdr", "e2e": "trustedrouter/e2e",
		"confidential": "trustedrouter/confidential", "eu": "trustedrouter/eu",
		"us": "trustedrouter/us", "synth": "trustedrouter/synth",
		"selector": "trustedrouter/selector", "mapreduce": "trustedrouter/mapreduce",
		"subagent": "trustedrouter/subagent",
	}) {
		t.Fatalf("aliases = %#v", want)
	}
}

func TestAtomicOrchestrationToolBuilders(t *testing.T) {
	enabled, disabled := true, false
	workerTimeout := 45_000
	autoAdvice := true
	if got := FusionTool(FusionToolOptions{Enabled: &disabled})["parameters"].(map[string]any); got["enabled"] != false {
		t.Fatalf("fusion enabled = %#v", got)
	}
	if got := AdvisorTool(AdvisorToolOptions{Enabled: &enabled, WorkerTimeoutMs: &workerTimeout, AutoInitialAdvice: &autoAdvice})["parameters"].(map[string]any); !reflect.DeepEqual(got, map[string]any{
		"enabled": true, "worker_timeout_ms": 45_000, "auto_initial_advice": true,
	}) {
		t.Fatalf("advisor = %#v", got)
	}
	prompt := "pick verbatim"
	maxTokens := 128
	selector := SelectorTool(SelectorToolOptions{
		Enabled:        &enabled,
		AnalysisModels: []string{"panel/a", "panel/b"}, SelectorModels: []string{"selector/a"},
		SelectorPrompt: &prompt, MaxCompletionTokens: &maxTokens,
	})
	if got := selector["parameters"].(map[string]any); !reflect.DeepEqual(got, map[string]any{
		"analysis_models": []string{"panel/a", "panel/b"},
		"enabled":         true,
		"selector_models": []string{"selector/a"},
		"selector_prompt": "pick verbatim", "max_completion_tokens": 128,
	}) {
		t.Fatalf("selector = %#v", selector)
	}

	maxParts := 8
	mapper, parallel, reducer := "split", "solve", "merge"
	mapReduce := MapReduceTool(MapReduceToolOptions{
		Enabled:      &enabled,
		MapperModels: []string{"mapper/a"}, ParallelModels: []string{"worker/a"},
		ReducerModels: []string{"reducer/a"}, MaxParts: &maxParts,
		MapperPrompt: &mapper, ParallelPrompt: &parallel, ReducerPrompt: &reducer,
	})
	if got := mapReduce["parameters"].(map[string]any); len(got) != 8 || got["max_parts"] != 8 || got["enabled"] != true {
		t.Fatalf("mapreduce = %#v", mapReduce)
	}

	controller, worker, instructions := "controller/a", "worker/a", "delegate"
	depth, maxCalls := 2, 3
	temperature := 0.2
	subagent := SubagentTool(SubagentToolOptions{
		Enabled:         &enabled,
		ControllerModel: &controller, Model: &worker, Instructions: &instructions,
		Depth: &depth, MaxSubagentCalls: &maxCalls, Temperature: &temperature,
		Tools:     []map[string]any{{"type": "function"}},
		Reasoning: map[string]any{"effort": "high"},
	})
	if got := subagent["parameters"].(map[string]any); got["controller_model"] != controller || got["max_subagent_calls"] != 3 || got["enabled"] != true || !reflect.DeepEqual(got["reasoning"], map[string]any{"effort": "high"}) {
		t.Fatalf("subagent = %#v", subagent)
	}
}

func TestProviderPreferencesUseGatewayWireSchema(t *testing.T) {
	prefs := ProviderPreferences{
		Usage: "credits", Quantizations: []string{"fp8"},
		MaxPrice: map[string]any{"prompt": 1.25, "completion": 4.5},
	}
	encoded, err := json.Marshal(prefs)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(encoded, &body); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"usage": "credits", "quantizations": []any{"fp8"},
		"max_price": map[string]any{"prompt": 1.25, "completion": 4.5},
	}
	if !reflect.DeepEqual(body, want) {
		t.Fatalf("provider = %#v", body)
	}
}

func TestProviderPreferencesApplyToEveryInferenceRequest(t *testing.T) {
	prefs := ConfidentialProvider()
	requests := []any{
		ChatRequest{Messages: []map[string]any{}, Provider: &prefs},
		ResponsesRequest{Input: "hello", Provider: &prefs},
		MessagesRequest{Model: "model/a", Messages: []map[string]any{}, Provider: &prefs},
		EmbeddingsRequest{Model: "model/a", Input: "hello", Provider: &prefs},
	}
	for _, request := range requests {
		encoded, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		if err := json.Unmarshal(encoded, &body); err != nil {
			t.Fatal(err)
		}
		provider, ok := body["provider"].(map[string]any)
		if !ok || provider["min_privacy"] != "confidential" || provider["data_collection"] != "deny" {
			t.Fatalf("provider missing from %T: %s", request, encoded)
		}
	}
}

func TestErrorAttributionRetainsRawPayload(t *testing.T) {
	payload := map[string]any{"error": map[string]any{
		"message": "upstream unavailable", "layer": "provider", "source": "upstream",
		"provider": "example", "request_id": "req_123", "future_field": true,
	}}
	err := classifyError(502, "upstream unavailable", payload, nil)
	internal, ok := err.(*InternalError)
	if !ok {
		t.Fatalf("error = %T", err)
	}
	if internal.Layer != "provider" || internal.Source != "upstream" || internal.Provider != "example" || internal.RequestID != "req_123" {
		t.Fatalf("attribution = %#v", internal.embeddedError)
	}
	if !reflect.DeepEqual(internal.Payload, payload) {
		t.Fatal("raw payload changed")
	}
}
