package trustedrouter

// orchestration_tools.go is the ORCHESTRATION BUILDERS layer (L7):
// fusion/advisor/selector/mapreduce/subagent tool builders, the model tables
// they key on, and the option-lifting tables that move typed orchestration
// options into gateway tool specs. Wire schemas here are pinned by the
// cross-SDK parity tests and must not change.

import "strings"

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

// FusionToolOptions configures a trustedrouter:fusion tool.
type FusionToolOptions struct {
	// Enabled explicitly enables or disables this tool on a concrete model.
	Enabled *bool
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
	// PanelPrompt adds instructions to each panel model.
	PanelPrompt *string
	// SynthesisPrompt adds instructions to the final synthesizer.
	SynthesisPrompt *string
}

// FusionTool builds a trustedrouter:fusion tool spec.
func FusionTool(opts FusionToolOptions) map[string]any {
	parameters := map[string]any{}
	setPtr(parameters, "enabled", opts.Enabled)
	setPtr(parameters, "preset", opts.Preset)
	setSlice(parameters, "analysis_models", opts.AnalysisModels)
	setPtr(parameters, "model", opts.Model)
	setPtr(parameters, "selection_strategy", opts.SelectionStrategy)
	setSlice(parameters, "fallback_judges", opts.FallbackJudges)
	setSlice(parameters, "fallback_final_models", opts.FallbackFinalModels)
	setPtr(parameters, "max_completion_tokens", opts.MaxCompletionTokens)
	setPtr(parameters, "max_tool_calls", opts.MaxToolCalls)
	setPtr(parameters, "panel_prompt", opts.PanelPrompt)
	setPtr(parameters, "synthesis_prompt", opts.SynthesisPrompt)
	return map[string]any{"type": "trustedrouter:fusion", "parameters": parameters}
}

// AdvisorToolOptions configures a trustedrouter:advisor tool.
type AdvisorToolOptions struct {
	// Enabled explicitly enables or disables this tool on a concrete model.
	Enabled *bool
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
	// WorkerTimeoutMs configures the worker timeout in milliseconds.
	WorkerTimeoutMs *int
	// AdvisorTimeoutMs configures the advisor timeout in milliseconds.
	AdvisorTimeoutMs *int
	// AutoInitialAdvice asks advisors before the first worker turn.
	AutoInitialAdvice *bool
}

// AdvisorTool builds a trustedrouter:advisor tool spec.
func AdvisorTool(opts AdvisorToolOptions) map[string]any {
	parameters := map[string]any{}
	setPtr(parameters, "enabled", opts.Enabled)
	setPtr(parameters, "depth", opts.Depth)
	setSlice(parameters, "worker_models", opts.WorkerModels)
	setSlice(parameters, "advisor_models", opts.AdvisorModels)
	setPtr(parameters, "max_get_advice_calls", opts.MaxGetAdviceCalls)
	setPtr(parameters, "advisor_max_tokens", opts.AdvisorMaxTokens)
	setPtr(parameters, "worker_timeout_ms", opts.WorkerTimeoutMs)
	setPtr(parameters, "advisor_timeout_ms", opts.AdvisorTimeoutMs)
	setPtr(parameters, "auto_initial_advice", opts.AutoInitialAdvice)
	return map[string]any{"type": "trustedrouter:advisor", "parameters": parameters}
}

// SelectorToolOptions configures a trustedrouter:selector tool.
type SelectorToolOptions struct {
	Enabled             *bool
	AnalysisModels      []string
	SelectorModels      []string
	SelectorPrompt      *string
	MaxCompletionTokens *int
}

// SelectorTool builds a trustedrouter:selector tool spec.
func SelectorTool(opts SelectorToolOptions) map[string]any {
	parameters := map[string]any{}
	setPtr(parameters, "enabled", opts.Enabled)
	setSlice(parameters, "analysis_models", opts.AnalysisModels)
	setSlice(parameters, "selector_models", opts.SelectorModels)
	setPtr(parameters, "selector_prompt", opts.SelectorPrompt)
	setPtr(parameters, "max_completion_tokens", opts.MaxCompletionTokens)
	return map[string]any{"type": "trustedrouter:selector", "parameters": parameters}
}

// MapReduceToolOptions configures a trustedrouter:mapreduce tool.
type MapReduceToolOptions struct {
	Enabled             *bool
	MapperModels        []string
	ParallelModels      []string
	ReducerModels       []string
	MaxParts            *int
	MapperPrompt        *string
	ParallelPrompt      *string
	ReducerPrompt       *string
	MaxCompletionTokens *int
}

// MapReduceTool builds a trustedrouter:mapreduce tool spec.
func MapReduceTool(opts MapReduceToolOptions) map[string]any {
	parameters := map[string]any{}
	setPtr(parameters, "enabled", opts.Enabled)
	setSlice(parameters, "mapper_models", opts.MapperModels)
	setSlice(parameters, "parallel_models", opts.ParallelModels)
	setSlice(parameters, "reducer_models", opts.ReducerModels)
	setPtr(parameters, "max_parts", opts.MaxParts)
	setPtr(parameters, "mapper_prompt", opts.MapperPrompt)
	setPtr(parameters, "parallel_prompt", opts.ParallelPrompt)
	setPtr(parameters, "reducer_prompt", opts.ReducerPrompt)
	setPtr(parameters, "max_completion_tokens", opts.MaxCompletionTokens)
	return map[string]any{"type": "trustedrouter:mapreduce", "parameters": parameters}
}

// SubagentToolOptions configures a trustedrouter:subagent tool.
type SubagentToolOptions struct {
	Enabled             *bool
	ControllerModel     *string
	Model               *string
	Instructions        *string
	Depth               *int
	MaxSubagentCalls    *int
	MaxCompletionTokens *int
	Temperature         *float64
	Reasoning           any
	Tools               []map[string]any
}

// SubagentTool builds a trustedrouter:subagent tool spec.
func SubagentTool(opts SubagentToolOptions) map[string]any {
	parameters := map[string]any{}
	setPtr(parameters, "enabled", opts.Enabled)
	setPtr(parameters, "controller_model", opts.ControllerModel)
	setPtr(parameters, "model", opts.Model)
	setPtr(parameters, "instructions", opts.Instructions)
	setPtr(parameters, "depth", opts.Depth)
	setPtr(parameters, "max_subagent_calls", opts.MaxSubagentCalls)
	setPtr(parameters, "max_completion_tokens", opts.MaxCompletionTokens)
	setPtr(parameters, "temperature", opts.Temperature)
	if opts.Reasoning != nil {
		parameters["reasoning"] = opts.Reasoning
	}
	if opts.Tools != nil {
		parameters["tools"] = append([]map[string]any(nil), opts.Tools...)
	}
	return map[string]any{"type": "trustedrouter:subagent", "parameters": parameters}
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
		"worker_timeout_ms",
		"advisor_timeout_ms",
		"auto_initial_advice",
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
