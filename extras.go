package trustedrouter

// extras.go is ATTEMPT-ASSEMBLY input shaping (L4): lifting the reserved
// Extra-map keys (api_key, workspace_id, idempotency_key, timeout,
// extra_headers) into typed CallOptions before a request is built. Typed
// CallOptions always win over Extra-map values.

import "time"

func chatCallOptions(req ChatRequest) CallOptions {
	callOpts := req.CallOptions
	extra := req.Extra
	if callOpts.APIKey == nil {
		if value, ok := stringExtra(extra, "api_key"); ok {
			callOpts.APIKey = &value
		}
	}
	if callOpts.WorkspaceID == nil {
		if value, ok := stringExtra(extra, "workspace_id"); ok {
			callOpts.WorkspaceID = &value
		}
	}
	if callOpts.IdempotencyKey == "" {
		if value, ok := stringExtra(extra, "idempotency_key"); ok {
			callOpts.IdempotencyKey = value
		}
	}
	if callOpts.Timeout == nil {
		if timeout, ok := timeoutExtra(extra, "timeout"); ok {
			callOpts.Timeout = &timeout
		}
	}
	if headers := headersExtra(extra, "extra_headers"); len(headers) > 0 {
		merged := make(map[string]string, len(headers)+len(callOpts.ExtraHeaders))
		for key, value := range headers {
			merged[key] = value
		}
		for key, value := range callOpts.ExtraHeaders {
			merged[key] = value
		}
		callOpts.ExtraHeaders = merged
	}
	return callOpts
}

func responsesCallOptions(req ResponsesRequest, routeAllReserved bool) CallOptions {
	callOpts := req.CallOptions
	extra := req.Extra
	if routeAllReserved && callOpts.APIKey == nil {
		if value, ok := stringExtra(extra, "api_key"); ok {
			callOpts.APIKey = &value
		}
	}
	if callOpts.WorkspaceID == nil {
		if value, ok := stringExtra(extra, "workspace_id"); ok {
			callOpts.WorkspaceID = &value
		}
	}
	if routeAllReserved && callOpts.IdempotencyKey == "" {
		if value, ok := stringExtra(extra, "idempotency_key"); ok {
			callOpts.IdempotencyKey = value
		}
	}
	if routeAllReserved && callOpts.Timeout == nil {
		if timeout, ok := timeoutExtra(extra, "timeout"); ok {
			callOpts.Timeout = &timeout
		}
	}
	if routeAllReserved {
		if headers := headersExtra(extra, "extra_headers"); len(headers) > 0 {
			merged := make(map[string]string, len(headers)+len(callOpts.ExtraHeaders))
			for key, value := range headers {
				merged[key] = value
			}
			for key, value := range callOpts.ExtraHeaders {
				merged[key] = value
			}
			callOpts.ExtraHeaders = merged
		}
	}
	return callOpts
}

func timeoutExtra(extra map[string]any, key string) (time.Duration, bool) {
	value, ok := extra[key]
	if !ok {
		return 0, false
	}
	switch v := value.(type) {
	case int:
		return time.Duration(v) * time.Second, true
	case float64:
		return time.Duration(v * float64(time.Second)), true
	default:
		return 0, false
	}
}

func stringExtra(extra map[string]any, key string) (string, bool) {
	value, ok := extra[key]
	if !ok {
		return "", false
	}
	s, ok := value.(string)
	return s, ok
}

func headersExtra(extra map[string]any, key string) map[string]string {
	value, ok := extra[key]
	if !ok {
		return nil
	}
	switch headers := value.(type) {
	case map[string]string:
		out := make(map[string]string, len(headers))
		for key, value := range headers {
			out[key] = value
		}
		return out
	case map[string]any:
		out := make(map[string]string, len(headers))
		for key, value := range headers {
			if s, ok := value.(string); ok {
				out[key] = s
			}
		}
		return out
	default:
		return nil
	}
}
