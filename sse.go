package trustedrouter

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/http"
	"strings"
)

var errSSEUnexpectedEOF = errors.New("SSE stream ended before a terminal event")

func iterSSEEvents(r io.Reader) iter.Seq2[map[string]any, error] {
	return func(yield func(map[string]any, error) bool) {
		// Divergence from trusted-router-py: bare-\r SSE line endings are unsupported.
		reader := bufio.NewReader(r)
		var frame []string
		for {
			line, err := reader.ReadString('\n')
			if len(line) > 0 {
				line = strings.TrimRight(line, "\r\n")
				if line == "" {
					event, terminal, frameErr := parseSSEFrame(frame)
					frame = nil
					if frameErr != nil {
						yield(nil, frameErr)
						return
					}
					if event != nil && !yield(event, nil) {
						return
					}
					if terminal {
						return
					}
				} else {
					frame = append(frame, line)
				}
			}
			if err != nil {
				if err != io.EOF {
					yield(nil, err)
					return
				}
				event, terminal, frameErr := parseSSEFrame(frame)
				if frameErr != nil {
					yield(nil, frameErr)
					return
				}
				if event != nil && !yield(event, nil) {
					return
				}
				if !terminal {
					yield(nil, errSSEUnexpectedEOF)
				}
				return
			}
		}
	}
}

func iterSSEChunks(r io.Reader) iter.Seq2[map[string]any, error] {
	return func(yield func(map[string]any, error) bool) {
		// Divergence from trusted-router-py: bare-\r SSE line endings are unsupported.
		reader := bufio.NewReader(r)
		var frame []string
		for {
			line, err := reader.ReadString('\n')
			if len(line) > 0 {
				line = strings.TrimRight(line, "\r\n")
				if line == "" {
					chunk, terminal, frameErr := parseChatSSEFrame(frame)
					frame = nil
					if frameErr != nil {
						yield(nil, frameErr)
						return
					}
					if chunk != nil && !yield(chunk, nil) {
						return
					}
					if terminal {
						return
					}
				} else {
					frame = append(frame, line)
				}
			}
			if err != nil {
				if err != io.EOF {
					yield(nil, err)
					return
				}
				chunk, terminal, frameErr := parseChatSSEFrame(frame)
				if frameErr != nil {
					yield(nil, frameErr)
					return
				}
				if chunk != nil && !yield(chunk, nil) {
					return
				}
				if !terminal {
					yield(nil, errSSEUnexpectedEOF)
				}
				return
			}
		}
	}
}

func eventFromSSEFrame(lines []string) map[string]any {
	event, _, _ := parseSSEFrame(lines)
	return event
}

func parseSSEFrame(lines []string) (map[string]any, bool, error) {
	if len(lines) == 0 {
		return nil, false, nil
	}
	var eventName *string
	var dataParts []string
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "event:"):
			name := strings.TrimSpace(line[len("event:"):])
			eventName = &name
		case strings.HasPrefix(line, "data:"):
			dataParts = append(dataParts, strings.TrimSpace(line[len("data:"):]))
		}
	}
	data := strings.TrimSpace(strings.Join(dataParts, "\n"))
	if data == "" {
		return nil, false, nil
	}
	if data == "[DONE]" {
		return nil, true, nil
	}

	var payload any
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return nil, false, fmt.Errorf("invalid SSE JSON: %w", err)
	}
	obj, ok := payload.(map[string]any)
	if !ok {
		var event any
		if eventName != nil {
			event = *eventName
		}
		return map[string]any{"event": event, "data": payload}, false, nil
	}
	if eventName != nil && *eventName != "" {
		if _, exists := obj["event"]; !exists {
			withEvent := map[string]any{"event": *eventName}
			for key, value := range obj {
				withEvent[key] = value
			}
			return withEvent, isTerminalResponseEvent(*eventName, withEvent), nil
		}
	}
	name := ""
	if eventName != nil {
		name = *eventName
	}
	return obj, isTerminalResponseEvent(name, obj), nil
}

func parseChatSSEFrame(lines []string) (map[string]any, bool, error) {
	var dataParts []string
	for _, line := range lines {
		if strings.HasPrefix(line, "data:") {
			dataParts = append(dataParts, strings.TrimSpace(line[len("data:"):]))
		}
	}
	data := strings.TrimSpace(strings.Join(dataParts, "\n"))
	if data == "" {
		return nil, false, nil
	}
	if data == "[DONE]" {
		return nil, true, nil
	}
	var chunk map[string]any
	if err := json.Unmarshal([]byte(data), &chunk); err != nil {
		return nil, false, fmt.Errorf("invalid SSE JSON: %w", err)
	}
	if chunk == nil {
		return nil, false, errors.New("chat SSE data must be a JSON object")
	}
	if _, failed := chunk["error"]; failed {
		return nil, false, fmt.Errorf("chat SSE error event: %v", chunk["error"])
	}
	return chunk, false, nil
}

func isTerminalResponseEvent(eventName string, payload map[string]any) bool {
	name := eventName
	if typed, ok := payload["type"].(string); ok && typed != "" {
		name = typed
	}
	switch name {
	case "response.completed", "response.failed", "response.incomplete", "error":
		return true
	default:
		return false
	}
}

func raiseForStreamResponse(resp *http.Response) error {
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return transportRetryError(err)
	}
	return classifyError(resp.StatusCode, truncateString(string(body), 240), nil, resp.Header)
}
