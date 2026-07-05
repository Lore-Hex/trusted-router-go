package trustedrouter

import (
	"bufio"
	"encoding/json"
	"io"
	"iter"
	"net/http"
	"strings"
)

//lint:ignore U1000 wired to the Responses API in increment 2
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
					event := eventFromSSEFrame(frame)
					frame = nil
					if event != nil && !yield(event, nil) {
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
				event := eventFromSSEFrame(frame)
				if event != nil {
					yield(event, nil)
				}
				return
			}
		}
	}
}

func parseSSELine(line string) map[string]any {
	if !strings.HasPrefix(line, "data: ") {
		return nil
	}
	payload := strings.TrimSpace(line[len("data: "):])
	if payload == "" || payload == "[DONE]" {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(payload), &out); err != nil {
		// Divergence from trusted-router-py: non-object JSON data frames are skipped.
		return nil
	}
	return out
}

func iterSSEChunks(r io.Reader) iter.Seq2[map[string]any, error] {
	return func(yield func(map[string]any, error) bool) {
		// Divergence from trusted-router-py: bare-\r SSE line endings are unsupported.
		reader := bufio.NewReader(r)
		for {
			line, err := reader.ReadString('\n')
			if len(line) > 0 {
				line = strings.TrimRight(line, "\r\n")
				if isSSEDoneLine(line) {
					// Divergence from trusted-router-py: [DONE] terminates iteration.
					return
				}
				chunk := parseSSELine(line)
				if chunk != nil && !yield(chunk, nil) {
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					yield(nil, err)
				}
				return
			}
		}
	}
}

func isSSEDoneLine(line string) bool {
	if !strings.HasPrefix(line, "data: ") {
		return false
	}
	return strings.TrimSpace(line[len("data: "):]) == "[DONE]"
}

//lint:ignore U1000 wired to the Responses API in increment 2
func eventFromSSEFrame(lines []string) map[string]any {
	if len(lines) == 0 {
		return nil
	}
	var eventName string
	var dataParts []string
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "event:"):
			eventName = strings.TrimSpace(line[len("event:"):])
		case strings.HasPrefix(line, "data:"):
			dataParts = append(dataParts, strings.TrimSpace(line[len("data:"):]))
		}
	}
	data := strings.TrimSpace(strings.Join(dataParts, "\n"))
	if data == "" || data == "[DONE]" {
		return nil
	}

	var payload any
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		payload = map[string]any{"data": data}
	}
	obj, ok := payload.(map[string]any)
	if !ok {
		return map[string]any{"event": eventName, "data": payload}
	}
	if eventName != "" {
		if _, exists := obj["event"]; !exists {
			withEvent := map[string]any{"event": eventName}
			for key, value := range obj {
				withEvent[key] = value
			}
			return withEvent
		}
	}
	return obj
}

func raiseForStreamResponse(resp *http.Response) error {
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return transportRetryError(err)
	}
	return classifyError(resp.StatusCode, truncateString(string(body), 240), nil, resp.Header)
}
