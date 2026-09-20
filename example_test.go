package trustedrouter_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	trustedrouter "github.com/Lore-Hex/trusted-router-go"
)

func ExampleClient_ChatCompletions() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer example-key" {
			http.Error(w, "unexpected request", 400)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, `data: {"id":"example","choices":[{"index":0,"delta":{"role":"assistant","content":"Hello from TrustedRouter!"},"finish_reason":"stop"}]}

data: [DONE]

`)
	}))
	defer server.Close()
	client, err := trustedrouter.NewClient(trustedrouter.Options{APIKey: "example-key", BaseURL: server.URL + "/v1"})
	if err != nil {
		panic(err)
	}
	defer client.Close()
	response, err := client.ChatCompletions(context.Background(), trustedrouter.ChatRequest{Model: trustedrouter.AutoModel, Messages: []map[string]any{{"role": "user", "content": "Hello"}}})
	if err != nil {
		panic(err)
	}
	fmt.Println(*response.Choices[0].Message.Content)
	// Output: Hello from TrustedRouter!
}
