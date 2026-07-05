package trustedrouter

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
)

func TestBillingCheckoutWireShape(t *testing.T) {
	type seenRequest struct {
		method         string
		path           string
		workspace      string
		idempotencyKey string
		body           map[string]any
	}
	var seen []seenRequest
	client := newIncrement3TestClient(t, Options{WorkspaceID: "client-workspace"}, func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, seenRequest{
			method:         r.Method,
			path:           r.URL.Path,
			workspace:      r.Header.Get("x-trustedrouter-workspace"),
			idempotencyKey: r.Header.Get("idempotency-key"),
			body:           decodeRequestBody(t, r),
		})
		if r.Method != http.MethodPost || r.URL.Path != "/billing/checkout" {
			t.Fatalf("unexpected request = %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"url": "https://checkout.example/session", "status": "open", "future": "kept"})
	})

	paymentMethod := "card"
	workspace := "billing-workspace"
	successURL := "https://app.example/success"
	cancelURL := "https://app.example/cancel"
	resp, err := client.BillingCheckout(context.Background(), BillingCheckoutRequest{
		Amount:        "25.50",
		PaymentMethod: &paymentMethod,
		WorkspaceID:   &workspace,
		SuccessURL:    &successURL,
		CancelURL:     &cancelURL,
		CallOptions:   CallOptions{IdempotencyKey: "checkout-idem"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Extra["future"] != "kept" || resp.URL == nil || *resp.URL != "https://checkout.example/session" {
		t.Fatalf("checkout response = %#v", resp)
	}

	if _, err := client.StablecoinCheckout(context.Background(), BillingCheckoutRequest{Amount: 42}); err != nil {
		t.Fatal(err)
	}

	want := []seenRequest{
		{
			method:         http.MethodPost,
			path:           "/billing/checkout",
			workspace:      "billing-workspace",
			idempotencyKey: "checkout-idem",
			body: map[string]any{
				"amount":         "25.50",
				"payment_method": "card",
				"workspace_id":   "billing-workspace",
				"success_url":    "https://app.example/success",
				"cancel_url":     "https://app.example/cancel",
			},
		},
		{
			method:    http.MethodPost,
			path:      "/billing/checkout",
			workspace: "client-workspace",
			body:      map[string]any{"amount": float64(42), "payment_method": "stablecoin"},
		},
	}
	if !reflect.DeepEqual(seen, want) {
		t.Fatalf("seen = %#v\nwant = %#v", seen, want)
	}
}

func TestAccountEndpointsAndStatusWireShape(t *testing.T) {
	type seenRequest struct {
		method        string
		url           string
		path          string
		query         string
		authorization string
		workspace     string
	}
	var seen []seenRequest
	client := newIncrement3TestClient(t, Options{
		APIKey:      "client-key",
		WorkspaceID: "client-workspace",
	}, func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, seenRequest{
			method:        r.Method,
			url:           r.URL.String(),
			path:          r.URL.Path,
			query:         r.URL.RawQuery,
			authorization: r.Header.Get("authorization"),
			workspace:     r.Header.Get("x-trustedrouter-workspace"),
		})
		switch r.URL.Path {
		case "/auth/session":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"authenticated": true,
				"user":          map[string]any{"id": "user_1", "email": "u@example.test", "role": "owner"},
				"session_id":    "sess_1",
			})
		case "/auth/logout":
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		case "/auth/userinfo":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"sub":          "user_1",
					"email":        "u@example.test",
					"workspace_id": "ws_1",
					"plan":         "pro",
				},
			})
		case "/activity":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activities": []map[string]any{{"id": "act_1", "created_at": 12, "extra": "kept"}},
			})
		case "/status.json":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
		default:
			t.Fatalf("unexpected path = %s", r.URL.Path)
		}
	})

	session, err := client.AuthSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !session.Authenticated || session.Extra["session_id"] != "sess_1" || session.User.Extra["role"] != "owner" {
		t.Fatalf("session = %#v", session)
	}
	logout, err := client.Logout(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if logout.Extra["ok"] != true {
		t.Fatalf("logout = %#v", logout)
	}
	info, err := client.UserInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.Data.Sub != "user_1" || info.Data.Extra["plan"] != "pro" {
		t.Fatalf("userinfo = %#v", info)
	}
	activity, err := client.Activity(context.Background(), map[string]string{
		"limit":        "10",
		"workspace_id": "ws_1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(activity.Activities) != 1 || activity.Activities[0].Extra["extra"] != "kept" {
		t.Fatalf("activity = %#v", activity)
	}
	status, err := client.Status(context.Background(), "https://status.example.test/status.json")
	if err != nil {
		t.Fatal(err)
	}
	if status["status"] != "ok" {
		t.Fatalf("status = %#v", status)
	}

	want := []seenRequest{
		{method: http.MethodGet, url: "https://example.test/auth/session", path: "/auth/session", authorization: "Bearer client-key", workspace: "client-workspace"},
		{method: http.MethodPost, url: "https://example.test/auth/logout", path: "/auth/logout", authorization: "Bearer client-key", workspace: "client-workspace"},
		{method: http.MethodGet, url: "https://example.test/auth/userinfo", path: "/auth/userinfo", authorization: "Bearer client-key", workspace: "client-workspace"},
		{method: http.MethodGet, url: "https://example.test/activity?limit=10&workspace_id=ws_1", path: "/activity", query: "limit=10&workspace_id=ws_1", authorization: "Bearer client-key", workspace: "client-workspace"},
		{method: http.MethodGet, url: "https://status.example.test/status.json", path: "/status.json"},
	}
	if !reflect.DeepEqual(seen, want) {
		t.Fatalf("seen = %#v\nwant = %#v", seen, want)
	}
}

func TestStatusUsesDefaultURL(t *testing.T) {
	var seenMethod, seenURL string
	client, err := NewClient(Options{
		HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
			seenMethod = r.Method
			seenURL = r.URL.String()
			return jsonResponse(http.StatusOK, map[string]any{"status": "ok"}, nil), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	status, err := client.Status(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if status["status"] != "ok" {
		t.Fatalf("status = %#v", status)
	}
	if seenMethod != http.MethodGet || seenURL != DefaultStatusURL {
		t.Fatalf("request = %s %s, want GET %s", seenMethod, seenURL, DefaultStatusURL)
	}
}
