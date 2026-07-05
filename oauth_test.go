package trustedrouter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestRandomOAuthStateAndPKCEGolden(t *testing.T) {
	state := RandomOAuthState()
	if len(state) != 22 || strings.ContainsAny(state, "=+/") {
		t.Fatalf("state = %q", state)
	}
	if got := len(RandomOAuthState(32)); got != 43 {
		t.Fatalf("32-byte state length = %d", got)
	}

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	pair := CreateOAuthPkcePair(verifier)
	want := OAuthPkcePair{
		CodeVerifier:        verifier,
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
	}
	if pair != want {
		t.Fatalf("pair = %#v, want %#v", pair, want)
	}
}

func TestOAuthAuthorizeURLGoldenMatrix(t *testing.T) {
	client, err := NewClient(Options{
		BaseURL:        "https://gw.internal/v1/",
		ControlBaseURL: "https://control.internal/v1/",
	})
	if err != nil {
		t.Fatal(err)
	}

	full, err := client.OAuthAuthorizeURL(OAuthAuthorizeURLOptions{
		CallbackURL:         "https://app.example/cb?state=old&x=1",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		KeyLabel:            "My Laptop",
		Limit:               25,
		UsageLimitType:      "monthly",
		ExpiresAt:           "2026-12-31T00:00:00Z",
		SpawnAgent:          "agent_1",
		SpawnCloud:          "cloud_1",
		State:               "csrf-state",
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(full)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "https" || parsed.Host != "control.internal" || parsed.Path != "/v1/auth" {
		t.Fatalf("authorize URL = %s", full)
	}
	query := parsed.Query()
	callback, err := url.Parse(query.Get("callback_url"))
	if err != nil {
		t.Fatal(err)
	}
	if callback.String() != "https://app.example/cb?state=csrf-state&x=1" {
		t.Fatalf("callback_url = %s", callback)
	}
	wantQuery := map[string][]string{
		"callback_url":          {callback.String()},
		"code_challenge":        {"challenge"},
		"code_challenge_method": {"S256"},
		"key_label":             {"My Laptop"},
		"limit":                 {"25"},
		"usage_limit_type":      {"monthly"},
		"expires_at":            {"2026-12-31T00:00:00Z"},
		"spawn_agent":           {"agent_1"},
		"spawn_cloud":           {"cloud_1"},
	}
	if !reflect.DeepEqual(map[string][]string(query), wantQuery) {
		t.Fatalf("query = %#v\nwant = %#v", map[string][]string(query), wantQuery)
	}

	minimal, err := client.OAuthAuthorizeURL(OAuthAuthorizeURLOptions{CallbackURL: "https://app.example/cb"})
	if err != nil {
		t.Fatal(err)
	}
	minimalParsed, err := url.Parse(minimal)
	if err != nil {
		t.Fatal(err)
	}
	if minimalParsed.Query().Get("callback_url") != "https://app.example/cb" || minimalParsed.Query().Get("state") != "" {
		t.Fatalf("minimal authorize URL = %s", minimal)
	}
	withChallengeDefault, err := client.OAuthAuthorizeURL(OAuthAuthorizeURLOptions{
		CallbackURL:   "https://app.example/cb",
		CodeChallenge: "challenge",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := mustParseURL(t, withChallengeDefault).Query().Get("code_challenge_method"); got != "S256" {
		t.Fatalf("default method = %q", got)
	}
}

func TestOAuthAuthorizeURLValidationErrors(t *testing.T) {
	client, err := NewClient(Options{})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		opts OAuthAuthorizeURLOptions
		want string
	}{
		{
			name: "empty callback URL",
			opts: OAuthAuthorizeURLOptions{},
			want: "callbackUrl is required",
		},
		{
			name: "unparseable callback URL",
			opts: OAuthAuthorizeURLOptions{CallbackURL: "http://[::1"},
			want: "invalid callbackUrl",
		},
		{
			name: "method without challenge",
			opts: OAuthAuthorizeURLOptions{
				CallbackURL:         "https://app.example/cb",
				CodeChallengeMethod: "S256",
			},
			want: "codeChallenge is required when codeChallengeMethod is set",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := client.OAuthAuthorizeURL(tc.opts); err == nil || !strings.Contains(err.Error(), tc.want) || got != "" {
				t.Fatalf("OAuthAuthorizeURL() = %q, %v; want error containing %q", got, err, tc.want)
			}
		})
	}
}

func TestCreateOAuthAuthorizationReturnsAuthorizeURLError(t *testing.T) {
	client, err := NewClient(Options{})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := client.CreateOAuthAuthorization(CreateOAuthAuthorizationOptions{})
	if err == nil || !strings.Contains(err.Error(), "callbackUrl is required") {
		t.Fatalf("CreateOAuthAuthorization() = %#v, %v", auth, err)
	}
}

func TestCreateOAuthAuthorizationRespectsPinnedVerifierAndState(t *testing.T) {
	client, err := NewClient(Options{})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := client.CreateOAuthAuthorization(CreateOAuthAuthorizationOptions{
		CallbackURL:  "https://app.example/cb",
		CodeVerifier: "pinned-verifier",
		State:        "pinned-state",
		KeyLabel:     "agent",
		Limit:        "5",
	})
	if err != nil {
		t.Fatal(err)
	}
	if auth.CodeVerifier != "pinned-verifier" || auth.State != "pinned-state" {
		t.Fatalf("authorization = %#v", auth)
	}
	parsed := mustParseURL(t, auth.URL)
	callback := mustParseURL(t, parsed.Query().Get("callback_url"))
	if parsed.Query().Get("code_challenge") != auth.CodeChallenge ||
		parsed.Query().Get("code_challenge_method") != "S256" ||
		parsed.Query().Get("key_label") != "agent" ||
		parsed.Query().Get("limit") != "5" ||
		callback.Query().Get("state") != "pinned-state" {
		t.Fatalf("authorization URL = %s", auth.URL)
	}
}

func TestExchangeOAuthKeyPostsWithoutAuthorization(t *testing.T) {
	var seen struct {
		method        string
		path          string
		authorization string
		workspace     string
		body          map[string]any
	}
	client := newIncrement3TestClient(t, Options{
		APIKey:      "client-key",
		WorkspaceID: "client-workspace",
	}, func(w http.ResponseWriter, r *http.Request) {
		seen.method = r.Method
		seen.path = r.URL.Path
		seen.authorization = r.Header.Get("authorization")
		seen.workspace = r.Header.Get("x-trustedrouter-workspace")
		seen.body = decodeRequestBody(t, r)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"key":      "sk-tr-v1-delegated",
			"user_id":  "user_1",
			"identity": map[string]any{"sub": "user_1", "email": "u@example.test", "extra": "kept"},
			"data":     map[string]any{"scope": "limited"},
			"future":   "kept",
		})
	})

	token, err := client.ExchangeOAuthKey(context.Background(), OAuthKeyExchangeRequest{
		Code:                "auth-code",
		CodeVerifier:        "verifier",
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	if token.Key != "sk-tr-v1-delegated" || token.UserID == nil || *token.UserID != "user_1" ||
		token.Identity == nil || token.Identity.Extra["extra"] != "kept" ||
		token.Data["scope"] != "limited" || token.Extra["future"] != "kept" {
		t.Fatalf("token = %#v", token)
	}

	want := struct {
		method        string
		path          string
		authorization string
		workspace     string
		body          map[string]any
	}{
		method:    http.MethodPost,
		path:      "/auth/keys",
		workspace: "client-workspace",
		body: map[string]any{
			"code":                  "auth-code",
			"code_verifier":         "verifier",
			"code_challenge_method": "S256",
		},
	}
	if !reflect.DeepEqual(seen, want) {
		t.Fatalf("seen = %#v\nwant = %#v", seen, want)
	}
}

func TestExchangeOAuthKeyRequiresCode(t *testing.T) {
	client, err := NewClient(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ExchangeOAuthKey(context.Background(), OAuthKeyExchangeRequest{}); err == nil || err.Error() != "code is required" {
		t.Fatalf("err = %v", err)
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
