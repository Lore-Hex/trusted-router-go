package trustedrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
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
		cookie        string
		workspace     string
		idempotency   string
		proxyAuth     string
		xAPIKey       string
		telemetry     string
		publicDefault string
		body          map[string]any
	}
	client := newIncrement3TestClient(t, Options{
		APIKey:      "client-key",
		WorkspaceID: "client-workspace",
		Headers: map[string]string{
			"Authorization":         "Bearer header-secret",
			"Proxy-Authorization":   "Basic proxy-secret",
			"Cookie":                "session=secret",
			"X-Api-Key":             "alternate-secret",
			"Idempotency-Key":       "stale-key",
			"X-Tr-Client":           "stale-telemetry",
			"X-Conformance-Default": "public-client",
		},
	}, func(w http.ResponseWriter, r *http.Request) {
		seen.method = r.Method
		seen.path = r.URL.Path
		seen.authorization = r.Header.Get("authorization")
		seen.cookie = r.Header.Get("cookie")
		seen.workspace = r.Header.Get("x-trustedrouter-workspace")
		seen.idempotency = r.Header.Get("idempotency-key")
		seen.proxyAuth = r.Header.Get("proxy-authorization")
		seen.xAPIKey = r.Header.Get("x-api-key")
		seen.telemetry = r.Header.Get("x-tr-client")
		seen.publicDefault = r.Header.Get("x-conformance-default")
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
		cookie        string
		workspace     string
		idempotency   string
		proxyAuth     string
		xAPIKey       string
		telemetry     string
		publicDefault string
		body          map[string]any
	}{
		method:        http.MethodPost,
		path:          "/auth/keys",
		publicDefault: "public-client",
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

// TestAuthWireFixtures exercises literal producer bytes through public HTTP paths.
func TestAuthWireFixtures(t *testing.T) {
	raw, err := os.ReadFile("testdata/auth-wire-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	type wireCases struct {
		Accept map[string]json.RawMessage `json:"accept"`
		Reject map[string]json.RawMessage `json:"reject"`
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"exchange", "userinfo"} {
		var cases wireCases
		if err := json.Unmarshal(wire[endpoint], &cases); err != nil {
			t.Fatal(err)
		}
		for verdict, payloads := range map[string]map[string]json.RawMessage{"accept": cases.Accept, "reject": cases.Reject} {
			for name, payload := range payloads {
				t.Run(endpoint+"/"+verdict+"/"+name, func(t *testing.T) {
					client, err := NewClient(Options{HTTPClient: newRoundTripClient(func(r *http.Request) (*http.Response, error) {
						method, path := http.MethodPost, "/auth/keys"
						if endpoint == "userinfo" {
							method, path = http.MethodGet, "/auth/userinfo"
						}
						if r.Method != method || !strings.HasSuffix(r.URL.Path, path) {
							t.Fatalf("request = %s %s", r.Method, r.URL.Path)
						}
						return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(payload))}, nil
					})})
					if err != nil {
						t.Fatal(err)
					}
					defer client.Close()
					var got any
					if endpoint == "exchange" {
						got, err = client.ExchangeOAuthKey(context.Background(), OAuthKeyExchangeRequest{Code: "code"})
					} else {
						got, err = client.UserInfo(context.Background())
					}
					if verdict == "reject" {
						var shape *ResponseShapeError
						if !errors.As(err, &shape) {
							t.Fatalf("want typed shape error, got %T: %v", err, err)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					var want any
					if err := json.Unmarshal(payload, &want); err != nil {
						t.Fatal(err)
					}
					assertWireFields(t, want, authWireValue(reflect.ValueOf(got)))
				})
			}
		}
	}
}

// Reconstruct public typed fields plus Extra, so every producer field is checked,
// including unknown nested identity data and null legacy subjects.
func authWireValue(v reflect.Value) any {
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		return authWireValue(v.Elem())
	}
	if v.Kind() != reflect.Struct {
		return v.Interface()
	}
	out := map[string]any{}
	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		if field.Name == "Extra" {
			if extra, ok := v.Field(i).Interface().(map[string]any); ok {
				for k, value := range extra {
					out[k] = value
				}
			}
			continue
		}
		key := strings.Split(field.Tag.Get("json"), ",")[0]
		if key != "" && key != "-" {
			out[key] = authWireValue(v.Field(i))
		}
	}
	return out
}

func assertWireFields(t *testing.T, want, got any) {
	t.Helper()
	if fields, ok := want.(map[string]any); ok {
		actual, ok := got.(map[string]any)
		if !ok {
			t.Fatalf("want object %v, got %T", want, got)
		}
		for key, value := range fields {
			next, exists := actual[key]
			if !exists {
				t.Fatalf("missing field %s", key)
			}
			assertWireFields(t, value, next)
		}
	} else if !reflect.DeepEqual(want, got) {
		t.Fatalf("wire field = %#v, want %#v", got, want)
	}
}
