package trustedrouter

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OAuthPkcePair is a PKCE verifier/challenge pair.
type OAuthPkcePair struct {
	// CodeVerifier is the high-entropy verifier kept by the client.
	CodeVerifier string `json:"code_verifier"`
	// CodeChallenge is the S256 challenge sent in the authorize URL.
	CodeChallenge string `json:"code_challenge"`
	// CodeChallengeMethod is always "S256" for generated pairs.
	CodeChallengeMethod string `json:"code_challenge_method"`
}

// OAuthAuthorizeURLOptions configures an OAuth authorize URL.
type OAuthAuthorizeURLOptions struct {
	CallbackURL         string
	CodeChallenge       string
	CodeChallengeMethod string
	KeyLabel            string
	Limit               any
	UsageLimitType      string
	ExpiresAt           string
	SpawnAgent          string
	SpawnCloud          string
	State               string
}

// OAuthAuthorizeUrlOptions is an alias for callers using the TypeScript-style name.
type OAuthAuthorizeUrlOptions = OAuthAuthorizeURLOptions

// CreateOAuthAuthorizationOptions configures CreateOAuthAuthorization.
type CreateOAuthAuthorizationOptions struct {
	CallbackURL    string
	CodeVerifier   string
	KeyLabel       string
	Limit          any
	UsageLimitType string
	ExpiresAt      string
	SpawnAgent     string
	SpawnCloud     string
	State          string
}

// OAuthAuthorization contains all values needed to start and later finish the OAuth flow.
type OAuthAuthorization struct {
	OAuthPkcePair
	// State is the CSRF token embedded into the callback URL.
	State string `json:"state"`
	// URL is the browser authorize URL.
	URL string `json:"url"`
}

// OAuthKeyExchangeRequest configures an OAuth key exchange.
type OAuthKeyExchangeRequest struct {
	Code                string
	CodeVerifier        string
	CodeChallengeMethod string
	Timeout             *time.Duration
}

// OAuthKeyExchangeResponse is the response returned by POST /auth/keys.
type OAuthKeyExchangeResponse struct {
	// Key is the delegated bearer key.
	Key string `json:"key"`
	// UserID is the owning user id, when returned.
	UserID *string `json:"user_id,omitempty"`
	// Identity is the verified identity, when returned.
	Identity *OAuthIdentity `json:"identity,omitempty"`
	// Data contains the opaque response data field.
	Data map[string]any `json:"data,omitempty"`
	// Extra contains unknown exchange fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes an OAuth key exchange response and preserves unknown fields in Extra.
func (o *OAuthKeyExchangeResponse) UnmarshalJSON(data []byte) error {
	type alias OAuthKeyExchangeResponse
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*o = OAuthKeyExchangeResponse(out)
	o.Extra = extraFields(data, "key", "user_id", "identity", "data")
	return nil
}

// OAuthIdentity is the verified identity returned by OAuth endpoints.
type OAuthIdentity struct {
	Sub           string         `json:"sub"`
	Email         *string        `json:"email,omitempty"`
	EmailVerified *bool          `json:"email_verified,omitempty"`
	WalletAddress *string        `json:"wallet_address,omitempty"`
	Extra         map[string]any `json:"-"`
}

// UnmarshalJSON decodes an OAuth identity and preserves unknown fields in Extra.
func (o *OAuthIdentity) UnmarshalJSON(data []byte) error {
	type alias OAuthIdentity
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*o = OAuthIdentity(out)
	o.Extra = extraFields(data, "sub", "email", "email_verified", "wallet_address")
	return nil
}

// RandomOAuthState returns an opaque URL-safe CSRF/state token.
func RandomOAuthState(byteLength ...int) string {
	length := 16
	if len(byteLength) > 0 {
		length = byteLength[0]
	}
	return randomBase64URL(length)
}

// CreateOAuthPkcePair builds a PKCE S256 pair. Pass a verifier to reuse one.
func CreateOAuthPkcePair(codeVerifier ...string) OAuthPkcePair {
	verifier := ""
	if len(codeVerifier) > 0 {
		verifier = codeVerifier[0]
	}
	if verifier == "" {
		verifier = randomBase64URL(32)
	}
	return OAuthPkcePair{
		CodeVerifier:        verifier,
		CodeChallenge:       sha256Base64URL(verifier),
		CodeChallengeMethod: "S256",
	}
}

// OAuthAuthorizeURL builds the browser authorize URL.
func (c *Client) OAuthAuthorizeURL(opts OAuthAuthorizeURLOptions) (string, error) {
	return oauthAuthorizeURL(c.controlBaseURL, opts)
}

// CreateOAuthAuthorization generates PKCE/state and builds the authorize URL.
func (c *Client) CreateOAuthAuthorization(opts CreateOAuthAuthorizationOptions) (OAuthAuthorization, error) {
	pkce := CreateOAuthPkcePair(opts.CodeVerifier)
	state := opts.State
	if state == "" {
		state = RandomOAuthState()
	}
	authorizeURL, err := c.OAuthAuthorizeURL(OAuthAuthorizeURLOptions{
		CallbackURL:         opts.CallbackURL,
		CodeChallenge:       pkce.CodeChallenge,
		CodeChallengeMethod: pkce.CodeChallengeMethod,
		KeyLabel:            opts.KeyLabel,
		Limit:               opts.Limit,
		UsageLimitType:      opts.UsageLimitType,
		ExpiresAt:           opts.ExpiresAt,
		SpawnAgent:          opts.SpawnAgent,
		SpawnCloud:          opts.SpawnCloud,
		State:               state,
	})
	if err != nil {
		return OAuthAuthorization{}, err
	}
	return OAuthAuthorization{
		OAuthPkcePair: pkce,
		State:         state,
		URL:           authorizeURL,
	}, nil
}

// ExchangeOAuthKey exchanges an OAuth authorization code for a delegated key.
func (c *Client) ExchangeOAuthKey(ctx context.Context, req OAuthKeyExchangeRequest) (*OAuthKeyExchangeResponse, error) {
	if req.Code == "" {
		return nil, &Error{Message: "code is required"}
	}
	body := map[string]any{"code": req.Code}
	if req.CodeVerifier != "" {
		body["code_verifier"] = req.CodeVerifier
	}
	if req.CodeChallengeMethod != "" {
		body["code_challenge_method"] = req.CodeChallengeMethod
	}
	emptyAPIKey := ""
	callOpts := CallOptions{APIKey: &emptyAPIKey, Timeout: req.Timeout}
	var out OAuthKeyExchangeResponse
	if err := c.controlRequest(ctx, http.MethodPost, "/auth/keys", body, &out, &callOpts); err != nil {
		return nil, err
	}
	return &out, nil
}

func oauthAuthorizeURL(baseURL string, opts OAuthAuthorizeURLOptions) (string, error) {
	if opts.CallbackURL == "" {
		return "", fmt.Errorf("callbackUrl is required")
	}
	method := opts.CodeChallengeMethod
	if method == "" && opts.CodeChallenge != "" {
		method = "S256"
	}
	if method != "" && opts.CodeChallenge == "" {
		return "", fmt.Errorf("codeChallenge is required when codeChallengeMethod is set")
	}
	if _, err := url.Parse(opts.CallbackURL); err != nil {
		return "", fmt.Errorf("invalid callbackUrl: %w", err)
	}

	callbackURL := opts.CallbackURL
	if opts.State != "" {
		withState, err := callbackURLWithState(callbackURL, opts.State)
		if err != nil {
			return "", err
		}
		callbackURL = withState
	}

	authorize, err := url.Parse(strings.TrimRight(baseURL, "/") + "/auth")
	if err != nil {
		return "", err
	}
	query := authorize.Query()
	query.Set("callback_url", callbackURL)
	if opts.CodeChallenge != "" {
		query.Set("code_challenge", opts.CodeChallenge)
	}
	if method != "" {
		query.Set("code_challenge_method", method)
	}
	if opts.KeyLabel != "" {
		query.Set("key_label", opts.KeyLabel)
	}
	if opts.Limit != nil {
		query.Set("limit", fmt.Sprint(opts.Limit))
	}
	if opts.UsageLimitType != "" {
		query.Set("usage_limit_type", opts.UsageLimitType)
	}
	if opts.ExpiresAt != "" {
		query.Set("expires_at", opts.ExpiresAt)
	}
	if opts.SpawnAgent != "" {
		query.Set("spawn_agent", opts.SpawnAgent)
	}
	if opts.SpawnCloud != "" {
		query.Set("spawn_cloud", opts.SpawnCloud)
	}
	authorize.RawQuery = query.Encode()
	return authorize.String(), nil
}

func callbackURLWithState(callbackURL, state string) (string, error) {
	parsed, err := url.Parse(callbackURL)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("state", state)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func randomBase64URL(byteLength int) string {
	if byteLength < 0 {
		byteLength = 0
	}
	raw := make([]byte, byteLength)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func sha256Base64URL(text string) string {
	digest := sha256.Sum256([]byte(text))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
