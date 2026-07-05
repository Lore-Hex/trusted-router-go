package trustedrouter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

// AuthSessionResponse is the response returned by the auth session endpoint.
type AuthSessionResponse struct {
	// Authenticated indicates whether the request has an authenticated session.
	Authenticated bool `json:"authenticated"`
	// User is the authenticated user, when present.
	User *AuthSessionUser `json:"user,omitempty"`
	// Extra contains unknown session fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes an auth session response and preserves unknown fields in Extra.
func (a *AuthSessionResponse) UnmarshalJSON(data []byte) error {
	type alias AuthSessionResponse
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*a = AuthSessionResponse(out)
	a.Extra = extraFields(data, "authenticated", "user")
	return nil
}

// AuthSessionUser is the user shape returned by the auth session endpoint.
type AuthSessionUser struct {
	// ID is the user identifier.
	ID string `json:"id"`
	// Email is the user's email, when present.
	Email *string `json:"email,omitempty"`
	// Extra contains unknown user fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes an auth session user and preserves unknown fields in Extra.
func (u *AuthSessionUser) UnmarshalJSON(data []byte) error {
	type alias AuthSessionUser
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*u = AuthSessionUser(out)
	u.Extra = extraFields(data, "id", "email")
	return nil
}

// LogoutResponse is the response returned by the logout endpoint.
type LogoutResponse struct {
	// Extra contains all response fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes a logout response and preserves all fields in Extra.
func (l *LogoutResponse) UnmarshalJSON(data []byte) error {
	var all map[string]any
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}
	l.Extra = all
	return nil
}

// UserInfoResponse is the envelope returned by GET /auth/userinfo.
type UserInfoResponse struct {
	// Data is the verified identity bound to the key.
	Data UserInfoData `json:"data"`
	// Extra contains unknown top-level response fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes a userinfo response and preserves unknown fields in Extra.
func (u *UserInfoResponse) UnmarshalJSON(data []byte) error {
	type alias UserInfoResponse
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*u = UserInfoResponse(out)
	u.Extra = extraFields(data, "data")
	return nil
}

// UserInfoData is the data payload returned by GET /auth/userinfo.
type UserInfoData struct {
	// Sub is the OIDC subject.
	Sub string `json:"sub"`
	// Email is the user's email, when present.
	Email *string `json:"email,omitempty"`
	// EmailVerified indicates whether the email is verified.
	EmailVerified *bool `json:"email_verified,omitempty"`
	// WalletAddress is the user's wallet address, when present.
	WalletAddress *string `json:"wallet_address,omitempty"`
	// WorkspaceID is the active workspace, when present.
	WorkspaceID *string `json:"workspace_id,omitempty"`
	// CreatedAt is the ISO-8601 creation timestamp string.
	CreatedAt *string `json:"created_at,omitempty"`
	// Extra contains unknown userinfo fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes userinfo data and preserves unknown fields in Extra.
func (u *UserInfoData) UnmarshalJSON(data []byte) error {
	type alias UserInfoData
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*u = UserInfoData(out)
	u.Extra = extraFields(data, "sub", "email", "email_verified", "wallet_address", "workspace_id", "created_at")
	return nil
}

// ActivityResponse is the response returned by the activity endpoint.
type ActivityResponse struct {
	// Activities contains recent generation activity.
	Activities []Activity `json:"activities"`
	// Extra contains unknown top-level response fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes an activity response and preserves unknown fields in Extra.
func (a *ActivityResponse) UnmarshalJSON(data []byte) error {
	type alias ActivityResponse
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*a = ActivityResponse(out)
	a.Extra = extraFields(data, "activities")
	return nil
}

// Activity is one activity item.
type Activity struct {
	// ID is the activity identifier.
	ID string `json:"id"`
	// CreatedAt is the creation timestamp when returned.
	CreatedAt *int `json:"created_at,omitempty"`
	// Type is the activity type.
	Type *string `json:"type,omitempty"`
	// Metadata contains activity metadata.
	Metadata map[string]string `json:"metadata,omitempty"`
	// Extra contains unknown activity fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes an activity item and preserves unknown fields in Extra.
func (a *Activity) UnmarshalJSON(data []byte) error {
	type alias Activity
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*a = Activity(out)
	a.Extra = extraFields(data, "id", "created_at", "type", "metadata")
	return nil
}

// AuthSession fetches the current auth session.
func (c *Client) AuthSession(ctx context.Context) (*AuthSessionResponse, error) {
	var out AuthSessionResponse
	if err := c.controlRequest(ctx, http.MethodGet, "/auth/session", nil, &out, nil); err != nil {
		return nil, err
	}
	return &out, nil
}

// Logout logs out the current auth session.
func (c *Client) Logout(ctx context.Context) (*LogoutResponse, error) {
	var out LogoutResponse
	if err := c.controlRequest(ctx, http.MethodPost, "/auth/logout", nil, &out, nil); err != nil {
		return nil, err
	}
	return &out, nil
}

// UserInfo fetches the OIDC-style profile for the configured key.
func (c *Client) UserInfo(ctx context.Context) (*UserInfoResponse, error) {
	var out UserInfoResponse
	if err := c.controlRequest(ctx, http.MethodGet, "/auth/userinfo", nil, &out, nil); err != nil {
		return nil, err
	}
	return &out, nil
}

// Activity lists recent generations for the authenticated key/workspace.
func (c *Client) Activity(ctx context.Context, params map[string]string) (*ActivityResponse, error) {
	var out ActivityResponse
	if err := c.controlRequest(ctx, http.MethodGet, activityPath(params), nil, &out, nil); err != nil {
		return nil, err
	}
	return &out, nil
}

// Status fetches the TrustedRouter status document from an absolute URL outside the API base.
func (c *Client) Status(ctx context.Context, statusURL string) (map[string]any, error) {
	if statusURL == "" {
		statusURL = DefaultStatusURL
	}
	resp, err := c.absoluteRequest(ctx, http.MethodGet, statusURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := decodeResponse(ctx, resp, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func activityPath(params map[string]string) string {
	if len(params) == 0 {
		return "/activity"
	}
	query := url.Values{}
	for key, value := range params {
		query.Set(key, value)
	}
	encoded := query.Encode()
	if encoded == "" {
		return "/activity"
	}
	return "/activity?" + encoded
}

func (c *Client) absoluteRequest(ctx context.Context, method, requestURL string) (*http.Response, error) {
	timeout, hasTimeout := c.effectiveTimeout(nil)
	attemptCtx, cancel := contextWithOptionalTimeout(ctx, timeout, hasTimeout)
	req, err := http.NewRequestWithContext(attemptCtx, method, requestURL, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	for key, value := range c.headers {
		req.Header.Set(key, value)
	}
	req.Header.Set("user-agent", userAgent())
	resp, err := c.httpClient.Do(req)
	if err != nil {
		cancel()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, transportRetryError(err)
	}
	if hasTimeout {
		resp.Body = cancelOnCloseReadCloser{ReadCloser: resp.Body, cancel: cancel}
	}
	return resp, nil
}
