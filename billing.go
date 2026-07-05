package trustedrouter

import (
	"context"
	"encoding/json"
	"net/http"
)

// BillingCheckoutRequest configures a billing checkout request.
type BillingCheckoutRequest struct {
	// Amount is a string-or-number amount accepted by the TrustedRouter billing endpoint.
	Amount any
	// PaymentMethod optionally selects a payment method.
	PaymentMethod *string
	// WorkspaceID routes the checkout to a workspace and is also included in the request body.
	WorkspaceID *string
	// SuccessURL is the post-checkout success URL.
	SuccessURL *string
	// CancelURL is the checkout cancellation URL.
	CancelURL *string
	// CallOptions configures per-call headers, auth, workspace, idempotency, and timeout.
	CallOptions
}

// MarshalJSON encodes the body sent to the billing checkout endpoint.
func (r BillingCheckoutRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(billingCheckoutBody(r))
}

// CheckoutResponse is the response returned by the billing checkout endpoint.
type CheckoutResponse struct {
	// URL is the checkout URL.
	URL *string `json:"url,omitempty"`
	// Status is the checkout session status.
	Status *string `json:"status,omitempty"`
	// Extra contains unknown checkout fields.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes a checkout response and preserves unknown fields in Extra.
func (c *CheckoutResponse) UnmarshalJSON(data []byte) error {
	type alias CheckoutResponse
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*c = CheckoutResponse(out)
	c.Extra = extraFields(data, "url", "status")
	return nil
}

// BillingCheckout creates a checkout session.
func (c *Client) BillingCheckout(ctx context.Context, req BillingCheckoutRequest) (*CheckoutResponse, error) {
	var out CheckoutResponse
	callOpts := req.CallOptions
	if callOpts.WorkspaceID == nil {
		callOpts.WorkspaceID = req.WorkspaceID
	}
	if err := c.controlRequest(ctx, http.MethodPost, "/billing/checkout", billingCheckoutBody(req), &out, &callOpts); err != nil {
		return nil, err
	}
	return &out, nil
}

// StablecoinCheckout creates a stablecoin checkout session.
func (c *Client) StablecoinCheckout(ctx context.Context, req BillingCheckoutRequest) (*CheckoutResponse, error) {
	stablecoin := "stablecoin"
	req.PaymentMethod = &stablecoin
	return c.BillingCheckout(ctx, req)
}

func billingCheckoutBody(req BillingCheckoutRequest) map[string]any {
	body := map[string]any{"amount": req.Amount}
	if req.PaymentMethod != nil {
		body["payment_method"] = *req.PaymentMethod
	}
	if req.WorkspaceID != nil {
		body["workspace_id"] = *req.WorkspaceID
	}
	if req.SuccessURL != nil {
		body["success_url"] = *req.SuccessURL
	}
	if req.CancelURL != nil {
		body["cancel_url"] = *req.CancelURL
	}
	return body
}
