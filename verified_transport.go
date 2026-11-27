package trustedrouter

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

func validImagePins(p AttestationPolicy) bool {
	pins := p.ExpectedImageDigests
	if len(pins) == 0 {
		pins = []string{p.ExpectedImageDigest}
	}
	for _, pin := range pins {
		digest, ok := strings.CutPrefix(pin, "sha256:")
		if !ok || len(digest) != 64 {
			return false
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return false
		}
	}
	return true
}

func newVerifiedTransport(policy AttestationPolicy) *http.Transport {
	return verifiedTransport(policy, VerifyGatewaySession)
}

func verifiedTransport(policy AttestationPolicy, verify func(context.Context, VerifyGatewaySessionOptions) (*GatewaySession, error)) *http.Transport {
	// No proxy, no session reuse between requests, no HTTP/2 coalescing.
	// net/http writes headers and body only after this dial returns.
	return &http.Transport{DisableKeepAlives: true, DialTLSContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
		s, err := verify(ctx, VerifyGatewaySessionOptions{BaseURL: "https://" + addr, Policy: policy})
		if err != nil {
			return nil, err
		}
		if s.reader.Buffered() != 0 {
			_ = s.Conn.Close()
			return nil, fmt.Errorf("unexpected bytes after gateway attestation")
		}
		return s.Conn, nil
	}}
}

func privateInferenceRequested(spec requestSpec) bool {
	for _, base := range spec.candidates {
		u, err := url.Parse(base)
		if err == nil {
			for _, label := range strings.Split(strings.ToLower(u.Hostname()), ".") {
				if label == "confidential" || label == "trusted" {
					return true
				}
			}
		}
	}
	var r struct {
		Model    string
		Models   []string
		Provider struct {
			MinPrivacy string `json:"min_privacy"`
		}
	}
	if err := json.Unmarshal(spec.body, &r); err != nil {
		switch strings.TrimRight(spec.path, "/") {
		case "/chat/completions", "/messages", "/responses", "/embeddings":
			return spec.hasBody
		default:
			return false
		}
	}
	switch strings.ToLower(strings.TrimSpace(r.Provider.MinPrivacy)) {
	case "trusted", "confidential", "max", "maximum", "e2e", "e2ee":
		return true
	}
	for _, id := range append(r.Models, r.Model) {
		base, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(id)), ":")
		switch base {
		case "trustedrouter/trusted", "nyte/trusted", "trustedrouter/e2e", "nyte/e2e", "trustedrouter/confidential", "nyte/confidential":
			return true
		}
	}
	return false
}
