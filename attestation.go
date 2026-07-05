package trustedrouter

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// GCPIssuer is the issuer used by Google's Confidential Space attestation JWTs.
const GCPIssuer = "https://confidentialcomputing.googleapis.com"

// GCPJWKSURI is Google's public JWKS for the Confidential Space signer.
const GCPJWKSURI = "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com"

// ExporterLabel is the RFC 9266 tls-exporter channel-binding label committed by G6.
const ExporterLabel = "EXPORTER-Channel-Binding"

// ExporterLength is the byte length of the G6 TLS exporter channel binding.
const ExporterLength = 32

const defaultAttestationAudience = "quill-cloud"

// AttestationVerificationError reports a failed attestation trust check.
type AttestationVerificationError struct {
	// Message is the Python-compatible verification failure text.
	Message string
	// Err is the wrapped low-level error, when one exists.
	Err error
}

// Error returns the attestation verification failure message.
func (e *AttestationVerificationError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

// Unwrap returns the wrapped low-level error, when one exists.
func (e *AttestationVerificationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// AttestationPolicy pins the attested workload values that must match.
type AttestationPolicy struct {
	// GCPAudience is the required JWT audience. Empty defaults to "quill-cloud".
	GCPAudience string `json:"gcp_audience"`
	// ExpectedCertSHA256 pins the TLS leaf certificate SHA-256 committed by the JWT.
	ExpectedCertSHA256 string `json:"expected_cert_sha256,omitempty"`
	// ExpectedImageDigest pins the workload container image digest.
	ExpectedImageDigest string `json:"expected_image_digest,omitempty"`
	// ExpectedImageReference pins the workload container image reference.
	ExpectedImageReference string `json:"expected_image_reference,omitempty"`
}

// GatewayAttestation is a verified gateway attestation result.
type GatewayAttestation struct {
	// CertSHA256 is the SHA-256 of the gateway TLS leaf cert committed by the JWT.
	CertSHA256 string `json:"cert_sha256"`
	// ImageDigest is the attested workload container image digest.
	ImageDigest string `json:"image_digest"`
	// ImageReference is the attested workload container image reference.
	ImageReference string `json:"image_reference"`
	// Nonce is the caller nonce matched in the JWT, when one was supplied.
	Nonce *string `json:"nonce"`
	// ExpiresAt is the JWT exp claim, when present.
	ExpiresAt *int `json:"expires_at"`
	// Issuer is the JWT issuer, when present.
	Issuer *string `json:"issuer"`
	// Audience is the policy audience that matched the JWT.
	Audience string `json:"audience"`
	// RawClaims contains the verified JWT claims.
	RawClaims map[string]any `json:"raw_claims"`
}

// AsMap returns the compact Python as_dict-compatible attestation summary.
func (g GatewayAttestation) AsMap() map[string]any {
	return map[string]any{
		"cert_sha256":     g.CertSHA256,
		"image_digest":    g.ImageDigest,
		"image_reference": g.ImageReference,
		"nonce":           optionalString(g.Nonce),
		"expires_at":      optionalInt(g.ExpiresAt),
		"issuer":          optionalString(g.Issuer),
		"audience":        g.Audience,
	}
}

// TrustReleaseTLS contains TLS metadata from the public trust release.
type TrustReleaseTLS struct {
	Mode     string         `json:"mode,omitempty"`
	Hostname string         `json:"hostname,omitempty"`
	Extra    map[string]any `json:"-"`
}

// UnmarshalJSON decodes TLS metadata and preserves unknown fields in Extra.
func (t *TrustReleaseTLS) UnmarshalJSON(data []byte) error {
	type alias TrustReleaseTLS
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*t = TrustReleaseTLS(out)
	t.Extra = extraFields(data, "mode", "hostname")
	return nil
}

// TrustReleaseDataPolicy contains prompt/data handling commitments from the trust release.
type TrustReleaseDataPolicy struct {
	PromptOutputStorage      bool           `json:"prompt_output_storage"`
	ControlPlanePromptAccess bool           `json:"control_plane_prompt_access"`
	Extra                    map[string]any `json:"-"`
}

// UnmarshalJSON decodes data-policy metadata and preserves unknown fields in Extra.
func (p *TrustReleaseDataPolicy) UnmarshalJSON(data []byte) error {
	type alias TrustReleaseDataPolicy
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*p = TrustReleaseDataPolicy(out)
	p.Extra = extraFields(data, "prompt_output_storage", "control_plane_prompt_access")
	return nil
}

// TrustRelease is the parsed public TrustedRouter trust-release document.
type TrustRelease struct {
	Platform            string                  `json:"platform,omitempty"`
	SourceRepo          string                  `json:"source_repo,omitempty"`
	SourceRepositories  map[string]string       `json:"source_repositories,omitempty"`
	SourceCommit        string                  `json:"source_commit,omitempty"`
	ImageReference      string                  `json:"image_reference,omitempty"`
	ImageDigest         string                  `json:"image_digest,omitempty"`
	AttestationIssuer   string                  `json:"attestation_issuer,omitempty"`
	AttestationAudience string                  `json:"attestation_audience,omitempty"`
	APIBaseURL          string                  `json:"api_base_url,omitempty"`
	TLS                 *TrustReleaseTLS        `json:"tls,omitempty"`
	DataPolicy          *TrustReleaseDataPolicy `json:"data_policy,omitempty"`
	Extra               map[string]any          `json:"-"`
}

// UnmarshalJSON decodes a trust release and preserves unknown fields in Extra.
func (t *TrustRelease) UnmarshalJSON(data []byte) error {
	type alias TrustRelease
	var out alias
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*t = TrustRelease(out)
	t.Extra = extraFields(data, "platform", "source_repo", "source_repositories", "source_commit", "image_reference", "image_digest", "attestation_issuer", "attestation_audience", "api_base_url", "tls", "data_policy")
	return nil
}

// PolicyFromTrustReleaseOptions configures PolicyFromTrustRelease.
type PolicyFromTrustReleaseOptions struct {
	// Release is an already-fetched trust release. Nil fetches TrustReleaseURL.
	Release *TrustRelease
	// Audience overrides the default "quill-cloud" attestation audience.
	Audience string
	// CertSHA256 optionally pins the gateway TLS leaf cert SHA-256.
	CertSHA256 string
	// TrustReleaseURL is fetched when Release is nil. Empty uses DefaultTrustReleaseURL.
	TrustReleaseURL string
	// HTTPClient is the HTTP client used when Release is nil.
	HTTPClient *http.Client
}

// PolicyFromTrustRelease builds an attestation policy from the public trust release.
func PolicyFromTrustRelease(ctx context.Context, opts PolicyFromTrustReleaseOptions) (AttestationPolicy, error) {
	release := opts.Release
	if release == nil {
		var err error
		release, err = fetchTrustRelease(ctx, opts.TrustReleaseURL, opts.HTTPClient, true)
		if err != nil {
			return AttestationPolicy{}, err
		}
	}
	audience := opts.Audience
	if audience == "" {
		audience = defaultAttestationAudience
	}
	return AttestationPolicy{
		GCPAudience:            audience,
		ExpectedCertSHA256:     opts.CertSHA256,
		ExpectedImageDigest:    release.ImageDigest,
		ExpectedImageReference: release.ImageReference,
	}, nil
}

// VerifyGatewayAttestationOptions configures VerifyGatewayAttestation.
type VerifyGatewayAttestationOptions struct {
	// Policy is the attestation policy to enforce.
	Policy AttestationPolicy
	// NonceHex is the caller nonce expected in the JWT nonce list. Empty means no nonce check.
	NonceHex string
	// TLSCertDER is the live TLS leaf cert in DER form. When set, its SHA-256 must match the JWT.
	TLSCertDER []byte
	// TLSExporter is the RFC 9266 exporter derived on the SAME TLS connection that fetched the document.
	// When set, its hex must be bound in the JWT nonce list and NonceHex must be a fresh,
	// distinct value that is also bound; this closes the G6 single-slot relay attack.
	TLSExporter []byte
	// JWKS is a pre-fetched JWKS. Nil fetches JWKSURL.
	JWKS map[string]any
	// JWKSURL is fetched when JWKS is nil. Empty uses GCPJWKSURI.
	JWKSURL string
	// HTTPClient is the HTTP client used when JWKS is nil.
	HTTPClient *http.Client
}

// Attestation fetches the gateway attestation JWT as raw bytes.
func (c *Client) Attestation(ctx context.Context) ([]byte, error) {
	resp, err := c.absoluteRequest(ctx, http.MethodGet, attestationURL(c.baseURL))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	if resp.StatusCode >= 400 {
		payload, ok := parseJSONPayload(body)
		if !ok {
			return nil, classifyError(resp.StatusCode, truncateString(string(body), 240), nil, resp.Header)
		}
		return nil, classifyError(resp.StatusCode, errorMessage(payload), payload, resp.Header)
	}
	return body, nil
}

// TrustRelease fetches and parses the public trust release.
func (c *Client) TrustRelease(ctx context.Context, trustURL string) (*TrustRelease, error) {
	if trustURL == "" {
		trustURL = DefaultTrustReleaseURL
	}
	resp, err := c.absoluteRequest(ctx, http.MethodGet, trustURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out TrustRelease
	if err := decodeResponse(ctx, resp, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// FetchTrustRelease fetches and parses the public trust release.
func FetchTrustRelease(ctx context.Context, trustURL string) (*TrustRelease, error) {
	return fetchTrustRelease(ctx, trustURL, nil, true)
}

// VerifyGatewayAttestation verifies a GCP Confidential Space attestation JWT.
func VerifyGatewayAttestation(ctx context.Context, document []byte, opts VerifyGatewayAttestationOptions) (*GatewayAttestation, error) {
	header, payload, signingInput, signature, err := jwtSplit(document)
	if err != nil {
		return nil, err
	}
	jwks := opts.JWKS
	if jwks == nil {
		jwks, err = fetchJWKS(ctx, opts.JWKSURL, opts.HTTPClient)
		if err != nil {
			return nil, err
		}
	}
	if err := verifyRS256(jwks, header, signingInput, signature); err != nil {
		return nil, err
	}
	return checkAttestationClaims(payload, opts.Policy, opts.NonceHex, opts.TLSCertDER, opts.TLSExporter)
}

func attestationURL(baseURL string) string {
	root := strings.TrimRight(baseURL, "/")
	root = strings.TrimSuffix(root, "/v1")
	return root + "/attestation"
}

func fetchTrustRelease(ctx context.Context, trustURL string, httpClient *http.Client, defaultTimeout bool) (*TrustRelease, error) {
	if trustURL == "" {
		trustURL = DefaultTrustReleaseURL
	}
	requestCtx, cancel := contextWithDefaultTimeout(ctx, 30*time.Second, defaultTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, trustURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("user-agent", userAgent())
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		if ctxErr := requestCtx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, transportRetryError(err)
	}
	defer resp.Body.Close()
	var out TrustRelease
	if err := decodeResponse(requestCtx, resp, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func fetchJWKS(ctx context.Context, jwksURL string, httpClient *http.Client) (map[string]any, error) {
	if jwksURL == "" {
		jwksURL = GCPJWKSURI
	}
	requestCtx, cancel := contextWithDefaultTimeout(ctx, 10*time.Second, true)
	defer cancel()

	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, attestationErr("Invalid JWKS URL", err)
	}
	req.Header.Set("user-agent", userAgent())
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		if ctxErr := requestCtx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, attestationErr(fmt.Sprintf("JWKS fetch returned HTTP %d", resp.StatusCode), nil)
	}
	var out map[string]any
	decoder := json.NewDecoder(resp.Body)
	decoder.UseNumber()
	if err := decoder.Decode(&out); err != nil {
		return nil, attestationErr("JWKS response is not JSON", err)
	}
	if _, ok := jwksKeys(out); !ok {
		return nil, attestationErr(fmt.Sprintf("GCP JWKS at %s returned unexpected shape", jwksURL), nil)
	}
	return out, nil
}

func contextWithDefaultTimeout(ctx context.Context, timeout time.Duration, enabled bool) (context.Context, context.CancelFunc) {
	if !enabled {
		return ctx, func() {}
	}
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

func jwtSplit(token []byte) (map[string]any, map[string]any, []byte, []byte, error) {
	text := strings.TrimSpace(string(token))
	parts := strings.Split(text, ".")
	if len(parts) != 3 {
		return nil, nil, nil, nil, attestationErr(fmt.Sprintf("expected 3 JWT segments, got %d", len(parts)), nil)
	}
	hB64, pB64, sB64 := parts[0], parts[1], parts[2]
	headerBytes, err := b64urlDecode(hB64)
	if err != nil {
		return nil, nil, nil, nil, attestationErr(fmt.Sprintf("invalid JWT encoding: %s", err), err)
	}
	payloadBytes, err := b64urlDecode(pB64)
	if err != nil {
		return nil, nil, nil, nil, attestationErr(fmt.Sprintf("invalid JWT encoding: %s", err), err)
	}
	signature, err := b64urlDecode(sB64)
	if err != nil {
		return nil, nil, nil, nil, attestationErr(fmt.Sprintf("invalid JWT encoding: %s", err), err)
	}
	header, err := decodeJSONObject(headerBytes)
	if err != nil {
		return nil, nil, nil, nil, attestationErr(fmt.Sprintf("invalid JWT encoding: %s", err), err)
	}
	payload, err := decodeJSONObject(payloadBytes)
	if err != nil {
		return nil, nil, nil, nil, attestationErr(fmt.Sprintf("invalid JWT encoding: %s", err), err)
	}
	signingInput := []byte(hB64 + "." + pB64)
	return header, payload, signingInput, signature, nil
}

func b64urlDecode(segment string) ([]byte, error) {
	padding := (4 - len(segment)%4) % 4
	// base64.URLEncoding is intentionally strict here: fail closed rather than matching the reference's lenient decoder.
	return base64.URLEncoding.DecodeString(segment + strings.Repeat("=", padding))
}

func decodeJSONObject(data []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var out map[string]any
	if err := decoder.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func verifyRS256(jwks map[string]any, header map[string]any, signingInput []byte, signature []byte) error {
	if header["alg"] != "RS256" {
		return attestationErr(fmt.Sprintf("unsupported JWT alg %s; expected RS256", pyRepr(header["alg"])), nil)
	}
	kid := header["kid"]
	keys, ok := jwksKeys(jwks)
	if !ok {
		return attestationErr(fmt.Sprintf("GCP JWKS at %s returned unexpected shape", GCPJWKSURI), nil)
	}
	var matching map[string]any
	for _, key := range keys {
		if key["kid"] == kid {
			matching = key
			break
		}
	}
	if matching == nil {
		return attestationErr(fmt.Sprintf("no JWK with kid=%s in JWKS — gateway key may have rotated", pyRepr(kid)), nil)
	}
	if matching["kty"] != "RSA" {
		return attestationErr("expected RSA key in JWKS", nil)
	}
	nString, nOK := matching["n"].(string)
	eString, eOK := matching["e"].(string)
	if !nOK || !eOK {
		return attestationErr("malformed JWK: missing RSA parameter", nil)
	}
	nBytes, err := b64urlDecode(nString)
	if err != nil {
		return attestationErr(fmt.Sprintf("malformed JWK: %s", err), err)
	}
	eBytes, err := b64urlDecode(eString)
	if err != nil {
		return attestationErr(fmt.Sprintf("malformed JWK: %s", err), err)
	}
	n := new(big.Int).SetBytes(nBytes)
	eBig := new(big.Int).SetBytes(eBytes)
	if !eBig.IsInt64() || eBig.Sign() <= 0 {
		return attestationErr("malformed JWK: invalid exponent", nil)
	}
	publicKey := rsa.PublicKey{N: n, E: int(eBig.Int64())}
	digest := sha256.Sum256(signingInput)
	if err := rsa.VerifyPKCS1v15(&publicKey, crypto.SHA256, digest[:], signature); err != nil {
		return attestationErr("JWT signature verification failed", err)
	}
	return nil
}

func jwksKeys(jwks map[string]any) ([]map[string]any, bool) {
	raw, ok := jwks["keys"]
	if !ok {
		return nil, false
	}
	switch keys := raw.(type) {
	case []map[string]any:
		return keys, true
	case []any:
		out := make([]map[string]any, 0, len(keys))
		for _, key := range keys {
			m, ok := key.(map[string]any)
			if !ok {
				return nil, false
			}
			out = append(out, m)
		}
		return out, true
	default:
		return nil, false
	}
}

func checkAttestationClaims(claims map[string]any, policy AttestationPolicy, nonceHex string, tlsCertDER []byte, tlsExporter []byte) (*GatewayAttestation, error) {
	now := time.Now().Unix()
	expValue, expOK := intClaim(claims["exp"])
	if expOK && expValue <= now {
		return nil, attestationErr(fmt.Sprintf("JWT expired at %d (now=%d)", expValue, now), nil)
	}

	iss, _ := claims["iss"].(string)
	if iss != GCPIssuer {
		return nil, attestationErr(fmt.Sprintf("unexpected issuer %s; expected %s", pyRepr(claims["iss"]), GCPIssuer), nil)
	}

	audience := policy.GCPAudience
	if audience == "" {
		audience = defaultAttestationAudience
	}
	audList := audienceList(claims["aud"])
	if !containsString(audList, audience) {
		return nil, attestationErr(fmt.Sprintf("audience %s not in JWT aud %s", pyRepr(audience), pyRepr(audList)), nil)
	}

	submods, _ := claims["submods"].(map[string]any)
	container, _ := submods["container"].(map[string]any)
	imageDigest, _ := container["image_digest"].(string)
	imageReference, _ := container["image_reference"].(string)

	if policy.ExpectedImageDigest != "" && !safeEq(imageDigest, policy.ExpectedImageDigest) {
		return nil, attestationErr(fmt.Sprintf("image_digest mismatch: workload=%s, policy=%s", pyRepr(imageDigest), pyRepr(policy.ExpectedImageDigest)), nil)
	}
	if policy.ExpectedImageReference != "" && !safeEq(imageReference, policy.ExpectedImageReference) {
		return nil, attestationErr(fmt.Sprintf("image_reference mismatch: workload=%s, policy=%s", pyRepr(imageReference), pyRepr(policy.ExpectedImageReference)), nil)
	}

	nonces := nonceList(claims)
	var nonceMatch *string
	if len(tlsExporter) > 0 && nonceHex == "" {
		return nil, attestationErr("fresh nonce required with exporter binding", nil)
	}
	if nonceHex != "" {
		if !containsString(nonces, nonceHex) {
			return nil, attestationErr(fmt.Sprintf("nonce %s not present in JWT nonces %s", pyRepr(nonceHex), pyRepr(nonces)), nil)
		}
		nonce := nonceHex
		nonceMatch = &nonce
	}
	if len(tlsExporter) > 0 {
		exporterHex := fmt.Sprintf("%x", tlsExporter)
		if !containsString(nonces, exporterHex) {
			return nil, attestationErr(fmt.Sprintf("TLS exporter %s not present in JWT nonces %s", pyRepr(exporterHex), pyRepr(nonces)), nil)
		}
		// G6/RFC 9266 relay closure: the caller nonce must consume the enclave's
		// one external nonce slot independently from the TLS exporter commitment.
		if safeEq(nonceHex, exporterHex) {
			return nil, attestationErr("fresh nonce must be distinct from TLS exporter for G6 relay closure", nil)
		}
	}

	certSHA, _ := claims["tls_cert_sha256"].(string)
	if certSHA == "" {
		certSHA, _ = claims["workload_tls_cert_sha256"].(string)
	}
	if certSHA == "" {
		certSHA = findCertInNonces(nonces, tlsCertDER)
	}
	if len(certSHA) != 64 {
		return nil, attestationErr("JWT does not commit to a TLS cert SHA-256 — cannot bind connection", nil)
	}
	certSHA = strings.ToLower(certSHA)

	if tlsCertDER != nil {
		actual := sha256Hex(tlsCertDER)
		if !safeEq(actual, certSHA) {
			return nil, attestationErr(fmt.Sprintf("TLS cert mismatch: connection=%s, JWT=%s", pyRepr(actual), pyRepr(certSHA)), nil)
		}
	}
	if policy.ExpectedCertSHA256 != "" && !safeEq(certSHA, strings.ToLower(policy.ExpectedCertSHA256)) {
		return nil, attestationErr("JWT-committed cert SHA-256 doesn't match policy pin", nil)
	}

	var expPtr *int
	if expOK {
		exp := int(expValue)
		expPtr = &exp
	}
	var issuerPtr *string
	if iss != "" {
		issuer := iss
		issuerPtr = &issuer
	}
	return &GatewayAttestation{
		CertSHA256:     certSHA,
		ImageDigest:    imageDigest,
		ImageReference: imageReference,
		Nonce:          nonceMatch,
		ExpiresAt:      expPtr,
		Issuer:         issuerPtr,
		Audience:       audience,
		RawClaims:      claims,
	}, nil
}

func intClaim(value any) (int64, bool) {
	switch v := value.(type) {
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return i, true
		}
		f, err := v.Float64()
		if err == nil && math.Trunc(f) == f {
			return int64(f), true
		}
	case float64:
		if math.Trunc(v) == v {
			return int64(v), true
		}
	case int:
		return int64(v), true
	case int64:
		return v, true
	case int32:
		return int64(v), true
	}
	return 0, false
}

func audienceList(value any) []string {
	switch v := value.(type) {
	case string:
		return []string{v}
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func nonceList(claims map[string]any) []string {
	if nonces := stringListClaim(claims["eat_nonce"]); len(nonces) > 0 {
		return nonces
	}
	return stringListClaim(claims["nonces"])
}

func stringListClaim(value any) []string {
	switch v := value.(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func findCertInNonces(nonces []string, tlsCertDER []byte) string {
	if tlsCertDER == nil {
		return ""
	}
	actual := sha256Hex(tlsCertDER)
	for _, nonce := range nonces {
		if hmac.Equal([]byte(strings.ToLower(nonce)), []byte(actual)) {
			return strings.ToLower(nonce)
		}
	}
	return ""
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:])
}

func safeEq(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func attestationErr(message string, err error) *AttestationVerificationError {
	return &AttestationVerificationError{Message: message, Err: err}
}

func pyRepr(value any) string {
	switch v := value.(type) {
	case nil:
		return "None"
	case string:
		return "'" + strings.ReplaceAll(v, "'", "\\'") + "'"
	case json.Number:
		return v.String()
	case []string:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			parts = append(parts, pyRepr(item))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			parts = append(parts, pyRepr(item))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case bool:
		if v {
			return "True"
		}
		return "False"
	case fmt.Stringer:
		return v.String()
	default:
		return fmt.Sprint(v)
	}
}

func optionalString(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func optionalInt(value *int) any {
	if value == nil {
		return nil
	}
	return *value
}
