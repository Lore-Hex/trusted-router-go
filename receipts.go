package trustedrouter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	receiptType                = "inference-receipt+jws"
	receiptKeyCommitmentDomain = "inference-receipt-key-v1\x00"

	// ReceiptAttestationVerified means the signing key was bound by verified
	// attestation evidence.
	ReceiptAttestationVerified = "verified"
	// ReceiptAttestationUnverified means attestation checking was explicitly
	// disabled for a compact receipt, whose evidence is delivered separately.
	ReceiptAttestationUnverified = "unverified_by_this_sdk"
)

var receiptNoncePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,88}$`)

// ReceiptVerificationError is the common base for every fail-closed receipt
// verification error.
type ReceiptVerificationError struct {
	// Message is the human-readable verification failure.
	Message string
	// Err is the underlying cause of the failure.
	Err error
}

// Error returns the verification failure message.
func (e *ReceiptVerificationError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

// Unwrap returns the underlying error for errors.Is and errors.As.
func (e *ReceiptVerificationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// ReceiptStructureError reports a malformed compact or flattened JWS.
type ReceiptStructureError struct{ *ReceiptVerificationError }

// Unwrap returns the underlying error for errors.Is and errors.As.
func (e *ReceiptStructureError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.ReceiptVerificationError
}

// ReceiptHeaderError reports an invalid or unsupported protected JWS header.
type ReceiptHeaderError struct{ *ReceiptVerificationError }

// Unwrap returns the underlying error for errors.Is and errors.As.
func (e *ReceiptHeaderError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.ReceiptVerificationError
}

// ReceiptSignatureError reports a failed Ed25519 signature check.
type ReceiptSignatureError struct{ *ReceiptVerificationError }

// Unwrap returns the underlying error for errors.Is and errors.As.
func (e *ReceiptSignatureError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.ReceiptVerificationError
}

// ReceiptClaimsError reports missing, malformed, or unsupported claims.
type ReceiptClaimsError struct{ *ReceiptVerificationError }

// Unwrap returns the underlying error for errors.Is and errors.As.
func (e *ReceiptClaimsError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.ReceiptVerificationError
}

// MissingBindingError reports required caller traffic that was not supplied
// for a receipt digest binding.
type MissingBindingError struct{ *ReceiptClaimsError }

// Unwrap returns the underlying error for errors.Is and errors.As.
func (e *MissingBindingError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.ReceiptClaimsError
}

// ReceiptIssuerError reports an invalid receipt issuer or a mismatch with the
// caller's pinned issuer origin.
type ReceiptIssuerError struct{ *ReceiptClaimsError }

// Unwrap returns the underlying error for errors.Is and errors.As.
func (e *ReceiptIssuerError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.ReceiptClaimsError
}

// ReceiptTimeError reports an invalid issue time or age bound.
type ReceiptTimeError struct{ *ReceiptClaimsError }

// Unwrap returns the underlying error for errors.Is and errors.As.
func (e *ReceiptTimeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.ReceiptClaimsError
}

// ReceiptNonceError reports an invalid or mismatched nonce.
type ReceiptNonceError struct{ *ReceiptClaimsError }

// Unwrap returns the underlying error for errors.Is and errors.As.
func (e *ReceiptNonceError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.ReceiptClaimsError
}

// ReceiptUpstreamError reports an invalid upstream tier or verification window.
type ReceiptUpstreamError struct{ *ReceiptClaimsError }

// Unwrap returns the underlying error for errors.Is and errors.As.
func (e *ReceiptUpstreamError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.ReceiptClaimsError
}

// ReceiptHashError reports an invalid hash claim or exact-byte digest mismatch.
type ReceiptHashError struct{ *ReceiptVerificationError }

// Unwrap returns the underlying error for errors.Is and errors.As.
func (e *ReceiptHashError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.ReceiptVerificationError
}

// ReceiptAttestationError reports invalid signing-key attestation evidence.
type ReceiptAttestationError struct{ *ReceiptVerificationError }

// Unwrap returns the underlying error for errors.Is and errors.As.
func (e *ReceiptAttestationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.ReceiptVerificationError
}

// MissingAttestationError reports required attestation evidence that is absent.
type MissingAttestationError struct{ *ReceiptAttestationError }

// Unwrap returns the underlying error for errors.Is and errors.As.
func (e *MissingAttestationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.ReceiptAttestationError
}

// UnsupportedAttestationError reports an attestation kind this SDK cannot chain.
type UnsupportedAttestationError struct{ *ReceiptAttestationError }

// Unwrap returns the underlying error for errors.Is and errors.As.
func (e *UnsupportedAttestationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.ReceiptAttestationError
}

func receiptBase(message string, err error) *ReceiptVerificationError {
	return &ReceiptVerificationError{Message: message, Err: err}
}

func receiptStructure(message string, err error) error {
	return &ReceiptStructureError{receiptBase(message, err)}
}

func receiptHeader(message string, err error) error {
	return &ReceiptHeaderError{receiptBase(message, err)}
}

func receiptSignature(message string, err error) error {
	return &ReceiptSignatureError{receiptBase(message, err)}
}

func receiptClaims(message string, err error) error {
	return &ReceiptClaimsError{receiptBase(message, err)}
}

func receiptMissingBinding(message string) error {
	return &MissingBindingError{&ReceiptClaimsError{receiptBase(message, nil)}}
}

func receiptIssuer(message string, err error) error {
	return &ReceiptIssuerError{&ReceiptClaimsError{receiptBase(message, err)}}
}

func receiptTime(message string, err error) error {
	return &ReceiptTimeError{&ReceiptClaimsError{receiptBase(message, err)}}
}

func receiptNonce(message string, err error) error {
	return &ReceiptNonceError{&ReceiptClaimsError{receiptBase(message, err)}}
}

func receiptUpstream(message string, err error) error {
	return &ReceiptUpstreamError{&ReceiptClaimsError{receiptBase(message, err)}}
}

func receiptHash(message string, err error) error {
	return &ReceiptHashError{receiptBase(message, err)}
}

func receiptAttestation(message string, err error) error {
	return &ReceiptAttestationError{receiptBase(message, err)}
}

func receiptMissingAttestation(message string) error {
	return &MissingAttestationError{&ReceiptAttestationError{receiptBase(message, nil)}}
}

func receiptUnsupportedAttestation(message string) error {
	return &UnsupportedAttestationError{&ReceiptAttestationError{receiptBase(message, nil)}}
}

// ReceiptHashClaims describes one exact-byte SHA-256 hash domain.
type ReceiptHashClaims struct {
	// Alg identifies the hash algorithm.
	Alg string `json:"alg"`
	// Hash is the encoded digest of the exact bound bytes.
	Hash string `json:"hash"`
	// Of identifies the byte domain covered by the hash.
	Of string `json:"of"`
	// Events is the bound stream event count when supplied.
	Events *int64 `json:"events,omitempty"`
}

// ReceiptModelClaims records the router's exact model selection metadata.
type ReceiptModelClaims struct {
	// Requested is the model requested by the caller.
	Requested string `json:"requested"`
	// Selected is the model selected by the router.
	Selected string `json:"selected"`
	// Provider identifies the selected upstream provider.
	Provider string `json:"provider"`
	// Endpoint identifies the selected upstream endpoint.
	Endpoint string `json:"endpoint"`
}

// ReceiptUpstreamClaims records how the serving enclave verified its upstream.
type ReceiptUpstreamClaims struct {
	// Tier is the upstream verification tier.
	Tier string `json:"tier"`
	// Policy identifies the upstream verification policy.
	Policy string `json:"policy,omitempty"`
	// VerifiedAt is the upstream verification Unix timestamp when supplied.
	VerifiedAt *int64 `json:"verified_at,omitempty"`
	// VerificationExpiresAt is the upstream verification expiration Unix timestamp when supplied.
	VerificationExpiresAt *int64 `json:"verification_expires_at,omitempty"`
	// CertSHA256 is the upstream certificate SHA-256 fingerprint.
	CertSHA256 string `json:"cert_sha256,omitempty"`
}

// ReceiptClaims is the verified v1 receipt payload plus attestation status.
type ReceiptClaims struct {
	// RV is the receipt format version.
	RV int64 `json:"rv"`
	// Issuer is the signed issuer origin.
	Issuer string `json:"iss"`
	// IssuedAt is the receipt issuance Unix timestamp.
	IssuedAt int64 `json:"iat"`
	// JTI is the unique receipt identifier.
	JTI string `json:"jti"`
	// GenerationID identifies the inference generation when supplied.
	GenerationID string `json:"gen,omitempty"`
	// Nonce is the caller nonce bound into the receipt.
	Nonce string `json:"nonce,omitempty"`
	// Route identifies the signed inference route.
	Route string `json:"route"`
	// Request describes the exact request-byte hash binding.
	Request ReceiptHashClaims `json:"req"`
	// Response describes the response-byte or stream hash binding.
	Response ReceiptHashClaims `json:"resp"`
	// Model records the requested and selected model identities.
	Model ReceiptModelClaims `json:"model"`
	// Upstream records the serving enclave upstream verification.
	Upstream ReceiptUpstreamClaims `json:"upstream"`
	// AttestationSHA256 pins the exact separately supplied attestation bytes.
	AttestationSHA256 string `json:"att_sha256,omitempty"`
	// AttestationStatus reports whether signing-key attestation was verified.
	AttestationStatus string `json:"attestation_status"`
	// Attestation is an alias for AttestationStatus, matching the other SDKs.
	Attestation string `json:"attestation"`
}

// VerifyReceiptOptions configures VerifyReceipt. RequestBody and exactly one
// response representation are required unless RequireBindings explicitly
// points to false. A non-nil empty byte slice is a present, empty body.
type VerifyReceiptOptions struct {
	// RequestBody supplies the exact serialized request bytes; nil means absent.
	RequestBody []byte
	// ResponseBody supplies the exact non-streaming response bytes; nil means absent.
	ResponseBody []byte
	// ResponseStream supplies the exact SSE response bytes; nil means absent.
	ResponseStream []byte
	// Attestation supplies the exact GCP attestation-document bytes pinned by a
	// compact receipt's att_sha256 claim. For a flattened receipt, supplied
	// bytes must exactly match the document embedded in its protected header.
	Attestation []byte
	// ExpectedNonce pins the caller nonce when non-nil.
	ExpectedNonce *string
	// MaxAgeSeconds limits receipt age in seconds when non-nil.
	MaxAgeSeconds *float64
	// Now overrides the current Unix time in seconds for verification.
	Now *float64
	// RequireAttestation defaults to true; false explicitly permits unavailable compact-receipt attestation.
	RequireAttestation *bool
	// RequireBindings defaults to true. Set it to a pointer to false only for
	// deliberate signature-only or partial-binding inspection.
	RequireBindings *bool
}

type receiptEnvelope struct {
	protected     string
	payload       string
	signature     string
	flattened     bool
	flattenedJSON map[string]any
}

type receiptSSEEvent struct {
	name    []byte
	payload []byte
	done    bool
}

// VerifyReceipt verifies a compact or flattened v1 inference receipt against
// a required, pinned HTTPS issuer origin and the caller's exact traffic bytes.
//
// Compact receipts carry only an att_sha256 pin. Fetch /receipt-attestation
// and retry when necessary until SHA-256 of the returned per-instance document
// matches that pin, then pass its exact bytes in VerifyReceiptOptions.Attestation.
// Flattened receipts carry the document in their protected header.
func VerifyReceipt(receipt any, expectedIssuer string, opts VerifyReceiptOptions) (*ReceiptClaims, error) {
	if err := requireReceiptTrafficBindings(opts); err != nil {
		return nil, err
	}
	canonicalExpectedIssuer, err := canonicalReceiptHTTPSOrigin(expectedIssuer, "expected_issuer")
	if err != nil {
		return nil, err
	}
	envelope, err := parseReceiptEnvelope(receipt)
	if err != nil {
		return nil, err
	}
	header, publicKey, err := parseReceiptHeader(envelope)
	if err != nil {
		return nil, err
	}
	payloadBytes, err := verifyReceiptSignature(envelope, publicKey)
	if err != nil {
		return nil, err
	}
	decoded, err := decodeReceiptJSON(payloadBytes, "receipt claims")
	if err != nil {
		return nil, err
	}
	payload, ok := decoded.(map[string]any)
	if !ok {
		return nil, receiptClaims("rv claim check failed: receipt claims must be a JSON object", nil)
	}

	rv, ok := receiptInteger(payload["rv"])
	if !ok || rv != 1 {
		return nil, receiptClaims(fmt.Sprintf("rv claim check failed: expected integer 1, got %s", receiptRepr(payload["rv"])), nil)
	}
	issuer, err := requiredReceiptString(payload, "iss", "claims")
	if err != nil {
		return nil, err
	}
	canonicalIssuer, err := canonicalReceiptHTTPSOrigin(issuer, "iss claim")
	if err != nil {
		return nil, err
	}
	if !hmac.Equal([]byte(canonicalIssuer), []byte(canonicalExpectedIssuer)) {
		return nil, receiptIssuer(fmt.Sprintf("iss claim check failed: expected %q, got %q", canonicalExpectedIssuer, canonicalIssuer), nil)
	}
	iat, ok := receiptInteger(payload["iat"])
	if !ok {
		return nil, receiptTime("iat claim check failed: expected an integer", nil)
	}
	now := float64(0)
	if opts.Now == nil {
		now = float64(time.Now().UnixNano()) / 1e9
	} else if math.IsNaN(*opts.Now) || math.IsInf(*opts.Now, 0) {
		return nil, receiptTime("iat check failed: now must be finite Unix seconds", nil)
	} else {
		now = *opts.Now
	}
	if float64(iat) > now+60 {
		return nil, receiptTime(fmt.Sprintf("iat future-skew check failed: iat=%d is more than 60 seconds after now=%g", iat, now), nil)
	}
	if opts.MaxAgeSeconds != nil {
		maxAge := *opts.MaxAgeSeconds
		if maxAge < 0 || math.IsNaN(maxAge) || math.IsInf(maxAge, 0) {
			return nil, receiptTime("iat max-age check failed: max_age_seconds must be a finite non-negative number", nil)
		}
		if now-float64(iat) > maxAge {
			return nil, receiptTime(fmt.Sprintf("iat max-age check failed: receipt age %gs exceeds %gs", now-float64(iat), maxAge), nil)
		}
	}

	nonce, noncePresent := payload["nonce"]
	nonceString, nonceIsString := nonce.(string)
	if noncePresent && (!nonceIsString || !receiptNoncePattern.MatchString(nonceString)) {
		return nil, receiptNonce("nonce claim check failed: nonce must contain 1-88 base64url characters", nil)
	}
	if opts.ExpectedNonce != nil && (!nonceIsString || !hmac.Equal([]byte(nonceString), []byte(*opts.ExpectedNonce))) {
		return nil, receiptNonce(fmt.Sprintf("nonce match check failed: expected %q, got %s", *opts.ExpectedNonce, receiptRepr(nonce)), nil)
	}

	upstreamRaw, err := requiredReceiptMap(payload, "upstream", receiptUpstream)
	if err != nil {
		return nil, err
	}
	tier, _ := upstreamRaw["tier"].(string)
	var verifiedAt, expiresAt *int64
	switch tier {
	case "tee-verified":
		verified, valid := receiptInteger(upstreamRaw["verified_at"])
		if !valid {
			return nil, receiptUpstream("upstream.verified_at check failed: expected an integer", nil)
		}
		expires, valid := receiptInteger(upstreamRaw["verification_expires_at"])
		if !valid {
			return nil, receiptUpstream("upstream.verification_expires_at check failed: expected an integer", nil)
		}
		if verified > iat || iat >= expires {
			return nil, receiptUpstream("tee-verified window check failed: expected verified_at <= iat < verification_expires_at", nil)
		}
		verifiedAt, expiresAt = &verified, &expires
	case "tls-webpki":
	default:
		return nil, receiptUpstream(fmt.Sprintf("upstream.tier check failed: unsupported tier %s", receiptRepr(upstreamRaw["tier"])), nil)
	}

	reqRaw, err := requiredReceiptMap(payload, "req", receiptHash)
	if err != nil {
		return nil, err
	}
	req, reqDigest, err := parseReceiptDigestClaim(reqRaw, "req", false)
	if err != nil {
		return nil, err
	}
	if opts.RequestBody != nil {
		actual := sha256.Sum256(opts.RequestBody)
		if !hmac.Equal(actual[:], reqDigest) {
			return nil, receiptHash("request body hash check failed: req.hash does not match", nil)
		}
	}

	respRaw, err := requiredReceiptMap(payload, "resp", receiptHash)
	if err != nil {
		return nil, err
	}
	resp, respDigest, err := parseReceiptDigestClaim(respRaw, "resp", true)
	if err != nil {
		return nil, err
	}
	if opts.ResponseBody != nil && opts.ResponseStream != nil {
		return nil, receiptHash("response hash check failed: provide response_body or response_stream, not both", nil)
	}
	if opts.ResponseBody != nil {
		if resp.Of != "body" {
			return nil, receiptHash(fmt.Sprintf("response body hash check failed: resp.of is %q, expected 'body'", resp.Of), nil)
		}
		actual := sha256.Sum256(opts.ResponseBody)
		if !hmac.Equal(actual[:], respDigest) {
			return nil, receiptHash("response body hash check failed: resp.hash does not match", nil)
		}
	} else if opts.ResponseStream != nil {
		if resp.Of != "sse-data-v1" && resp.Of != "sse-events-v1" {
			return nil, receiptHash(fmt.Sprintf("response stream hash check failed: resp.of is %q, expected an SSE domain", resp.Of), nil)
		}
		actual, events, digestErr := receiptStreamDigest(opts.ResponseStream, resp.Of, envelope.flattenedJSON)
		if digestErr != nil {
			return nil, digestErr
		}
		if !hmac.Equal(actual, respDigest) {
			return nil, receiptHash("response stream hash check failed: resp.hash does not match", nil)
		}
		if resp.Events == nil || events != *resp.Events {
			return nil, receiptHash(fmt.Sprintf("response stream events check failed: counted %d, receipt claims %s", events, receiptRepr(respRaw["events"])), nil)
		}
	}

	jti, err := requiredReceiptString(payload, "jti", "claims")
	if err != nil {
		return nil, err
	}
	generation, err := optionalReceiptString(payload, "gen", "claims")
	if err != nil {
		return nil, err
	}
	route, err := requiredReceiptString(payload, "route", "claims")
	if err != nil {
		return nil, err
	}
	if route != "chat.completions" && route != "responses" {
		return nil, receiptClaims(fmt.Sprintf("route claim check failed: unsupported route %q", route), nil)
	}
	modelRaw, err := requiredReceiptMap(payload, "model", receiptClaims)
	if err != nil {
		return nil, err
	}
	requested, err := requiredReceiptString(modelRaw, "requested", "model")
	if err != nil {
		return nil, err
	}
	selected, err := requiredReceiptString(modelRaw, "selected", "model")
	if err != nil {
		return nil, err
	}
	provider, err := requiredReceiptString(modelRaw, "provider", "model")
	if err != nil {
		return nil, err
	}
	endpoint, err := requiredReceiptString(modelRaw, "endpoint", "model")
	if err != nil {
		return nil, err
	}
	policy, err := optionalReceiptString(upstreamRaw, "policy", "upstream")
	if err != nil {
		return nil, err
	}
	if tier == "tee-verified" && policy == "" {
		return nil, receiptUpstream("upstream.policy check failed: tee-verified receipts require a policy", nil)
	}
	certSHA256, err := optionalReceiptString(upstreamRaw, "cert_sha256", "upstream")
	if err != nil {
		return nil, err
	}
	attSHA256, err := optionalReceiptString(payload, "att_sha256", "claims")
	if err != nil {
		return nil, err
	}
	if attSHA256 != "" {
		digest, decodeErr := receiptB64URLDecode(attSHA256, "att_sha256 claim")
		if decodeErr != nil {
			return nil, receiptClaims(decodeErr.Error(), nil)
		}
		if len(digest) != sha256.Size {
			return nil, receiptClaims("att_sha256 claim check failed: SHA-256 digest must be 32 bytes", nil)
		}
	}
	if !envelope.flattened && attSHA256 == "" {
		return nil, receiptClaims("att_sha256 claim check failed: compact receipts must pin an attestation document", nil)
	}

	requireAttestation := true
	if opts.RequireAttestation != nil {
		requireAttestation = *opts.RequireAttestation
	}
	attestationStatus, err := verifyReceiptAttestation(envelope, header, publicKey, opts.Attestation, attSHA256, requireAttestation)
	if err != nil {
		return nil, err
	}

	claims := &ReceiptClaims{
		RV:                rv,
		Issuer:            issuer,
		IssuedAt:          iat,
		JTI:               jti,
		GenerationID:      generation,
		Nonce:             nonceString,
		Route:             route,
		Request:           req,
		Response:          resp,
		Model:             ReceiptModelClaims{Requested: requested, Selected: selected, Provider: provider, Endpoint: endpoint},
		Upstream:          ReceiptUpstreamClaims{Tier: tier, Policy: policy, VerifiedAt: verifiedAt, VerificationExpiresAt: expiresAt, CertSHA256: certSHA256},
		AttestationSHA256: attSHA256,
		AttestationStatus: attestationStatus,
		Attestation:       attestationStatus,
	}
	return claims, nil
}

func parseReceiptEnvelope(receipt any) (receiptEnvelope, error) {
	var text string
	var flattened map[string]any
	switch value := receipt.(type) {
	case string:
		text = strings.TrimSpace(value)
	case []byte:
		text = strings.TrimSpace(string(value))
	case map[string]any:
		flattened = value
	default:
		return receiptEnvelope{}, receiptStructure("JWS structure check failed: receipt must be compact string/bytes or flattened JWS", nil)
	}
	if flattened == nil {
		if strings.HasPrefix(text, "{") {
			decoded, err := decodeReceiptJSON([]byte(text), "JWS structure")
			if err != nil {
				return receiptEnvelope{}, err
			}
			var ok bool
			flattened, ok = decoded.(map[string]any)
			if !ok {
				return receiptEnvelope{}, receiptStructure("JWS structure check failed: flattened JWS must be a JSON object", nil)
			}
		} else {
			if !isASCII(text) {
				return receiptEnvelope{}, receiptStructure("JWS structure check failed: receipt bytes must be ASCII", nil)
			}
			parts := strings.Split(text, ".")
			if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
				return receiptEnvelope{}, receiptStructure(fmt.Sprintf("JWS structure check failed: compact JWS must have 3 non-empty segments, got %d", len(parts)), nil)
			}
			return receiptEnvelope{protected: parts[0], payload: parts[1], signature: parts[2]}, nil
		}
	}
	if _, present := flattened["header"]; present {
		return receiptEnvelope{}, receiptStructure("JWS structure check failed: unprotected flattened headers are not allowed", nil)
	}
	protected, protectedOK := flattened["protected"].(string)
	payload, payloadOK := flattened["payload"].(string)
	signature, signatureOK := flattened["signature"].(string)
	if !protectedOK || !payloadOK || !signatureOK || protected == "" || payload == "" || signature == "" {
		return receiptEnvelope{}, receiptStructure("JWS structure check failed: flattened JWS requires non-empty string protected, payload, and signature members", nil)
	}
	return receiptEnvelope{protected: protected, payload: payload, signature: signature, flattened: true, flattenedJSON: flattened}, nil
}

func parseReceiptHeader(envelope receiptEnvelope) (map[string]any, ed25519.PublicKey, error) {
	raw, err := receiptB64URLDecode(envelope.protected, "protected header")
	if err != nil {
		return nil, nil, err
	}
	decoded, err := decodeReceiptJSON(raw, "protected header")
	if err != nil {
		return nil, nil, err
	}
	header, ok := decoded.(map[string]any)
	if !ok {
		return nil, nil, receiptHeader("protected header check failed: header must be a JSON object", nil)
	}
	if header["alg"] != "EdDSA" {
		return nil, nil, receiptHeader(fmt.Sprintf("protected header alg check failed: expected 'EdDSA', got %s", receiptRepr(header["alg"])), nil)
	}
	if header["typ"] != receiptType {
		return nil, nil, receiptHeader(fmt.Sprintf("protected header typ check failed: expected %q, got %s", receiptType, receiptRepr(header["typ"])), nil)
	}
	jwk, ok := header["jwk"].(map[string]any)
	if !ok {
		return nil, nil, receiptHeader("protected header jwk check failed: jwk must be an object", nil)
	}
	_, hasPrivate := jwk["d"]
	if jwk["kty"] != "OKP" || jwk["crv"] != "Ed25519" || hasPrivate {
		return nil, nil, receiptHeader("protected header jwk check failed: expected a public OKP/Ed25519 JWK", nil)
	}
	x, ok := jwk["x"].(string)
	if !ok {
		return nil, nil, receiptHeader("protected header jwk.x check failed: x must be a string", nil)
	}
	publicKey, decodeErr := receiptB64URLDecode(x, "protected header jwk.x")
	if decodeErr != nil {
		return nil, nil, receiptHeader(decodeErr.Error(), nil)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, nil, receiptHeader(fmt.Sprintf("protected header jwk.x check failed: Ed25519 public key is %d bytes, expected 32", len(publicKey)), nil)
	}
	kid, ok := header["kid"].(string)
	if !ok {
		return nil, nil, receiptHeader("protected header kid check failed: kid must be a string", nil)
	}
	expectedKidBytes := sha256.Sum256(publicKey)
	expectedKid := base64.RawURLEncoding.EncodeToString(expectedKidBytes[:])
	if !hmac.Equal([]byte(kid), []byte(expectedKid)) {
		return nil, nil, receiptHeader(fmt.Sprintf("protected header kid check failed: expected %q, got %q", expectedKid, kid), nil)
	}
	return header, ed25519.PublicKey(publicKey), nil
}

func verifyReceiptSignature(envelope receiptEnvelope, publicKey ed25519.PublicKey) ([]byte, error) {
	payload, err := receiptB64URLDecode(envelope.payload, "JWS payload")
	if err != nil {
		return nil, err
	}
	signature, err := receiptB64URLDecode(envelope.signature, "JWS signature")
	if err != nil {
		return nil, receiptSignature(err.Error(), nil)
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, []byte(envelope.protected+"."+envelope.payload), signature) {
		return nil, receiptSignature("Ed25519 signature check failed", nil)
	}
	return payload, nil
}

func parseReceiptDigestClaim(record map[string]any, name string, response bool) (ReceiptHashClaims, []byte, error) {
	alg, _ := record["alg"].(string)
	if alg != "sha256" {
		return ReceiptHashClaims{}, nil, receiptHash(fmt.Sprintf("%s.alg check failed: expected 'sha256', got %s", name, receiptRepr(record["alg"])), nil)
	}
	hashValue, ok := record["hash"].(string)
	if !ok {
		return ReceiptHashClaims{}, nil, receiptHash(fmt.Sprintf("%s.hash check failed: required string is missing", name), nil)
	}
	digest, err := receiptB64URLDecode(hashValue, name+".hash")
	if err != nil {
		return ReceiptHashClaims{}, nil, receiptHash(err.Error(), nil)
	}
	if len(digest) != sha256.Size {
		return ReceiptHashClaims{}, nil, receiptHash(fmt.Sprintf("%s.hash check failed: SHA-256 digest must be 32 bytes", name), nil)
	}
	of, _ := record["of"].(string)
	allowed := of == "body"
	if response {
		allowed = allowed || of == "sse-data-v1" || of == "sse-events-v1"
	}
	if !allowed {
		return ReceiptHashClaims{}, nil, receiptHash(fmt.Sprintf("%s.of check failed: unsupported hash domain %s", name, receiptRepr(record["of"])), nil)
	}
	var events *int64
	eventsValue, eventsPresent := record["events"]
	if response && of != "body" {
		value, valid := receiptInteger(eventsValue)
		if !valid || value < 0 {
			return ReceiptHashClaims{}, nil, receiptHash(fmt.Sprintf("%s.events check failed: streaming receipts require a non-negative integer", name), nil)
		}
		events = &value
	} else if eventsPresent && eventsValue != nil {
		return ReceiptHashClaims{}, nil, receiptHash(fmt.Sprintf("%s.events check failed: body receipts must omit events", name), nil)
	}
	return ReceiptHashClaims{Alg: alg, Hash: hashValue, Of: of, Events: events}, digest, nil
}

func receiptStreamDigest(stream []byte, domain string, expectedReceipt map[string]any) ([]byte, int64, error) {
	hasher := sha256.New()
	var events int64
	offset := 0
	sawDone := false
	sawReceipt := false
	for offset < len(stream) {
		raw, next, ok := nextReceiptSSEEvent(stream, offset)
		if !ok {
			return nil, 0, receiptHash("response stream framing check failed: stream has an incomplete SSE tail", nil)
		}
		offset = next
		event, err := decodeReceiptSSEEvent(raw)
		if err != nil {
			return nil, 0, err
		}
		if sawDone {
			return nil, 0, receiptHash("response stream receipt position check failed: data event follows [DONE]", nil)
		}
		if event.done {
			sawDone = true
			continue
		}
		embedded, err := embeddedReceiptFromPayload(event.payload)
		if err != nil {
			return nil, 0, err
		}
		if embedded != nil {
			if sawReceipt {
				return nil, 0, receiptHash("response stream receipt position check failed: multiple receipt events", nil)
			}
			if expectedReceipt == nil || !reflect.DeepEqual(embedded, expectedReceipt) {
				return nil, 0, receiptHash("response stream receipt position check failed: embedded receipt does not match the verified flattened JWS", nil)
			}
			sawReceipt = true
			continue
		}
		if sawReceipt {
			return nil, 0, receiptHash("response stream receipt position check failed: receipt is not the last data event before [DONE]", nil)
		}
		switch domain {
		case "sse-data-v1":
			if len(event.name) != 0 {
				return nil, 0, receiptHash("response stream hash check failed: sse-data-v1 events must be unnamed", nil)
			}
		case "sse-events-v1":
			_, _ = hasher.Write(event.name)
			_, _ = hasher.Write([]byte{'\n'})
		default:
			return nil, 0, receiptHash(fmt.Sprintf("response stream hash check failed: unsupported domain %q", domain), nil)
		}
		_, _ = hasher.Write(event.payload)
		_, _ = hasher.Write([]byte{'\n'})
		events++
	}
	if !sawReceipt {
		return nil, 0, receiptHash("response stream receipt position check failed: receipt event is missing", nil)
	}
	if !sawDone {
		return nil, 0, receiptHash("response stream receipt position check failed: receipt is not followed by [DONE]", nil)
	}
	return hasher.Sum(nil), events, nil
}

func nextReceiptSSEEvent(data []byte, offset int) ([]byte, int, bool) {
	lf := bytes.Index(data[offset:], []byte("\n\n"))
	crlf := bytes.Index(data[offset:], []byte("\r\n\r\n"))
	if lf >= 0 {
		lf += offset
	}
	if crlf >= 0 {
		crlf += offset
	}
	if lf < 0 && crlf < 0 {
		return nil, offset, false
	}
	end := 0
	if lf >= 0 && (crlf < 0 || lf < crlf) {
		end = lf + 2
	} else {
		end = crlf + 4
	}
	return data[offset:end], end, true
}

func decodeReceiptSSEEvent(raw []byte) (receiptSSEEvent, error) {
	var body []byte
	if bytes.HasSuffix(raw, []byte("\r\n\r\n")) {
		body = raw[:len(raw)-4]
	} else if bytes.HasSuffix(raw, []byte("\n\n")) {
		body = raw[:len(raw)-2]
	} else {
		return receiptSSEEvent{}, receiptHash("response stream framing check failed: incomplete SSE event", nil)
	}
	var name, payload []byte
	sawName, sawData := false, false
	for _, originalLine := range bytes.Split(body, []byte{'\n'}) {
		line := originalLine
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		switch {
		case bytes.HasPrefix(line, []byte("data:")):
			if sawData {
				return receiptSSEEvent{}, receiptHash("response stream framing check failed: SSE event has multiple data fields", nil)
			}
			sawData = true
			payload = line[len("data:"):]
			if len(payload) > 0 && payload[0] == ' ' {
				payload = payload[1:]
			}
		case bytes.HasPrefix(line, []byte("event:")):
			if sawName {
				return receiptSSEEvent{}, receiptHash("response stream framing check failed: SSE event has multiple event fields", nil)
			}
			sawName = true
			name = line[len("event:"):]
			if len(name) > 0 && name[0] == ' ' {
				name = name[1:]
			}
		default:
			return receiptSSEEvent{}, receiptHash("response stream framing check failed: SSE event contains an unsupported field", nil)
		}
	}
	if !sawData {
		return receiptSSEEvent{}, receiptHash("response stream framing check failed: SSE event has no data field", nil)
	}
	return receiptSSEEvent{name: name, payload: payload, done: bytes.Equal(payload, []byte("[DONE]"))}, nil
}

func embeddedReceiptFromPayload(payload []byte) (map[string]any, error) {
	decoded, err := decodeReceiptJSON(payload, "response stream event JSON")
	if err != nil {
		return nil, nil //nolint:nilerr // SSE domains hash arbitrary payload bytes; non-JSON is not a receipt candidate.
	}
	object, ok := decoded.(map[string]any)
	if !ok {
		return nil, nil
	}
	receipt, present := object["inference_receipt"]
	if !present {
		return nil, nil
	}
	flattened, ok := receipt.(map[string]any)
	if !ok {
		return nil, receiptHash("response stream receipt position check failed: inference_receipt must be a flattened JWS object", nil)
	}
	return flattened, nil
}

var receiptPolicyFromTrustRelease = PolicyFromTrustRelease
var receiptVerifyReceiptKeyAttestation = VerifyReceiptKeyAttestation

func verifyReceiptAttestation(envelope receiptEnvelope, header map[string]any, publicKey []byte, suppliedAttestation []byte, attSHA256 string, require bool) (string, error) {
	var attestation []byte
	if !envelope.flattened {
		if suppliedAttestation == nil {
			if !require {
				return ReceiptAttestationUnverified, nil
			}
			return "", receiptMissingAttestation("attestation check failed: compact receipts omit attestation evidence; obtain the pinned document or explicitly set RequireAttestation to false")
		}
		if attSHA256 == "" {
			return "", receiptMissingAttestation("attestation check failed: compact receipt has no att_sha256 claim")
		}
		expectedDigest, err := receiptB64URLDecode(attSHA256, "att_sha256 claim")
		if err != nil {
			return "", receiptAttestation(err.Error(), err)
		}
		actualDigest := sha256.Sum256(suppliedAttestation)
		if !hmac.Equal(actualDigest[:], expectedDigest) {
			return "", receiptAttestation("att_sha256 check failed: supplied attestation does not match the compact receipt", nil)
		}
		attestation = suppliedAttestation
	} else {
		kind, kindOK := header["att_kind"].(string)
		if kind == "aws-nitro-cose" || kind == "azure-maa-jwt" {
			return "", receiptUnsupportedAttestation(fmt.Sprintf("attestation kind check failed: %q is not supported by this SDK", kind))
		}
		if !kindOK || kind == "" {
			if _, present := header["att_kind"]; !present || header["att_kind"] == nil {
				return "", receiptMissingAttestation("attestation check failed: flattened receipt has no att_kind")
			}
			return "", receiptUnsupportedAttestation(fmt.Sprintf("attestation kind check failed: unsupported att_kind %s", receiptRepr(header["att_kind"])))
		}
		if kind != "gcp-cs-jwt" {
			return "", receiptUnsupportedAttestation(fmt.Sprintf("attestation kind check failed: unsupported att_kind %q", kind))
		}
		embedded, ok := header["att"].(string)
		if !ok || embedded == "" {
			return "", receiptMissingAttestation("attestation check failed: flattened receipt has no embedded att")
		}
		attestation = []byte(embedded)
		if suppliedAttestation != nil && !hmac.Equal(suppliedAttestation, attestation) {
			return "", receiptAttestation("attestation check failed: supplied attestation does not match the flattened receipt's embedded attestation", nil)
		}
	}
	commitment := sha256.Sum256(append([]byte(receiptKeyCommitmentDomain), publicKey...))
	ctx := context.Background()
	policy, err := receiptPolicyFromTrustRelease(ctx, PolicyFromTrustReleaseOptions{})
	if err != nil {
		return "", receiptAttestation(fmt.Sprintf("GCP attestation check failed: %v", err), err)
	}
	err = receiptVerifyReceiptKeyAttestation(ctx, attestation, VerifyReceiptKeyAttestationOptions{
		Policy:           policy,
		KeyCommitmentHex: hex.EncodeToString(commitment[:]),
	})
	if err != nil {
		return "", receiptAttestation(fmt.Sprintf("GCP attestation check failed: %v", err), err)
	}
	return ReceiptAttestationVerified, nil
}

func receiptB64URLDecode(value string, check string) ([]byte, error) {
	if value == "" || strings.Contains(value, "=") {
		return nil, receiptStructure(check+" check failed: invalid base64url encoding", nil)
	}
	for _, char := range value {
		if (char < 'A' || char > 'Z') && (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '_' && char != '-' {
			return nil, receiptStructure(check+" check failed: invalid base64url encoding", nil)
		}
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, receiptStructure(check+" check failed: invalid base64url encoding", err)
	}
	return decoded, nil
}

func decodeReceiptJSON(data []byte, check string) (any, error) {
	if !utf8.Valid(data) {
		return nil, receiptStructure(check+" check failed: invalid JSON: invalid UTF-8", nil)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := decodeReceiptJSONValue(decoder)
	if err != nil {
		return nil, receiptStructure(fmt.Sprintf("%s check failed: invalid JSON: %v", check, err), err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple top-level JSON values")
		}
		return nil, receiptStructure(fmt.Sprintf("%s check failed: invalid JSON: %v", check, err), err)
	}
	return value, nil
}

func decodeReceiptJSONValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return token, nil
	}
	switch delim {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("object member name must be a string")
			}
			if _, duplicate := object[key]; duplicate {
				return nil, fmt.Errorf("duplicate JSON member %q", key)
			}
			value, err := decodeReceiptJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			if err == nil {
				err = errors.New("unterminated object")
			}
			return nil, err
		}
		return object, nil
	case '[':
		array := make([]any, 0)
		for decoder.More() {
			value, err := decodeReceiptJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			if err == nil {
				err = errors.New("unterminated array")
			}
			return nil, err
		}
		return array, nil
	default:
		return nil, fmt.Errorf("unexpected delimiter %q", delim)
	}
}

func requiredReceiptMap(object map[string]any, name string, makeError func(string, error) error) (map[string]any, error) {
	value, ok := object[name].(map[string]any)
	if !ok {
		return nil, makeError(fmt.Sprintf("%s claim check failed: required object is missing or invalid", name), nil)
	}
	return value, nil
}

func requiredReceiptString(object map[string]any, name, family string) (string, error) {
	value, ok := object[name].(string)
	if !ok || value == "" {
		return "", receiptClaims(fmt.Sprintf("%s %s check failed: required string is missing or empty", family, name), nil)
	}
	return value, nil
}

func optionalReceiptString(object map[string]any, name, family string) (string, error) {
	raw, present := object[name]
	if !present {
		return "", nil
	}
	value, ok := raw.(string)
	if !ok || value == "" {
		return "", receiptClaims(fmt.Sprintf("%s %s check failed: value must be a non-empty string", family, name), nil)
	}
	return value, nil
}

func requireReceiptTrafficBindings(opts VerifyReceiptOptions) error {
	if opts.RequireBindings != nil && !*opts.RequireBindings {
		return nil
	}
	missingRequest := opts.RequestBody == nil
	missingResponse := opts.ResponseBody == nil && opts.ResponseStream == nil
	switch {
	case missingRequest && missingResponse:
		return receiptMissingBinding("receipt binding check failed: missing request_body and response_body or response_stream")
	case missingRequest:
		return receiptMissingBinding("receipt binding check failed: missing request_body")
	case missingResponse:
		return receiptMissingBinding("receipt binding check failed: missing response_body or response_stream")
	default:
		return nil
	}
}

func canonicalReceiptHTTPSOrigin(value, check string) (string, error) {
	if value == "" {
		return "", receiptIssuer(check+" check failed: required HTTPS origin is missing", nil)
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", receiptIssuer(check+" check failed: invalid HTTPS origin", err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return "", receiptIssuer(check+" check failed: issuer origin must use https", nil)
	}
	if parsed.Opaque != "" || parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawFragment != "" {
		return "", receiptIssuer(check+" check failed: expected an origin with no path, query, or fragment", nil)
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" || strings.IndexFunc(host, unicode.IsSpace) >= 0 {
		return "", receiptIssuer(check+" check failed: invalid HTTPS origin host", nil)
	}
	port := parsed.Port()
	if port != "" {
		portNumber, parseErr := strconv.ParseUint(port, 10, 16)
		if parseErr != nil || portNumber > 65535 {
			return "", receiptIssuer(check+" check failed: invalid HTTPS origin", parseErr)
		}
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	canonical := "https://" + host
	if port != "" && port != "443" {
		canonical += ":" + port
	}

	// Restrict accepted spelling to case differences, one trailing slash, and
	// an explicit default HTTPS port. This rejects URL parser normalizations
	// such as escaped hosts while still canonicalizing :443 away.
	normalizedInput := strings.ToLower(strings.TrimSuffix(value, "/"))
	validInput := normalizedInput == canonical
	if port == "443" {
		validInput = normalizedInput == canonical+":443"
	}
	if !validInput {
		return "", receiptIssuer(check+" check failed: invalid HTTPS origin", nil)
	}
	return canonical, nil
}

func receiptInteger(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	integer, err := strconv.ParseInt(string(number), 10, 64)
	return integer, err == nil
}

func receiptRepr(value any) string {
	if value == nil {
		return "null"
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%v", value)
	}
	return string(encoded)
}

func isASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] > 0x7f {
			return false
		}
	}
	return true
}

// ReceiptCapture wraps a raw response stream, preserving every wire byte and
// discovering a flattened receipt as complete SSE events arrive.
type ReceiptCapture struct {
	source  io.Reader
	wire    []byte
	scanned int
	receipt map[string]any
}

// NewReceiptCapture constructs a raw response reader that captures exact SSE
// wire bytes. Read from the returned value in place of source.
func NewReceiptCapture(source io.Reader) *ReceiptCapture {
	return &ReceiptCapture{source: source}
}

// Read implements io.Reader and captures exactly the bytes returned by source.
func (c *ReceiptCapture) Read(buffer []byte) (int, error) {
	if c == nil || c.source == nil {
		return 0, io.EOF
	}
	n, err := c.source.Read(buffer)
	if n > 0 {
		c.wire = append(c.wire, buffer[:n]...)
		c.refreshReceipt()
	}
	return n, err
}

// CapturedBytes returns a copy of the exact bytes read so far.
func (c *ReceiptCapture) CapturedBytes() []byte {
	if c == nil {
		return nil
	}
	return append([]byte(nil), c.wire...)
}

// Receipt returns the parsed flattened receipt once its complete SSE event has
// been captured. The returned map must be treated as read-only.
func (c *ReceiptCapture) Receipt() map[string]any {
	if c == nil {
		return nil
	}
	return c.receipt
}

// Verify verifies the discovered receipt against a pinned issuer and all exact
// bytes captured so far.
func (c *ReceiptCapture) Verify(expectedIssuer string, opts VerifyReceiptOptions) (*ReceiptClaims, error) {
	if c == nil {
		return nil, receiptStructure("receipt capture check failed: no flattened receipt event has been captured", nil)
	}
	if c.receipt == nil {
		c.refreshReceipt()
	}
	if c.receipt == nil {
		return nil, receiptStructure("receipt capture check failed: no flattened receipt event has been captured", nil)
	}
	if opts.ResponseStream != nil {
		return nil, receiptHash("ReceiptCapture.Verify supplies ResponseStream from captured bytes", nil)
	}
	opts.ResponseStream = c.CapturedBytes()
	return VerifyReceipt(c.receipt, expectedIssuer, opts)
}

func (c *ReceiptCapture) refreshReceipt() {
	offset := c.scanned
	for offset < len(c.wire) {
		raw, next, ok := nextReceiptSSEEvent(c.wire, offset)
		if !ok {
			return
		}
		offset = next
		c.scanned = next
		event, err := decodeReceiptSSEEvent(raw)
		if err != nil {
			continue
		}
		embedded, err := embeddedReceiptFromPayload(event.payload)
		if err == nil && embedded != nil {
			c.receipt = embedded
		}
	}
}
