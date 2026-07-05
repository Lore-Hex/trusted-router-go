package trustedrouter

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestVerifyGatewayAttestationGoldenJWT(t *testing.T) {
	fixture := newAttestationFixture(t)
	token := fixture.mint(t, fixture.claims(nil))

	got, err := VerifyGatewayAttestation(context.Background(), token, VerifyGatewayAttestationOptions{
		Policy:     fixture.policy,
		NonceHex:   fixture.nonce,
		TLSCertDER: fixture.certDER,
		JWKS:       fixture.jwks,
	})
	if err != nil {
		t.Fatalf("VerifyGatewayAttestation returned error: %v", err)
	}
	if got.CertSHA256 != fixture.certSHA {
		t.Fatalf("CertSHA256 = %q, want %q", got.CertSHA256, fixture.certSHA)
	}
	if got.ImageDigest != fixture.imageDigest {
		t.Fatalf("ImageDigest = %q, want %q", got.ImageDigest, fixture.imageDigest)
	}
	if got.ImageReference != fixture.imageReference {
		t.Fatalf("ImageReference = %q, want %q", got.ImageReference, fixture.imageReference)
	}
	if got.Nonce == nil || *got.Nonce != fixture.nonce {
		t.Fatalf("Nonce = %#v, want %q", got.Nonce, fixture.nonce)
	}
	if got.ExpiresAt == nil || *got.ExpiresAt <= int(time.Now().Unix()) {
		t.Fatalf("ExpiresAt = %#v, want future exp", got.ExpiresAt)
	}
	if got.Issuer == nil || *got.Issuer != GCPIssuer {
		t.Fatalf("Issuer = %#v, want %q", got.Issuer, GCPIssuer)
	}
	if got.Audience != defaultAttestationAudience {
		t.Fatalf("Audience = %q, want %q", got.Audience, defaultAttestationAudience)
	}
	if got.RawClaims["submods"] == nil {
		t.Fatalf("RawClaims missing submods: %#v", got.RawClaims)
	}
	if summary := got.AsMap(); summary["cert_sha256"] != fixture.certSHA || summary["nonce"] != fixture.nonce {
		t.Fatalf("AsMap() = %#v", summary)
	}
}

func TestVerifyGatewayAttestationCertInNonces(t *testing.T) {
	fixture := newAttestationFixture(t)
	claims := fixture.claims(nil)
	delete(claims, "tls_cert_sha256")
	claims["eat_nonce"] = []string{fixture.nonce, fixture.certSHA}
	token := fixture.mint(t, claims)

	got, err := VerifyGatewayAttestation(context.Background(), token, VerifyGatewayAttestationOptions{
		Policy:     fixture.policy,
		NonceHex:   fixture.nonce,
		TLSCertDER: fixture.certDER,
		JWKS:       fixture.jwks,
	})
	if err != nil {
		t.Fatalf("VerifyGatewayAttestation returned error: %v", err)
	}
	if got.CertSHA256 != fixture.certSHA {
		t.Fatalf("CertSHA256 = %q, want %q", got.CertSHA256, fixture.certSHA)
	}
}

func TestCheckAttestationClaimsTLSExporterBinding(t *testing.T) {
	fixture := newAttestationFixture(t)
	exporter := make([]byte, ExporterLength)
	for i := range exporter {
		exporter[i] = byte(i + 1)
	}
	exporterHex := base16(exporter)
	freshNonce := strings.Repeat("12", ExporterLength)

	tests := []struct {
		name      string
		nonces    []string
		nonceHex  string
		wantError string
	}{
		{
			name:     "fresh nonce and exporter present and distinct",
			nonces:   []string{fixture.certSHA, "device-blob-hash", exporterHex, freshNonce},
			nonceHex: freshNonce,
		},
		{
			name:      "exporter absent",
			nonces:    []string{fixture.certSHA, freshNonce},
			nonceHex:  freshNonce,
			wantError: "TLS exporter",
		},
		{
			name:      "fresh nonce empty",
			nonces:    []string{fixture.certSHA, exporterHex, freshNonce},
			wantError: "fresh nonce required with exporter binding",
		},
		{
			name:      "relay exporter laundered through caller nonce",
			nonces:    []string{fixture.certSHA, exporterHex},
			nonceHex:  exporterHex,
			wantError: "fresh nonce must be distinct from TLS exporter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := fixture.claims(map[string]any{"eat_nonce": tt.nonces})
			got, err := checkAttestationClaims(claims, fixture.policy, tt.nonceHex, fixture.certDER, exporter)
			if tt.wantError == "" {
				if err != nil {
					t.Fatalf("checkAttestationClaims returned error: %v", err)
				}
				if got.Nonce == nil || *got.Nonce != freshNonce {
					t.Fatalf("Nonce = %#v, want %q", got.Nonce, freshNonce)
				}
				return
			}
			if err == nil {
				t.Fatal("checkAttestationClaims returned nil error")
			}
			var attErr *AttestationVerificationError
			if !errors.As(err, &attErr) {
				t.Fatalf("error type = %T, want AttestationVerificationError", err)
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantError)
			}
		})
	}
}

func TestVerifyGatewayAttestationRejections(t *testing.T) {
	fixture := newAttestationFixture(t)

	badSig := corruptJWTSignature(t, fixture.mint(t, fixture.claims(nil)))
	wrongIssuer := fixture.mint(t, fixture.claims(map[string]any{"iss": "https://example.invalid"}))
	expired := fixture.mint(t, fixture.claims(map[string]any{"exp": time.Now().Add(-time.Minute).Unix()}))
	good := fixture.mint(t, fixture.claims(nil))

	tests := []struct {
		name      string
		token     []byte
		policy    AttestationPolicy
		nonceHex  string
		certDER   []byte
		wantError string
	}{
		{
			name:      "bad signature",
			token:     badSig,
			policy:    fixture.policy,
			nonceHex:  fixture.nonce,
			certDER:   fixture.certDER,
			wantError: "JWT signature verification failed",
		},
		{
			name:      "wrong issuer",
			token:     wrongIssuer,
			policy:    fixture.policy,
			nonceHex:  fixture.nonce,
			certDER:   fixture.certDER,
			wantError: "unexpected issuer 'https://example.invalid'; expected https://confidentialcomputing.googleapis.com",
		},
		{
			name:      "expired",
			token:     expired,
			policy:    fixture.policy,
			nonceHex:  fixture.nonce,
			certDER:   fixture.certDER,
			wantError: "JWT expired at",
		},
		{
			name:  "digest mismatch",
			token: good,
			policy: AttestationPolicy{
				GCPAudience:            defaultAttestationAudience,
				ExpectedCertSHA256:     fixture.certSHA,
				ExpectedImageDigest:    "sha256:wrong",
				ExpectedImageReference: fixture.imageReference,
			},
			nonceHex:  fixture.nonce,
			certDER:   fixture.certDER,
			wantError: "image_digest mismatch: workload='sha256:feedface', policy='sha256:wrong'",
		},
		{
			name:      "nonce mismatch",
			token:     good,
			policy:    fixture.policy,
			nonceHex:  "missing",
			certDER:   fixture.certDER,
			wantError: "nonce 'missing' not present in JWT nonces ['abc123nonce']",
		},
		{
			name:      "cert mismatch",
			token:     good,
			policy:    fixture.policy,
			nonceHex:  fixture.nonce,
			certDER:   []byte("different cert"),
			wantError: "TLS cert mismatch:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyGatewayAttestation(context.Background(), tt.token, VerifyGatewayAttestationOptions{
				Policy:     tt.policy,
				NonceHex:   tt.nonceHex,
				TLSCertDER: tt.certDER,
				JWKS:       fixture.jwks,
			})
			if err == nil {
				t.Fatal("VerifyGatewayAttestation returned nil error")
			}
			var attErr *AttestationVerificationError
			if !errors.As(err, &attErr) {
				t.Fatalf("error type = %T, want AttestationVerificationError", err)
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantError)
			}
		})
	}
}

func TestVerifyGatewayAttestationShapeRejections(t *testing.T) {
	fixture := newAttestationFixture(t)

	tests := []struct {
		name      string
		token     []byte
		jwks      map[string]any
		wantError string
	}{
		{
			name:      "wrong segment count",
			token:     []byte("one.two"),
			jwks:      fixture.jwks,
			wantError: "expected 3 JWT segments, got 2",
		},
		{
			name:      "unsupported alg",
			token:     fixture.mintWithHeader(t, map[string]any{"alg": "HS256", "kid": fixture.kid}, fixture.claims(nil)),
			jwks:      fixture.jwks,
			wantError: "unsupported JWT alg 'HS256'; expected RS256",
		},
		{
			name:      "missing key",
			token:     fixture.mint(t, fixture.claims(nil)),
			jwks:      map[string]any{"keys": []any{}},
			wantError: "no JWK with kid='test-key' in JWKS — gateway key may have rotated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyGatewayAttestation(context.Background(), tt.token, VerifyGatewayAttestationOptions{
				Policy:     fixture.policy,
				NonceHex:   fixture.nonce,
				TLSCertDER: fixture.certDER,
				JWKS:       tt.jwks,
			})
			if err == nil {
				t.Fatal("VerifyGatewayAttestation returned nil error")
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantError)
			}
		})
	}
}

func TestFetchTrustReleaseAndPolicyFromTrustRelease(t *testing.T) {
	transport := attestationRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("user-agent") == "" {
			t.Error("missing user-agent")
		}
		if r.URL.String() != "https://trust.example/release.json" {
			t.Fatalf("request URL = %s", r.URL.String())
		}
		return attestationTestResponse(http.StatusOK, `{
			"platform": "gcp-confidential-space",
			"image_digest": "sha256:release",
			"image_reference": "us-docker.pkg.dev/project/gateway:prod",
			"attestation_issuer": "https://confidentialcomputing.googleapis.com",
			"attestation_audience": "quill-cloud",
			"tls": {"mode": "managed", "hostname": "api.trustedrouter.com"},
			"data_policy": {"prompt_output_storage": false, "control_plane_prompt_access": false},
			"extra_field": "kept"
		}`), nil
	})
	oldDefaultClient := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: transport}
	defer func() { http.DefaultClient = oldDefaultClient }()

	release, err := FetchTrustRelease(context.Background(), "https://trust.example/release.json")
	if err != nil {
		t.Fatalf("FetchTrustRelease returned error: %v", err)
	}
	if release.ImageDigest != "sha256:release" {
		t.Fatalf("ImageDigest = %q", release.ImageDigest)
	}
	if release.TLS == nil || release.TLS.Hostname != "api.trustedrouter.com" {
		t.Fatalf("TLS = %#v", release.TLS)
	}
	if release.Extra["extra_field"] != "kept" {
		t.Fatalf("Extra = %#v", release.Extra)
	}

	policy, err := PolicyFromTrustRelease(context.Background(), PolicyFromTrustReleaseOptions{
		Release:    release,
		Audience:   "custom-audience",
		CertSHA256: "abc",
	})
	if err != nil {
		t.Fatalf("PolicyFromTrustRelease returned error: %v", err)
	}
	if policy.GCPAudience != "custom-audience" ||
		policy.ExpectedCertSHA256 != "abc" ||
		policy.ExpectedImageDigest != release.ImageDigest ||
		policy.ExpectedImageReference != release.ImageReference {
		t.Fatalf("policy = %#v", policy)
	}

	fetchedPolicy, err := PolicyFromTrustRelease(context.Background(), PolicyFromTrustReleaseOptions{
		TrustReleaseURL: "https://trust.example/release.json",
		HTTPClient:      &http.Client{Transport: transport},
	})
	if err != nil {
		t.Fatalf("PolicyFromTrustRelease fetch returned error: %v", err)
	}
	if fetchedPolicy.GCPAudience != defaultAttestationAudience || fetchedPolicy.ExpectedImageDigest != "sha256:release" {
		t.Fatalf("fetched policy = %#v", fetchedPolicy)
	}
}

func TestClientAttestationAndTrustReleaseWireShape(t *testing.T) {
	transport := attestationRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("user-agent") == "" {
			t.Error("missing user-agent")
		}
		if r.Header.Get("authorization") != "" {
			t.Errorf("authorization header = %q, want empty", r.Header.Get("authorization"))
		}
		switch r.URL.String() {
		case "https://api.example/attestation":
			return attestationTestResponse(http.StatusOK, "jwt-bytes"), nil
		case "https://trust.example/trust.json":
			return attestationTestResponse(http.StatusOK, `{"image_digest":"sha256:trust","image_reference":"image:tag"}`), nil
		default:
			return attestationTestResponse(http.StatusNotFound, `{"error":{"message":"not found"}}`), nil
		}
	})

	client, err := NewClient(Options{
		APIKey:     "secret",
		BaseURL:    "https://api.example/v1",
		HTTPClient: &http.Client{Transport: transport},
	})
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}

	doc, err := client.Attestation(context.Background())
	if err != nil {
		t.Fatalf("Attestation returned error: %v", err)
	}
	if string(doc) != "jwt-bytes" {
		t.Fatalf("attestation = %q", doc)
	}

	release, err := client.TrustRelease(context.Background(), "https://trust.example/trust.json")
	if err != nil {
		t.Fatalf("TrustRelease returned error: %v", err)
	}
	if release.ImageDigest != "sha256:trust" || release.ImageReference != "image:tag" {
		t.Fatalf("release = %#v", release)
	}
}

type attestationFixture struct {
	key            *rsa.PrivateKey
	kid            string
	jwks           map[string]any
	policy         AttestationPolicy
	certDER        []byte
	certSHA        string
	nonce          string
	imageDigest    string
	imageReference string
}

func newAttestationFixture(t *testing.T) attestationFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	certDER := []byte("trusted-router test cert")
	certSum := sha256.Sum256(certDER)
	certSHA := strings.ToLower(base16(certSum[:]))
	kid := "test-key"
	imageDigest := "sha256:feedface"
	imageReference := "us-docker.pkg.dev/project/gateway:prod"
	return attestationFixture{
		key: key,
		kid: kid,
		jwks: map[string]any{"keys": []any{map[string]any{
			"kty": "RSA",
			"kid": kid,
			"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		}}},
		policy: AttestationPolicy{
			GCPAudience:            defaultAttestationAudience,
			ExpectedCertSHA256:     certSHA,
			ExpectedImageDigest:    imageDigest,
			ExpectedImageReference: imageReference,
		},
		certDER:        certDER,
		certSHA:        certSHA,
		nonce:          "abc123nonce",
		imageDigest:    imageDigest,
		imageReference: imageReference,
	}
}

func (f attestationFixture) claims(overrides map[string]any) map[string]any {
	claims := map[string]any{
		"iss":              GCPIssuer,
		"aud":              defaultAttestationAudience,
		"exp":              time.Now().Add(time.Hour).Unix(),
		"eat_nonce":        []string{f.nonce},
		"tls_cert_sha256":  f.certSHA,
		"submods":          map[string]any{"container": map[string]any{"image_digest": f.imageDigest, "image_reference": f.imageReference}},
		"additional_claim": "kept",
	}
	for key, value := range overrides {
		claims[key] = value
	}
	return claims
}

func (f attestationFixture) mint(t *testing.T, claims map[string]any) []byte {
	t.Helper()
	return f.mintWithHeader(t, map[string]any{"alg": "RS256", "kid": f.kid, "typ": "JWT"}, claims)
}

func (f attestationFixture) mintWithHeader(t *testing.T, header map[string]any, claims map[string]any) []byte {
	t.Helper()
	headerSegment := mustJWTJSONSegment(t, header)
	payloadSegment := mustJWTJSONSegment(t, claims)
	signingInput := headerSegment + "." + payloadSegment
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15 returned error: %v", err)
	}
	return []byte(signingInput + "." + base64.RawURLEncoding.EncodeToString(signature))
}

func mustJWTJSONSegment(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func corruptJWTSignature(t *testing.T, token []byte) []byte {
	t.Helper()
	parts := strings.Split(string(token), ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments", len(parts))
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("DecodeString returned error: %v", err)
	}
	signature[len(signature)-1] ^= 0x01
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	return []byte(strings.Join(parts, "."))
}

func base16(data []byte) string {
	const table = "0123456789abcdef"
	out := make([]byte, len(data)*2)
	for i, b := range data {
		out[i*2] = table[b>>4]
		out[i*2+1] = table[b&0x0f]
	}
	return string(out)
}

type attestationRoundTripFunc func(*http.Request) (*http.Response, error)

func (f attestationRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func attestationTestResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
