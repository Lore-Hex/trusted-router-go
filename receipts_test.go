package trustedrouter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const receiptTestNow = int64(1756224000)

func stringPointer(value string) *string     { return &value }
func testB64URL(value []byte) string         { return base64.RawURLEncoding.EncodeToString(value) }
func testDigest(value []byte) string         { digest := sha256.Sum256(value); return testB64URL(digest[:]) }
func receiptErrorIs[T error](err error) bool { var target T; return errors.As(err, &target) }
func requireNoReceiptError(t *testing.T, err error) { // keep failure output uniform across fixture cases
	t.Helper()
	if err != nil {
		t.Fatalf("VerifyReceipt returned error: %v", err)
	}
}

func baseReceiptClaims(responseOf string, responsePreimage []byte) map[string]any {
	resp := map[string]any{
		"alg":  "sha256",
		"hash": testDigest(responsePreimage),
		"of":   responseOf,
	}
	if responseOf != "body" {
		resp["events"] = 1
	}
	return map[string]any{
		"rv":    1,
		"iss":   "https://api.trustedrouter.com",
		"iat":   receiptTestNow,
		"jti":   "chatcmpl-test",
		"gen":   "gen-test",
		"nonce": "nonce_test",
		"route": "chat.completions",
		"req": map[string]any{
			"alg": "sha256", "hash": testDigest([]byte("request")), "of": "body",
		},
		"resp": resp,
		"model": map[string]any{
			"requested": "trustedrouter/auto",
			"selected":  "model",
			"provider":  "provider",
			"endpoint":  "model@provider/prepaid",
		},
		"upstream": map[string]any{
			"tier":                    "tee-verified",
			"policy":                  "chutes-tdx-nvidia-e2e-v1",
			"verified_at":             receiptTestNow - 60,
			"verification_expires_at": receiptTestNow + 60,
		},
		"att_sha256": testDigest([]byte("attestation")),
	}
}

type signedTestReceipt struct {
	receipt   any
	protected string
	payload   string
	signature string
	publicKey ed25519.PublicKey
}

func signTestReceipt(
	t *testing.T,
	claims map[string]any,
	flattened bool,
	headerUpdates map[string]any,
	signingOverride ed25519.PrivateKey,
) signedTestReceipt {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	header := map[string]any{
		"alg": "EdDSA",
		"typ": receiptType,
		"kid": testDigest(publicKey),
		"jwk": map[string]any{
			"kty": "OKP", "crv": "Ed25519", "x": testB64URL(publicKey),
		},
	}
	if flattened {
		header["att"] = "fake.jwt.token"
		header["att_kind"] = "gcp-cs-jwt"
	}
	for key, value := range headerUpdates {
		if value == nil {
			delete(header, key)
		} else {
			header[key] = value
		}
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	protected := testB64URL(headerBytes)
	payload := testB64URL(payloadBytes)
	signer := privateKey
	if signingOverride != nil {
		signer = signingOverride
	}
	signature := testB64URL(ed25519.Sign(signer, []byte(protected+"."+payload)))
	result := signedTestReceipt{
		protected: protected,
		payload:   payload,
		signature: signature,
		publicKey: publicKey,
	}
	if flattened {
		result.receipt = map[string]any{
			"protected": protected, "payload": payload, "signature": signature,
		}
	} else {
		result.receipt = protected + "." + payload + "." + signature
	}
	return result
}

func receiptEvent(t *testing.T, receipt any) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"id": "chatcmpl-test", "object": "chat.completion.chunk", "choices": []any{},
		"inference_receipt": receipt,
	})
	if err != nil {
		t.Fatalf("marshal receipt event: %v", err)
	}
	return append(append([]byte("data: "), payload...), []byte("\n\n")...)
}

func makeStreamReceipt(t *testing.T, eventsClaim int) (map[string]any, []byte) {
	t.Helper()
	payload := []byte(`{"choices":[{"delta":{"content":"hello"}}]}`)
	claims := baseReceiptClaims("sse-data-v1", append(append([]byte(nil), payload...), '\n'))
	delete(claims, "att_sha256")
	claims["resp"].(map[string]any)["events"] = eventsClaim
	signed := signTestReceipt(t, claims, true, nil, nil)
	receipt := signed.receipt.(map[string]any)
	stream := append(append(append([]byte("data: "), payload...), []byte("\n\n")...), receiptEvent(t, receipt)...)
	stream = append(stream, []byte("data: [DONE]\n\n")...)
	return receipt, stream
}

func stubReceiptAttestation(t *testing.T) {
	t.Helper()
	oldPolicy := receiptPolicyFromTrustRelease
	oldVerify := receiptVerifyReceiptKeyAttestation
	receiptPolicyFromTrustRelease = func(context.Context, PolicyFromTrustReleaseOptions) (AttestationPolicy, error) {
		return AttestationPolicy{ExpectedImageDigest: "sha256:test"}, nil
	}
	receiptVerifyReceiptKeyAttestation = func(context.Context, []byte, VerifyReceiptKeyAttestationOptions) error {
		return nil
	}
	t.Cleanup(func() {
		receiptPolicyFromTrustRelease = oldPolicy
		receiptVerifyReceiptKeyAttestation = oldVerify
	})
}

func TestReceiptFrozenFixtures(t *testing.T) {
	stubReceiptAttestation(t)
	root := filepath.Join("internal", "receipts", "testdata", "fixtures")
	for _, name := range []string{"compact-body", "chat-stream", "responses-stream"} {
		t.Run(name, func(t *testing.T) {
			directory := filepath.Join(root, name)
			var metadata struct {
				ExpectedNonce      string  `json:"expected_nonce"`
				RequireAttestation bool    `json:"require_attestation"`
				Now                float64 `json:"now"`
			}
			metadataBytes, err := os.ReadFile(filepath.Join(directory, "metadata.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
				t.Fatal(err)
			}
			receipt, err := os.ReadFile(filepath.Join(directory, "receipt.jws"))
			if err != nil {
				t.Fatal(err)
			}
			requestBody, err := os.ReadFile(filepath.Join(directory, "request.body"))
			if err != nil {
				t.Fatal(err)
			}
			opts := VerifyReceiptOptions{
				RequestBody:        requestBody,
				ExpectedNonce:      &metadata.ExpectedNonce,
				Now:                &metadata.Now,
				RequireAttestation: &metadata.RequireAttestation,
			}
			if name == "compact-body" {
				opts.ResponseBody, err = os.ReadFile(filepath.Join(directory, "response.body"))
			} else {
				opts.ResponseStream, err = os.ReadFile(filepath.Join(directory, "response.sse"))
			}
			if err != nil {
				t.Fatal(err)
			}
			verified, err := VerifyReceipt(receipt, opts)
			requireNoReceiptError(t, err)
			if verified.RV != 1 {
				t.Fatalf("RV = %d, want 1", verified.RV)
			}
		})
	}
}

func TestReceiptTamperMatrix(t *testing.T) {
	falseValue := false
	now := float64(receiptTestNow)
	baseOptions := VerifyReceiptOptions{Now: &now, RequireAttestation: &falseValue}

	t.Run("flipped payload byte", func(t *testing.T) {
		signed := signTestReceipt(t, baseReceiptClaims("body", []byte("response")), false, nil, nil)
		payload, _ := base64.RawURLEncoding.DecodeString(signed.payload)
		payload[len(payload)-2] ^= 1
		tampered := signed.protected + "." + testB64URL(payload) + "." + signed.signature
		_, err := VerifyReceipt(tampered, baseOptions)
		if !receiptErrorIs[*ReceiptSignatureError](err) {
			t.Fatalf("got %T (%v), want ReceiptSignatureError", err, err)
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		_, wrongSigner, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signed := signTestReceipt(t, baseReceiptClaims("body", []byte("response")), false, nil, wrongSigner)
		_, err = VerifyReceipt(signed.receipt, baseOptions)
		if !receiptErrorIs[*ReceiptSignatureError](err) {
			t.Fatalf("got %T (%v), want ReceiptSignatureError", err, err)
		}
	})

	t.Run("edited claim with stale signature", func(t *testing.T) {
		signed := signTestReceipt(t, baseReceiptClaims("body", []byte("response")), false, nil, nil)
		payload, _ := base64.RawURLEncoding.DecodeString(signed.payload)
		edited := bytes.Replace(payload, []byte(`"selected":"model"`), []byte(`"selected":"other"`), 1)
		tampered := signed.protected + "." + testB64URL(edited) + "." + signed.signature
		_, err := VerifyReceipt(tampered, baseOptions)
		if !receiptErrorIs[*ReceiptSignatureError](err) {
			t.Fatalf("got %T (%v), want ReceiptSignatureError", err, err)
		}
	})

	t.Run("wrong kid", func(t *testing.T) {
		signed := signTestReceipt(t, baseReceiptClaims("body", []byte("response")), false, map[string]any{"kid": testDigest([]byte("wrong"))}, nil)
		_, err := VerifyReceipt(signed.receipt, baseOptions)
		if !receiptErrorIs[*ReceiptHeaderError](err) {
			t.Fatalf("got %T (%v), want ReceiptHeaderError", err, err)
		}
	})

	t.Run("stream byte flip", func(t *testing.T) {
		stubReceiptAttestation(t)
		receipt, stream := makeStreamReceipt(t, 1)
		stream = bytes.Replace(stream, []byte("hello"), []byte("jello"), 1)
		_, err := VerifyReceipt(receipt, VerifyReceiptOptions{Now: &now, ResponseStream: stream})
		if !receiptErrorIs[*ReceiptHashError](err) {
			t.Fatalf("got %T (%v), want ReceiptHashError", err, err)
		}
	})

	t.Run("receipt not last", func(t *testing.T) {
		stubReceiptAttestation(t)
		receipt, stream := makeStreamReceipt(t, 1)
		extra := []byte("data: {\"choices\":[]}\n\n")
		stream = bytes.Replace(stream, []byte("data: [DONE]"), append(extra, []byte("data: [DONE]")...), 1)
		_, err := VerifyReceipt(receipt, VerifyReceiptOptions{Now: &now, ResponseStream: stream})
		if !receiptErrorIs[*ReceiptHashError](err) || !strings.Contains(err.Error(), "not the last") {
			t.Fatalf("got %T (%v), want last-position ReceiptHashError", err, err)
		}
	})

	t.Run("events off by one", func(t *testing.T) {
		stubReceiptAttestation(t)
		receipt, stream := makeStreamReceipt(t, 2)
		_, err := VerifyReceipt(receipt, VerifyReceiptOptions{Now: &now, ResponseStream: stream})
		if !receiptErrorIs[*ReceiptHashError](err) || !strings.Contains(err.Error(), "events check") {
			t.Fatalf("got %T (%v), want events ReceiptHashError", err, err)
		}
	})

	t.Run("future iat over 60 seconds", func(t *testing.T) {
		claims := baseReceiptClaims("body", []byte("response"))
		claims["iat"] = receiptTestNow + 61
		signed := signTestReceipt(t, claims, false, nil, nil)
		_, err := VerifyReceipt(signed.receipt, baseOptions)
		if !receiptErrorIs[*ReceiptTimeError](err) {
			t.Fatalf("got %T (%v), want ReceiptTimeError", err, err)
		}
	})

	t.Run("expired tee-verified window", func(t *testing.T) {
		claims := baseReceiptClaims("body", []byte("response"))
		claims["upstream"].(map[string]any)["verification_expires_at"] = receiptTestNow
		signed := signTestReceipt(t, claims, false, nil, nil)
		_, err := VerifyReceipt(signed.receipt, baseOptions)
		if !receiptErrorIs[*ReceiptUpstreamError](err) {
			t.Fatalf("got %T (%v), want ReceiptUpstreamError", err, err)
		}
	})

	t.Run("nonce mismatch", func(t *testing.T) {
		signed := signTestReceipt(t, baseReceiptClaims("body", []byte("response")), false, nil, nil)
		options := baseOptions
		options.ExpectedNonce = stringPointer("different")
		_, err := VerifyReceipt(signed.receipt, options)
		if !receiptErrorIs[*ReceiptNonceError](err) {
			t.Fatalf("got %T (%v), want ReceiptNonceError", err, err)
		}
	})

	t.Run("unsupported attestation kind", func(t *testing.T) {
		claims := baseReceiptClaims("body", []byte("response"))
		delete(claims, "att_sha256")
		signed := signTestReceipt(t, claims, true, map[string]any{"att_kind": "aws-nitro-cose"}, nil)
		_, err := VerifyReceipt(signed.receipt, baseOptions)
		if !receiptErrorIs[*UnsupportedAttestationError](err) {
			t.Fatalf("got %T (%v), want UnsupportedAttestationError", err, err)
		}
	})

	t.Run("missing attestation defaults to required", func(t *testing.T) {
		signed := signTestReceipt(t, baseReceiptClaims("body", []byte("response")), false, nil, nil)
		_, err := VerifyReceipt(signed.receipt, VerifyReceiptOptions{Now: &now})
		if !receiptErrorIs[*MissingAttestationError](err) {
			t.Fatalf("got %T (%v), want MissingAttestationError", err, err)
		}
	})

	t.Run("duplicate nested JSON member", func(t *testing.T) {
		signed := signTestReceipt(t, baseReceiptClaims("body", []byte("response")), false, nil, nil)
		payload, _ := base64.RawURLEncoding.DecodeString(signed.payload)
		duplicate := bytes.Replace(payload, []byte(`"provider":"provider"`), []byte(`"provider":"provider","provider":"provider"`), 1)
		if bytes.Equal(payload, duplicate) {
			t.Fatal("test payload did not contain provider member")
		}
		encoded := testB64URL(duplicate)
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		// Rebuild a matching public header so the duplicate check, not a stale
		// signature, is what rejects the receipt.
		publicKey := privateKey.Public().(ed25519.PublicKey)
		header := fmt.Sprintf(`{"alg":"EdDSA","typ":%q,"kid":%q,"jwk":{"kty":"OKP","crv":"Ed25519","x":%q}}`, receiptType, testDigest(publicKey), testB64URL(publicKey))
		protected := testB64URL([]byte(header))
		signature := testB64URL(ed25519.Sign(privateKey, []byte(protected+"."+encoded)))
		_, err = VerifyReceipt(protected+"."+encoded+"."+signature, baseOptions)
		if !receiptErrorIs[*ReceiptStructureError](err) {
			t.Fatalf("got %T (%v), want ReceiptStructureError", err, err)
		}
	})
}

func TestReceiptStreamingFramingFailures(t *testing.T) {
	stubReceiptAttestation(t)
	now := float64(receiptTestNow)
	receipt, stream := makeStreamReceipt(t, 1)
	cases := map[string][]byte{
		"multi-line data": bytes.Replace(stream, []byte("data: {\"choices\""), []byte("data: first\ndata: {\"choices\""), 1),
		"unknown field":   bytes.Replace(stream, []byte("data: {\"choices\""), []byte("id: 1\ndata: {\"choices\""), 1),
		"missing done":    bytes.TrimSuffix(stream, []byte("data: [DONE]\n\n")),
		"data after done": append(append([]byte(nil), stream...), []byte("data: {}\n\n")...),
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := VerifyReceipt(receipt, VerifyReceiptOptions{Now: &now, ResponseStream: candidate})
			if !receiptErrorIs[*ReceiptHashError](err) {
				t.Fatalf("got %T (%v), want ReceiptHashError", err, err)
			}
		})
	}
}

func TestReceiptGCPAttestationUsesKeyCommitmentSetMember(t *testing.T) {
	claims := baseReceiptClaims("body", []byte("response"))
	delete(claims, "att_sha256")
	signed := signTestReceipt(t, claims, true, nil, nil)
	oldPolicy := receiptPolicyFromTrustRelease
	oldVerify := receiptVerifyReceiptKeyAttestation
	receiptPolicyFromTrustRelease = func(context.Context, PolicyFromTrustReleaseOptions) (AttestationPolicy, error) {
		return AttestationPolicy{ExpectedImageDigest: "sha256:test"}, nil
	}
	var seenNonce string
	receiptVerifyReceiptKeyAttestation = func(_ context.Context, document []byte, opts VerifyReceiptKeyAttestationOptions) error {
		if string(document) != "fake.jwt.token" {
			t.Fatalf("attestation document = %q", document)
		}
		seenNonce = opts.KeyCommitmentHex
		return nil
	}
	t.Cleanup(func() {
		receiptPolicyFromTrustRelease = oldPolicy
		receiptVerifyReceiptKeyAttestation = oldVerify
	})
	now := float64(receiptTestNow)
	verified, err := VerifyReceipt(signed.receipt, VerifyReceiptOptions{Now: &now})
	requireNoReceiptError(t, err)
	commitment := sha256.Sum256(append([]byte(receiptKeyCommitmentDomain), signed.publicKey...))
	if seenNonce != hex.EncodeToString(commitment[:]) {
		t.Fatalf("nonce member = %q, want %q", seenNonce, hex.EncodeToString(commitment[:]))
	}
	if verified.AttestationStatus != ReceiptAttestationVerified {
		t.Fatalf("attestation status = %q", verified.AttestationStatus)
	}
}

func TestReceiptKeyBindingAcceptsNonceMembershipWithoutLiveChannel(t *testing.T) {
	for _, commitmentPosition := range []int{0, 2} {
		t.Run(fmt.Sprintf("position_%d", commitmentPosition), func(t *testing.T) {
			fixture := newAttestationFixture(t)
			claims := baseReceiptClaims("body", []byte("response"))
			delete(claims, "att_sha256")
			signed := signTestReceipt(t, claims, true, nil, nil)
			commitment := sha256.Sum256(append([]byte(receiptKeyCommitmentDomain), signed.publicKey...))
			commitmentHex := hex.EncodeToString(commitment[:])
			nonces := []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}
			nonces = append(nonces, "")
			copy(nonces[commitmentPosition+1:], nonces[commitmentPosition:])
			nonces[commitmentPosition] = commitmentHex
			attestationClaims := fixture.claims(map[string]any{
				"eat_nonce":       nonces,
				"tls_cert_sha256": nil,
			})

			oldPolicy := receiptPolicyFromTrustRelease
			oldVerify := receiptVerifyReceiptKeyAttestation
			receiptPolicyFromTrustRelease = func(context.Context, PolicyFromTrustReleaseOptions) (AttestationPolicy, error) {
				return fixture.policy, nil
			}
			receiptVerifyReceiptKeyAttestation = func(_ context.Context, document []byte, opts VerifyReceiptKeyAttestationOptions) error {
				if string(document) != "fake.jwt.token" {
					t.Fatalf("attestation document = %q", document)
				}
				_, err := checkAttestationClaimsForBinding(attestationClaims, opts.Policy, opts.KeyCommitmentHex, nil, nil, attestationBindingReceiptKey)
				return err
			}
			t.Cleanup(func() {
				receiptPolicyFromTrustRelease = oldPolicy
				receiptVerifyReceiptKeyAttestation = oldVerify
			})

			now := float64(receiptTestNow)
			verified, err := VerifyReceipt(signed.receipt, VerifyReceiptOptions{Now: &now})
			requireNoReceiptError(t, err)
			if verified.AttestationStatus != ReceiptAttestationVerified {
				t.Fatalf("attestation status = %q", verified.AttestationStatus)
			}

			_, err = checkAttestationClaims(attestationClaims, fixture.policy, commitmentHex, nil, nil)
			if err == nil || !strings.Contains(err.Error(), "TLS cert") {
				t.Fatalf("live-channel check error = %v, want TLS cert binding failure", err)
			}
		})
	}
}

func TestReceiptKeyBindingRejectsWrongCommitment(t *testing.T) {
	fixture := newAttestationFixture(t)
	claims := baseReceiptClaims("body", []byte("response"))
	delete(claims, "att_sha256")
	signed := signTestReceipt(t, claims, true, nil, nil)
	attestationClaims := fixture.claims(map[string]any{
		"eat_nonce":       []string{strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)},
		"tls_cert_sha256": nil,
	})

	oldPolicy := receiptPolicyFromTrustRelease
	oldVerify := receiptVerifyReceiptKeyAttestation
	receiptPolicyFromTrustRelease = func(context.Context, PolicyFromTrustReleaseOptions) (AttestationPolicy, error) {
		return fixture.policy, nil
	}
	receiptVerifyReceiptKeyAttestation = func(_ context.Context, _ []byte, opts VerifyReceiptKeyAttestationOptions) error {
		_, err := checkAttestationClaimsForBinding(attestationClaims, opts.Policy, opts.KeyCommitmentHex, nil, nil, attestationBindingReceiptKey)
		return err
	}
	t.Cleanup(func() {
		receiptPolicyFromTrustRelease = oldPolicy
		receiptVerifyReceiptKeyAttestation = oldVerify
	})

	now := float64(receiptTestNow)
	_, err := VerifyReceipt(signed.receipt, VerifyReceiptOptions{Now: &now})
	if !receiptErrorIs[*ReceiptAttestationError](err) || !strings.Contains(err.Error(), "not present in JWT nonces") {
		t.Fatalf("got %T (%v), want nonce-membership ReceiptAttestationError", err, err)
	}
}

func TestCompactReceiptVerifiesSuppliedPinnedAttestation(t *testing.T) {
	document := []byte("attestation")
	oldPolicy := receiptPolicyFromTrustRelease
	oldVerify := receiptVerifyReceiptKeyAttestation
	receiptPolicyFromTrustRelease = func(context.Context, PolicyFromTrustReleaseOptions) (AttestationPolicy, error) {
		return AttestationPolicy{ExpectedImageDigest: "sha256:test"}, nil
	}
	receiptVerifyReceiptKeyAttestation = func(_ context.Context, got []byte, _ VerifyReceiptKeyAttestationOptions) error {
		if !bytes.Equal(got, document) {
			t.Fatalf("attestation document = %q, want %q", got, document)
		}
		return nil
	}
	t.Cleanup(func() {
		receiptPolicyFromTrustRelease = oldPolicy
		receiptVerifyReceiptKeyAttestation = oldVerify
	})

	claims := baseReceiptClaims("body", []byte("response"))
	claims["att_sha256"] = testDigest(document)
	signed := signTestReceipt(t, claims, false, nil, nil)
	now := float64(receiptTestNow)

	verified, err := VerifyReceipt(signed.receipt, VerifyReceiptOptions{Now: &now, Attestation: document})
	requireNoReceiptError(t, err)
	if verified.AttestationStatus != ReceiptAttestationVerified {
		t.Fatalf("attestation status = %q", verified.AttestationStatus)
	}

	changed := append([]byte(nil), document...)
	changed[len(changed)-1] ^= 1
	_, err = VerifyReceipt(signed.receipt, VerifyReceiptOptions{Now: &now, Attestation: changed})
	if !receiptErrorIs[*ReceiptAttestationError](err) || !strings.Contains(err.Error(), "att_sha256 check failed") {
		t.Fatalf("got %T (%v), want att_sha256 ReceiptAttestationError", err, err)
	}
}

func TestFlattenedReceiptRejectsMismatchedSuppliedAttestation(t *testing.T) {
	stubReceiptAttestation(t)
	claims := baseReceiptClaims("body", []byte("response"))
	delete(claims, "att_sha256")
	signed := signTestReceipt(t, claims, true, nil, nil)
	now := float64(receiptTestNow)

	_, err := VerifyReceipt(signed.receipt, VerifyReceiptOptions{
		Now:         &now,
		Attestation: []byte("fake.jwt.tokenx"),
	})
	if !receiptErrorIs[*ReceiptAttestationError](err) || !strings.Contains(err.Error(), "does not match the flattened receipt's embedded attestation") {
		t.Fatalf("got %T (%v), want embedded-attestation mismatch", err, err)
	}
}

func TestReceiptCapturePreservesExactWireBytesAndVerifies(t *testing.T) {
	stubReceiptAttestation(t)
	receipt, stream := makeStreamReceipt(t, 1)
	_ = receipt
	source := &fixedChunkReader{chunks: [][]byte{stream[:17], stream[17:83], stream[83:]}}
	capture := NewReceiptCapture(source)
	read, err := io.ReadAll(capture)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(read, stream) || !bytes.Equal(capture.CapturedBytes(), stream) {
		t.Fatal("capture did not preserve exact wire bytes")
	}
	if capture.Receipt() == nil {
		t.Fatal("capture did not discover receipt")
	}
	now := float64(receiptTestNow)
	verified, err := capture.Verify(VerifyReceiptOptions{Now: &now})
	requireNoReceiptError(t, err)
	if verified.JTI != "chatcmpl-test" {
		t.Fatalf("JTI = %q", verified.JTI)
	}
}

type fixedChunkReader struct {
	chunks [][]byte
}

func (r *fixedChunkReader) Read(buffer []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	chunk := r.chunks[0]
	n := copy(buffer, chunk)
	if n == len(chunk) {
		r.chunks = r.chunks[1:]
	} else {
		r.chunks[0] = chunk[n:]
	}
	return n, nil
}
