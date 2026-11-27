package trustedrouter

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestPrivateChatNeedsPolicyBeforeNetwork(t *testing.T) {
	c, err := NewClient(Options{BaseURL: "https://not-contacted.invalid/v1"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.ChatCompletionsRawStream(context.Background(), ChatRequest{Model: "nyte/trusted"})
	if err == nil || !strings.Contains(err.Error(), "GatewayPolicy") {
		t.Fatalf("expected local policy refusal, got %v", err)
	}
}

func TestPrivateChatOnlyOnVerifiedConnection(t *testing.T) {
	cert, roots, der := newGatewaySessionTestCert(t)
	f := newAttestationFixture(t)
	f.imageDigest = "sha256:" + strings.Repeat("a", 64)
	f.policy.ExpectedImageDigest = f.imageDigest
	f.policy.ExpectedCertSHA256 = sha256Hex(der)
	old := verifyGatewaySessionTLSConfigHook
	verifyGatewaySessionTLSConfigHook = func(c *tls.Config) { c.RootCAs = roots }
	t.Cleanup(func() { verifyGatewaySessionTLSConfigHook = old })

	var mu sync.Mutex
	var evidenceConn string
	var posts int
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/attestation" && r.Method == "GET" {
			if r.Header.Get("Authorization") != "" || r.ContentLength > 0 {
				t.Error("sent credential or body before verification")
			}
			exporter, err := r.TLS.ExportKeyingMaterial(ExporterLabel, nil, ExporterLength)
			if err != nil {
				t.Error(err)
				return
			}
			b, err := mintGatewaySessionTestJWT(f, f.claims(map[string]any{
				"eat_nonce":       []string{sha256Hex(der), base16(exporter), r.URL.Query().Get("nonce")},
				"tls_cert_sha256": sha256Hex(der), "dbgstat": "disabled-since-boot",
			}))
			if err != nil {
				t.Error(err)
				return
			}
			evidenceConn = r.RemoteAddr
			w.Header().Set("Content-Length", strconv.Itoa(len(b)))
			_, _ = w.Write(b)
			return
		}
		posts++
		if r.Method != "POST" || r.URL.Path != "/v1/chat/completions" || r.RemoteAddr != evidenceConn || r.Header.Get("Authorization") != "Bearer synthetic" {
			t.Error("chat request not bound to verified session")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	s.StartTLS()
	defer s.Close()
	for _, ok := range []bool{true, false} {
		policy := f.policy
		if !ok {
			policy.ExpectedImageDigest = "sha256:" + strings.Repeat("b", 64)
		}
		zero := 0
		c, err := NewClient(Options{BaseURL: strings.Replace(s.URL, "127.0.0.1", "localhost", 1) + "/v1", APIKey: "synthetic", GatewayPolicy: &policy, MaxRetries: &zero})
		if err != nil {
			t.Fatal(err)
		}
		c.verifiedHTTPClient.Transport = verifiedTransport(policy, func(ctx context.Context, o VerifyGatewaySessionOptions) (*GatewaySession, error) {
			o.JWKS = f.jwks
			return VerifyGatewaySession(ctx, o)
		})
		stream, err := c.ChatCompletionsRawStream(context.Background(), ChatRequest{Model: "trustedrouter/trusted"})
		if (err == nil) != ok {
			t.Fatalf("valid pin=%v err=%v", ok, err)
		}
		if stream != nil {
			_, _ = io.Copy(io.Discard, stream)
			_ = stream.Close()
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if posts != 1 {
		t.Fatalf("got %d private POSTs; want only the valid-pin case", posts)
	}
}
