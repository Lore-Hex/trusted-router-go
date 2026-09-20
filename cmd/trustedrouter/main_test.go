package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The installed CLI has no trust-URL flag. This test-only process entry installs
// a private test CA, then invokes the unchanged main from the extracted artifact.
// No harness code is included in module.zip or the ordinary go-build binary.
const cliHarness = `package main
import("crypto/x509";"os";"testing")
func TestArtifactProcess(t *testing.T) {
 roots:=x509.NewCertPool()
 cert,err:=os.ReadFile(os.Getenv("TR_DX_CA"));if err!=nil{panic(err)}
 if !roots.AppendCertsFromPEM(cert){panic("invalid test CA")}
 x509.SetFallbackRoots(roots)
 for i,arg:=range os.Args {if arg=="--"{os.Args=append([]string{"trustedrouter"},os.Args[i+1:]...);main();return}}
 panic("missing CLI args")
}
`

func cliBuild(t *testing.T) (string, string) {
	t.Helper()
	// The mutation runner may reuse the once-built artifact: mutations here change
	// expected CLI contracts, never the binary. Normal go test always rebuilds.
	if bin := os.Getenv("TR_DX_CLI_BINARY"); bin != "" {
		return bin, bin + ".plain"
	}
	dir := t.TempDir()
	command := exec.Command("go", "test", "-count=1", "-run", "^TestReleaseArtifact$", ".")
	command.Dir = "../.."
	command.Env = append(os.Environ(), "TR_DX_OUTPUT="+dir)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("artifact: %v\n%s", err, out)
	}
	root := filepath.Join(dir, "module")
	harness := filepath.Join(root, "cmd/trustedrouter/artifact_process_test.go")
	if err := os.WriteFile(harness, []byte(cliHarness), 0600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "cli-test")
	if save := os.Getenv("TR_DX_CLI_SAVE"); save != "" {
		bin = save
	}
	for _, args := range [][]string{{"build", "-o", bin + ".plain", "./cmd/trustedrouter"}, {"test", "-c", "-o", bin, "./cmd/trustedrouter"}} {
		command = exec.Command("go", args...)
		command.Dir = root
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build CLI: %v\n%s", err, out)
		}
	}
	return bin, bin + ".plain"
}

type cliCase struct {
	signed         bool
	stdoutPattern  string
	name           string
	args           []string
	status         int
	stdout, stderr string
	jsonShape      map[string]any
	response       string
	httpStatus     int
	model          string
	maxTokens      int
	calls          int
	fallback       bool
	tls            bool
}

func TestCLI(t *testing.T) {
	bin, plain := cliBuild(t)
	cases := []cliCase{
		{name: "no-command", status: 2, stderr: "Usage:"},
		{name: "unknown-command", args: []string{"unknown"}, status: 2, stderr: "unknown command"},
		{name: "global-help", args: []string{"--help"}, status: 2, stderr: "Usage:"},
		{name: "global-short-help", args: []string{"-h"}, status: 2, stderr: "Usage:"},
		{name: "global-unknown-flag", args: []string{"--unknown"}, status: 2, stderr: "flag provided but not defined"},
		{name: "invalid-retries", args: []string{"--retries", "no", "models"}, status: 2, stderr: "invalid value"},
		{name: "invalid-base", args: []string{"--base-url", ":bad", "chat", "hi"}, status: 1, stderr: "error:"},
		{name: "chat-empty", args: []string{"chat"}, status: 2, stderr: "empty prompt"},
		{name: "chat-help", args: []string{"chat", "--help"}, status: 2, stderr: "Usage of trustedrouter chat"},
		{name: "chat-short-help", args: []string{"chat", "-h"}, status: 2, stderr: "Usage of trustedrouter chat"},
		{name: "chat-invalid-flag", args: []string{"chat", "--oops"}, status: 2, stderr: "flag provided but not defined"},
		{name: "chat-invalid-max-tokens", args: []string{"chat", "--max-tokens", "no", "hi"}, status: 2, stderr: "invalid value"},
		{name: "chat-defaults", args: []string{"chat", "hi"}, stdout: "hello\n", model: "trustedrouter/auto", maxTokens: 200, calls: 1},
		{name: "chat-model-max-tokens", args: []string{"chat", "--model", "model/test", "--max-tokens", "17", "hi"}, stdout: "hello\n", model: "model/test", maxTokens: 17, calls: 1},
		{name: "chat-short-model-fallback-key", args: []string{"chat", "-m", "model/short", "hi"}, stdout: "hello\n", model: "model/short", maxTokens: 200, calls: 1, fallback: true},
		{name: "chat-stream", args: []string{"chat", "--stream", "hi"}, stdout: "hello\n", model: "trustedrouter/auto", maxTokens: 200, calls: 1},
		{name: "chat-stream-false", args: []string{"chat", "--stream=false", "hi"}, stdout: "hello\n", model: "trustedrouter/auto", maxTokens: 200, calls: 1},
		{name: "chat-auth", args: []string{"chat", "hi"}, status: 3, stderr: "set TRUSTEDROUTER_API_KEY", httpStatus: 401, calls: 1},
		{name: "chat-stream-auth", args: []string{"chat", "--stream", "hi"}, status: 3, stderr: "set TRUSTEDROUTER_API_KEY", httpStatus: 401, calls: 1},
		{name: "chat-http-error", args: []string{"chat", "hi"}, status: 1, stderr: "HTTP 500", httpStatus: 500, calls: 1},
		{name: "chat-stream-broken", args: []string{"chat", "--stream", "hi"}, status: 1, stderr: "terminal event", response: "data: {}\n\n", calls: 1},
		{name: "retries-one", args: []string{"--retries", "1", "chat", "hi"}, status: 1, stderr: "HTTP 500", httpStatus: 500, calls: 2},
		{name: "models", args: []string{"models"}, jsonShape: map[string]any{"data": []any{map[string]any{"id": "fixture", "architecture": map[string]any{}, "pricing": map[string]any{}, "top_provider": map[string]any{}}}}, calls: 1},
		{name: "providers", args: []string{"providers"}, jsonShape: map[string]any{"data": []any{map[string]any{"id": "fixture"}}}, calls: 1},
		{name: "regions", args: []string{"regions"}, jsonShape: map[string]any{"data": []any{map[string]any{"id": "fixture"}}}, calls: 1},
		{name: "models-error", args: []string{"models"}, httpStatus: 401, status: 1, stderr: "HTTP 401", calls: 1},
		{name: "providers-error", args: []string{"providers"}, httpStatus: 500, status: 1, stderr: "HTTP 500", calls: 1},
		{name: "regions-error", args: []string{"regions"}, httpStatus: 500, status: 1, stderr: "HTTP 500", calls: 1},
		{name: "trust", args: []string{"trust"}, jsonShape: map[string]any{"platform": "fixture", "image_digest": "sha256:fixture"}, tls: true, calls: 1},
		{name: "trust-error", args: []string{"trust"}, httpStatus: 500, status: 1, stderr: "error:", tls: true, calls: 1},
		{name: "attest", args: []string{"attest"}, jsonShape: map[string]any{"document": "fixture"}, calls: 1},
		{name: "attest-error", args: []string{"attest"}, httpStatus: 500, status: 1, stderr: "HTTP 500", calls: 1},
		{name: "attest-help", args: []string{"attest", "--help"}, status: 2, stderr: "Usage of trustedrouter attest"},
		{name: "attest-short-help", args: []string{"attest", "-h"}, status: 2, stderr: "Usage of trustedrouter attest"},
		{name: "attest-invalid-flag", args: []string{"attest", "--oops"}, status: 2, stderr: "flag provided but not defined"},
		{name: "attest-connect-requires-session", args: []string{"attest", "--connect-ip", "127.0.0.1"}, status: 2, stderr: "requires --session"},
		{name: "attest-verify-success", args: []string{"attest", "--verify"}, signed: true, tls: true, calls: 3},
		{name: "attest-session-success", args: []string{"attest", "--session"}, signed: true, tls: true, calls: 4},
		{name: "attest-connect-success", args: []string{"attest", "--session", "--connect-ip", "127.0.0.1"}, signed: true, tls: true, calls: 4},
		{name: "attest-verify", args: []string{"attest", "--verify"}, status: 1, stderr: "JWT", tls: true, calls: 2},
		{name: "attest-session", args: []string{"attest", "--session"}, status: 1, stderr: "JWT", tls: true, calls: 2},
		{name: "attest-session-connect-ip", args: []string{"attest", "--session", "--connect-ip", "127.0.0.1"}, status: 1, stderr: "JWT", tls: true, calls: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			var cert tls.Certificate
			var ca []byte
			var signingKey *rsa.PrivateKey
			var fingerprint string
			expires := time.Now().Add(time.Hour).Unix()
			if tc.tls {
				cert, ca = cliCertificate(t)
				sum := sha256.Sum256(cert.Certificate[0])
				fingerprint = fmt.Sprintf("%x", sum[:])
			}
			if tc.signed {
				var err error
				signingKey, err = rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				if tc.name == "attest-verify-success" {
					tc.jsonShape = map[string]any{"cert_sha256": fingerprint, "image_digest": "sha256:fixture", "image_reference": "fixture/image", "nonce": nil, "expires_at": float64(expires), "issuer": "https://confidentialcomputing.googleapis.com", "audience": "quill-cloud"}
				} else {
					tc.stdoutPattern = "(?s)^JWT ok\nimage_digest ok: sha256:fixture\ncert-fp bound: " + fingerprint + "\nfresh nonce bound: [0-9a-f]{64}\nexporter bound: [0-9a-f]{64}\ndbgstat: disabled-since-boot\npin ok: follow-up stayed on the attested session\n$"
				}
			}
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				isTrust := r.URL.Path == "/trust/gcp-release.json" || strings.Contains(r.URL.Path, "/metadata/jwk/")
				if isTrust && r.Header.Get("Authorization") != "" {
					t.Error("credentials on trust request")
				}
				if !isTrust && r.URL.Path != "/attestation" && r.Header.Get("Authorization") != "Bearer fixture-key" {
					t.Errorf("authorization = %q", r.Header.Get("Authorization"))
				}
				if tc.httpStatus != 0 {
					w.WriteHeader(tc.httpStatus)
					fmt.Fprint(w, `{"error":{"message":"fixture error"}}`)
					return
				}
				if tc.response != "" {
					fmt.Fprint(w, tc.response)
					return
				}
				switch r.URL.Path {
				case "/v1/chat/completions":
					if r.Method != "POST" {
						t.Errorf("method %s", r.Method)
					}
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					if body["model"] != tc.model || body["max_tokens"] != float64(tc.maxTokens) || body["stream"] != true {
						t.Errorf("request body: %#v", body)
					}
					if !reflect.DeepEqual(body["messages"], []any{map[string]any{"role": "user", "content": "hi"}}) {
						t.Errorf("messages: %#v", body["messages"])
					}
					w.Header().Set("Content-Type", "text/event-stream")
					fmt.Fprint(w, "data: {\"id\":\"cli\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hello\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
				case "/v1/models", "/v1/providers", "/v1/regions":
					if r.Method != "GET" {
						t.Errorf("method %s", r.Method)
					}
					fmt.Fprint(w, `{"data":[{"id":"fixture"}]}`)
				case "/trust/gcp-release.json":
					fmt.Fprint(w, `{"platform":"fixture","image_digest":"sha256:fixture"}`)
				case "/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com":
					json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "fixture", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(signingKey.N.Bytes()), "e": "AQAB"}}})
				case "/attestation":
					if !tc.signed {
						fmt.Fprint(w, `{"document":"fixture"}`)
						break
					}
					exporter, err := r.TLS.ExportKeyingMaterial("EXPORTER-Channel-Binding", nil, 32)
					if err != nil {
						t.Error(err)
						return
					}
					claims := map[string]any{"iss": "https://confidentialcomputing.googleapis.com", "aud": "quill-cloud", "exp": expires, "dbgstat": "disabled-since-boot", "swname": "CONFIDENTIAL_SPACE", "secboot": true, "hwmodel": "GCP_AMD_SEV", "eat_nonce": []string{r.URL.Query().Get("nonce"), fmt.Sprintf("%x", exporter)}, "tls_cert_sha256": fingerprint, "submods": map[string]any{"container": map[string]any{"image_digest": "sha256:fixture", "image_reference": "fixture/image"}}}
					header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": "fixture"})
					payload, _ := json.Marshal(claims)
					input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
					digest := sha256.Sum256([]byte(input))
					sig, err := rsa.SignPKCS1v15(rand.Reader, signingKey, crypto.SHA256, digest[:])
					if err != nil {
						t.Error(err)
						return
					}
					fmt.Fprint(w, input+"."+base64.RawURLEncoding.EncodeToString(sig))
				default:
					t.Errorf("unexpected endpoint %s", r.URL)
					http.NotFound(w, r)
				}
			})
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/v1/") && r.URL.Path != "/v1/chat/completions" {
					t.Errorf("control request on inference plane: %s", r.URL.Path)
				}
				handler.ServeHTTP(w, r)
			}))
			var caPath string
			if tc.tls {
				server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
				server.StartTLS()
				caPath = filepath.Join(t.TempDir(), "ca.pem")
				if err := os.WriteFile(caPath, ca, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				server.Start()
			}
			defer server.Close()
			// A second listener proves --control-base-url selects the control plane.
			control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/models" && r.URL.Path != "/v1/providers" && r.URL.Path != "/v1/regions" {
					t.Errorf("inference request on control plane: %s", r.URL.Path)
				}
				handler.ServeHTTP(w, r)
			}))
			defer control.Close()
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "CONNECT" || (r.Host != "trust.trustedrouter.com:443" && r.Host != "www.googleapis.com:443") {
					t.Errorf("unexpected proxy request %s %s", r.Method, r.Host)
					http.Error(w, "blocked", http.StatusBadGateway)
					return
				}
				dst, err := net.Dial("tcp", server.Listener.Addr().String())
				if err != nil {
					t.Error(err)
					return
				}
				defer dst.Close()
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
				done := make(chan struct{})
				go func() { io.Copy(dst, conn); dst.Close(); close(done) }()
				io.Copy(conn, dst)
				conn.Close()
				<-done
			}))
			defer proxy.Close()
			args := append([]string{"--base-url", server.URL + "/v1", "--control-base-url", control.URL + "/v1", "--retries", "0"}, tc.args...)
			executable := plain
			if tc.tls {
				executable = bin
				args = append([]string{"-test.run=^TestArtifactProcess$", "--"}, args...)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, executable, args...)
			var env []string
			for _, value := range os.Environ() {
				key := strings.SplitN(value, "=", 2)[0]
				if key != "TRUSTEDROUTER_API_KEY" && key != "TR_API_KEY" && key != "HTTPS_PROXY" && key != "HTTP_PROXY" && key != "NO_PROXY" && key != "GODEBUG" {
					env = append(env, value)
				}
			}
			key := "TRUSTEDROUTER_API_KEY"
			if tc.fallback {
				key = "TR_API_KEY"
			}
			command.Env = append(env, key+"=fixture-key", "HTTPS_PROXY="+proxy.URL, "HTTP_PROXY="+proxy.URL, "NO_PROXY=", "GODEBUG=x509usefallbackroots=1", "TR_DX_CA="+caPath, "TRUSTEDROUTER_TELEMETRY=0")
			var stdout, stderr bytes.Buffer
			command.Stdout = &stdout
			command.Stderr = &stderr
			err := command.Run()
			if ctx.Err() != nil {
				t.Fatalf("CLI timed out: %s", stderr.String())
			}
			code := 0
			if err != nil {
				exit, ok := err.(*exec.ExitError)
				if !ok {
					t.Fatal(err)
				}
				code = exit.ExitCode()
			}
			wantStatus := tc.status
			wantStdout := tc.stdout
			wantPattern := tc.stdoutPattern
			wantStderr := tc.stderr
			wantJSON := tc.jsonShape
			switch os.Getenv("TR_DX_CLI_MUTATE") {
			case tc.name + ":exit":
				wantStatus = (wantStatus + 1) % 4
			case tc.name + ":shape":
				if wantJSON != nil {
					wantJSON = map[string]any{"wrong_shape": true}
				} else if wantStderr != "" {
					wantStderr = "impossible diagnostic shape"
				} else {
					wantPattern = ""
					wantStdout = "wrong output shape"
				}
			}
			if code != wantStatus {
				t.Errorf("exit = %d, want %d; stderr=%s", code, wantStatus, stderr.String())
			}
			if wantJSON != nil {
				var got map[string]any
				if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
					t.Fatalf("JSON: %v: %s", err, stdout.String())
				}
				if !reflect.DeepEqual(got, wantJSON) {
					t.Errorf("JSON shape = %#v, want %#v", got, wantJSON)
				}
			} else if wantPattern != "" {
				if !regexp.MustCompile(wantPattern).MatchString(stdout.String()) {
					t.Errorf("stdout pattern mismatch: %q", stdout.String())
				}
			} else if stdout.String() != wantStdout {
				t.Errorf("stdout = %q, want %q", stdout.String(), wantStdout)
			}
			if wantStderr == "" {
				if stderr.Len() != 0 {
					t.Errorf("unexpected stderr: %s", stderr.String())
				}
			} else if !strings.Contains(stderr.String(), wantStderr) {
				t.Errorf("stderr = %q, want %q", stderr.String(), wantStderr)
			}
			if got := int(calls.Load()); got != tc.calls {
				t.Errorf("calls = %d, want %d", got, tc.calls)
			}
		})
	}
}

func cliCertificate(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CLI test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"trust.trustedrouter.com", "www.googleapis.com", "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pair, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	if err != nil {
		t.Fatal(err)
	}
	return pair, certPEM
}
