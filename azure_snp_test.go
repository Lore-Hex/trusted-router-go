package trustedrouter

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	sevtest "github.com/google/go-sev-guest/testing"
	"github.com/google/go-sev-guest/verify/trust"
)

type fixtureAMDGetter struct{ cert, crl []byte }

func (g fixtureAMDGetter) Get(u string) ([]byte, error) {
	if strings.HasSuffix(u, "/crl") {
		return g.crl, nil
	}
	if strings.Contains(u, "/vcek/v1/Milan/") {
		return g.cert, nil
	}
	return nil, errors.New("unknown test endorsement URL")
}

func TestRawAMDPolicyAndNoJWTFallback(t *testing.T) {
	p := AzureSNPPolicy{ProductLine: "Milan", Measurement: strings.Repeat("01", 48), HostData: strings.Repeat("02", 32), MinimumTCB: 1, MinimumLaunchTCB: 1}
	for _, change := range []func(*AzureSNPPolicy){func(a *AzureSNPPolicy) { a.ProductLine = "unknown" }, func(a *AzureSNPPolicy) { a.Measurement = "" }, func(a *AzureSNPPolicy) { a.HostData = strings.Repeat("00", 32) }, func(a *AzureSNPPolicy) { a.MinimumLaunchTCB = 0 }, func(a *AzureSNPPolicy) { a.MinimumTCB = 0 }} {
		bad := p
		change(&bad)
		if err := (AttestationPolicy{AzureSNP: &bad}).checkAzureSNPPolicy(); err == nil {
			t.Fatal("invalid policy accepted")
		}
	}
	if err := (AttestationPolicy{AzureSNP: &p, ExpectedImageDigest: "other-policy"}).checkAzureSNPPolicy(); err == nil {
		t.Fatal("mixed policy accepted")
	}
	if _, err := VerifyGatewayAttestation(context.Background(), []byte("header.claims.signature"), VerifyGatewayAttestationOptions{Policy: AttestationPolicy{AzureSNP: &p}, NonceHex: strings.Repeat("ab", 32), TLSExporter: make([]byte, 32), TLSCertDER: []byte{1}}); err == nil {
		t.Fatal("accepted JWT instead of hardware report")
	}
}

func TestRawAMDSignatureSessionWorkloadAndTCB(t *testing.T) {
	now := time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC)
	start := now.Add(-time.Hour)
	builder := sevtest.AmdSignerBuilder{ProductName: "Milan-B1", CSPID: "test", TCB: 1, ArkCreationTime: start, AskCreationTime: start, AsvkCreationTime: start, VcekCreationTime: start, VlekCreationTime: start}
	builder.VcekCustom.Extensions = sevtest.CustomExtensions(kds.TCBParts{BlSpl: 1}, make([]byte, abi.ChipIDSize), "test", "Milan-B1")
	signer, err := builder.TestOnlyCertChain()
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: start, NextUpdate: now.Add(time.Hour)}, signer.Ark, signer.Keys.Ark)
	if err != nil {
		t.Fatal(err)
	}
	kds := fixtureAMDGetter{signer.Vcek.Raw, crl}
	p := AzureSNPPolicy{ProductLine: "Milan", Measurement: strings.Repeat("02", 48), HostData: strings.Repeat("03", 32), MinimumTCB: 1, MinimumLaunchTCB: 1}
	opts := VerifyGatewayAttestationOptions{Policy: AttestationPolicy{AzureSNP: &p}, TLSCertDER: []byte("synthetic TLS cert"), NonceHex: strings.Repeat("04", 32), TLSExporter: bytes.Repeat([]byte{5}, 32)}
	leaf := sha256.Sum256(opts.TLSCertDER)
	var input bytes.Buffer
	input.WriteString("trustedrouter/azure-snp/session/v1\x00")
	input.Write(leaf[:])
	input.Write(bytes.Repeat([]byte{4}, 32))
	input.Write(bytes.Repeat([]byte{5}, 32))
	binding := sha256.Sum256(input.Bytes())
	newReport := func(debug bool) []byte {
		raw := make([]byte, abi.ReportSize)
		binary.LittleEndian.PutUint32(raw, 2)
		binary.LittleEndian.PutUint64(raw[8:], abi.SnpPolicyToBytes(abi.SnpPolicy{Debug: debug}))
		binary.LittleEndian.PutUint32(raw[0x34:], 1)
		for _, offset := range []int{0x38, 0x180, 0x1e0, 0x1f0} {
			binary.LittleEndian.PutUint64(raw[offset:], 1)
		}
		copy(raw[0x50:], binding[:])
		copy(raw[0x90:], bytes.Repeat([]byte{2}, 48))
		copy(raw[0xc0:], bytes.Repeat([]byte{3}, 32))
		r, s, err := signer.Sign(abi.SignedComponent(raw))
		if err != nil {
			t.Fatal(err)
		}
		if err := abi.SetSignature(r, s, raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	run := func(raw []byte, o VerifyGatewayAttestationOptions, at time.Time) error {
		root := &trust.AMDRootCerts{ProductLine: "Milan", ProductCerts: &trust.ProductCerts{Ark: signer.Ark, Ask: signer.Ask}}
		_, err := verifyAzureSNPReport(context.Background(), raw, o, root, kds, at)
		return err
	}
	valid := newReport(false)
	official, err := trust.GetDefaultRootCerts("Milan")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = verifyAzureSNPReport(context.Background(), valid, opts, official, kds, now); err == nil {
		t.Fatal("synthetic endorsement accepted by AMD production roots")
	}
	if err := run(valid, opts, now); err != nil {
		t.Fatalf("%v: %v", err, errors.Unwrap(err))
	}
	tampered := bytes.Clone(valid)
	tampered[0x2a0] ^= 1
	if run(tampered, opts, now) == nil || run(newReport(true), opts, now) == nil || run(valid, opts, now.Add(2*time.Hour)) == nil {
		t.Fatal("invalid hardware evidence accepted")
	}
	for _, change := range []func(*VerifyGatewayAttestationOptions){func(o *VerifyGatewayAttestationOptions) { o.TLSExporter = bytes.Repeat([]byte{1}, 32) }, func(o *VerifyGatewayAttestationOptions) { o.NonceHex = strings.Repeat("aa", 32) }, func(o *VerifyGatewayAttestationOptions) { o.TLSCertDER = []byte{9} }, func(o *VerifyGatewayAttestationOptions) { o.Policy.AzureSNP.HostData = strings.Repeat("aa", 32) }, func(o *VerifyGatewayAttestationOptions) { o.Policy.AzureSNP.Measurement = strings.Repeat("aa", 48) }, func(o *VerifyGatewayAttestationOptions) { o.Policy.AzureSNP.MinimumTCB = 2 }, func(o *VerifyGatewayAttestationOptions) { o.Policy.AzureSNP.MinimumLaunchTCB = 2 }} {
		o := opts
		pp := p
		o.Policy.AzureSNP = &pp
		change(&o)
		if run(valid, o, now) == nil {
			t.Fatal("changed binding, workload, or TCB pin accepted")
		}
	}
}

func TestAzureSessionRefusesDowngradeBeforeRequest(t *testing.T) {
	cert, roots, _ := newGatewaySessionTestCert(t)
	old := verifyGatewaySessionTLSConfigHook
	verifyGatewaySessionTLSConfigHook = func(c *tls.Config) { c.RootCAs = roots }
	t.Cleanup(func() { verifyGatewaySessionTLSConfigHook = old })
	var requests atomic.Int32
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != "GET" || r.URL.Path != "/attestation" || r.URL.Query().Get("format") != "amd-snp-v1" || !digestPin(r.URL.Query().Get("nonce"), 32) || r.Header.Get("Authorization") != "" || r.ContentLength > 0 {
			t.Error("expected only a credential-free nonce challenge")
		}
		w.Header().Set("Content-Length", "3")
		_, _ = w.Write([]byte("jwt"))
	}))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	s.StartTLS()
	defer s.Close()
	zero := 0
	off := false
	client, err := NewClient(Options{BaseURL: strings.Replace(s.URL, "127.0.0.1", "localhost", 1) + "/v1", APIKey: "synthetic", RegionalFailover: &off, MaxRetries: &zero, GatewayPolicy: &AttestationPolicy{AzureSNP: &AzureSNPPolicy{ProductLine: "Milan", Measurement: strings.Repeat("02", 48), HostData: strings.Repeat("03", 32), MinimumTCB: 1, MinimumLaunchTCB: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ChatCompletionsRawStream(context.Background(), ChatRequest{Model: "nyte/trusted"}); err == nil || requests.Load() != 1 {
		t.Fatalf("expected one refused anonymous challenge, got %d requests: %v", requests.Load(), err)
	}
}
