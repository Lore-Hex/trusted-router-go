package trustedrouter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/validate"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
)

// AzureSNPPolicy pins the reviewed utility VM and the regional container
// enforcement policy. Obtain both independently; never copy them from the
// peer being verified. TCB floors use the packed AMD SEV-SNP ABI encoding.
type AzureSNPPolicy struct {
	// ProductLine is the AMD processor family, for example Milan.
	ProductLine string `json:"product_line"`
	// Measurement is the hex-encoded 48-byte SNP utility-VM launch measurement.
	Measurement string `json:"measurement_sha384"`
	// HostData is the hex-encoded 32-byte digest of the reviewed regional CCE policy.
	HostData string `json:"host_data_sha256"`
	// MinimumTCB is the minimum accepted reported firmware TCB, compared component by component.
	MinimumTCB uint64 `json:"minimum_tcb"`
	// MinimumLaunchTCB is the independently selected minimum firmware TCB at launch.
	MinimumLaunchTCB uint64 `json:"minimum_launch_tcb"`
}

func digestPin(v string, n int) bool {
	b, err := hex.DecodeString(v)
	return err == nil && len(b) == n && !bytes.Equal(b, make([]byte, n))
}

func (p AttestationPolicy) checkAzureSNPPolicy() error {
	a := p.AzureSNP
	if a == nil || p.AllowDebug || p.GCPAudience != "" || p.PinsImageIdentity() {
		return attestationErr("raw AMD verification cannot be combined with GCP or debug policies", nil)
	}
	if _, err := kds.ParseProductLine(a.ProductLine); err != nil {
		return attestationErr("unsupported AMD product line", err)
	}
	if !digestPin(a.Measurement, 48) || !digestPin(a.HostData, 32) || a.MinimumTCB == 0 || a.MinimumLaunchTCB == 0 {
		return attestationErr("raw AMD policy requires explicit UVM, HOST_DATA, reported and launch TCB pins", nil)
	}
	return nil
}

// The SDK never sends gateway headers, credentials or prompts to AMD. Use a
// dedicated client and bind the library's non-contextual CRL lookup to ctx.
var snpKDSClient = &http.Client{
	Transport:     &http.Transport{ResponseHeaderTimeout: 5 * time.Second},
	Timeout:       8 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

type amdKDS struct{ ctx context.Context }

func (g amdKDS) Get(raw string) ([]byte, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != "kdsintf.amd.com" || u.User != nil || !strings.HasPrefix(u.Path, "/vcek/v1/") {
		return nil, fmt.Errorf("unexpected AMD endorsement URL")
	}
	req, err := http.NewRequestWithContext(g.ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := snpKDSClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // Read-only response cleanup.
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AMD KDS returned HTTP %d", resp.StatusCode)
	}
	const max = 1 << 20
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if len(b) > max {
		return nil, fmt.Errorf("AMD KDS response too large")
	}
	return b, nil
}

func verifyAzureSNP(ctx context.Context, doc []byte, opts VerifyGatewayAttestationOptions) (*GatewayAttestation, error) {
	if err := opts.Policy.checkAzureSNPPolicy(); err != nil {
		return nil, err
	}
	root, err := trust.GetDefaultRootCerts(opts.Policy.AzureSNP.ProductLine)
	if err != nil {
		return nil, attestationErr("missing embedded AMD root", err)
	}
	return verifyAzureSNPReport(ctx, doc, opts, root, amdKDS{ctx}, time.Now())
}

func verifyAzureSNPReport(ctx context.Context, doc []byte, opts VerifyGatewayAttestationOptions, root *trust.AMDRootCerts, getter trust.HTTPSGetter, now time.Time) (*GatewayAttestation, error) {
	p := opts.Policy.AzureSNP
	nonce, err := hex.DecodeString(opts.NonceHex)
	if err != nil || len(nonce) != 32 || len(opts.TLSExporter) != 32 || len(opts.TLSCertDER) == 0 || bytes.Equal(nonce, opts.TLSExporter) {
		return nil, attestationErr("raw AMD verification requires distinct nonce and TLS exporter and a leaf certificate", nil)
	}
	leaf := sha256.Sum256(opts.TLSCertDER)
	certHex := hex.EncodeToString(leaf[:])
	if opts.Policy.ExpectedCertSHA256 != "" && !strings.EqualFold(certHex, opts.Policy.ExpectedCertSHA256) {
		return nil, attestationErr("raw AMD TLS leaf pin mismatch", nil)
	}
	if len(doc) != abi.ReportSize {
		return nil, attestationErr("expected exact AMD SEV-SNP binary report (not a JWT)", nil)
	}
	if err := abi.ValidateReportFormat(doc); err != nil {
		return nil, attestationErr("invalid AMD report format", err)
	}
	r, err := abi.ReportToProto(doc)
	if err != nil {
		return nil, attestationErr("invalid AMD report", err)
	}
	info, err := abi.ParseSignerInfo(r.GetSignerInfo())
	if err != nil || info.SigningKey != abi.VcekReportSigner {
		return nil, attestationErr("AMD VCEK endorsement required", err)
	}
	preimage := append([]byte("trustedrouter/azure-snp/session/v1\x00"), leaf[:]...)
	preimage = append(preimage, nonce...)
	h := sha256.Sum256(append(preimage, opts.TLSExporter...))
	var binding [64]byte
	copy(binding[:], h[:])
	host, err := hex.DecodeString(p.HostData)
	if err != nil {
		return nil, err
	}
	measurement, err := hex.DecodeString(p.Measurement)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(r.ReportData, binding[:]) || !bytes.Equal(r.HostData, host) || !bytes.Equal(r.Measurement, measurement) {
		return nil, attestationErr("AMD report does not match the TLS session or selected workload", nil)
	}
	if fms := r.GetCpuid1EaxFms(); fms != 0 && kds.ProductLineFromFms(fms) != p.ProductLine {
		return nil, attestationErr("AMD product line mismatch", nil)
	}
	vcek, err := getter.Get(kds.VCEKCertURL(p.ProductLine, r.ChipId, kds.TCBVersion(r.GetReportedTcb())))
	if err != nil {
		return nil, attestationErr("AMD endorsement unavailable", err)
	}
	a := &spb.Attestation{Report: r, CertificateChain: &spb.CertificateChain{VcekCert: vcek}}
	vo := &verify.Options{Now: now, Getter: getter, CheckRevocations: true, DisableCertFetching: true, TrustedRoots: map[string][]*trust.AMDRootCerts{p.ProductLine: {root}}}
	if err := verify.SnpAttestationContext(ctx, a, vo); err != nil {
		return nil, attestationErr("AMD hardware signature or endorsement failed", err)
	}
	if root.CRL == nil || root.CRL.ThisUpdate.After(now) || !now.Before(root.CRL.NextUpdate) {
		return nil, attestationErr("AMD revocation list not current", nil)
	}
	cert, err := x509.ParseCertificate(vcek)
	if err != nil {
		return nil, attestationErr("invalid VCEK", err)
	}
	if err := verify.SnpReportSignature(doc, cert); err != nil {
		return nil, attestationErr("AMD signature does not cover the received bytes", err)
	}
	for _, entry := range root.CRL.RevokedCertificateEntries {
		if cert.SerialNumber.Cmp(entry.SerialNumber) == 0 {
			return nil, attestationErr("AMD endorsement key revoked", nil)
		}
	}
	vmpl := 0
	if err := validate.SnpAttestation(a, &validate.Options{VMPL: &vmpl, GuestPolicy: abi.SnpPolicy{SMT: true}, ReportData: binding[:], Measurement: measurement, HostData: host, MinimumTCB: kds.DecomposeTCBVersion(kds.TCBVersion(p.MinimumTCB)), MinimumLaunchTCB: kds.DecomposeTCBVersion(kds.TCBVersion(p.MinimumLaunchTCB))}); err != nil {
		return nil, attestationErr("AMD workload or firmware policy failed", err)
	}
	issuer := "AMD SEV-SNP"
	return &GatewayAttestation{Issuer: &issuer, Nonce: &opts.NonceHex, CertSHA256: certHex, RawClaims: map[string]any{"measurement": p.Measurement, "host_data": p.HostData, "product_line": p.ProductLine, "reported_tcb": r.GetReportedTcb(), "launch_tcb": r.GetLaunchTcb()}}, nil
}
