package trustedrouter

import (
	"bufio"
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
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestVerifyGatewaySessionLoopback(t *testing.T) {
	fixture := newAttestationFixture(t)
	cert, roots, leafDER := newGatewaySessionTestCert(t)
	certSHA := sha256Hex(leafDER)
	policy := fixture.policy
	policy.ExpectedCertSHA256 = certSHA

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if localLoopbackListenUnavailable(err) {
			t.Skipf("localhost listeners are not permitted in this sandbox: %v", err)
		}
		t.Fatalf("Listen returned error: %v", err)
	}
	defer listener.Close()

	serverErrors := make(chan error, 8)
	serverExporters := make(chan []byte, 4)
	var signMu sync.Mutex
	go serveGatewaySessionTestTLS(listener, cert, fixture, certSHA, serverExporters, serverErrors, &signMu)

	oldTLSHook := verifyGatewaySessionTLSConfigHook
	verifyGatewaySessionTLSConfigHook = func(config *tls.Config) {
		config.RootCAs = roots
	}
	t.Cleanup(func() {
		verifyGatewaySessionTLSConfigHook = oldTLSHook
	})

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort returned error: %v", err)
	}
	baseURL := "https://localhost:" + port + "/v1"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	session1, err := VerifyGatewaySession(ctx, VerifyGatewaySessionOptions{
		BaseURL:   baseURL,
		Policy:    policy,
		JWKS:      fixture.jwks,
		ConnectIP: "127.0.0.1",
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("VerifyGatewaySession session1 returned error: %v", err)
	}
	defer session1.Conn.Close()
	serverExporter1 := receiveSessionExporter(t, serverExporters)
	if !bytes.Equal(session1.Exporter, serverExporter1) {
		t.Fatalf("session1 exporter = %x, server exporter = %x", session1.Exporter, serverExporter1)
	}
	if !bytes.Equal(session1.LeafDER, leafDER) {
		t.Fatalf("LeafDER mismatch")
	}
	if session1.Attestation.CertSHA256 != certSHA {
		t.Fatalf("CertSHA256 = %q, want %q", session1.Attestation.CertSHA256, certSHA)
	}
	if session1.Attestation.Nonce == nil || *session1.Attestation.Nonce == base16(session1.Exporter) {
		t.Fatalf("Nonce = %#v, want fresh nonce distinct from exporter", session1.Attestation.Nonce)
	}
	if _, err := session1.FetchAttestationAgain(ctx); err != nil {
		t.Fatalf("FetchAttestationAgain returned error: %v", err)
	}

	session2, err := VerifyGatewaySession(ctx, VerifyGatewaySessionOptions{
		BaseURL:   baseURL,
		Policy:    policy,
		JWKS:      fixture.jwks,
		ConnectIP: "127.0.0.1",
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("VerifyGatewaySession session2 returned error: %v", err)
	}
	defer session2.Conn.Close()
	serverExporter2 := receiveSessionExporter(t, serverExporters)
	if !bytes.Equal(session2.Exporter, serverExporter2) {
		t.Fatalf("session2 exporter = %x, server exporter = %x", session2.Exporter, serverExporter2)
	}
	if bytes.Equal(session1.Exporter, session2.Exporter) {
		t.Fatalf("second TLS session reused exporter %x", session2.Exporter)
	}
	assertNoSessionServerError(t, serverErrors)
}

func TestVerifyGatewaySessionRetainsBufferedResponseBytes(t *testing.T) {
	fixture := newAttestationFixture(t)
	cert, roots, leafDER := newGatewaySessionTestCert(t)
	certSHA := sha256Hex(leafDER)
	policy := fixture.policy
	policy.ExpectedCertSHA256 = certSHA

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if localLoopbackListenUnavailable(err) {
			t.Skipf("localhost listeners are not permitted in this sandbox: %v", err)
		}
		t.Fatalf("Listen returned error: %v", err)
	}
	defer listener.Close()

	serverErrors := make(chan error, 4)
	clientClosed := make(chan struct{}, 1)
	extra := []byte("extra bytes after attestation body")
	var signMu sync.Mutex
	go serveGatewaySessionOneShotTestTLS(listener, cert, fixture, certSHA, gatewaySessionOneShotResponse{
		connectionHeader: "keep-alive",
		extra:            extra,
		clientClosed:     clientClosed,
	}, serverErrors, &signMu)

	oldTLSHook := verifyGatewaySessionTLSConfigHook
	verifyGatewaySessionTLSConfigHook = func(config *tls.Config) {
		config.RootCAs = roots
	}
	t.Cleanup(func() {
		verifyGatewaySessionTLSConfigHook = oldTLSHook
	})

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort returned error: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, err := VerifyGatewaySession(ctx, VerifyGatewaySessionOptions{
		BaseURL:   "https://localhost:" + port + "/v1",
		Policy:    policy,
		JWKS:      fixture.jwks,
		ConnectIP: "127.0.0.1",
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("VerifyGatewaySession returned error: %v", err)
	}

	got := make([]byte, len(extra))
	_ = session.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = io.ReadFull(session.Reader(), got)
	_ = session.Conn.SetReadDeadline(time.Time{})
	if err != nil {
		_ = session.Conn.Close()
		t.Fatalf("ReadFull retained reader returned error: %v", err)
	}
	if !bytes.Equal(got, extra) {
		_ = session.Conn.Close()
		t.Fatalf("retained reader bytes = %q, want %q", got, extra)
	}
	_ = session.Conn.Close()
	assertClientClosedSession(t, clientClosed)
	assertNoSessionServerError(t, serverErrors)
}

func TestVerifyGatewaySessionRejectsConnectionCloseResponse(t *testing.T) {
	fixture := newAttestationFixture(t)
	cert, roots, leafDER := newGatewaySessionTestCert(t)
	certSHA := sha256Hex(leafDER)
	policy := fixture.policy
	policy.ExpectedCertSHA256 = certSHA

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if localLoopbackListenUnavailable(err) {
			t.Skipf("localhost listeners are not permitted in this sandbox: %v", err)
		}
		t.Fatalf("Listen returned error: %v", err)
	}
	defer listener.Close()

	serverErrors := make(chan error, 4)
	clientClosed := make(chan struct{}, 1)
	var signMu sync.Mutex
	go serveGatewaySessionOneShotTestTLS(listener, cert, fixture, certSHA, gatewaySessionOneShotResponse{
		connectionHeader: "close",
		clientClosed:     clientClosed,
	}, serverErrors, &signMu)

	oldTLSHook := verifyGatewaySessionTLSConfigHook
	verifyGatewaySessionTLSConfigHook = func(config *tls.Config) {
		config.RootCAs = roots
	}
	t.Cleanup(func() {
		verifyGatewaySessionTLSConfigHook = oldTLSHook
	})

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort returned error: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, err := VerifyGatewaySession(ctx, VerifyGatewaySessionOptions{
		BaseURL:   "https://localhost:" + port + "/v1",
		Policy:    policy,
		JWKS:      fixture.jwks,
		ConnectIP: "127.0.0.1",
		Timeout:   5 * time.Second,
	})
	if err == nil {
		if session != nil {
			_ = session.Conn.Close()
		}
		t.Fatalf("VerifyGatewaySession returned nil error for Connection: close response")
	}
	if !strings.Contains(err.Error(), "Connection: close") {
		t.Fatalf("VerifyGatewaySession error = %v, want Connection: close rejection", err)
	}
	assertClientClosedSession(t, clientClosed)
	assertNoSessionServerError(t, serverErrors)
}

func serveGatewaySessionTestTLS(listener net.Listener, cert tls.Certificate, fixture attestationFixture, certSHA string, exporters chan<- []byte, errors chan<- error, signMu *sync.Mutex) {
	for {
		rawConn, err := listener.Accept()
		if err != nil {
			if !errorsIsClosed(err) {
				errors <- err
			}
			return
		}
		go handleGatewaySessionTestConn(rawConn, cert, fixture, certSHA, exporters, errors, signMu)
	}
}

type gatewaySessionOneShotResponse struct {
	connectionHeader string
	extra            []byte
	clientClosed     chan<- struct{}
}

func serveGatewaySessionOneShotTestTLS(listener net.Listener, cert tls.Certificate, fixture attestationFixture, certSHA string, response gatewaySessionOneShotResponse, errors chan<- error, signMu *sync.Mutex) {
	rawConn, err := listener.Accept()
	if err != nil {
		if !errorsIsClosed(err) {
			errors <- err
		}
		return
	}
	handleGatewaySessionOneShotTestConn(rawConn, cert, fixture, certSHA, response, errors, signMu)
}

func handleGatewaySessionOneShotTestConn(rawConn net.Conn, cert tls.Certificate, fixture attestationFixture, certSHA string, response gatewaySessionOneShotResponse, errors chan<- error, signMu *sync.Mutex) {
	conn := tls.Server(rawConn, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		errors <- err
		return
	}
	state := conn.ConnectionState()
	exporter, err := state.ExportKeyingMaterial(ExporterLabel, nil, ExporterLength)
	if err != nil {
		errors <- err
		return
	}

	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		errors <- err
		return
	}
	_, _ = io.Copy(io.Discard, req.Body)
	_ = req.Body.Close()

	nonce := req.URL.Query().Get("nonce")
	nonces := []string{certSHA, base16(exporter)}
	if nonce != "" {
		nonces = append(nonces, nonce)
	}
	claims := fixture.claims(map[string]any{
		"eat_nonce":       nonces,
		"tls_cert_sha256": certSHA,
		"dbgstat":         "disabled",
	})
	signMu.Lock()
	token, err := mintGatewaySessionTestJWT(fixture, claims)
	signMu.Unlock()
	if err != nil {
		errors <- err
		return
	}
	header := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: %s\r\n\r\n", len(token), response.connectionHeader)
	if _, err := io.WriteString(conn, header); err != nil {
		errors <- err
		return
	}
	if _, err := conn.Write(token); err != nil {
		errors <- err
		return
	}
	if len(response.extra) > 0 {
		if _, err := conn.Write(response.extra); err != nil {
			errors <- err
			return
		}
	}
	if response.clientClosed != nil {
		waitForGatewaySessionClientClose(conn, response.clientClosed, errors)
	}
}

func waitForGatewaySessionClientClose(conn net.Conn, clientClosed chan<- struct{}, errors chan<- error) {
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var buf [1]byte
	_, err := conn.Read(buf[:])
	if err == io.EOF || errorsIsClosed(err) {
		clientClosed <- struct{}{}
		return
	}
	if timeoutErr, ok := err.(net.Error); ok && timeoutErr.Timeout() {
		errors <- fmt.Errorf("timed out waiting for client to close unpinnable session")
		return
	}
	if err != nil {
		errors <- err
		return
	}
	errors <- fmt.Errorf("client wrote to session before closing")
}

func handleGatewaySessionTestConn(rawConn net.Conn, cert tls.Certificate, fixture attestationFixture, certSHA string, exporters chan<- []byte, errors chan<- error, signMu *sync.Mutex) {
	conn := tls.Server(rawConn, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		errors <- err
		return
	}
	state := conn.ConnectionState()
	exporter, err := state.ExportKeyingMaterial(ExporterLabel, nil, ExporterLength)
	if err != nil {
		errors <- err
		return
	}
	exporter = append([]byte(nil), exporter...)
	exporters <- exporter

	reader := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err == io.EOF || strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			errors <- err
			return
		}
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()

		nonce := req.URL.Query().Get("nonce")
		nonces := []string{certSHA, base16(exporter)}
		if nonce != "" {
			nonces = append(nonces, nonce)
		}
		claims := fixture.claims(map[string]any{
			"eat_nonce":       nonces,
			"tls_cert_sha256": certSHA,
			"dbgstat":         "disabled",
		})
		signMu.Lock()
		token, err := mintGatewaySessionTestJWT(fixture, claims)
		signMu.Unlock()
		if err != nil {
			errors <- err
			return
		}
		header := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n", len(token))
		if _, err := io.WriteString(conn, header); err != nil {
			errors <- err
			return
		}
		if _, err := conn.Write(token); err != nil {
			errors <- err
			return
		}
		if req.Close {
			return
		}
	}
}

func newGatewaySessionTestCert(t *testing.T) (tls.Certificate, *x509.CertPool, []byte) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey CA returned error: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TrustedRouter Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate CA returned error: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate CA returned error: %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey leaf returned error: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate leaf returned error: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("ParseCertificate leaf returned error: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	return tls.Certificate{
		Certificate: [][]byte{leafDER, caDER},
		PrivateKey:  leafKey,
		Leaf:        leafCert,
	}, roots, leafDER
}

func mintGatewaySessionTestJWT(fixture attestationFixture, claims map[string]any) ([]byte, error) {
	header := map[string]any{"alg": "RS256", "kid": fixture.kid, "typ": "JWT"}
	headerSegment, err := jwtJSONSegment(header)
	if err != nil {
		return nil, err
	}
	payloadSegment, err := jwtJSONSegment(claims)
	if err != nil {
		return nil, err
	}
	signingInput := headerSegment + "." + payloadSegment
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, fixture.key, crypto.SHA256, digest[:])
	if err != nil {
		return nil, err
	}
	return []byte(signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)), nil
}

func jwtJSONSegment(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func receiveSessionExporter(t *testing.T, exporters <-chan []byte) []byte {
	t.Helper()
	select {
	case exporter := <-exporters:
		return exporter
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server exporter")
		return nil
	}
}

func assertNoSessionServerError(t *testing.T, errors <-chan error) {
	t.Helper()
	select {
	case err := <-errors:
		t.Fatalf("loopback server error: %v", err)
	default:
	}
}

func assertClientClosedSession(t *testing.T, clientClosed <-chan struct{}) {
	t.Helper()
	select {
	case <-clientClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for client to close session")
	}
}

func errorsIsClosed(err error) bool {
	return errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection")
}
