package trustedrouter

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const defaultGatewaySessionTimeout = 15 * time.Second

// VerifyGatewaySessionOptions configures VerifyGatewaySession.
type VerifyGatewaySessionOptions struct {
	// BaseURL is the gateway API base URL, e.g. https://api.trustedrouter.com/v1.
	BaseURL string
	// Policy is the attestation policy to enforce.
	Policy AttestationPolicy
	// JWKS is a pre-fetched JWKS. Nil fetches JWKSURL.
	JWKS map[string]any
	// JWKSURL is fetched when JWKS is nil. Empty uses GCPJWKSURI.
	JWKSURL string
	// HTTPClient is the HTTP client used for JWKS fetches only.
	HTTPClient *http.Client
	// ConnectIP dials this IP while keeping SNI and Host pinned to the BaseURL host.
	ConnectIP string
	// Timeout bounds the dial, attestation fetch, and verification. Empty defaults to 15s.
	Timeout time.Duration
}

// GatewaySession is a verified, pinned gateway TLS session.
type GatewaySession struct {
	Attestation *GatewayAttestation
	// Conn is the live TLS connection whose exporter was committed by Attestation.
	// The caller owns and must close it. Use Reader for reads; it may already
	// hold bytes read ahead while parsing attestation responses.
	Conn *tls.Conn
	// Exporter is the RFC 9266 tls-exporter channel binding for Conn.
	Exporter []byte
	// LeafDER is the DER-encoded peer leaf certificate from Conn.
	LeafDER []byte

	reader          *bufio.Reader
	hostHeader      string
	attestationPath string
	timeout         time.Duration
}

// verifyGatewaySessionTLSConfigHook lets package tests add a local root without
// disabling certificate verification. It is nil in production.
var verifyGatewaySessionTLSConfigHook func(*tls.Config)

// VerifyGatewaySession verifies the G6 attestation bound to a live TLS session.
func VerifyGatewaySession(ctx context.Context, opts VerifyGatewaySessionOptions) (*GatewaySession, error) {
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = defaultGatewaySessionTimeout
	}
	requestCtx, cancel := contextWithDefaultTimeout(ctx, timeout, true)
	defer cancel()

	target, err := parseGatewaySessionTarget(opts.BaseURL, opts.ConnectIP)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		ServerName: target.serverName,
		MinVersion: tls.VersionTLS13,
	}
	if verifyGatewaySessionTLSConfigHook != nil {
		verifyGatewaySessionTLSConfigHook(tlsConfig)
	}
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config:    tlsConfig,
	}
	rawConn, err := dialer.DialContext(requestCtx, "tcp", target.dialAddress)
	if err != nil {
		if ctxErr := requestCtx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	conn, ok := rawConn.(*tls.Conn)
	if !ok {
		_ = rawConn.Close()
		return nil, fmt.Errorf("TLS dial returned %T, want *tls.Conn", rawConn)
	}
	success := false
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificates")
	}
	leafDER := append([]byte(nil), state.PeerCertificates[0].Raw...)
	exporter, err := state.ExportKeyingMaterial(ExporterLabel, nil, ExporterLength)
	if err != nil {
		return nil, err
	}
	exporter = append([]byte(nil), exporter...)

	reader := bufio.NewReader(conn)
	freshNonce, err := randomNonceHex(ExporterLength)
	if err != nil {
		return nil, err
	}
	document, err := fetchAttestationOnConn(requestCtx, conn, reader, target.hostHeader, target.attestationPath, freshNonce, timeout)
	if err != nil {
		return nil, err
	}
	attestation, err := VerifyGatewayAttestation(requestCtx, document, VerifyGatewayAttestationOptions{
		Policy:      opts.Policy,
		NonceHex:    freshNonce,
		TLSCertDER:  leafDER,
		TLSExporter: exporter,
		JWKS:        opts.JWKS,
		JWKSURL:     opts.JWKSURL,
		HTTPClient:  opts.HTTPClient,
	})
	if err != nil {
		return nil, err
	}

	success = true
	return &GatewaySession{
		Attestation:     attestation,
		Conn:            conn,
		Exporter:        exporter,
		LeafDER:         leafDER,
		reader:          reader,
		hostHeader:      target.hostHeader,
		attestationPath: target.attestationPath,
		timeout:         timeout,
	}, nil
}

// Reader returns the retained reader for Conn.
//
// Callers that continue using the pinned stream must read through this reader
// rather than Conn directly, otherwise bytes buffered during attestation
// response parsing can be skipped and the HTTP stream can desynchronize.
func (s *GatewaySession) Reader() *bufio.Reader {
	if s == nil {
		return nil
	}
	return s.reader
}

// FetchAttestationAgain fetches /attestation on the already verified pinned TLS connection.
func (s *GatewaySession) FetchAttestationAgain(ctx context.Context) ([]byte, error) {
	if s == nil || s.Conn == nil || s.reader == nil {
		return nil, fmt.Errorf("nil gateway session")
	}
	timeout := s.timeout
	if timeout == 0 {
		timeout = defaultGatewaySessionTimeout
	}
	return fetchAttestationOnConn(ctx, s.Conn, s.reader, s.hostHeader, s.attestationPath, "", timeout)
}

type gatewaySessionTarget struct {
	serverName      string
	hostHeader      string
	dialAddress     string
	attestationPath string
}

func parseGatewaySessionTarget(baseURL string, connectIP string) (gatewaySessionTarget, error) {
	if baseURL == "" {
		baseURL = DefaultAPIBaseURL
	}
	root := strings.TrimRight(baseURL, "/")
	root = strings.TrimSuffix(root, "/v1")
	parsed, err := url.Parse(root)
	if err != nil {
		return gatewaySessionTarget{}, err
	}
	if parsed.Scheme != "https" {
		return gatewaySessionTarget{}, fmt.Errorf("gateway session requires https base URL")
	}
	if parsed.User != nil {
		return gatewaySessionTarget{}, fmt.Errorf("gateway session base URL must not contain userinfo")
	}
	serverName := parsed.Hostname()
	if serverName == "" {
		return gatewaySessionTarget{}, fmt.Errorf("missing host in base URL")
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	dialHost := serverName
	if connectIP != "" {
		dialHost = connectIP
	}
	hostHeader := parsed.Host
	if hostHeader == "" {
		hostHeader = serverName
	}

	path := parsed.EscapedPath()
	if path == "" || path == "/" {
		path = "/attestation"
	} else {
		path = strings.TrimRight(path, "/") + "/attestation"
	}
	return gatewaySessionTarget{
		serverName:      serverName,
		hostHeader:      hostHeader,
		dialAddress:     net.JoinHostPort(dialHost, port),
		attestationPath: path,
	}, nil
}

func randomNonceHex(length int) (string, error) {
	nonce := make([]byte, length)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return hex.EncodeToString(nonce), nil
}

func fetchAttestationOnConn(ctx context.Context, conn *tls.Conn, reader *bufio.Reader, hostHeader string, attestationPath string, nonceHex string, timeout time.Duration) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if reader == nil {
		return nil, fmt.Errorf("nil gateway session reader")
	}
	clearDeadline := setConnContextDeadline(ctx, conn, timeout)
	defer clearDeadline()

	target := attestationPath
	if nonceHex != "" {
		target += "?nonce=" + url.QueryEscape(nonceHex)
	}
	request := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: keep-alive\r\n\r\n", target, hostHeader, userAgent())
	n, err := io.WriteString(conn, request)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	if n != len(request) {
		return nil, io.ErrShortWrite
	}

	resp, err := readGatewaySessionHTTPResponse(reader)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	if err := requireGatewaySessionKeepAlive(resp); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if resp.statusCode != http.StatusOK {
		return nil, fmt.Errorf("attestation returned HTTP %d: %s", resp.statusCode, truncateString(string(resp.body), 240))
	}
	return resp.body, nil
}

type gatewaySessionHTTPResponse struct {
	proto      string
	protoMajor int
	protoMinor int
	statusCode int
	header     http.Header
	body       []byte
}

func readGatewaySessionHTTPResponse(reader *bufio.Reader) (*gatewaySessionHTTPResponse, error) {
	textReader := textproto.NewReader(reader)
	statusLine, err := textReader.ReadLine()
	if err != nil {
		return nil, err
	}
	proto, status, ok := strings.Cut(statusLine, " ")
	if !ok {
		return nil, fmt.Errorf("malformed attestation HTTP status line: %q", statusLine)
	}
	protoMajor, protoMinor, ok := http.ParseHTTPVersion(proto)
	if !ok || protoMajor != 1 || protoMinor > 1 {
		return nil, fmt.Errorf("unsupported attestation HTTP version: %q", proto)
	}
	statusCodeText, _, _ := strings.Cut(status, " ")
	if len(statusCodeText) != 3 {
		return nil, fmt.Errorf("malformed attestation HTTP status code: %q", statusCodeText)
	}
	statusCode, err := strconv.Atoi(statusCodeText)
	if err != nil {
		return nil, fmt.Errorf("malformed attestation HTTP status code: %q", statusCodeText)
	}

	mimeHeader, err := textReader.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	header := http.Header(mimeHeader)
	contentLength, err := gatewaySessionContentLength(header)
	if err != nil {
		return nil, err
	}
	if transferEncoding := strings.TrimSpace(header.Get("Transfer-Encoding")); transferEncoding != "" && !strings.EqualFold(transferEncoding, "identity") {
		return nil, fmt.Errorf("attestation response has unsupported Transfer-Encoding %q", transferEncoding)
	}

	// Read only the declared body bytes from the retained reader. Any read-ahead
	// bytes stay buffered for the caller instead of being stranded in a throwaway
	// response reader.
	body := make([]byte, int(contentLength))
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	return &gatewaySessionHTTPResponse{
		proto:      proto,
		protoMajor: protoMajor,
		protoMinor: protoMinor,
		statusCode: statusCode,
		header:     header,
		body:       body,
	}, nil
}

func gatewaySessionContentLength(header http.Header) (int64, error) {
	values := header.Values("Content-Length")
	if len(values) == 0 {
		return 0, fmt.Errorf("attestation response missing Content-Length")
	}
	var contentLength int64 = -1
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				return 0, fmt.Errorf("invalid attestation Content-Length %q", value)
			}
			parsed, err := strconv.ParseInt(part, 10, 64)
			if err != nil || parsed < 0 {
				return 0, fmt.Errorf("invalid attestation Content-Length %q", part)
			}
			if contentLength >= 0 && contentLength != parsed {
				return 0, fmt.Errorf("conflicting attestation Content-Length values")
			}
			contentLength = parsed
		}
	}
	if contentLength < 0 {
		return 0, fmt.Errorf("attestation response missing Content-Length")
	}
	if contentLength > int64(int(^uint(0)>>1)) {
		return 0, fmt.Errorf("attestation response too large")
	}
	return contentLength, nil
}

func requireGatewaySessionKeepAlive(resp *gatewaySessionHTTPResponse) error {
	hasClose, hasKeepAlive := gatewaySessionConnectionTokens(resp.header)
	if hasClose {
		return fmt.Errorf("attestation response unpinnable: server sent Connection: close")
	}
	if resp.protoMajor == 1 && resp.protoMinor == 0 && !hasKeepAlive {
		return fmt.Errorf("attestation response unpinnable: HTTP/1.0 response without Connection: keep-alive")
	}
	return nil
}

func gatewaySessionConnectionTokens(header http.Header) (hasClose bool, hasKeepAlive bool) {
	for _, value := range header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			switch strings.ToLower(strings.TrimSpace(token)) {
			case "close":
				hasClose = true
			case "keep-alive":
				hasKeepAlive = true
			}
		}
	}
	return hasClose, hasKeepAlive
}

func setConnContextDeadline(ctx context.Context, conn net.Conn, timeout time.Duration) func() {
	deadline := time.Time{}
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	if ctxDeadline, ok := ctx.Deadline(); ok && (deadline.IsZero() || ctxDeadline.Before(deadline)) {
		deadline = ctxDeadline
	}
	if !deadline.IsZero() {
		_ = conn.SetDeadline(deadline)
	}

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-done:
		}
	}()
	return func() {
		close(done)
		_ = conn.SetDeadline(time.Time{})
	}
}
