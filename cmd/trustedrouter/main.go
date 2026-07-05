package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	trustedrouter "github.com/Lore-Hex/trusted-router-go"
)

type globalOptions struct {
	baseURL        string
	controlBaseURL string
	retries        int
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(argv []string) int {
	globals, cmd, args, ok := parseGlobal(argv)
	if !ok {
		return 2
	}
	ctx := context.Background()
	switch cmd {
	case "chat":
		return cmdChat(ctx, globals, args)
	case "models", "providers", "regions":
		return cmdList(ctx, globals, cmd)
	case "trust":
		return cmdTrust(ctx)
	case "attest":
		return cmdAttest(ctx, globals, args)
	default:
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n", cmd)
		usage()
		return 2
	}
}

func parseGlobal(argv []string) (globalOptions, string, []string, bool) {
	var opts globalOptions
	opts.retries = 2
	fs := flag.NewFlagSet("trustedrouter", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&opts.baseURL, "base-url", "", "custom API base URL")
	fs.StringVar(&opts.controlBaseURL, "control-base-url", "", "custom control-plane base URL")
	fs.IntVar(&opts.retries, "retries", 2, "auto-retry count for 429/5xx")
	fs.Usage = usage
	if err := fs.Parse(argv); err != nil {
		return opts, "", nil, false
	}
	if fs.NArg() == 0 {
		usage()
		return opts, "", nil, false
	}
	return opts, fs.Arg(0), fs.Args()[1:], true
}

func usage() {
	fmt.Fprintf(os.Stderr, `TrustedRouter CLI v%s

Usage:
  trustedrouter [--base-url URL] [--control-base-url URL] [--retries N] chat [flags] "hello"
  trustedrouter [--base-url URL] [--control-base-url URL] [--retries N] models
  trustedrouter [--base-url URL] [--control-base-url URL] [--retries N] providers
  trustedrouter [--base-url URL] [--control-base-url URL] [--retries N] regions
  trustedrouter trust
  trustedrouter [--base-url URL] [--control-base-url URL] [--retries N] attest [--verify]

Reads bearer from $TRUSTEDROUTER_API_KEY or $TR_API_KEY.
`, trustedrouter.Version)
}

func newClient(opts globalOptions) (*trustedrouter.Client, error) {
	maxRetries := opts.retries
	return trustedrouter.NewClient(trustedrouter.Options{
		APIKey:         bearer(),
		BaseURL:        opts.baseURL,
		ControlBaseURL: opts.controlBaseURL,
		MaxRetries:     &maxRetries,
	})
}

func bearer() string {
	if value := os.Getenv("TRUSTEDROUTER_API_KEY"); value != "" {
		return value
	}
	return os.Getenv("TR_API_KEY")
}

func cmdChat(ctx context.Context, globals globalOptions, argv []string) int {
	fs := flag.NewFlagSet("trustedrouter chat", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	model := trustedrouter.AutoModel
	maxTokens := 200
	stream := false
	fs.StringVar(&model, "model", trustedrouter.AutoModel, "model id")
	fs.StringVar(&model, "m", trustedrouter.AutoModel, "model id")
	fs.IntVar(&maxTokens, "max-tokens", 200, "maximum output tokens")
	fs.BoolVar(&stream, "stream", false, "stream text to stdout")
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	prompt := strings.Join(fs.Args(), " ")
	if prompt == "" {
		fmt.Fprintln(os.Stderr, "error: empty prompt")
		return 2
	}
	client, err := newClient(globals)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	req := trustedrouter.ChatRequest{
		Model:    model,
		Messages: []map[string]any{{"role": "user", "content": prompt}},
		Extra:    map[string]any{"max_tokens": maxTokens},
	}
	if stream {
		for text, err := range client.ChatCompletionsText(ctx, req) {
			if err != nil {
				return printCLIError(err, true)
			}
			fmt.Print(text)
		}
		fmt.Println()
		return 0
	}
	resp, err := client.ChatCompletions(ctx, req)
	if err != nil {
		return printCLIError(err, true)
	}
	content := ""
	if len(resp.Choices) > 0 && resp.Choices[0].Message.Content != nil {
		content = *resp.Choices[0].Message.Content
	}
	fmt.Println(content)
	return 0
}

func cmdList(ctx context.Context, globals globalOptions, name string) int {
	client, err := newClient(globals)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	switch name {
	case "models":
		value, err := client.Models(ctx, nil)
		if err != nil {
			return printCLIError(err, false)
		}
		return printJSON(value)
	case "providers":
		value, err := client.Providers(ctx)
		if err != nil {
			return printCLIError(err, false)
		}
		return printJSON(value)
	case "regions":
		value, err := client.Regions(ctx)
		if err != nil {
			return printCLIError(err, false)
		}
		return printJSON(value)
	default:
		return 2
	}
}

func cmdTrust(ctx context.Context) int {
	release, err := trustedrouter.FetchTrustRelease(ctx, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return printJSON(release)
}

func cmdAttest(ctx context.Context, globals globalOptions, argv []string) int {
	fs := flag.NewFlagSet("trustedrouter attest", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	verify := false
	fs.BoolVar(&verify, "verify", false, "verify against the trust release; TLS-cert binding is fetched over a second connection, so it proves the host presented the attested cert on some connection, not necessarily the doc-serving one")
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	client, err := newClient(globals)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	doc, err := client.Attestation(ctx)
	if err != nil {
		return printCLIError(err, false)
	}
	if !verify {
		_, _ = os.Stdout.Write(doc)
		return 0
	}
	certDER, err := fetchTLSCertDER(ctx, client.BaseURL())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	policy, err := trustedrouter.PolicyFromTrustRelease(ctx, trustedrouter.PolicyFromTrustReleaseOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	result, err := trustedrouter.VerifyGatewayAttestation(ctx, doc, trustedrouter.VerifyGatewayAttestationOptions{
		Policy:     policy,
		TLSCertDER: certDER,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return printJSON(result.AsMap())
}

func fetchTLSCertDER(ctx context.Context, baseURL string) ([]byte, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing host in base URL")
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err := conn.HandshakeContext(dialCtx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificates")
	}
	return state.PeerCertificates[0].Raw, nil
}

func printJSON(value any) int {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	fmt.Println(string(data))
	return 0
}

func printCLIError(err error, authHint bool) int {
	var authErr *trustedrouter.AuthenticationError
	if authHint && errors.As(err, &authErr) {
		fmt.Fprintf(os.Stderr, "error: %v (set TRUSTEDROUTER_API_KEY)\n", err)
		return 3
	}
	var trErr *trustedrouter.Error
	if errors.As(err, &trErr) {
		fmt.Fprintf(os.Stderr, "error: HTTP %d: %v\n", trErr.StatusCode, err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	return 1
}
