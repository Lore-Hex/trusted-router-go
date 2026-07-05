# trusted-router-go

Go SDK for TrustedRouter. It provides OpenAI-compatible chat and responses
surfaces on `https://api.trustedrouter.com/v1`, Anthropic-style messages,
Fusion orchestration, control-plane helpers on `https://trustedrouter.com/v1`,
OAuth delegated-key helpers, and gateway attestation verification.

## Install

```sh
go get github.com/Lore-Hex/trusted-router-go
```

## Quickstart

```go
package main

import (
	"context"
	"fmt"
	"os"

	trustedrouter "github.com/Lore-Hex/trusted-router-go"
)

func main() {
	ctx := context.Background()
	client, err := trustedrouter.NewClient(trustedrouter.Options{
		APIKey: os.Getenv("TRUSTEDROUTER_API_KEY"),
	})
	if err != nil {
		panic(err)
	}

	resp, err := client.ChatCompletions(ctx, trustedrouter.ChatRequest{
		Model: trustedrouter.AutoModel,
		Messages: []map[string]any{
			{"role": "user", "content": "Say hello in one sentence."},
		},
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(*resp.Choices[0].Message.Content)
}
```

Streaming text:

```go
for text, err := range client.ChatCompletionsText(ctx, trustedrouter.ChatRequest{
	Model: trustedrouter.FastModel,
	Messages: []map[string]any{
		{"role": "user", "content": "Write a short haiku."},
	},
}) {
	if err != nil {
		panic(err)
	}
	fmt.Print(text)
}
```

Fusion:

```go
strategy := trustedrouter.SelectionStrategySynthesizeNonRefusals
resp, err := client.Fusion(ctx, trustedrouter.FusionRequest{
	Messages: []map[string]any{
		{"role": "user", "content": "Compare SQLite and Postgres for a small SaaS."},
	},
	AnalysisModels:     trustedrouter.FusionFreedomPanel,
	FallbackJudges:     trustedrouter.FusionFreedomFallbackJudges,
	SelectionStrategy:  &strategy,
})
```

Messages:

```go
maxTokens := 512
msg, err := client.Messages(ctx, trustedrouter.MessagesRequest{
	Model: "anthropic/claude-sonnet-4",
	Messages: []map[string]any{
		{"role": "user", "content": "Summarize this SDK."},
	},
	MaxTokens: &maxTokens,
})
```

## Routing And Models

Core constants:

- `DefaultAPIBaseURL`, `DefaultControlBaseURL`, `DefaultTrustReleaseURL`, `DefaultStatusURL`
- `AutoModel`, `FastModel`, `FusionModel`, `AdvisorModel`
- `FusionFreedomPanel`, `FusionFreedomFallbackJudges`, `FusionFreedomFallbackFinals`

Inference methods use `DefaultAPIBaseURL` by default. Regional failover is on
by default and re-requests `api.trustedrouter.com`, which is a global load
balancer; per-region API hostnames are not used. Pass `BaseURL` for a
custom/self-hosted inference endpoint.

Control-plane methods (`Models`, `Providers`, `Regions`, `Credits`, auth,
OAuth key exchange, broadcast destinations, billing checkout, and activity)
use `DefaultControlBaseURL` and do not participate in regional inference
failover. Pass `ControlBaseURL` to override that plane.

## Errors

HTTP failures return typed errors that unwrap to `*trustedrouter.Error`:

```go
var rate *trustedrouter.RateLimitError
if errors.As(err, &rate) {
	fmt.Println("retry after", rate.RetryAfter)
}

var trErr *trustedrouter.Error
if errors.As(err, &trErr) {
	fmt.Println(trErr.StatusCode, trErr.Payload)
}
```

## Timeouts

`Options.Timeout` defaults to `DefaultRequestTimeout` per attempt. Set a
pointer to `0` to disable SDK timeouts. `CallOptions.Timeout` overrides a
single call. Non-streaming retries get a fresh per-attempt timeout. Streaming
calls use the timeout to open response headers, then as the idle gap between
chunks, not as a total stream lifetime. `Fusion` defaults to
`DefaultFusionTimeout` unless you override it.

## OAuth Loopback

```go
loopback, err := trustedrouter.StartOAuthLoopback(trustedrouter.OAuthLoopbackOptions{})
if err != nil {
	panic(err)
}
defer loopback.Close()

auth, err := client.CreateOAuthAuthorization(trustedrouter.CreateOAuthAuthorizationOptions{
	CallbackURL: loopback.CallbackURL(),
	KeyLabel:    "desktop app",
})
if err != nil {
	panic(err)
}
fmt.Println("open:", auth.URL)

callback, err := loopback.Wait(ctx)
if err != nil {
	panic(err)
}
token, err := client.ExchangeOAuthKey(ctx, trustedrouter.OAuthKeyExchangeRequest{
	Code:                callback.Code,
	CodeVerifier:        auth.CodeVerifier,
	CodeChallengeMethod: auth.CodeChallengeMethod,
})
```

## Attestation Verification

```go
doc, err := client.Attestation(ctx)
if err != nil {
	panic(err)
}
policy, err := trustedrouter.PolicyFromTrustRelease(ctx, trustedrouter.PolicyFromTrustReleaseOptions{})
if err != nil {
	panic(err)
}

// tlsCertDER must be the DER bytes of the live gateway TLS leaf certificate.
att, err := trustedrouter.VerifyGatewayAttestation(ctx, doc, trustedrouter.VerifyGatewayAttestationOptions{
	Policy:     policy,
	TLSCertDER: tlsCertDER,
})
if err != nil {
	var verifyErr *trustedrouter.AttestationVerificationError
	if errors.As(err, &verifyErr) {
		panic(verifyErr)
	}
	panic(err)
}
fmt.Println(att.AsMap())
```

The `trustedrouter attest --verify` CLI command performs the TLS certificate
fetch and full verification flow.

## CLI

```sh
TRUSTEDROUTER_API_KEY=sk-tr-v1-... trustedrouter chat "hello"
trustedrouter --control-base-url https://trustedrouter.com/v1 providers
trustedrouter trust
trustedrouter attest --verify
```

`TR_API_KEY` is accepted as the same fallback env var as the Python SDK.

## Parity

See [PARITY.md](./PARITY.md) for symbol-by-symbol parity with the sibling SDKs:

- `trusted-router-py`
- `trusted-router-js`
- `trusted-router-swift`

Licensed under Apache-2.0. See [LICENSE](./LICENSE).
