# trusted-router-go

Go SDK for TrustedRouter. It provides OpenAI-compatible chat and responses
surfaces on `https://api.trustedrouter.com/v1`, Anthropic-style messages,
Fusion orchestration, control-plane helpers on `https://trustedrouter.com/v1`,
OAuth delegated-key helpers, and gateway attestation verification.

The package also exposes the same stable routing/privacy aliases and five
atomic orchestration builders as the other official SDKs: Synth, Advisor,
Selector, MapReduce, and Subagent.

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

## Privacy and orchestration

Privacy and US provider-jurisdiction requirements are typed provider
preferences and remain hard constraints even when a model is explicit. Use
`EUModel` for the EU-focused routing pool:

```go
request := trustedrouter.ChatRequest{
	Model:    "z-ai/glm-5.2",
	Messages: []map[string]any{{"role": "user", "content": "Review this contract."}},
	Provider: trustedrouter.ConfidentialProvider(),
}
```

Use `FusionTool`, `AdvisorTool`, `SelectorTool`, `MapReduceTool`, or
`SubagentTool` to build custom orchestration. Stable named models and privacy
aliases are exported from `constants.go`.

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

## Domain Failover

`DefaultAPIBaseURL` is one name on one DNS provider, and the domain sits above
every cloud behind it. A zone that stops answering, a registrar lock, or a
resolver handing out a stale record takes the API down no matter how many
regions are healthy.

`AliasAPIBaseURLs` — `api.allyrouter.com` and `api.uptimerouter.com` — are exact
aliases of the primary, on separate domains served by separate DNS providers,
resolving to the same attested enclaves. The client walks them in order after
the primary, so a healthy deployment never touches them. Nothing to configure;
it is on by default.

Failover changes host only on connection failures and on `502`, `503`, or
`504`. A `500` means a server received and processed the request. You are not
charged twice for it — authorization is idempotent per `Idempotency-Key` and
settlement happens once — but the work would run a second time, so the answer
could differ and TrustedRouter pays the provider again. A 500 is retried on the
same host.

Aliases are used only for the default base URL. A custom `Options.BaseURL` — a
private deployment, a test server, a regional pin — is never rewritten. Set
`Options.RegionalFailover` to a pointer to `false` to keep every attempt on a
single host.

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

Standalone trust-release and JWKS retrieval is credential-free: the SDK uses a
fresh private client when none is supplied, never consults `http.DefaultClient`,
does not follow redirects, and ignores a supplied client's cookie jar. Supplied
clients are shallow-cloned and are not mutated. A custom `RoundTripper` is an
explicit caller-owned trust boundary: it runs after the SDK's final credential
header scrub and can still alter the outgoing request.

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
