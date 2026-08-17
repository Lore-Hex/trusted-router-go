# TrustedRouter Go SDK Parity

This document maps the public TrustedRouter JS declarations in
`.reference/trusted-router-js/src/index.d.ts` and the public Python
`client.py`, `oauth.py`, and `attestation.py` surfaces to Go. `parity_test.go`
touches every Go symbol named here so removals fail at compile time.

## Two-plane routing (intentional divergence from the reference SDKs)

The Go SDK intentionally splits traffic between the attested inference plane
and the TrustedRouter control plane. This is a production-correctness fix that
the older reference SDKs predate: the attested `api.trustedrouter.com/v1` plane
serves inference routes only, while `trustedrouter.com/v1` serves control
routes.

Inference-plane methods use `DefaultAPIBaseURL` or a configured `BaseURL`:
`Request`, `RawRequest`, `ChatCompletions`, `ChatCompletionsChunks`,
`ChatCompletionsText`, `ChatCompletionsRawStream`, `Fusion`, `Embeddings`,
`Messages`, `Responses`, `ResponsesEvents`, `ResponsesRawStream`,
`ResponsesInputTokens`, and `Attestation`.

Regional failover intentionally diverges from older reference SDKs: production
uses `api.trustedrouter.com` as a global load balancer, so the Go SDK
re-requests the apex instead of constructing per-region API hostnames.

## Stream-open retry semantics (aligned with trusted-router-py)

Buffered and streaming-open requests run through the SAME transport engine
(`transport.go do()`), so stream opens carry the full retry/failover
semantics of the buffered path. This matches trusted-router-py's landed
behavior, where all four request drivers share one sans-IO retry controller.
Concretely, a stream open now:

- consults `retryable()` and the `x-should-retry` verdict (previously a 429
  or an `x-should-retry: true` was NOT retried on stream open, and an
  `x-should-retry: false` was only honored by accident of the failover-status
  gate) — `TestALabelledSpent502IsNotRetriedOnStreamOpen`,
  `TestALabelledRetryableStatusIsRetriedOnStreamOpen`;
- walks the candidate list on failoverable statuses and transport errors
  (previously pinned to `baseURLs[0]` forever) —
  `TestStreamOpenWalksCandidatesAndHonorsRetryAfter`,
  `TestRegionalFailoverAndChatIdempotency`;
- honors `retry-after`/`retry-after-ms` as the backoff floor —
  `TestStreamOpenWalksCandidatesAndHonorsRetryAfter`;
- retries in place when `RegionalFailover` is disabled (previously a pinned
  client's failed stream open returned immediately: transport retry was
  wrongly gated on the failover flag) — `TestPinnedStreamRetriesInPlace`.

Divergence from trusted-router-py held constant on purpose: py gates the
streaming transport-error ADVANCE on `regional_failover`; Go gates the same
advance on the engine's failover flag (`spec.failover`). Both satisfy
"the failover flag governs WHERE, never WHETHER" through their own mechanism.
Retries still happen only before any body bytes are surfaced: a broken OPEN
stream propagates and never reconnects.

Control-plane methods use `DefaultControlBaseURL`: `Models`, `Providers`,
`Regions`, `Credits`, `BroadcastDestinations`, `CreateBroadcastDestination`,
`GetBroadcastDestination`, `UpdateBroadcastDestination`,
`DeleteBroadcastDestination`, `TestBroadcastDestination`, `BillingCheckout`,
`StablecoinCheckout`, `AuthSession`, `Logout`, `UserInfo`, `Activity`,
`OAuthAuthorizeURL`, `CreateOAuthAuthorization`, and `ExchangeOAuthKey`.
`Status`, `TrustRelease`, and `FetchTrustRelease` fetch their configured
absolute metadata URLs rather than either `/v1` plane.

## JS `index.d.ts`

| JS symbol | Go symbol | Notes |
| --- | --- | --- |
| `VERSION` | `Version` | Package version constant. |
| `DEFAULT_API_BASE_URL` | `DefaultAPIBaseURL` | Intentional divergence: default host updated to `api.trustedrouter.com`; see the two-plane note. |
| `DEFAULT_CONTROL_BASE_URL` | `DefaultControlBaseURL` | Go-only (no reference equivalent; see two-plane note). |
| `DEFAULT_TRUST_RELEASE_URL` | `DefaultTrustReleaseURL` | Same value. |
| `DEFAULT_STATUS_URL` | `DefaultStatusURL` | Same value. |
| `AUTO_MODEL` | `AutoModel` | Same value. |
| `FAST_MODEL` | `FastModel` | Same value. |
| `FUSION_MODEL` | `FusionModel` | Same value. |
| `ADVISOR_MODEL` | `AdvisorModel` | Same value. |
| `FUSION_FREEDOM_PANEL` | `FusionFreedomPanel` | Same model list. |
| `FUSION_FREEDOM_FALLBACK_JUDGES` | `FusionFreedomFallbackJudges` | Same judge list. |
| `REGION_HOSTS` | N/A | Per-region API hostnames were removed; `api.trustedrouter.com` is the global load balancer. |
| `DEFAULT_FAILOVER_REGIONS` | N/A | Failover re-requests the apex instead of walking a region list. |
| `regionBaseUrl` | N/A | Per-region API hostnames were removed. |
| `FusionSelectionStrategy` | `SelectionStrategySynthesize`, `SelectionStrategySynthesizeNonRefusals`, `SelectionStrategyFirstSuccess`, `SelectionStrategyFirstNonRefusal` | Go exposes constants for the literal set. |
| `FusionToolOptions` | `FusionToolOptions` | Field names are Go idiomatic. |
| `FusionTool` | `map[string]any` from `FusionTool` | Go returns the JSON tool spec directly. |
| `fusionTool` | `FusionTool` | Same JSON shape. |
| `AdvisorToolOptions` | `AdvisorToolOptions` | Field names are Go idiomatic. |
| `AdvisorTool` | `map[string]any` from `AdvisorTool` | Go returns the JSON tool spec directly. |
| `advisorTool` | `AdvisorTool` | Same JSON shape. |
| `selectorTool` | `SelectorTool` | Same JSON shape. |
| `mapReduceTool` | `MapReduceTool` | Same JSON shape. |
| `subagentTool` | `SubagentTool` | Same JSON shape. |
| `ProviderPreferences` | `ProviderPreferences` | Hard ZDR, confidential, US, provider allow/deny/order, billing-source, quantization, fallback, and sort controls. EU routing uses `EUModel`. |
| `TrustedRouterError` | `Error` | Base typed SDK error. |
| `BadRequestError` | `BadRequestError` | Same HTTP class. |
| `AuthenticationError` | `AuthenticationError` | Same HTTP class. |
| `PermissionDeniedError` | `PermissionDeniedError` | Same HTTP class. |
| `NotFoundError` | `NotFoundError` | Same HTTP class. |
| `EndpointNotSupportedError` | `EndpointNotSupportedError` | Same HTTP class. |
| `RateLimitError` | `RateLimitError` | Includes `RetryAfter`. |
| `InternalError` | `InternalError` | Same HTTP class. |
| `TrustedRouterHeaders` | N/A | Go uses `http.Header`/`map[string]string`. |
| `TrustedRouterFetch` | N/A | Go uses `*http.Client`. |
| `TrustedRouterOptions` | `Options` | Constructor options. |
| `PerCallOptions` | `CallOptions` | Per-call overrides. |
| `RequestOptions` | `CallOptions` plus `Request`/`RawRequest` args | Go separates method/path/body from options. |
| `ModelListOptions` | `ModelListOptions` | Same filters. |
| `ChatMessage` | `ChatMessage` | Typed response message. Request messages remain `[]map[string]any`. |
| `ChatChoice` | `ChatChoice` | Same response role. |
| `ChatUsage` | `ChatUsage` | Same usage fields. |
| `ChatCompletion` | `ChatCompletion` | Same collected chat shape. |
| `ChatCompletionChunk` | `ChatCompletionChunk`, `ChatChoiceChunk`, `ChatChoiceDelta` | Go exposes nested chunk structs. |
| `ChatRequest` | `ChatRequest` | Same request surface with Go field names. |
| `FusionRequest` | `FusionRequest` | Same Fusion helper surface. |
| `EmbeddingsRequest` | `EmbeddingsRequest` | Same embeddings body. |
| `MessagesRequest` | `MessagesRequest` | Same Anthropic-style body. |
| `ResponsesRequest` | `ResponsesRequest` | Same Responses body. |
| `ResponseObject` | `ResponseObject` | Same top-level Responses result. |
| `ResponseInputTokens` | `ResponseInputTokens` | Same token count result. |
| `BroadcastDestinationRequest` | `BroadcastDestinationRequest` | Same create/update body surface. |
| `BillingCheckoutRequest` | `BillingCheckoutRequest` | Same checkout body surface. |
| `OAuthPkcePair` | `OAuthPkcePair` | Same PKCE fields. |
| `OAuthAuthorizeUrlOptions` | `OAuthAuthorizeURLOptions`, `OAuthAuthorizeUrlOptions` | Go keeps an alias for JS-style casing. |
| `CreateOAuthAuthorizationOptions` | `CreateOAuthAuthorizationOptions` | Same flow options. |
| `OAuthAuthorization` | `OAuthAuthorization` | Same authorize result. |
| `OAuthKeyExchangeRequest` | `OAuthKeyExchangeRequest` | Same exchange body. |
| `OAuthKeyExchangeResponse` | `OAuthKeyExchangeResponse` | Same exchange result. |
| `OAuthIdentity` | `OAuthIdentity` | Same identity fields. |
| `UserInfoData` | `UserInfoData` | Same userinfo data fields. |
| `UserInfoResponse` | `UserInfoResponse` | Same userinfo envelope. |
| `TrustedRouter` constructor | `NewClient` | Go is sync with `context.Context`. |
| `TrustedRouter.apiKey` | `Client.APIKey` | Accessor instead of public field. |
| `TrustedRouter.baseUrl` | `Client.BaseURL` | Accessor instead of public field. |
| `TrustedRouter.controlBaseUrl` | `Client.ControlBaseURL` | Accessor instead of public field. |
| `TrustedRouter.region` | N/A | Per-region API hostnames were removed. |
| `TrustedRouter.fetch` | N/A | Go uses `Options.HTTPClient`. |
| `TrustedRouter.defaultHeaders` | `Client.DefaultHeaders` | Accessor returns a copy. |
| `TrustedRouter.maxRetries` | `Client.MaxRetries` | Accessor instead of public field. |
| `TrustedRouter.baseUrls` | `Client.BaseURLs` | Accessor returns a copy. |
| `TrustedRouter.request` | `Client.Request` | Same low-level JSON request role. |
| `TrustedRouter.rawRequest` | `Client.RawRequest` | Same raw response role. |
| `TrustedRouter.chatCompletions` | `Client.ChatCompletions` | Collected chat completion. |
| `TrustedRouter.chatCompletionsChunks` | `Client.ChatCompletionsChunks` | Parsed chunk iterator. |
| `TrustedRouter.chatCompletionsText` | `Client.ChatCompletionsText` | Text iterator. |
| `TrustedRouter.chatCompletionsRawStream` | `Client.ChatCompletionsRawStream` | Raw SSE stream. |
| `TrustedRouter.fusion` | `Client.Fusion` | Fusion helper. |
| `TrustedRouter.models` | `Client.Models` | Model catalog via control base. |
| `TrustedRouter.providers` | `Client.Providers` | Provider catalog via control base. |
| `TrustedRouter.regions` | `Client.Regions` | Region catalog via control base. |
| `TrustedRouter.credits` | `Client.Credits` | Credits endpoint via control base. |
| `TrustedRouter.embeddings` | `Client.Embeddings` | Embeddings endpoint. |
| `TrustedRouter.messages` | `Client.Messages` | Anthropic Messages endpoint. |
| `TrustedRouter.responses` | `Client.Responses` | OpenAI Responses endpoint. |
| `TrustedRouter.responsesEvents` | `Client.ResponsesEvents` | Parsed Responses events. |
| `TrustedRouter.responsesRawStream` | `Client.ResponsesRawStream` | Raw Responses stream. |
| `TrustedRouter.responsesInputTokens` | `Client.ResponsesInputTokens` | Responses token counting. |
| `TrustedRouter.broadcastDestinations` | `Client.BroadcastDestinations` | Broadcast destination list via control base. |
| `TrustedRouter.createBroadcastDestination` | `Client.CreateBroadcastDestination` | Broadcast destination create via control base. |
| `TrustedRouter.getBroadcastDestination` | `Client.GetBroadcastDestination` | Broadcast destination get via control base. |
| `TrustedRouter.updateBroadcastDestination` | `Client.UpdateBroadcastDestination` | Broadcast destination patch via control base. |
| `TrustedRouter.deleteBroadcastDestination` | `Client.DeleteBroadcastDestination` | Broadcast destination delete via control base. |
| `TrustedRouter.testBroadcastDestination` | `Client.TestBroadcastDestination` | Broadcast destination test via control base. |
| `TrustedRouter.status` | `Client.Status` | Status document fetch. |
| `TrustedRouter.billingCheckout` | `Client.BillingCheckout` | Checkout endpoint via control base. |
| `TrustedRouter.stablecoinCheckout` | `Client.StablecoinCheckout` | Stablecoin convenience wrapper via control base. |
| `TrustedRouter.authSession` | `Client.AuthSession` | Auth session endpoint via control base. |
| `TrustedRouter.logout` | `Client.Logout` | Logout endpoint via control base. |
| `TrustedRouter.userInfo` | `Client.UserInfo` | Userinfo endpoint via control base. |
| `TrustedRouter.oauthAuthorizeUrl` | `Client.OAuthAuthorizeURL` | Authorize URL builder derived from control base. |
| `TrustedRouter.createOAuthAuthorization` | `Client.CreateOAuthAuthorization` | PKCE/state authorize helper. |
| `TrustedRouter.exchangeOAuthKey` | `Client.ExchangeOAuthKey` | Key exchange endpoint via control base. |
| `TrustedRouter.activity` | `Client.Activity` | Activity endpoint via control base. |
| `TrustedRouter.attestation` | `Client.Attestation` | Raw attestation JWT. |
| `TrustedRouter.trustRelease` | `Client.TrustRelease` | Trust-release fetch. |
| `fetchTrustRelease` | `FetchTrustRelease` | Package-level trust-release fetch. |
| `trustRelease` | `FetchTrustRelease` | JS alias maps to same Go helper. |
| `randomOAuthState` | `RandomOAuthState` | State token helper. |
| `createOAuthPkcePair` | `CreateOAuthPkcePair` | PKCE helper. |
| `collectCompletion` | `CollectCompletion` | Chat chunk collector. |

## Python `client.py`, `oauth.py`, `attestation.py`

| Python symbol | Go symbol | Notes |
| --- | --- | --- |
| `DEFAULT_API_BASE_URL` | `DefaultAPIBaseURL` | Intentional divergence: default host updated to `api.trustedrouter.com`; see the two-plane note. |
| `DEFAULT_CONTROL_BASE_URL` | `DefaultControlBaseURL` | Go-only (no reference equivalent; see two-plane note). |
| `DEFAULT_TRUST_RELEASE_URL` | `DefaultTrustReleaseURL` | Same value. |
| `DEFAULT_STATUS_URL` | `DefaultStatusURL` | Same value. |
| `DEFAULT_REQUEST_TIMEOUT_SECONDS` | `DefaultRequestTimeout` | Go uses `time.Duration`. |
| `DEFAULT_FUSION_TIMEOUT_SECONDS` | `DefaultFusionTimeout` | Go uses `time.Duration`. |
| `AUTO_MODEL` | `AutoModel` | Same value. |
| `FAST_MODEL` | `FastModel` | Same value. |
| `FUSION_MODEL` | `FusionModel` | Same value. |
| `ADVISOR_MODEL` | `AdvisorModel` | Same value. |
| `FUSION_FREEDOM_PANEL` | `FusionFreedomPanel` | Same list. |
| `FUSION_FREEDOM_FALLBACK_JUDGES` | `FusionFreedomFallbackJudges` | Same list. |
| `FUSION_FREEDOM_FALLBACK_FINALS` | `FusionFreedomFallbackFinals` | Same list. |
| `REGION_HOSTS` | N/A | Per-region API hostnames were removed; `api.trustedrouter.com` is the global load balancer. |
| `DEFAULT_FAILOVER_REGIONS` | N/A | Failover re-requests the apex instead of walking a region list. |
| `region_base_url` | N/A | Per-region API hostnames were removed. |
| `fusion_tool` | `FusionTool` | Same JSON shape. |
| `advisor_tool` | `AdvisorTool` | Same JSON shape. |
| `selector_tool` | `SelectorTool` | Same JSON shape. |
| `map_reduce_tool` | `MapReduceTool` | Same JSON shape. |
| `subagent_tool` | `SubagentTool` | Same JSON shape. |
| `ProviderPreferences` | `ProviderPreferences` | Same hard routing and privacy constraints. |
| `TrustedRouterError` | `Error` | Base SDK error. |
| `BadRequestError` | `BadRequestError` | Same HTTP class. |
| `AuthenticationError` | `AuthenticationError` | Same HTTP class. |
| `PermissionDeniedError` | `PermissionDeniedError` | Same HTTP class. |
| `NotFoundError` | `NotFoundError` | Same HTTP class. |
| `EndpointNotSupportedError` | `EndpointNotSupportedError` | Same HTTP class. |
| `RateLimitError` | `RateLimitError` | Same HTTP class and retry-after. |
| `InternalError` | `InternalError` | Same HTTP class. |
| `TrustedRouter` | `Client` from `NewClient` | Go is sync and context-based. |
| `TrustedRouter.close`, context-manager methods | N/A | Go `Client` owns no closeable resources. |
| `TrustedRouter.request` | `Client.Request` | Same low-level JSON request role. |
| `TrustedRouter.chat_completions_stream` | `Client.ChatCompletionsText` | Text streaming iterator. |
| `TrustedRouter.chat_completions_chunk_stream` | `Client.ChatCompletionsChunks` | Parsed chunk iterator. |
| `TrustedRouter.chat_completions` | `Client.ChatCompletions` | Collected completion. |
| `TrustedRouter.fusion` | `Client.Fusion` | Fusion helper. |
| `TrustedRouter.models` | `Client.Models` | Model catalog via control base. |
| `TrustedRouter.providers` | `Client.Providers` | Provider catalog via control base. |
| `TrustedRouter.regions` | `Client.Regions` | Region catalog via control base. |
| `TrustedRouter.credits` | `Client.Credits` | Credits endpoint via control base. |
| `TrustedRouter.embeddings` | `Client.Embeddings` | Embeddings endpoint. |
| `TrustedRouter.messages` | `Client.Messages` | Messages endpoint. |
| `TrustedRouter.responses` | `Client.Responses` | Responses endpoint. |
| `TrustedRouter.responses_stream` | `Client.ResponsesEvents` | Parsed event iterator. |
| `TrustedRouter.responses_raw_stream` | `Client.ResponsesRawStream` | Raw SSE stream. |
| `TrustedRouter.responses_input_tokens` | `Client.ResponsesInputTokens` | Token counting. |
| `TrustedRouter.billing_checkout` | `Client.BillingCheckout` | Checkout endpoint via control base. |
| `TrustedRouter.stablecoin_checkout` | `Client.StablecoinCheckout` | Stablecoin wrapper via control base. |
| `TrustedRouter.auth_session` | `Client.AuthSession` | Auth session endpoint via control base. |
| `TrustedRouter.logout` | `Client.Logout` | Logout endpoint via control base. |
| `TrustedRouter.activity` | `Client.Activity` | Activity endpoint via control base. |
| `TrustedRouter.broadcast_destinations` | `Client.BroadcastDestinations` | Broadcast destination list via control base. |
| `TrustedRouter.create_broadcast_destination` | `Client.CreateBroadcastDestination` | Broadcast destination create via control base. |
| `TrustedRouter.get_broadcast_destination` | `Client.GetBroadcastDestination` | Broadcast destination get via control base. |
| `TrustedRouter.update_broadcast_destination` | `Client.UpdateBroadcastDestination` | Broadcast destination patch via control base. |
| `TrustedRouter.delete_broadcast_destination` | `Client.DeleteBroadcastDestination` | Broadcast destination delete via control base. |
| `TrustedRouter.test_broadcast_destination` | `Client.TestBroadcastDestination` | Broadcast destination test via control base. |
| `TrustedRouter.status` | `Client.Status` | Status fetch. |
| `TrustedRouter.attestation` | `Client.Attestation` | Raw attestation JWT. |
| `TrustedRouter.trust_release` | `Client.TrustRelease` | Trust-release fetch. |
| `AsyncTrustedRouter` and async methods | N/A | Go is synchronous with `context.Context` cancellation by design. |
| `fetch_trust_release` | `FetchTrustRelease` | Package-level trust-release fetch. |
| `PKCEPair` | `OAuthPkcePair` | Same fields, Go keeps SDK-wide OAuth prefix. |
| `OAuthAuthorization` | `OAuthAuthorization` | Same authorize result. |
| `OAuthToken` | `OAuthKeyExchangeResponse` | Go names the exchange response after the endpoint. |
| `random_oauth_state` | `RandomOAuthState` | State token helper. |
| `create_pkce_pair` | `CreateOAuthPkcePair` | PKCE helper. |
| `oauth_authorize_url` | `Client.OAuthAuthorizeURL` | Go builds from a configured client/control base URL. |
| `create_oauth_authorization` | `Client.CreateOAuthAuthorization` | PKCE/state authorize helper. |
| `exchange_oauth_key` | `Client.ExchangeOAuthKey` | Go uses the configured client/control base URL. |
| `exchange_oauth_key_async` | N/A | Go uses sync method plus `context.Context`. |
| `fetch_userinfo` | `Client.UserInfo` | Go returns the typed envelope. |
| `fetch_userinfo_async` | N/A | Go uses sync method plus `context.Context`. |
| `GCP_ISSUER` | `GCPIssuer` | Same value. |
| `GCP_JWKS_URI` | `GCPJWKSURI` | Same value. |
| `AttestationVerificationError` | `AttestationVerificationError` | Same failure messages for verifier paths. |
| `AttestationPolicy` | `AttestationPolicy` | Go uses Python-derived field names. |
| `GatewayAttestation` | `GatewayAttestation` | Result fields mirror Swift shape with Go casing. |
| `GatewayAttestation.as_dict` | `GatewayAttestation.AsMap` | Compact result summary. |
| `policy_from_trust_release` | `PolicyFromTrustRelease` | Same defaults; Go takes an options struct. |
| `verify_gateway_attestation` | `VerifyGatewayAttestation` | Same JWT/JWKS/claim verification. |

## Client telemetry header channel (`_telemetry.py`)

Contract v1 of `docs/client-telemetry.md` (Lore-Hex/quill-router), header
channel only. The beacon channel is deliberately absent: the contract's
rollout ordering ships header-only PRs in the non-Python SDKs (§9 step 7)
and forbids beacons in a second SDK until the Python contract has been live
and calibrated (§10). `absoluteRequest` in `transport.go` is the reserved
out-of-engine attach point for the later beacon sender.

| Python symbol | Go symbol | Notes |
| --- | --- | --- |
| `RequestRecorder` | `requestRecorder` (unexported) | Header-channel subset: begin_attempt/on_response/on_transport_error/on_moved/header_value. Beacon-only fields (ttfb, request_id, retry_after, sampling) arrive with the beacon PR. |
| `host_enum` | `hostEnum` | Same closed vocabulary, same scheme+hostname comparison against the SDK's own base-URL constants. |
| `classify_transport_error` | `classifyTransportError` | httpx exception classes become Go `net`/`crypto/tls`/`syscall` error-chain checks; classified before `transportRetryError` flattens the chain. |
| `resolve_telemetry_enabled` | `resolveTelemetryEnabled` | Same precedence: explicit > `TRUSTEDROUTER_TELEMETRY` > `DO_NOT_TRACK` > default on only for TrustedRouter hosts. |
| `telemetry: bool | None` client arg | `Options.Telemetry *bool` | Same nil-resolves semantics beside `RegionalFailover`. |
| `TELEMETRY_*` constants | unexported `telemetry*` constants | Pinned by `TestTelemetryParityConstants` (beacon path, schema version, Host/Endpoint/Outcome/ErrorClass enums). |
| `TelemetryReporter` | N/A | Beacon sender; deferred per §9/§10 as above. |
| `telemetry_sample_rate` client arg | N/A | Governs beacon sampling only; arrives with the beacon PR. |
