# Boundary audit results

Completed in the worktree without a commit. No runtime dependencies or cross-SDK parity fixtures changed. The library has 208 Test functions (196 before, 12 added); CLI tests remain out of scope. The mutation runner also has a test covering killed, surviving, and stale mutations plus byte restoration.

The [pre-edit verdict table](boundary-audit.md) records the decisions before implementation. The [complete original site index](boundary-sites.md) lists 399 source/class matches across 191 function groups, with original file:line and verdict. It includes safe sites, rather than searching only for the repaired pattern.

## Behavior and compatibility

- Exchange requires a string `key`; it does not require `data`, `identity`, or `user_id`. Userinfo requires a nonnull `data` object. Invalid auth shapes return `*ResponseShapeError`. Producer metadata and unknown nested fields continue through the existing typed fields and `Extra` maps.
- **Public type correction:** `UserInfoData.Sub` is now `*string`, preserving the literal production `{data:{sub:null,workspace_id}}` response. Callers reading Sub must check nil and dereference. The former string type could not represent the producer contract. Other public field types and method signatures are unchanged.
- Trust parsing rejects nonobject, duplicate-key, trailing, and unreadable JSON. JWT key IDs must be strings before comparison. Missing/wrong-typed image claims cannot match empty pins. Expiration conversion rejects nonfinite/out-of-range floats.
- HTTP header layers merge case-insensitively through `http.Header`, with typed per-call options taking precedence. Existing public single-value maps remain compatible. The SDK does not collapse repeated response header values during these merges.
- Loopback address assertions are checked; its server has a header-read timeout and its listener uses a context. Invalid tool-call numeric conversion uses the existing zero fallback. Partial telemetry policy bytes are discarded without changing status-based acknowledgement/retry decisions.

## Static gates

`.golangci.yml` enables **errcheck, govet, staticcheck, forcetypeassert, errorlint, bodyclose, noctx, nilerr, unconvert, gosec**. `errcheck.check-blank` is true; exclusion presets are empty and issue-count limits are disabled. **No gosec rules are globally excluded.** CI pins `golangci/golangci-lint-action@v8` to **v2.6.0**, before race tests. The old standalone staticcheck step is replaced.

`scripts/boundary-check` supplements lint using stdlib AST and Go type information: it rejects any direct index operation on `net/http.Header` (including aliases), and calls to `encoding/json.Decoder.DisallowUnknownFields`. It checks library, CLI, and tooling source. CI runs it before lint; the mutation command runs it too, so the requested local CI command also includes this gate.

Tests exclude errcheck, forcetypeassert, errorlint, bodyclose, noctx and gosec because fixtures intentionally use unchecked writes/assertions, synthetic transports and TLS. Tests retain govet, staticcheck, nilerr and unconvert. One compile-time public API signature test suppresses staticcheck QF1011 because removing explicit function types would remove its purpose. The supplemental boundary checker uses production GoFiles, excluding test fixtures.

Errcheck retains upstream default exclusions for operations documented infallible (buffer/builder/hash writes, rand.Read and pipe CloseWithError) and best-effort standard console printing. No application-specific function exclusions were added. Every explicit source suppression is listed below.

Static limits: schema requiredness, nullable producer fields, optional attribution versus consumed trust values, and arbitrary plain-map semantics cannot generally be inferred by these analyzers. These require the recorded source audit, literal wire test, and mutations. Nilness checks cover statically provable errors, not all possible runtime shapes. The static gate is not claimed to prove an arbitrary JSON schema correct.

Local lint command: `GOTOOLCHAIN=auto go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.6.0 run ./...`. Version 2.6.0 exists, but requires Go >=1.24 to build; automatic toolchain selection used Go 1.26.8 for the linter. Library vet/build/test/race/mutations used the supplied Go 1.23.4, and go.mod remains Go 1.23. Writable GOPATH, GOMODCACHE, GOCACHE, and GOLANGCI_LINT_CACHE were placed under /private/tmp. An unwritable optional goimports index-cache warning did not prevent lint from reporting zero issues.

## Verification

| Check | Result |
|---|---|
| gofmt; go vet ./...; go mod tidy -diff | PASS |
| golangci-lint v2.6.0 run ./... | PASS, 0 issues (library, CLI, tooling) |
| go test -race ./... | PASS, root package 15.407s; mutation-runner tests 2.852s |
| go run ./scripts/mutation-check | PASS, 21/21 killed, 4/4 static probes rejected, **78.845s wall time** |
| SDK conformance --sdk go --sdk-root go=$PWD | **25 passed, 0 failed, 0 skipped**; loopback binding worked, not sandbox-blocked |
| git diff --check | PASS |

Exact local command chain used (after configuring writable caches and PATH):

```sh
test -z "$(gofmt -l .)" &&
go vet ./... &&
go mod tidy -diff &&
GOTOOLCHAIN=auto go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.6.0 run ./... &&
go test -race ./... &&
go run ./scripts/mutation-check
```

Conformance command:

```sh
/private/tmp/claude-501/-Users-jperla-josh/733bc505-7008-406e-bff3-ff2a10df6555/scratchpad/sdk-conformance/.venv/bin/tr-conformance --sdk go --sdk-root go="$PWD"
```

## Literal wire fixture

`testdata/auth-wire-fixtures.json` is verified byte-identical to the shared source. SHA-256:

```text
ba492afe81f7616bca062ab7ed35f70d42042e6f6f60794ac9e2a599574df1d2
```

`oauth_test.go:302` loads every accept/reject case and drives ExchangeOAuthKey or UserInfo through the real HTTP/parsing path. It checks the method/path, all producer fields (including unknown nested metadata and legacy null), and rejects with errors.As to *ResponseShapeError. One mutation invents a required exchange data field; this test fails.

## Fails-without-fix results

The runner creates a temporary copy, verifies each before pattern occurs exactly once, and runs a passing baseline of 12 focused tests. For every mutant it runs `go test -count=1 -run '^TestName$' .`, requires the named test to fail, and rejects compilation/infrastructure failures as invalid proof. A defer restores the original bytes from memory and verifies them, including on errors/cancellation; git checkout is never used. Surviving and stale mutants exit nonzero, covered by runner tests. The working repository is never mutated by the runner.

| Mutation | Current repair site | Focused test | Result / wall time |
|---|---|---|---|
| exchange-required-key | `oauth.go:89` | `TestAuthWireFixtures` | KILLED, 1.99s |
| userinfo-required-object | `account.go:80` | `TestAuthWireFixtures` | KILLED, 3.083s |
| auth-required-field-shape | `boundary.go:22` | `TestAuthWireFixtures` | KILLED, 2.6s |
| legacy-null-subject | `account.go:118` | `TestAuthWireFixtures` | KILLED, 2.476s |
| wire-fixture-no-required-data | `oauth.go:89` | `TestAuthWireFixtures` | KILLED, 4.125s |
| jwt-key-id-shape | `attestation.go:533` | `TestAttestationKeyIDShape` | KILLED, 1.991s |
| trust-json-strict-decoding | `attestation.go:518` | `TestAttestationJSONObjectBoundary` | KILLED, 2.173s |
| trust-json-object-shape | `attestation.go:523` | `TestAttestationJSONObjectBoundary` | KILLED, 3.986s |
| jwks-strict-decoding | `attestation.go:460` | `TestJWKSJSONObjectBoundary` | KILLED, 1.975s |
| nonempty-image-claim | `attestation.go:866` | `TestEmptyImagePinCannotMatchMissingClaim` | KILLED, 2.565s |
| expiration-float-bounds | `attestation.go:793` | `TestAttestationIntegerBounds` | KILLED, 3.294s |
| chatCallOptions-header-merge | `extras.go:14` | `TestHeaderMergeCaseInsensitive` | KILLED, 2.46s |
| responsesCallOptions-header-merge | `extras.go:43` | `TestHeaderMergeCaseInsensitive` | KILLED, 1.971s |
| stream-header-merge | `chat.go:274` | `TestStreamHeaderOverrideCaseInsensitive` | KILLED, 2.441s |
| loopback-address-shape | `oauth_loopback.go:253` | `TestOAuthLoopbackAddressShape` | KILLED, 3.854s |
| tool-call-index-overflow | `chat_types.go:698` | `TestToolCallIndexOverflow` | KILLED, 1.529s |
| partial-telemetry-policy | `telemetry_reporter.go:1200` | `TestTelemetryPartialPolicyIsDiscarded` | KILLED, 1.737s |
| exchange-typed-error | `oauth.go:95` | `TestAuthWireFixtures` | KILLED, 2.368s |
| userinfo-typed-error | `account.go:86` | `TestAuthWireFixtures` | KILLED, 3.634s |
| jwks-read-error | `attestation.go:457` | `TestJWKSReadError` | KILLED, 1.711s |
| header-canonicalization | `extras.go:134` | `TestHeaderMergeCaseInsensitive` | KILLED, 1.595s |

| Static negative proof | Gate finding | Result |
|---|---|---|
| Class 1: unchecked v.(string) | forcetypeassert | REJECTED, 9.088s |
| Class 2: DisallowUnknownFields | wire-pass-through | REJECTED, 2.135s |
| Class 3: h["x-probe"] on http.Header | header-access | REJECTED, 2.068s |
| Class 4: _ = json.Unmarshal(...) | errcheck | REJECTED, 7.674s |

Each static probe compiles first and runs separately in the temporary copy; rejection must identify both the injected file and the intended rule. The temporary probe is removed in a defer. CI runs these proofs after race tests as part of mutation-check.

## Every inline suppression

No file-wide production suppressions. Gosec exceptions are only G115 for timestamp bit serialization/nonnegative PIDs, G404 for nonsecurity retry jitter, and G304 for local tooling paths with explicit provenance. All other gosec rules remain enabled.

| Site | Linter | Invariant / reason |
|---|---|---|
| `account.go:215` | errcheck | Close is best-effort cleanup; preserve the completed operation result. |
| `attestation.go:306` | errcheck | Close is best-effort cleanup; preserve the completed operation result. |
| `attestation.go:334` | errcheck | Close is best-effort cleanup; preserve the completed operation result. |
| `attestation.go:420` | errcheck | Close is best-effort cleanup; preserve the completed operation result. |
| `attestation.go:452` | errcheck | Close is best-effort cleanup; preserve the completed operation result. |
| `chat.go:108` | errcheck | Close is best-effort cleanup; preserve the completed operation result. |
| `cmd/trustedrouter/main.go:125` | errcheck | Close is best-effort cleanup; preserve the completed operation result. |
| `cmd/trustedrouter/main.go:159` | errcheck | Close is best-effort cleanup; preserve the completed operation result. |
| `cmd/trustedrouter/main.go:210` | errcheck | Close is best-effort cleanup; preserve the completed operation result. |
| `cmd/trustedrouter/main.go:264` | errcheck | Close is best-effort cleanup; preserve the completed operation result. |
| `cmd/trustedrouter/main.go:305` | errcheck | Close is best-effort cleanup; preserve the completed operation result. |
| `cmd/trustedrouter/main.go:308` | errcheck | Close is best-effort cleanup; preserve the completed operation result. |
| `cmd/trustedrouter/main.go:311` | errcheck | Close is best-effort cleanup; preserve the completed operation result. |
| `oauth_loopback.go:153` | errcheck | Close is best-effort cleanup; preserve the completed operation result. |
| `oauth_loopback.go:242` | errcheck | Browser disconnect cannot revoke a delivered OAuth result. |
| `planes.go:26` | errcheck | Close is best-effort cleanup; preserve the completed operation result. |
| `planes.go:46` | errcheck | Close is best-effort cleanup; preserve the completed operation result. |
| `planes.go:55` | errcheck | Close is best-effort cleanup; preserve the completed operation result. |
| `receipts.go:861` | nilerr | SSE domains hash arbitrary payload bytes; non-JSON is not a receipt candidate. |
| `responses.go:138` | errcheck | Close is best-effort cleanup; preserve the completed operation result. |
| `responses_test.go:318` | staticcheck | Explicit function types are compile-time public API compatibility assertions (QF1011). |
| `scripts/mutation-check/main.go:49` | gosec | G304: fixed file in the explicitly selected local repository. |
| `scripts/mutation-check/main.go:68` | gosec | G304: validated relative path from the embedded manifest, inside the temporary copy. |
| `scripts/mutation-check/main.go:102` | gosec | G304: embedded manifest selects a source file in the temporary copy. |
| `scripts/mutation-check/main.go:113` | gosec | G304: verify the exact file just restored in the temporary copy. |
| `scripts/mutation-check/main.go:172` | gosec | G304: WalkDir selected a regular file under the repository; symlinks are rejected. |
| `session.go:99` | errcheck | Close is best-effort cleanup; preserve the completed operation result. |
| `session.go:105` | errcheck | Close is best-effort cleanup; preserve the completed operation result. |
| `session.go:275` | errcheck | Close is best-effort cleanup; preserve the completed operation result. |
| `session.go:411` | errcheck | This live TLS connection supports deadlines; a concurrent close makes failure harmless. |
| `session.go:418` | errcheck | This live TLS connection supports deadlines; a concurrent close makes failure harmless. |
| `session.go:424` | errcheck | This live TLS connection supports deadlines; a concurrent close makes failure harmless. |
| `sse.go:253` | errcheck | Close is best-effort cleanup; preserve the completed operation result. |
| `telemetry.go:329` | errorlint | Inspect one allowlisted chain link without invoking hostile Is/As/Unwrap methods. |
| `telemetry.go:410` | errorlint | Inspect one allowlisted chain link without invoking hostile Is/As/Unwrap methods. |
| `telemetry.go:485` | errorlint | Inspect one allowlisted chain link without invoking hostile Is/As/Unwrap methods. |
| `telemetry.go:501` | errorlint | Inspect one allowlisted chain link without invoking hostile Is/As/Unwrap methods. |
| `telemetry.go:523` | errorlint | Inspect one allowlisted chain link without invoking hostile Is/As/Unwrap methods. |
| `telemetry.go:543` | errorlint | Inspect one allowlisted chain link without invoking hostile Is/As/Unwrap methods. |
| `telemetry.go:933` | errcheck | Telemetry panic payloads are deliberately discarded to protect the user request. |
| `telemetry_reporter.go:532` | gosec | G115: encode timestamp bits for uniqueness, not arithmetic. |
| `telemetry_reporter.go:1162` | errcheck | Optional diagnostics cannot change delivery semantics. |
| `telemetry_reporter.go:1199` | errcheck | Close is best-effort cleanup; preserve the completed operation result. |
| `transport.go:432` | gosec | G115: encode timestamp bits for uniqueness, not arithmetic. |
| `transport.go:433` | gosec | G115: OS process IDs are nonnegative. |
| `transport.go:527` | gosec | G404: retry jitter is not security entropy. |
| `transport.go:566` | errcheck | A failed drain still closes the failed attempt before retry. |
| `transport.go:567` | errcheck | Close is best-effort cleanup; preserve the completed operation result. |

## Every changed file and location

Locations below cover each current diff hunk; new files start at line 1. Audit and verification documents are included.

| File / current locations | Change |
|---|---|
| `.github/workflows/ci.yml:27`, `.github/workflows/ci.yml:38` | Add boundary checker and pinned lint before race tests; mutation/static proofs after race tests. |
| `.golangci.yml:1` | Pinned v2 config with all requested linters; check blank errors; explicit test exceptions. |
| `account.go:80`, `account.go:86`, `account.go:95`, `account.go:215` | Require userinfo data, typed errors, nullable Sub, explicit cleanup suppression. |
| `attestation.go:3`, `attestation.go:306`, `attestation.go:334`, `attestation.go:420`, `attestation.go:452`, `attestation.go:456`, `attestation.go:518`, `attestation.go:522`, `attestation.go:533`, `attestation.go:775`, `attestation.go:779`, `attestation.go:792`, `attestation.go:867` | Strict trust/JWKS JSON and body reads, key-ID shape, numeric bounds, nonempty image matching; cleanup reasons. |
| `attestation_test.go:14`, `attestation_test.go:731`, `attestation_test.go:833` | Six focused trust regressions and simpler embedded public-key selector. |
| `billing_account_test.go:157` | Update subject assertion for accurately nullable public type. |
| `boundary.go:1` | Typed auth shape error and consumed-field guard. |
| `chat.go:108`, `chat.go:154`, `chat.go:272` | Canonical stream header merge; cleanup reason. |
| `chat_test.go:664` | Numeric tool-call overflow regression. |
| `chat_types.go:698` | Handle Int64 conversion errors. |
| `cmd/trustedrouter/main.go:125`, `cmd/trustedrouter/main.go:159`, `cmd/trustedrouter/main.go:210`, `cmd/trustedrouter/main.go:223`, `cmd/trustedrouter/main.go:264`, `cmd/trustedrouter/main.go:305`, `cmd/trustedrouter/main.go:308`, `cmd/trustedrouter/main.go:311` | Handle raw stdout write failure; document best-effort cleanup. No CLI tests added. |
| `docs/boundary-audit-results.md:1` | Verification, compatibility, all mutation results, suppressions and change locations. |
| `docs/boundary-audit.md:1` | Pre-edit site verdict table and lint-expanded audit. |
| `docs/boundary-sites.md:1` | Exhaustive original source-site inventory. |
| `extras.go:8`, `extras.go:38`, `extras.go:68`, `extras.go:122` | Central http.Header merge with deterministic layer ordering and case-insensitive precedence. |
| `oauth.go:89`, `oauth.go:95` | Require only key; wrap shape failures in ResponseShapeError. |
| `oauth_loopback.go:104`, `oauth_loopback.go:108`, `oauth_loopback.go:125`, `oauth_loopback.go:128`, `oauth_loopback.go:153`, `oauth_loopback.go:242`, `oauth_loopback.go:251` | Checked address extraction, context-aware listen, header-read timeout, errors.Is for server shutdown, cleanup/write reasons. |
| `oauth_loopback_test.go:7`, `oauth_loopback_test.go:236` | Focused wrong/nil address regression. |
| `oauth_test.go:4`, `oauth_test.go:7`, `oauth_test.go:11`, `oauth_test.go:300` | Literal producer fixture through public parsing paths, field/Extra preservation, typed reject errors. |
| `planes.go:26`, `planes.go:46`, `planes.go:55` | Document cleanup invariants for errcheck. |
| `receipts.go:428`, `receipts.go:861`, `receipts.go:946` | Equivalent Boolean expressions for staticcheck; explain opaque SSE payload handling for nilerr. |
| `responses.go:138` | Document cleanup invariant for errcheck. |
| `responses_test.go:318` | Keep explicit compile-time public API signature assertions with reasoned staticcheck suppression. |
| `scripts/boundary-check/main.go:1` | Stdlib typed static gate for header indexing and strict pass-through decoding. |
| `scripts/mutation-check/main.go:1` | Stdlib copy/mutate/focused-test/restore runner with strict stale and survivor handling. |
| `scripts/mutation-check/main_test.go:1` | Verify killed/surviving/stale outcomes and exact byte restoration. |
| `scripts/mutation-check/mutations.json:1` | 21 exact before/after mutations with focused test names. |
| `scripts/mutation-check/static.go:1` | Four independent compile-first negative static proofs, pinned lint v2.6.0. |
| `session.go:99`, `session.go:105`, `session.go:275`, `session.go:411`, `session.go:418`, `session.go:424` | Document cleanup and live-connection deadline invariants. |
| `sse.go:154`, `sse.go:253` | Explicitly handle the legacy convenience helper parse error; cleanup reason. |
| `telemetry.go:329`, `telemetry.go:410`, `telemetry.go:485`, `telemetry.go:501`, `telemetry.go:523`, `telemetry.go:543`, `telemetry.go:933`, `telemetry.go:1518` | Explain bounded allowlisted error-chain inspection and panic isolation; use existing safe sentinel helper for EOF. |
| `telemetry_reporter.go:532`, `telemetry_reporter.go:1162`, `telemetry_reporter.go:1199` | Discard partial policy on read errors; explain diagnostics, entropy encoding and cleanup. |
| `telemetry_reporter_test.go:935` | Focused partial-policy read regression. |
| `testdata/auth-wire-fixtures.json:1` | Verbatim shared producer payloads. |
| `transport.go:432`, `transport.go:527`, `transport.go:566` | Explain timestamp/PID bit encoding, nonsecurity jitter and best-effort retry cleanup. |
| `transport_test.go:254` | Focused case-insensitive chat/responses/stream header regressions. |
