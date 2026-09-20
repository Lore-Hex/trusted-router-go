# Consumer DX and CLI audit

Worktree changes only; no commit, tag, publication, runtime dependency, or CLI behavior change.

## Artifact audit and publication boundary

| Inventory | Files | Meaning |
|---|---:|---|
| [Before](../testdata/artifact-before.txt) | 87 | Original tracked module tree, confirmed with `golang.org/x/mod/zip.CreateFromDir` on a temporary `git archive HEAD` extraction. Includes 25 test files, 13 fixture files, five tooling files (categories overlap), CI and audit documents. |
| [Release ZIP after](../testdata/release-files.txt) | 33 | 29 root library sources, CLI source, LICENSE, README.md and go.mod. No tests, tools, CI, fixtures or scratch files. |
| [Development tree after](../testdata/module-files.txt) | 96 | Exact intended source inventory, including the new tests, inventories and report. Unknown files fail `TestModuleInventory`. |

`consumer_dx_test.go:56` builds a module ZIP, opens it, and compares its actual entry list with the independent release inventory. It selects root non-test Go files plus CLI sources and the three release documents. A stray file in that source set fails the listing assertion. The module identity and Go version come from `go list -m -json`; no vendoring is involved. The scratch test additionally downloads this ZIP through a local file proxy with an isolated module cache, so the Go tool validates the module ZIP before use.

**Go publication limitation:** a normal Go proxy builds a ZIP from the tagged repository tree. Go has no npm-style package exclude manifest and explicitly disables Git `export-ignore`. Therefore tagging the development tree still ships development files. The clean ZIP and extracted `module/` directory produced here are release artifacts: publish that source-only tree as the release tag, or serve the ZIP from a Go module proxy. Uploading a release attachment alone does not change `go get` from the ordinary GitHub tag. No such remote/tag operation was performed. This audit does not claim that an existing public release was cleaned. See the [Go module ZIP rules](https://go.dev/ref/mod#zip-files) and [Go's Git archive implementation](https://github.com/golang/go/blob/go1.23.4/src/cmd/go/internal/modfetch/codehost/git.go#L887).

Build and retain the artifact outside the repository:

```sh
export PATH="/opt/homebrew/bin:$HOME/go/bin:$PATH"
export GOCACHE=/private/tmp/tr-go-cache
export GOMODCACHE=/private/tmp/tr-go-mod
export GOPATH=/private/tmp/tr-go-path
TR_DX_OUTPUT=/private/tmp/tr-go-dx2-release go test -count=1 -v -run '^TestReleaseArtifact$' .
unzip -Z1 /private/tmp/tr-go-dx2-release/module.zip
```

The ZIP uses module prefix `github.com/Lore-Hex/trusted-router-go@v0.4.0/`. `listing.txt` contains the 33 relative paths, and `module/` contains only the extracted artifact. The command's output directory should be empty before building a release; ordinary tests always use fresh temporary directories.

## Metadata and consumer documentation

| Metadata | Before | After |
|---|---|---|
| Description | README introduction and package comment | Retained; asserted |
| License | Apache-2.0 LICENSE and README footer | Explicit metadata row; asserted |
| Repository | Implicit module path | Explicit HTTPS repository URL; asserted |
| Homepage | API URLs only | Explicit product homepage; asserted |
| Documentation | No explicit package-doc URL | pkg.go.dev URL; asserted |
| Keywords/topics | No list | Go, TrustedRouter, OpenAI, Anthropic, LLM, privacy, attestation; asserted |
| Minimum Go | `go 1.23` | Unchanged, also visible in README; asserted through `go list -m -json` |

Go does not define description/license/keywords/homepage fields in go.mod, so these live in README rather than invented module directives. No remote GitHub topics were modified. The README parity link now points to the repository URL because PARITY.md is deliberately absent from the release artifact. CLI installation is documented.

`TestExportedDocumentation` uses go/doc plus AST inspection to require package, exported type, function, method, const/var and named-field comments. Missing comments on receipt/shape errors, trust metadata, provider preferences, OAuth and orchestration fields were added. `go vet ./...` also runs. The scratch consumer checks editor-visible public types by compilation and checks rendered documentation with `go doc github.com/Lore-Hex/trusted-router-go.Client.ChatCompletions`.

## Scratch consumer and examples

`TestScratchConsumer` builds the release, serves its `.zip`, `.mod` and `.info` through `GOPROXY=file://…`, and invokes `go mod download -json github.com/Lore-Hex/trusted-router-go@v0.4.0` with `GOSUMDB=off`, `GOWORK=off`, `GOFLAGS=-modcacherw` and an isolated `GOMODCACHE`. It creates another temporary module outside the repository with a `replace` pointing at the **downloaded artifact**, copies `example_test.go`, and runs `go test -v .`. The example makes one authenticated chat call against httptest and checks its printed result. It also builds the CLI and runs go doc. No source-tree replace is used.

Exact reproducible manual smoke using the extracted artifact:

```sh
TR_DX_OUTPUT=/private/tmp/tr-go-dx2-release go test -count=1 -run '^TestReleaseArtifact$' .
repo="$PWD"
consumer=$(mktemp -d /private/tmp/tr-go-consumer.XXXXXX)
cp example_test.go "$consumer/example_test.go"
cd "$consumer"
go mod init consumer.example/smoke
go mod edit -go=1.23
go mod edit -require=github.com/Lore-Hex/trusted-router-go@v0.4.0
go mod edit -replace=github.com/Lore-Hex/trusted-router-go=/private/tmp/tr-go-dx2-release/module
GOWORK=off GOPROXY=off GOSUMDB=off go test -v .
GOWORK=off GOPROXY=off GOSUMDB=off go doc github.com/Lore-Hex/trusted-router-go.Client.ChatCompletions
cd "$repo"
go test -count=1 -v -run '^(TestScratchConsumer|TestDocumentationExamples|ExampleClient_ChatCompletions)$' .
```

All nine Go fences in README are extracted verbatim and compiled against an extracted release in separate temporary consumer modules. Complete programs retain their exact imports. Fragments receive a surrounding client/context/error/input scope and unused-result sinks; snippet contents are not repaired by the harness. Future Go fences anywhere under docs are discovered automatically. Shell fences in README and docs are parsed with `sh -n`; historical CI/conformance snippets are syntax-checked rather than recursively executed. CLI sample operations are separately exercised by the built-artifact CLI suite. Unknown fenced languages and unclosed fences fail.

The privacy example previously did not compile: `ChatRequest.Provider` requires `*ProviderPreferences`. It now creates `provider := trustedrouter.ConfidentialProvider()` and passes `&provider`. The public `ExampleClient_ChatCompletions` compiles and executes with httptest; its fake server correctly emits SSE, including the terminal event required by the SDK.

## Command × option coverage

Before: **zero CLI tests**; none of the commands/options below had CLI-level coverage. After: **42 subprocess cases**, each with exit status and stdout/stderr or exact JSON assertions.

| Command | Options exercised | Result coverage |
|---|---|---|
| Global parser | `--base-url`, `--control-base-url`, `--retries`, `--help`, `-h`; bad/unknown flags; no/unknown command | Independent inference/control listeners; retry 0 vs 1 request counts; malformed base; exits 1 and 2 |
| chat | `--model`, `-m`, `--max-tokens`, `--stream`, `--stream=false`, `--help`, `-h`; bad values/flags | Request model/tokens/prompt/stream and bearer assertions; exact text; empty prompt, truncated SSE, HTTP 500, HTTP 401/auth hint; exits 0/1/2/3 |
| models | All three global endpoint/retry flags | Exact catalog JSON, HTTP 401; exits 0/1 |
| providers | All three global endpoint/retry flags | Exact catalog JSON, HTTP 500; exits 0/1 |
| regions | All three global endpoint/retry flags | Exact catalog JSON, HTTP 500; exits 0/1 |
| trust | No command-specific options | Exact trust-release JSON and HTTP failure; credential-free HTTPS; exits 0/1 |
| attest | `--verify`, `--session`, `--connect-ip`, `--help`, `-h`; bad flags | Raw document JSON, fully verified result JSON, successful exporter-bound pinned sessions and follow-up, malformed JWT and HTTP errors, connect-IP dependency; exits 0/1/2 |

Both credential environment variables are exercised. Unknown options and help preserve their existing exit code 2. The malformed base preserves its existing operation-error exit code 1.

Ordinary requests execute the plain `go build` CLI. Trust and verified-attestation cases execute a test binary compiled from the extracted artifact plus a test-only main wrapper. The wrapper installs a private root using x509.SetFallbackRoots, then invokes the **unchanged CLI main**. A local CONNECT proxy routes fixed trust/JWKS HTTPS destinations to the fake server; real TLS certificate checks, JWT signatures, nonce/exporter bindings and pinned follow-up still run. No live service or certificate-verification bypass is used. The wrapper is never in the release ZIP.

## Negative proofs

`python3 scripts/dx-mutation-check.py` copies the tree to a temporary directory, runs a passing baseline, applies each mutation individually and requires the named test and diagnostic to fail. Every source mutation restores and byte-checks the original file; CLI mutations override one expected exit or output contract per subprocess, then disappear with that process. Build/infrastructure failures cannot count as kills. CI runs this command after the existing Wave 1 gate.

| Guard mutation | Focused test | Result |
|---|---|---|
| Add `cmd/trustedrouter/stray.txt` to the artifact source set | TestReleaseArtifact | KILLED |
| Add unapproved `testdata/stray.json` | TestModuleInventory | KILLED |
| Replace README NewClient with nonexistent symbol | TestDocumentationExamples | KILLED |
| Remove package documentation URL from metadata | TestReleaseArtifact | KILLED |
| Remove NewClient doc | TestExportedDocumentation | KILLED |
| Remove ProviderPreferences type doc | TestExportedDocumentation | KILLED |
| Remove package doc | TestExportedDocumentation | KILLED |
| Remove ResponseShapeError.Unwrap doc | TestExportedDocumentation | KILLED |
| Remove receipt RequestBody field doc | TestExportedDocumentation | KILLED |
| Remove DefaultAPIBaseURL constant doc | TestExportedDocumentation | KILLED |
| Change consumer example expected output | TestScratchConsumer | KILLED |
| Corrupt module ZIP before Go download | TestScratchConsumer | KILLED |
| Remove rendered ChatCompletions doc | TestScratchConsumer | KILLED |

Each CLI row below was independently rerun with a wrong expected exit code and a wrong JSON/text/diagnostic shape:

| CLI case | Wrong exit | Wrong shape |
|---|---|---|
| no-command | KILLED | KILLED |
| unknown-command | KILLED | KILLED |
| global-help | KILLED | KILLED |
| global-short-help | KILLED | KILLED |
| global-unknown-flag | KILLED | KILLED |
| invalid-retries | KILLED | KILLED |
| invalid-base | KILLED | KILLED |
| chat-empty | KILLED | KILLED |
| chat-help | KILLED | KILLED |
| chat-short-help | KILLED | KILLED |
| chat-invalid-flag | KILLED | KILLED |
| chat-invalid-max-tokens | KILLED | KILLED |
| chat-defaults | KILLED | KILLED |
| chat-model-max-tokens | KILLED | KILLED |
| chat-short-model-fallback-key | KILLED | KILLED |
| chat-stream | KILLED | KILLED |
| chat-stream-false | KILLED | KILLED |
| chat-auth | KILLED | KILLED |
| chat-stream-auth | KILLED | KILLED |
| chat-http-error | KILLED | KILLED |
| chat-stream-broken | KILLED | KILLED |
| retries-one | KILLED | KILLED |
| models | KILLED | KILLED |
| providers | KILLED | KILLED |
| regions | KILLED | KILLED |
| models-error | KILLED | KILLED |
| providers-error | KILLED | KILLED |
| regions-error | KILLED | KILLED |
| trust | KILLED | KILLED |
| trust-error | KILLED | KILLED |
| attest | KILLED | KILLED |
| attest-error | KILLED | KILLED |
| attest-help | KILLED | KILLED |
| attest-short-help | KILLED | KILLED |
| attest-invalid-flag | KILLED | KILLED |
| attest-connect-requires-session | KILLED | KILLED |
| attest-verify-success | KILLED | KILLED |
| attest-session-success | KILLED | KILLED |
| attest-connect-success | KILLED | KILLED |
| attest-verify | KILLED | KILLED |
| attest-session | KILLED | KILLED |
| attest-session-connect-ip | KILLED | KILLED |

## Verification

| Check | Result |
|---|---|
| gofmt, go vet ./..., go mod tidy -diff | PASS on Go 1.23.4 |
| boundary static gate | PASS, 0 findings |
| golangci-lint v2.6.0 | PASS, 0 issues; automatic Go 1.26.8 toolchain used to run the linter |
| go test -race ./... | PASS; root 24.545s, CLI 8.767s |
| go test ./cmd/... | PASS, 42 subprocess cases |
| Wave 1 mutation/static gate | 21/21 mutations killed, 4/4 static probes rejected; 72.582s |
| Consumer/CLI mutation gate | **97/97 killed**: 13 consumer/doc/artifact probes plus 84 independent CLI exit/shape probes; 54.92s |
| SDK conformance | **25 passed, 0 failed, 0 skipped**; localhost binding worked |
| Scratch consumer | PASS; actual manual temp project `/private/tmp/tr-go-consumer.UTGpTO` |
| Documentation | All nine Go examples compile; httptest Example executes locally and from the downloaded ZIP; shell fences parse |
| Canonical module ZIP audit | x/mod ZIP inventories match the recorded original 87 files and clean release 33 files |
| Production behavior | All 29 library files and the CLI have identical non-comment, non-semicolon Go token streams to baseline |
| git diff --check | PASS |

Full local CI command set (with the writable caches and PATH above):

```sh
export GOLANGCI_LINT_CACHE=/private/tmp/tr-go-lint-cache
test -z "$(gofmt -l .)"
go vet ./...
go mod tidy -diff
go run ./scripts/boundary-check
GOTOOLCHAIN=auto go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.6.0 run ./...
go test -race ./...
go run ./scripts/mutation-check
python3 scripts/dx-mutation-check.py
/private/tmp/claude-501/-Users-jperla-josh/733bc505-7008-406e-bff3-ff2a10df6555/scratchpad/sdk-conformance/.venv/bin/tr-conformance --sdk go --sdk-root go="$PWD"
```

The source-only artifact is validated locally; no claim is made that the ordinary GitHub source tag has the clean release inventory. That requires the publication action described above.

## Change locations

Every changed tracked hunk and every new file is indexed below. Existing production Go changes consist only of documentation and gofmt alignment; `cmd/trustedrouter/main.go`, go.mod, and dependency declarations are unchanged.

| File: current changed-hunk starts | Change |
|---|---|
| `.github/workflows/ci.yml:40` | Run the new negative-proof gate. |
| `README.md:12`, `README.md:68`, `README.md:72`, `README.md:289`, `README.md:292`, `README.md:303` | Add metadata and CLI installation, fix the provider pointer example and artifact-safe parity link. |
| `attestation.go:134`, `attestation.go:156`, `attestation.go:178` | Document trust-release fields. |
| `boundary.go:11`, `boundary.go:16`, `boundary.go:18` | Document the shape-error field and methods. |
| `cmd/trustedrouter/main_test.go:1` | Build artifact binaries; fake HTTP/TLS/JWKS servers; 42 CLI contracts; mutation hooks. |
| `consumer_dx_test.go:1` | Build/assert ZIP, inventory module tree, enforce docs, validate local-proxy download and scratch consumer. |
| `docs/consumer-dx-results.md:1` | Artifact/metadata audit, coverage table, commands, verification, mutation results and change locations. |
| `documentation_test.go:1` | Extract and compile every Go fence; parse shell fences; reject unsupported/unclosed fences. |
| `example_test.go:1` | Executable public httptest chat example with checked output. |
| `oauth.go:28`, `oauth.go:34`, `oauth.go:55`, `oauth.go:65`, `oauth.go:86`, `oauth.go:92`, `oauth.go:127` | Document public OAuth options, exchange input and identity fields. |
| `oauth_loopback.go:53` | Document callback code/state fields. |
| `orchestration_tools.go:106`, `orchestration_tools.go:131`, `orchestration_tools.go:168`, `orchestration_tools.go:182` | Document selector, map-reduce and subagent options. |
| `provider.go:5` | Document routing/privacy/provider preference fields. |
| `receipts.go:43`, `receipts.go:45`, `receipts.go:49`, `receipts.go:57`, `receipts.go:68`, `receipts.go:79`, `receipts.go:90`, `receipts.go:101`, `receipts.go:113`, `receipts.go:125`, `receipts.go:136`, `receipts.go:147`, `receipts.go:158`, `receipts.go:169`, `receipts.go:180`, `receipts.go:191`, `receipts.go:202`, `receipts.go:268`, `receipts.go:280`, `receipts.go:282`, `receipts.go:292`, `receipts.go:300`, `receipts.go:306`, `receipts.go:340`, `receipts.go:349` | Document receipt error methods, claims and verification options. |
| `scripts/dx-mutation-check.py:1` | Baseline, isolated mutations, restoration, 13 consumer probes and 84 CLI probes. |
| `session.go:45` | Document the session attestation field. |
| `testdata/artifact-before.txt:1` | Original canonical source ZIP inventory. |
| `testdata/module-files.txt:1` | Exact intended development-source inventory. |
| `testdata/release-files.txt:1` | Independent clean release ZIP inventory. |

