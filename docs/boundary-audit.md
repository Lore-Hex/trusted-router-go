# Boundary audit (inventory before edits)

Line numbers in this first table refer to the starting worktree. “Fixed” identifies the repair selected before implementation; final locations and verification are recorded below. The sweep covers all root library Go files; internal/ contains receipt fixtures, not Go source. CLI tests are out of scope, CLI lint is included.

| Class | Sites (original file:line) | Verdict and reason |
|---|---|---|
| 1 | errors.go:169,174,177; extras.go:89,104,113,123; broadcast.go:217; chat.go:265 | Already-safe: comma-ok assertions/type switches; nil map reads are safe; these are optional attribution or caller options. |
| 1 | chat_types.go:482,483,487,488,541,576,578,583,588,603,607,674,690,706 | Already-safe: checked assertions; slot.function is constructed locally as a nonnil map at 466, never replaced by wire data. Unknown metadata is retained; absent optional deltas are not required. |
| 1 | attestation.go:548,549,579,585,614,619,623,627,631,654–657,712,714,763,787,795,812,822,899 | Already-safe assertions: comma-ok/type switches and nil-safe map reads; trust checks compare required values. Empty image match issue separately below. |
| 1 | attestation.go:530,537 | Fixed: comparing two untyped wire kid values can panic on arrays/maps; validate string key identifiers before equality. |
| 1 | receipts.go:358,404,416,581,598,616–618,634,644,652,663,691,695,706,863,871,903,916,981,993,1037,1045,1057,1130 | Already-safe: checked assertions; required fields reject wrong types with receipt error families; numeric claims use json.Number. |
| 1 | sse.go:34,196,245; transport.go:320; session.go:97; telemetry.go:329,370,375,485,501,523,543,755,759,769,775; telemetry_reporter.go:482,1049,1217; orchestration_tools.go:280 | Already-safe: type switches/comma-ok. No unchecked external type assertions found. |
| 2,4 | oauth.go:88 | Fixed: require key string (not data); preserve optional producer fields and Extra; return SDK typed shape errors. |
| 2,4 | account.go:79,93,109 | Fixed: require nonnull data object; Sub becomes *string because producer emits null. Preserve metadata. |
| 2 | oauth.go:109; account.go:21,43,61,129,155; billing.go:41; broadcast.go:55,87; models.go:37,92,131,157,181,205,225,247,267,289,309; chat_types.go:141,182,218,257,296,335,374; messages.go:53,98,129; responses.go:53,99; embeddings.go:50,99,152; attestation.go:141,160,190 | Intentionally-unchanged: optional struct fields are NOT required; no DisallowUnknownFields. Alias decoding rejects incompatible known field types and Extra retains unknown fields. No producer evidence supports changing other public field types. Embedding union explicitly tries both supported shapes. |
| 2 | errors.go:177,289,292,298; oauth.go:240; attestation.go:899; receipts.go:1144 | Intentionally-unchanged: error attribution/message rendering is diagnostic, never a retry or trust decision; OAuth limit is caller input; repr helpers format diagnostics. No numeric ID reformatting in consumed paths. |
| 2,4 | attestation.go:516; attestation.go:457 | Fixed: trust JSON must be one object, rejecting null, duplicate keys and trailing JSON (reuse strict receipt JSON tokenizer); JWKS fetch must use same parser. |
| 2,4 | attestation.go:663,674,856 | Fixed: empty image pins must never match a missing/wrong-typed claim coerced to empty string. |
| 2,4 | attestation.go:762 | Fixed: reject nonfinite/out-of-range numeric expiration before float-to-int conversion. |
| 3 | extras.go:34,71; chat.go:154 | Fixed: map merges are case-sensitive and can make typed/caller overrides nondeterministic. Merge through http.Header.Set/Get then retain public single-value map API. |
| 3 | client.go:41,80,148,225; transport.go:289,343,351 | Intentionally-unchanged public maps: existing API is single-valued; transport canonicalizes with Set. No repeated response headers are merged into these maps. |
| 3 | broadcast.go:32,188 | Intentionally-unchanged: JSON configuration sent to server, not HTTP request header assembly. |
| 3 | transport.go:495,511; attestation.go:408,440; telemetry_reporter.go:1189–1193; retry_policy.go:45,88,96; telemetry.go:964,977; telemetry_reporter.go:965,1112; session.go:320,346,388 | Already-safe: net/http.Header operations; credentials enter through Set before Del; response Values preserves repetition; MIME reader canonicalizes. |
| 4 | chat.go:43,46; oauth.go:124,133; attestation.go:485,666,677; receipts.go:607–610,836,845; session.go:113 | Already-safe: explicit len/nil checks before wire-derived access. TLS certificate entries are nonnil by crypto/tls construction. |
| 4 | transport.go:173–174; telemetry.go:303,1343; telemetry_reporter.go:382,874,879 | Already-safe: candidate lists built nonempty by plane router; local queues/counters have length guards, not decoded JSON. |
| 4 | errors.go:241,273; sse.go:189,227; chat.go:125; models.go:389; receipts.go:958–1033 | Already-safe: decode errors checked. extraFields is called only after successful same-object decode. Strict receipt tokenizer rejects duplicates/trailing data and preserves numbers. |
| 4 | errors.go:253; transport.go:240; retry_policy.go:112,131; telemetry_reporter.go:1073,1109; receipts.go:1232,1236 | Intentionally-unchanged: retry/terminal classification comes from HTTP status and headers, not malformed error JSON; malformed optional telemetry policy is ignored; receipt capture skips unrelated SSE payloads but verification still requires a valid signed receipt. |
| 4 | sse.go:154 | Intentionally-unchanged: legacy private convenience helper discards parse error for tests; production iterators call the error-returning parser. |

No env/storage JSON decoders and no DisallowUnknownFields calls exist. Env inputs are strings/bools, not dynamic JSON. No new required pass-through fields are planned.

Lint-expanded inventory (same audit classes):

| Class | Original site | Verdict |
|---|---|---|
| 1 | oauth_loopback.go:108 | Fixed: checked TCP address helper; stdlib listener normally guarantees type, nil/wrong-type helper input now returns an error. |
| 4 | telemetry_reporter.go:1200 | Fixed: a failed body read discards partial optional policy bytes; the already-received status still owns acknowledgement. |
| 4 | chat_types.go:698 | Fixed: check Int64 conversion error and retain default index 0 on invalid input; no silent saturated index on overflow. |
| 4 | sse.go:154 | Already-safe private test convenience helper now explicitly checks parse errors; behavior unchanged. |
| 3 | oauth_loopback.go:104,119 | Fixed lint hygiene: context-aware listen and header-read timeout; no response schema change. |


The complete original source-site index is [boundary-sites.md](boundary-sites.md). Final file locations, mutation results, static limitations, all suppressions, and verification are in [boundary-audit-results.md](boundary-audit-results.md).
