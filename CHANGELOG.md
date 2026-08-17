# Changelog

## Unreleased

- Send the `x-tr-client` client-observed reliability telemetry header (contract v1, header channel only). Content-free by construction — closed enums and bounded integers — never sent to custom base URLs or on control-plane calls, and disabled by `Telemetry: false`, `TRUSTEDROUTER_TELEMETRY=0`, or `DO_NOT_TRACK=1`.
- Drop the trailing OS token from the User-Agent so it parses as `trusted-router-go/SEMVER go/version`, the shape the telemetry contract (§3.1) derives the SDK identity from.
- Regional failover now re-requests `api.trustedrouter.com` as the global load balancer; per-region API hostnames were removed.
- Bound and harden the transport-error message. The typed SDK error is now capped at 2048 bytes in total (prefix included) and cuts on a rune boundary, so one pathological transport error value cannot balloon or mangle it. Flattening a caller-injected error value can also no longer take the process down: rendering still goes through fmt with the same `%s` verb as before — so an error's own `fmt.Formatter` keeps rendering, and redacting, exactly as it did — and a recover guard now covers the one shape fmt re-panics on, an `Error()` that panics with a value whose `Error()` panics in turn, which reaches the SDK unwrapped on the mid-stream body path. A plainly panicking `Error()` was already survivable through fmt and still renders fmt's `%!s(PANIC=...)` marker, now bounded.
