# Changelog

## Unreleased

- Send the `x-tr-client` client-observed reliability telemetry header (contract v1, header channel only). Content-free by construction — closed enums and bounded integers — never sent to custom base URLs or on control-plane calls, and disabled by `Telemetry: false`, `TRUSTEDROUTER_TELEMETRY=0`, or `DO_NOT_TRACK=1`.
- Drop the trailing OS token from the User-Agent so it parses as `trusted-router-go/SEMVER go/version`, the shape the telemetry contract (§3.1) derives the SDK identity from.
- Regional failover now re-requests `api.trustedrouter.com` as the global load balancer; per-region API hostnames were removed.
