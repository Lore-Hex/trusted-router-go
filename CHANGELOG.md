# Changelog

## Unreleased

- Regional failover now re-requests `api.trustedrouter.com` as the global load balancer; per-region API hostnames were removed.
- Flatten transport errors defensively at retry exhaustion: a hostile error value (panicking `Error()` from a caller-injected `http.Client`) now yields a bounded placeholder inside the typed SDK error instead of fmt's `%!s(PANIC=...)` marker, and messages are capped at 2048 bytes.
