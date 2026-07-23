# Changelog

## Unreleased

- Bound each command timeout to 300 seconds, the derived host fetch budget to
  1,815 seconds, plaintext cache TTL to 30 days, and isolated session-tree
  inspection to 1,024 entries and 64 MiB of regular files.
- Validate the lossless raw cache JSON before Hermes `DiskCache.read`, reject
  duplicate/extra/malformed/nonfinite/future/mismatched entries, and bind
  `fetched_at` into the SHA-256 integrity envelope.
- Expand case-normalized runtime-control destination rejection across process,
  shell, loader, Git/SSH, proxy/trust, config/temp, runtime, package-manager,
  Windows, and common developer-tool controls while preserving ordinary API
  secret mappings.
- Reject Make and interactive-shell command controls, and fail safely when an
  oversized inherited host timeout cannot be converted to a float.

## 1.0.0

- Add the runtime-only Proton Pass bulk secret source with plain-PAT identity
  enforcement and profile-isolated session state.
- Fail closed on malformed, partial, oversized, unknown-state, duplicate, or
  runtime-control environment mappings.
- Add trusted fixed-location CLI discovery, executable/path validation,
  session-tree binding, symlink-resistant state handling, and atomic reset.
- Add opt-in plaintext caching with a context-bound integrity envelope and
  eager stale-cache cleanup; caching remains disabled by default.