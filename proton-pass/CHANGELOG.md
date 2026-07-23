# Changelog

## 1.0.0

- Add the runtime-only Proton Pass bulk secret source with plain-PAT identity
  enforcement and profile-isolated session state.
- Fail closed on malformed, partial, oversized, unknown-state, duplicate, or
  runtime-control environment mappings.
- Add trusted fixed-location CLI discovery, executable/path validation,
  session-tree binding, symlink-resistant state handling, and atomic reset.
- Add opt-in plaintext caching with a context-bound integrity envelope and
  eager stale-cache cleanup; caching remains disabled by default.