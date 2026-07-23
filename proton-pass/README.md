# Proton Pass runtime secret source

A standalone Hermes Agent plugin that loads environment variables from Proton
Pass at startup. It is deliberately **runtime-only and read-only**:

- accepts only the native `PROTON_PASS_PERSONAL_ACCESS_TOKEN` bootstrap variable;
- requires a plain PAT with access limited to the selected vault (Viewer role is recommended);
- explicitly rejects structured Agent identities and normal human sessions;
- uses exactly one `pass-cli item list <vault> --output json --show-secrets` bulk read;
- never uses `item view`, Agent reasons, interactive login, or write operations;
- gives `pass-cli` an isolated, profile-scoped home/session and a minimal child environment;
- keeps the PAT out of argv, output, logs, cache files, and session fingerprints.

## Requirements

- Hermes Agent with secret-source plugin API v1.
- [Proton Pass CLI](https://github.com/protonpass/pass-cli) **2.1.0 or newer**.
- A dedicated plain Proton Pass PAT, narrowly scoped to the configured vault.
  Assign Viewer access where Proton Pass account administration permits it.

## Install

This repository contains multiple plugins. Install the subdirectory with the
Hermes-supported identifier syntax:

```sh
hermes plugins install spectra-the-bot/hermes-plugins/proton-pass
```

Enable `proton-pass` when prompted (or use `hermes plugins enable proton-pass`),
then configure Hermes:

```yaml
plugins:
  enabled:
    - proton-pass

secrets:
  sources:
    - proton_pass
  proton_pass:
    enabled: true
    vault: "Hermes Runtime"
    binary_path: ""              # empty: fixed standard-location discovery
    command_timeout_seconds: 30
    cache_ttl_seconds: 0          # default: no plaintext secret-value cache
    override_existing: false      # opt in only if vault values should overwrite env
```

Store the PAT through the installer prompt or in the active profile's Hermes
`.env`:

```text
PROTON_PASS_PERSONAL_ACCESS_TOKEN=<plain-PAT>
```

Do not place Agent tokens in this variable. Do not configure a shared
`PROTON_PASS_SESSION_DIR`; the plugin always supplies its own state path under
the active `HERMES_HOME`. Vault names beginning with `-` are rejected because
the public CLI contract takes the vault name as a positional argument.

With an empty `binary_path`, inherited `PATH` is deliberately ignored. On
POSIX systems the plugin checks `~/.local/bin/pass-cli`,
`/opt/homebrew/bin/pass-cli`, `/usr/local/bin/pass-cli`, and
`/usr/bin/pass-cli`, in that order. The resolved executable must be a regular,
executable file whose target and ancestors are owned by the current user or
root and are not group/world-writable. Explicit paths receive the same checks;
safe package-manager symlinks are resolved before validation. Windows users
must set an absolute `binary_path` because Proton does not document one stable
system-wide installation location.

Restart Hermes after installation/configuration. Directory plugins are
discovered after the first dotenv load in the discovering process, so the
source applies to subsequently spawned Hermes processes (gateway children,
cron sessions, and subagents).

## Supported item mapping

Only documented public `pass-cli item list --output json --show-secrets`
shapes are mapped:

| Proton Pass shape | Environment mapping |
|---|---|
| Active `Login` item | item `content.title` → `Login.password` |
| `content.extra_fields` | field `name` → `Hidden` or `Text` value |
| Active `Custom.sections[].section_fields` | field `name` → `Hidden` or `Text` value |

Exactly `Trashed` items are ignored. Exactly `Active` items are parsed; every
other or missing state rejects the fetch. Unknown item types and unsupported
field variants are ignored. Invalid environment names, empty supported values,
duplicate names, malformed active item structures, malformed JSON, partial
output, or configured structural-size limits reject the **entire** fetch.
Values are never logged.

Runtime-control destinations are always reserved and reject the entire fetch:
`PATH`, `PYTHONPATH`, `PYTHONHOME`, `LD_PRELOAD`, `LD_LIBRARY_PATH`,
`NODE_OPTIONS`, `RUBYOPT`, `PERL5OPT`, `BASH_ENV`, `ENV`, `ZDOTDIR`,
`SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`,
`NODE_EXTRA_CA_CERTS`, and every name beginning with `DYLD_`, `HERMES_`, or
`PROTON_PASS_`. This denylist prevents vault fields from changing execution,
runtime loading, trust stores, or Hermes/Proton control state.

## Session and cache security

The plugin creates profile-specific state below
`<HERMES_HOME>/state/proton-pass/`. A SHA-256 binding covers the PAT, verified
plain-PAT identity name, parser mode, privilege class, and a deterministic
digest of the isolated session tree; raw PAT material is never persisted.
Token rotation, a different account, or replacement session data causes a
fresh login in the owned session. Agent and human identity structures fail
closed. Existing profile, state, session, lock, fingerprint, and cache path
components are checked without following symlinks. Session reset first
atomically renames the owned session directory before deleting the retired
tree.

`cache_ttl_seconds: 0` disables secret-value caching. A positive value opts in
to Hermes' shared plaintext `DiskCache`, stored at
`<HERMES_HOME>/cache/proton_pass_cache.json` with the framework's atomic-write
and POSIX permission semantics. Version and identity checks still occur before
a cache read. An integrity envelope binds all returned names and values to the
cache context; a missing, malformed, altered, expired, or mismatched entry is a
total miss and the old cache file is removed before refetching. TTL zero also
removes this plugin's existing cache before every fetch. Treat that cache as a
secret store on every platform.

When disabling or uninstalling the plugin, revoke its PAT and manually remove
`<HERMES_HOME>/cache/proton_pass_cache.json` and
`<HERMES_HOME>/state/proton-pass/` if retained state is not wanted. Atomic
unlink/replace is not guaranteed secure deletion on SSDs, snapshots, backups,
or copy-on-write filesystems.

## Threat-model boundary

This source cannot verify the vault role because `pass-cli info --output json`
does not expose PAT vault grants. Creating a dedicated PAT and limiting it to
Viewer access on only the runtime vault is an operator provisioning step.

Hermes' required `run_secret_cli` helper captures command output before it
returns, so this plugin cannot enforce a true streaming output cap. It applies
a conservative post-capture byte limit and decoded item, field, name, and value
limits before parsing results into the cache. Filesystem checks use `lstat`,
`O_NOFOLLOW` where available, canonical executable targets, and atomic rename,
but cannot eliminate all check/use races. Windows reparse points and ACLs do
not receive a publisher/DACL guarantee here; Windows operators should install
the official CLI in an access-controlled location and configure that absolute
path. The plugin intentionally does not attempt brittle platform code-signing
or publisher validation.
