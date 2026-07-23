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
    command_timeout_seconds: 30   # finite, positive, maximum 300 seconds
    cache_ttl_seconds: 0          # 0 disables caching; maximum 2,592,000 seconds
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

Runtime-control destinations are compared case-insensitively against a
conservative denylist and reject the entire fetch. Categories include process
and shell controls (`PATH`, `SHELL`, `COMSPEC`, `PATHEXT`), loader and language
runtime controls (`LD_*`, `DYLD_*`, `PYTHON*`, `NODE_*`, `RUBY*`, `PERL*`, Java
option variables), VCS/SSH controls (`GIT_*`, `HG*`, `SVN_*`, `P4*`, `SSH_*`),
proxies and network trust, config/home/temp paths (`XDG_*`, `HOME`, `TMP*`),
package managers, and OpenSSL, curl, wget, Docker, Kubernetes, Hermes, and
Proton Pass controls.
Examples rejected in any letter case include `GIT_SSH_COMMAND`, `SSH_ASKPASS`,
`JAVA_TOOL_OPTIONS`, `ALL_PROXY`, `XDG_CONFIG_HOME`, `NPM_CONFIG_PREFIX`,
`OPENSSL_CONF`, `DOCKER_HOST`, and `KUBECONFIG`. This is a defense-in-depth
control list, not a claim to enumerate every environment variable interpreted
by every executable. Ordinary secret destinations such as `AWS_ACCESS_KEY_ID`,
`OPENAI_API_KEY`, and `DATABASE_URL` remain supported.

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
tree. Session binding inspects at most 1,024 tree entries and 64 MiB of regular
file data; exceeding either limit fails the fetch before an unbounded walk or
file read.

`cache_ttl_seconds: 0` disables secret-value caching. A positive value opts in
to Hermes' shared plaintext `DiskCache`, stored at
`<HERMES_HOME>/cache/proton_pass_cache.json` with the framework's atomic-write
and POSIX permission semantics. Version and identity checks still occur before
a cache read. Before calling `DiskCache.read`, the plugin opens the raw cache
without following a final symlink where the platform supports `O_NOFOLLOW` and
strictly validates JSON structure, duplicate keys, all secret member types,
the exact serialized cache key, and a finite positive timestamp no more than
five seconds in the future and still within the configured TTL. The integrity
envelope binds all returned names, values, and `fetched_at` to the cache
context. A missing, malformed, altered, expired, future-dated, or mismatched
entry is a total miss and the old cache file is removed before one fresh bulk
read. TTL zero also removes this plugin's existing cache before every fetch.
Treat that cache as a secret store on every platform.

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
limits before parsing results into the cache. `command_timeout_seconds` is
explicitly bounded at 300 seconds, so the host fetch budget is finite and at
most 1,815 seconds; `cache_ttl_seconds` is bounded at 2,592,000 seconds (30
days). Values above either limit, including huge finite values, are rejected
before CLI execution. Filesystem checks use `lstat`,
`O_NOFOLLOW` where available, canonical executable targets, and atomic rename,
but cannot eliminate all check/use races. Windows reparse points and ACLs do
not receive a publisher/DACL guarantee here; Windows operators should install
the official CLI in an access-controlled location and configure that absolute
path. The plugin intentionally does not attempt brittle platform code-signing
or publisher validation.
