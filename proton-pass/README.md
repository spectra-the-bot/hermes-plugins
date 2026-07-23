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
    binary_path: ""              # empty: discover pass-cli on PATH
    command_timeout_seconds: 30
    cache_ttl_seconds: 0          # default: no plaintext secret-value cache
    override_existing: true
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

Non-`Active` items (trashed/deleted) are ignored. Unknown item types and
unsupported field variants are ignored. Invalid environment names, empty
supported values, duplicate names, malformed active item structures, malformed JSON,
or partial output reject the **entire** fetch. Values are never logged.

## Session and cache security

The plugin creates profile-specific state below
`<HERMES_HOME>/state/proton-pass/`. A SHA-256 binding covers the PAT, verified
plain-PAT identity name, parser mode, and privilege class; raw PAT material is
never persisted. Token rotation or a different account causes a fresh login in
the owned session. Agent and human identity structures fail closed.

`cache_ttl_seconds: 0` disables secret-value caching. A positive value opts in
to Hermes' shared plaintext `DiskCache`, stored at
`<HERMES_HOME>/cache/proton_pass_cache.json` with the framework's atomic-write
and POSIX permission semantics. Version and identity checks still occur before
a cache read. Treat that cache as a secret store on every platform.

## Threat-model boundary

This source cannot verify the vault role because `pass-cli info --output json`
does not expose PAT vault grants. Creating a dedicated PAT and limiting it to
Viewer access on only the runtime vault is an operator provisioning step.
