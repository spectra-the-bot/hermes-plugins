# hermes-plugins

Production-ready standalone plugins for [Hermes Agent](https://github.com/NousResearch/hermes-agent).

## Plugins

| Plugin | Description | Install identifier |
|---|---|---|
| [Proton Pass](proton-pass/) | Runtime-only bulk secret source using a plain read-only PAT; Agent identities are rejected. | `spectra-the-bot/hermes-plugins/proton-pass` |
| [Discord Provisioning](discord-provisioning/) | Safely create Discord channels and roles and manage channel permission overwrites without replacing `discord_admin`. | `spectra-the-bot/hermes-plugins/discord-provisioning` |

Install a plugin subdirectory with:

```sh
hermes plugins install spectra-the-bot/hermes-plugins/<plugin-directory>
```

Each plugin directory is a self-contained Hermes directory-plugin artifact.
