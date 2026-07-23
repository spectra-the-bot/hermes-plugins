# hermes-plugins

Production-ready standalone plugins for [Hermes Agent](https://github.com/NousResearch/hermes-agent).

## Plugins

| Plugin | Description | Install identifier |
|---|---|---|
| [Proton Pass](proton-pass/) | Runtime-only bulk secret source using a plain read-only PAT; Agent identities are rejected. | `spectra-the-bot/hermes-plugins/proton-pass` |

Install a plugin subdirectory with:

```sh
hermes plugins install spectra-the-bot/hermes-plugins/proton-pass
```

Each plugin directory is a self-contained Hermes directory-plugin artifact.
