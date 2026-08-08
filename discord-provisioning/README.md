# Discord Provisioning for Hermes Agent

A public, reusable Hermes plugin that adds three privileged Discord provisioning actions:

- `create_channel`
- `create_role`
- `set_channel_permissions`

It registers a separate `discord_provisioning` tool in the `discord-provisioning` toolset. It does **not** replace or override Hermes' built-in `discord_admin` tool.

## Install

```sh
hermes plugins install spectra-the-bot/hermes-plugins/discord-provisioning
```

Enable the plugin in the profile that should be allowed to provision Discord:

```yaml
plugins:
  enabled:
    - discord-provisioning
```

Set `DISCORD_BOT_TOKEN` through that profile's normal Hermes secret source. The plugin resolves the token with Hermes' active-profile secret scope; it never reads another profile's configuration or embeds a token.

Start a new Hermes session or restart the gateway after installation or configuration changes.

## Action policy

The plugin requires its actions to be explicitly listed in Hermes' `discord.server_actions` allowlist. A missing, empty, or malformed setting disables the provisioning tool.

```yaml
discord:
  server_actions:
    - create_channel
    - create_role
    - set_channel_permissions
```

The handler checks this policy on every call, not just when the schema is loaded. Names belonging to built-in `discord_admin` actions may coexist in the same list and are ignored by this plugin.

For profile isolation, only install and enable the plugin in profiles that need it. The tool occupies its own `discord-provisioning` toolset, so restricted agents and cron jobs can omit that toolset or add it to `agent.disabled_toolsets`.

## Discord permissions

The bot needs only the permissions required by the selected operation:

- `create_channel`: `MANAGE_CHANNELS`
- `create_role`: `MANAGE_ROLES`, with the bot's highest role above the new role
- `set_channel_permissions`: `MANAGE_ROLES`, channel visibility, and sufficient role hierarchy

Discord server, channel, category, role, and member IDs are supplied per call. The plugin has no deployment-specific IDs, paths, defaults, bundles, or credentials.

## Safety behavior

- Uses explicit named Discord permissions instead of raw bitmasks or deployment-specific bundles.
- Rejects unknown permission names and `ADMINISTRATOR` in channel overwrites.
- Requires operator configuration—not a tool-call argument—before creating an Administrator role.
- Requires separate operator configuration before positively granting channel permissions to `@everyone`.
- Reads and merges the existing channel overwrite, preserving permissions that the call does not name.
- Requires at least one `allow_permissions`, `deny_permissions`, or `clear_permissions` entry, preventing accidental empty-overwrite replacement.
- Rejects permissions present in more than one allow/deny/clear list.
- Validates every Discord snowflake before constructing a REST path.
- Bounds Discord response and error bodies and produces action-specific `403` diagnostics.
- Supports an optional `audit_log_reason` on writes.
- Does not automatically retry writes. Channel and role creation are non-idempotent; inspect Discord state before retrying an uncertain call.

`set_channel_permissions` is a read-modify-write operation:

- `allow_permissions` adds bits to allow and removes the same bits from deny.
- `deny_permissions` adds bits to deny and removes the same bits from allow.
- `clear_permissions` removes bits from both allow and deny.
- All unnamed existing bits are preserved.

Do not run concurrent overwrite edits for the same target; Discord does not provide a conditional update for this endpoint, so concurrent read-modify-write calls can race.

## High-risk operator flags

Both flags default to disabled and must be literal YAML booleans. They cannot be enabled by model-supplied tool arguments.

```yaml
discord:
  allow_administrator_roles: false
  allow_everyone_permission_grants: false
```

- `allow_administrator_roles`: permits `create_role` to include `ADMINISTRATOR`.
- `allow_everyone_permission_grants`: permits positive `@everyone` channel grants. Denials remain available without this flag.

Enable either only in a tightly controlled profile after reviewing the bot token's Discord permissions and role hierarchy.

## Tool examples

Create a text channel under a category:

```json
{
  "action": "create_channel",
  "guild_id": "<guild-id>",
  "name": "project-chat",
  "channel_type": "text",
  "parent_id": "<category-id>",
  "topic": "Project coordination",
  "audit_log_reason": "Create project coordination channel"
}
```

Create a narrowly scoped role:

```json
{
  "action": "create_role",
  "guild_id": "<guild-id>",
  "name": "project-member",
  "permissions": ["VIEW_CHANNEL", "SEND_MESSAGES"],
  "audit_log_reason": "Create project member role"
}
```

Patch a member overwrite while preserving all unnamed existing bits:

```json
{
  "action": "set_channel_permissions",
  "channel_id": "<channel-id>",
  "target_id": "<member-id>",
  "target_type": "member",
  "allow_permissions": ["VIEW_CHANNEL", "SEND_MESSAGES", "READ_MESSAGE_HISTORY"],
  "deny_permissions": ["MENTION_EVERYONE"],
  "clear_permissions": ["ATTACH_FILES"],
  "audit_log_reason": "Update project member channel access"
}
```
