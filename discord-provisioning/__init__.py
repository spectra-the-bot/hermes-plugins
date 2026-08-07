"""Reusable Discord server provisioning tools for Hermes Agent.

The plugin deliberately uses Discord's REST API instead of a gateway client. This
keeps it independent of any one Hermes gateway process while preserving active-
profile secret scoping through :func:`agent.secret_scope.get_secret`.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from typing import Any

from agent.secret_scope import get_secret

logger = logging.getLogger(__name__)

DISCORD_API_BASE = "https://discord.com/api/v10"
_TOOL_NAME = "discord_provisioning"
_TOOLSET = "discord-provisioning"
_ACTIONS = ("create_channel", "create_role", "set_channel_permissions")
_REQUIRED_PARAMS = {
    "create_channel": ("guild_id", "name"),
    "create_role": ("guild_id", "name"),
    "set_channel_permissions": ("channel_id", "target_id", "target_type"),
}
_RESPONSE_LIMIT = 1024 * 1024
_ERROR_LIMIT = 64 * 1024

# Discord API v10 permission flags. Named permissions keep models and operators
# from having to calculate or paste opaque bitmasks.
_PERMISSION_BITS = {
    "CREATE_INSTANT_INVITE": 1 << 0,
    "KICK_MEMBERS": 1 << 1,
    "BAN_MEMBERS": 1 << 2,
    "ADMINISTRATOR": 1 << 3,
    "MANAGE_CHANNELS": 1 << 4,
    "MANAGE_GUILD": 1 << 5,
    "ADD_REACTIONS": 1 << 6,
    "VIEW_AUDIT_LOG": 1 << 7,
    "PRIORITY_SPEAKER": 1 << 8,
    "STREAM": 1 << 9,
    "VIEW_CHANNEL": 1 << 10,
    "SEND_MESSAGES": 1 << 11,
    "SEND_TTS_MESSAGES": 1 << 12,
    "MANAGE_MESSAGES": 1 << 13,
    "EMBED_LINKS": 1 << 14,
    "ATTACH_FILES": 1 << 15,
    "READ_MESSAGE_HISTORY": 1 << 16,
    "MENTION_EVERYONE": 1 << 17,
    "USE_EXTERNAL_EMOJIS": 1 << 18,
    "VIEW_GUILD_INSIGHTS": 1 << 19,
    "CONNECT": 1 << 20,
    "SPEAK": 1 << 21,
    "MUTE_MEMBERS": 1 << 22,
    "DEAFEN_MEMBERS": 1 << 23,
    "MOVE_MEMBERS": 1 << 24,
    "USE_VAD": 1 << 25,
    "CHANGE_NICKNAME": 1 << 26,
    "MANAGE_NICKNAMES": 1 << 27,
    "MANAGE_ROLES": 1 << 28,
    "MANAGE_WEBHOOKS": 1 << 29,
    "MANAGE_GUILD_EXPRESSIONS": 1 << 30,
    "USE_APPLICATION_COMMANDS": 1 << 31,
    "REQUEST_TO_SPEAK": 1 << 32,
    "MANAGE_EVENTS": 1 << 33,
    "MANAGE_THREADS": 1 << 34,
    "CREATE_PUBLIC_THREADS": 1 << 35,
    "CREATE_PRIVATE_THREADS": 1 << 36,
    "USE_EXTERNAL_STICKERS": 1 << 37,
    "SEND_MESSAGES_IN_THREADS": 1 << 38,
    "USE_EMBEDDED_ACTIVITIES": 1 << 39,
    "MODERATE_MEMBERS": 1 << 40,
    "VIEW_CREATOR_MONETIZATION_ANALYTICS": 1 << 41,
    "USE_SOUNDBOARD": 1 << 42,
    "CREATE_GUILD_EXPRESSIONS": 1 << 43,
    "CREATE_EVENTS": 1 << 44,
    "USE_EXTERNAL_SOUNDS": 1 << 45,
    "SEND_VOICE_MESSAGES": 1 << 46,
    "SET_VOICE_CHANNEL_STATUS": 1 << 48,
    "SEND_POLLS": 1 << 49,
    "USE_EXTERNAL_APPS": 1 << 50,
    "PIN_MESSAGES": 1 << 51,
    "BYPASS_SLOWMODE": 1 << 52,
}


class DiscordAPIError(RuntimeError):
    """A bounded Discord REST error suitable for operator diagnostics."""

    def __init__(self, status: int, body: str):
        self.status = status
        self.body = body
        super().__init__(f"Discord API error {status}: {body}")


def _error(message: str, **details: Any) -> str:
    return json.dumps({"error": message, **details})


def _get_bot_token() -> str | None:
    """Resolve the token from the active Hermes profile's secret scope."""
    return (get_secret("DISCORD_BOT_TOKEN", "") or "").strip() or None


def _read_limited(source: Any, limit: int, label: str) -> bytes:
    payload = bytes(source.read(limit + 1))
    if len(payload) > limit:
        raise DiscordAPIError(502, f"Discord API {label} exceeded {limit} bytes")
    return payload


def _discord_request(
    method: str,
    path: str,
    token: str,
    *,
    body: Mapping[str, Any] | None = None,
    audit_log_reason: str | None = None,
    timeout: int = 15,
) -> Any:
    data = json.dumps(dict(body)).encode() if body is not None else None
    headers = {
        "Authorization": f"Bot {token}",
        "Content-Type": "application/json",
        "User-Agent": "Hermes-Discord-Provisioning/1.0",
    }
    if audit_log_reason:
        headers["X-Audit-Log-Reason"] = urllib.parse.quote(audit_log_reason, safe="")
    request = urllib.request.Request(  # noqa: S310 -- fixed HTTPS Discord API base
        f"{DISCORD_API_BASE}{path}",
        data=data,
        method=method,
        headers=headers,
    )
    try:
        # The origin is a module constant and path components are validated snowflakes.
        with urllib.request.urlopen(  # noqa: S310  # nosec B310
            request, timeout=timeout
        ) as response:
            if response.status == 204:
                return None
            payload = _read_limited(response, _RESPONSE_LIMIT, "response")
            return json.loads(payload.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            payload = _read_limited(exc, _ERROR_LIMIT, "error response")
            error_body = payload.decode("utf-8", errors="replace")
        except DiscordAPIError as too_large:
            error_body = too_large.body
        except Exception:
            error_body = ""
        raise DiscordAPIError(exc.code, error_body) from exc
    except urllib.error.URLError as exc:
        raise DiscordAPIError(503, f"Discord API unavailable: {exc.reason}") from exc


def _discord_config() -> Mapping[str, Any] | None:
    """Load the active profile's Discord configuration, failing closed."""
    try:
        from hermes_cli.config import load_config

        config = load_config() or {}
    except Exception:
        logger.exception("Could not load Discord configuration; denying provisioning actions")
        return None

    if not isinstance(config, Mapping):
        logger.error("Hermes config is not a mapping; denying provisioning actions")
        return None
    discord_config = config.get("discord") or {}
    if not isinstance(discord_config, Mapping):
        logger.error("discord config is not a mapping; denying provisioning actions")
        return None
    return discord_config


def _allowed_actions() -> frozenset[str]:
    """Return explicitly enabled plugin actions from ``discord.server_actions``.

    Missing, empty, or malformed configuration fails closed. Values for built-in
    Discord actions are intentionally ignored so this plugin can share the
    allowlist with ``discord_admin`` without overriding it.
    """
    discord_config = _discord_config()
    if discord_config is None:
        return frozenset()

    raw = discord_config.get("server_actions")
    if raw is None or raw == "":
        return frozenset()
    if isinstance(raw, str):
        configured = [item.strip() for item in raw.split(",") if item.strip()]
    elif isinstance(raw, Sequence) and not isinstance(raw, (bytes, bytearray)):
        configured = [str(item).strip() for item in raw if str(item).strip()]
    else:
        logger.error("discord.server_actions has an invalid type; denying provisioning actions")
        return frozenset()
    return frozenset(action for action in configured if action in _ACTIONS)


def _operator_flag(name: str) -> bool:
    discord_config = _discord_config()
    return discord_config is not None and discord_config.get(name) is True


def _administrator_roles_allowed() -> bool:
    return _operator_flag("allow_administrator_roles")


def _everyone_permission_grants_allowed() -> bool:
    return _operator_flag("allow_everyone_permission_grants")


def _check_requirements() -> bool:
    return bool(_get_bot_token()) and bool(_allowed_actions())


def _validate_snowflake(value: Any, field: str) -> str:
    snowflake = str(value or "").strip()
    if not snowflake.isascii() or not snowflake.isdigit() or not 1 <= len(snowflake) <= 20:
        raise ValueError(f"{field} must be a decimal Discord snowflake ID")
    return snowflake


def _permission_mask(permission_names: Any = None) -> tuple[int, list[str]]:
    names: list[str] = []
    if permission_names:
        if isinstance(permission_names, str):
            raw_names: Sequence[Any] = permission_names.split(",")
        elif isinstance(permission_names, Sequence) and not isinstance(
            permission_names, (bytes, bytearray)
        ):
            raw_names = permission_names
        else:
            raise ValueError("Permission names must be an array or comma-separated string")
        names.extend(str(name).strip().upper() for name in raw_names if str(name).strip())

    names = list(dict.fromkeys(names))
    unknown = [name for name in names if name not in _PERMISSION_BITS]
    if unknown:
        raise ValueError(f"Unknown Discord permission(s): {', '.join(unknown)}")

    mask = 0
    for name in names:
        mask |= _PERMISSION_BITS[name]
    return mask, names


def _audit_log_reason(args: Mapping[str, Any]) -> str | None:
    reason = str(args.get("audit_log_reason") or "").strip()
    if not reason:
        return None
    if len(reason) > 512:
        raise ValueError("audit_log_reason must be at most 512 characters")
    return reason


def _discord_write(
    method: str,
    path: str,
    token: str,
    args: Mapping[str, Any],
    *,
    body: Mapping[str, Any],
) -> Any:
    kwargs: dict[str, Any] = {"body": body}
    reason = _audit_log_reason(args)
    if reason:
        kwargs["audit_log_reason"] = reason
    return _discord_request(method, path, token, **kwargs)


def _parse_permission_mask(value: Any, field: str) -> int:
    text = str(value if value is not None else "0")
    if not text.isascii() or not text.isdigit():
        raise DiscordAPIError(502, f"Discord API returned an invalid {field} permission mask")
    return int(text)


def _create_channel(token: str, args: Mapping[str, Any]) -> str:
    guild_id = _validate_snowflake(args.get("guild_id"), "guild_id")
    name = str(args.get("name") or "").strip()
    if not name:
        raise ValueError("name must not be empty")
    if len(name) > 100:
        raise ValueError("name must be at most 100 characters")

    channel_type = str(args.get("channel_type") or "text")
    channel_types = {"text": 0, "voice": 2, "category": 4}
    if channel_type not in channel_types:
        raise ValueError("channel_type must be text, voice, or category")

    body: dict[str, Any] = {"name": name, "type": channel_types[channel_type]}
    parent_id = str(args.get("parent_id") or "").strip()
    if parent_id:
        if channel_type == "category":
            raise ValueError("A category channel cannot have parent_id")
        body["parent_id"] = _validate_snowflake(parent_id, "parent_id")
    topic = str(args.get("topic") or "").strip()
    if topic:
        if channel_type != "text":
            raise ValueError("topic is supported only for text channels")
        if len(topic) > 1024:
            raise ValueError("topic must be at most 1024 characters")
        body["topic"] = topic

    channel = _discord_write("POST", f"/guilds/{guild_id}/channels", token, args, body=body)
    return json.dumps(
        {
            "success": True,
            "channel_id": channel["id"],
            "name": channel.get("name"),
            "type": channel_type,
            "guild_id": channel.get("guild_id", guild_id),
            "parent_id": channel.get("parent_id"),
            "topic": channel.get("topic"),
        }
    )


def _create_role(token: str, args: Mapping[str, Any]) -> str:
    guild_id = _validate_snowflake(args.get("guild_id"), "guild_id")
    name = str(args.get("name") or "").strip()
    if not name:
        raise ValueError("name must not be empty")
    if len(name) > 100:
        raise ValueError("name must be at most 100 characters")

    mask, permission_names = _permission_mask(args.get("permissions"))
    if "ADMINISTRATOR" in permission_names and not _administrator_roles_allowed():
        raise ValueError(
            "Refusing to create an Administrator role unless the operator sets "
            "discord.allow_administrator_roles: true; prefer channel-scoped permissions"
        )

    role = _discord_write(
        "POST",
        f"/guilds/{guild_id}/roles",
        token,
        args,
        body={
            "name": name,
            "permissions": str(mask),
            "hoist": args.get("hoist") is True,
            "mentionable": args.get("mentionable") is True,
        },
    )
    return json.dumps(
        {
            "success": True,
            "role_id": role["id"],
            "name": role.get("name"),
            "permissions": role.get("permissions", str(mask)),
            "permission_names": permission_names,
            "position": role.get("position"),
            "managed": role.get("managed", False),
        }
    )


def _set_channel_permissions(token: str, args: Mapping[str, Any]) -> str:
    channel_id = _validate_snowflake(args.get("channel_id"), "channel_id")
    target_id = _validate_snowflake(args.get("target_id"), "target_id")
    target_type = str(args.get("target_type") or "")
    target_types = {"role": 0, "member": 1}
    if target_type not in target_types:
        raise ValueError("target_type must be role or member")

    allow, allow_names = _permission_mask(args.get("allow_permissions"))
    deny, deny_names = _permission_mask(args.get("deny_permissions"))
    clear, clear_names = _permission_mask(args.get("clear_permissions"))
    changed_names = set(allow_names) | set(deny_names) | set(clear_names)
    if not changed_names:
        raise ValueError(
            "set_channel_permissions requires at least one allow_permissions, "
            "deny_permissions, or clear_permissions value"
        )
    if "ADMINISTRATOR" in changed_names:
        raise ValueError("ADMINISTRATOR is guild-wide and is not valid in a channel overwrite")
    overlap = (
        (set(allow_names) & set(deny_names))
        | (set(allow_names) & set(clear_names))
        | (set(deny_names) & set(clear_names))
    )
    if overlap:
        raise ValueError(f"Allow/deny/clear permission lists overlap: {', '.join(sorted(overlap))}")

    channel = _discord_request("GET", f"/channels/{channel_id}", token)
    if not isinstance(channel, Mapping):
        raise DiscordAPIError(502, "Discord API returned an invalid channel object")
    guild_id = _validate_snowflake(channel.get("guild_id"), "channel.guild_id")
    overwrite_type = target_types[target_type]
    existing_allow = 0
    existing_deny = 0
    overwrites = channel.get("permission_overwrites") or []
    if not isinstance(overwrites, Sequence) or isinstance(overwrites, (str, bytes, bytearray)):
        raise DiscordAPIError(502, "Discord API returned invalid permission_overwrites")
    for overwrite in overwrites:
        if not isinstance(overwrite, Mapping):
            raise DiscordAPIError(502, "Discord API returned an invalid permission overwrite")
        if str(overwrite.get("id")) == target_id and overwrite.get("type") == overwrite_type:
            existing_allow = _parse_permission_mask(overwrite.get("allow"), "allow")
            existing_deny = _parse_permission_mask(overwrite.get("deny"), "deny")
            break

    if (
        target_type == "role"
        and target_id == guild_id
        and allow
        and not _everyone_permission_grants_allowed()
    ):
        raise ValueError(
            "Refusing a positive @everyone grant unless the operator sets "
            "discord.allow_everyone_permission_grants: true"
        )

    final_allow = (existing_allow | allow) & ~deny & ~clear
    final_deny = (existing_deny | deny) & ~allow & ~clear
    _discord_write(
        "PUT",
        f"/channels/{channel_id}/permissions/{target_id}",
        token,
        args,
        body={
            "type": overwrite_type,
            "allow": str(final_allow),
            "deny": str(final_deny),
        },
    )
    return json.dumps(
        {
            "success": True,
            "channel_id": channel_id,
            "guild_id": guild_id,
            "target_id": target_id,
            "target_type": target_type,
            "allow": str(final_allow),
            "deny": str(final_deny),
            "allowed_permissions_added": allow_names,
            "denied_permissions_added": deny_names,
            "permissions_cleared": clear_names,
        }
    )


_ACTION_HANDLERS = {
    "create_channel": _create_channel,
    "create_role": _create_role,
    "set_channel_permissions": _set_channel_permissions,
}


def _enrich_api_error(action: str, error: DiscordAPIError) -> str:
    hints = {
        "create_channel": "The bot needs MANAGE_CHANNELS in this server.",
        "create_role": "The bot needs MANAGE_ROLES and sufficient role hierarchy position.",
        "set_channel_permissions": (
            "The bot needs MANAGE_ROLES, channel visibility, and sufficient role hierarchy."
        ),
    }
    if error.status == 403:
        return f"Discord API 403 on '{action}'. {hints[action]} Raw: {error.body}"
    if error.status == 429:
        return f"Discord rate-limited '{action}'. Retry after the interval in: {error.body}"
    return str(error)


def discord_provisioning_handler(args: Mapping[str, Any], **_kwargs: Any) -> str:
    """Dispatch one allowlisted provisioning action."""
    token = _get_bot_token()
    if not token:
        return _error("DISCORD_BOT_TOKEN is not configured in the active Hermes profile")

    action = str(args.get("action") or "")
    handler = _ACTION_HANDLERS.get(action)
    if handler is None:
        return _error("Unknown action", available_actions=list(_ACTIONS))

    allowed = _allowed_actions()
    if action not in allowed:
        return _error(
            f"Action '{action}' is disabled by discord.server_actions",
            allowed_actions=sorted(allowed),
        )

    missing = [name for name in _REQUIRED_PARAMS[action] if not args.get(name)]
    if missing:
        return _error(f"Missing required parameters: {', '.join(missing)}")

    try:
        return handler(token, args)
    except ValueError as exc:
        return _error(str(exc))
    except DiscordAPIError as exc:
        logger.warning("Discord provisioning action %s failed: %s", action, exc)
        return _error(_enrich_api_error(action, exc))
    except Exception as exc:
        logger.exception("Unexpected Discord provisioning failure in %s", action)
        return _error(f"Unexpected error: {exc}")


_PERMISSION_ENUM = sorted(_PERMISSION_BITS)
DISCORD_PROVISIONING_SCHEMA: dict[str, Any] = {
    "name": _TOOL_NAME,
    "description": (
        "Provision Discord channels, roles, and channel permission overwrites through the "
        "Discord REST API. Every guild/channel/role/member ID must be supplied per call; "
        "the plugin contains no deployment-specific defaults. Runtime execution is gated "
        "by the active profile's discord.server_actions allowlist. Creating channels and "
        "roles is non-idempotent: inspect Discord state before retrying an uncertain call. "
        "Permission updates merge with the existing overwrite and preserve unnamed bits."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": list(_ACTIONS)},
            "guild_id": {"type": "string", "description": "Discord server ID."},
            "channel_id": {"type": "string", "description": "Discord channel ID."},
            "target_id": {
                "type": "string",
                "description": "Role or member ID for a channel overwrite.",
            },
            "target_type": {"type": "string", "enum": ["role", "member"]},
            "name": {"type": "string", "description": "New channel or role name."},
            "channel_type": {
                "type": "string",
                "enum": ["text", "voice", "category"],
                "description": "Channel type; defaults to text.",
            },
            "parent_id": {"type": "string", "description": "Optional category ID."},
            "topic": {"type": "string", "description": "Optional text-channel topic."},
            "permissions": {
                "type": "array",
                "items": {"type": "string", "enum": _PERMISSION_ENUM},
                "description": "Named guild permissions for create_role.",
            },
            "allow_permissions": {
                "type": "array",
                "items": {"type": "string", "enum": _PERMISSION_ENUM},
                "description": "Permissions to add to allow and remove from deny.",
            },
            "deny_permissions": {
                "type": "array",
                "items": {"type": "string", "enum": _PERMISSION_ENUM},
                "description": "Permissions to add to deny and remove from allow.",
            },
            "clear_permissions": {
                "type": "array",
                "items": {"type": "string", "enum": _PERMISSION_ENUM},
                "description": (
                    "Permissions to remove from both allow and deny while preserving all "
                    "other existing overwrite bits."
                ),
            },
            "hoist": {"type": "boolean", "description": "Hoist a newly created role."},
            "mentionable": {
                "type": "boolean",
                "description": "Make a newly created role mentionable.",
            },
            "audit_log_reason": {
                "type": "string",
                "maxLength": 512,
                "description": "Optional reason recorded in Discord's audit log.",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
}


def register(ctx: Any) -> None:
    """Register the isolated provisioning tool without replacing discord_admin."""
    ctx.register_tool(
        name=_TOOL_NAME,
        toolset=_TOOLSET,
        schema=DISCORD_PROVISIONING_SCHEMA,
        handler=discord_provisioning_handler,
        check_fn=_check_requirements,
        requires_env=["DISCORD_BOT_TOKEN"],
        description="Create Discord channels and roles and manage channel overwrites.",
        emoji="🏗️",
    )
