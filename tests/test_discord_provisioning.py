from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock, call

import pytest

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_PATH = ROOT / "discord-provisioning" / "__init__.py"


@pytest.fixture
def plugin() -> ModuleType:
    spec = importlib.util.spec_from_file_location("discord_provisioning_plugin", PLUGIN_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def allow_all(monkeypatch: pytest.MonkeyPatch, plugin: ModuleType) -> None:
    monkeypatch.setattr(plugin, "_allowed_actions", lambda: frozenset(plugin._ACTIONS))
    monkeypatch.setattr(plugin, "_get_bot_token", lambda: "test-token")


def test_permission_mask_named(plugin: ModuleType) -> None:
    mask, names = plugin._permission_mask(["view_channel", "SEND_MESSAGES"])
    assert mask & (1 << 10)
    assert mask & (1 << 11)
    assert len(names) == len(set(names))
    assert "ADMINISTRATOR" not in names


def test_permission_mask_rejects_unknown(plugin: ModuleType) -> None:
    with pytest.raises(ValueError, match="Unknown Discord permission"):
        plugin._permission_mask(["ROOT_EVERYTHING"])


def test_create_text_channel(monkeypatch: pytest.MonkeyPatch, plugin: ModuleType) -> None:
    allow_all(monkeypatch, plugin)
    request = Mock(
        return_value={
            "id": "22",
            "name": "project-chat",
            "type": 0,
            "guild_id": "111",
            "parent_id": "10",
            "topic": "Project coordination",
        }
    )
    monkeypatch.setattr(plugin, "_discord_request", request)

    result = json.loads(
        plugin.discord_provisioning_handler(
            {
                "action": "create_channel",
                "guild_id": "111",
                "name": "project-chat",
                "channel_type": "text",
                "parent_id": "10",
                "topic": "Project coordination",
                "audit_log_reason": "Create project channel",
            }
        )
    )

    assert result["success"] is True
    assert result["channel_id"] == "22"
    request.assert_called_once_with(
        "POST",
        "/guilds/111/channels",
        "test-token",
        body={
            "name": "project-chat",
            "type": 0,
            "parent_id": "10",
            "topic": "Project coordination",
        },
        audit_log_reason="Create project channel",
    )


def test_category_rejects_parent(monkeypatch: pytest.MonkeyPatch, plugin: ModuleType) -> None:
    allow_all(monkeypatch, plugin)
    result = json.loads(
        plugin.discord_provisioning_handler(
            {
                "action": "create_channel",
                "guild_id": "111",
                "name": "Category",
                "channel_type": "category",
                "parent_id": "10",
            }
        )
    )
    assert "cannot have parent_id" in result["error"]


def test_rejects_non_snowflake_path_input(
    monkeypatch: pytest.MonkeyPatch, plugin: ModuleType
) -> None:
    allow_all(monkeypatch, plugin)
    request = Mock()
    monkeypatch.setattr(plugin, "_discord_request", request)
    result = json.loads(
        plugin.discord_provisioning_handler(
            {"action": "create_channel", "guild_id": "../admin", "name": "bad"}
        )
    )
    assert "snowflake" in result["error"]
    request.assert_not_called()


def test_create_role_with_named_permissions(
    monkeypatch: pytest.MonkeyPatch, plugin: ModuleType
) -> None:
    allow_all(monkeypatch, plugin)
    request = Mock(
        return_value={
            "id": "2",
            "name": "project-member",
            "permissions": "3072",
            "position": 1,
            "managed": False,
        }
    )
    monkeypatch.setattr(plugin, "_discord_request", request)

    result = json.loads(
        plugin.discord_provisioning_handler(
            {
                "action": "create_role",
                "guild_id": "111",
                "name": "project-member",
                "permissions": ["VIEW_CHANNEL", "SEND_MESSAGES"],
                "mentionable": True,
            }
        )
    )

    assert result["success"] is True
    assert result["role_id"] == "2"
    request.assert_called_once_with(
        "POST",
        "/guilds/111/roles",
        "test-token",
        body={
            "name": "project-member",
            "permissions": "3072",
            "hoist": False,
            "mentionable": True,
        },
    )


def test_administrator_role_requires_operator_configuration(
    monkeypatch: pytest.MonkeyPatch, plugin: ModuleType
) -> None:
    allow_all(monkeypatch, plugin)
    result = json.loads(
        plugin.discord_provisioning_handler(
            {
                "action": "create_role",
                "guild_id": "111",
                "name": "administrator",
                "permissions": ["ADMINISTRATOR"],
            }
        )
    )
    assert "discord.allow_administrator_roles" in result["error"]


def test_administrator_role_operator_opt_in(
    monkeypatch: pytest.MonkeyPatch, plugin: ModuleType
) -> None:
    allow_all(monkeypatch, plugin)
    monkeypatch.setattr(plugin, "_administrator_roles_allowed", lambda: True)
    request = Mock(return_value={"id": "2", "name": "administrator"})
    monkeypatch.setattr(plugin, "_discord_request", request)
    result = json.loads(
        plugin.discord_provisioning_handler(
            {
                "action": "create_role",
                "guild_id": "111",
                "name": "administrator",
                "permissions": ["ADMINISTRATOR"],
            }
        )
    )
    assert result["success"] is True


def test_set_channel_permissions_merges_existing_overwrite(
    monkeypatch: pytest.MonkeyPatch, plugin: ModuleType
) -> None:
    allow_all(monkeypatch, plugin)
    request = Mock(
        side_effect=[
            {
                "id": "22",
                "guild_id": "111",
                "permission_overwrites": [
                    {
                        "id": "42",
                        "type": 1,
                        "allow": str(1 << 10),
                        "deny": str(1 << 20),
                    }
                ],
            },
            None,
        ]
    )
    monkeypatch.setattr(plugin, "_discord_request", request)

    result = json.loads(
        plugin.discord_provisioning_handler(
            {
                "action": "set_channel_permissions",
                "channel_id": "22",
                "target_id": "42",
                "target_type": "member",
                "allow_permissions": ["SEND_MESSAGES", "CONNECT"],
                "deny_permissions": ["ATTACH_FILES"],
                "clear_permissions": ["VIEW_CHANNEL"],
            }
        )
    )

    expected_allow, _ = plugin._permission_mask(["SEND_MESSAGES", "CONNECT"])
    expected_deny, _ = plugin._permission_mask(["ATTACH_FILES"])
    assert result["allow"] == str(expected_allow)
    assert result["deny"] == str(expected_deny)
    assert request.call_args_list == [
        call("GET", "/channels/22", "test-token"),
        call(
            "PUT",
            "/channels/22/permissions/42",
            "test-token",
            body={"type": 1, "allow": str(expected_allow), "deny": str(expected_deny)},
        ),
    ]


def test_channel_permissions_refuses_empty_mutation(
    monkeypatch: pytest.MonkeyPatch, plugin: ModuleType
) -> None:
    allow_all(monkeypatch, plugin)
    request = Mock()
    monkeypatch.setattr(plugin, "_discord_request", request)
    result = json.loads(
        plugin.discord_provisioning_handler(
            {
                "action": "set_channel_permissions",
                "channel_id": "22",
                "target_id": "42",
                "target_type": "member",
            }
        )
    )
    assert "at least one" in result["error"]
    request.assert_not_called()


def test_everyone_grant_requires_operator_configuration(
    monkeypatch: pytest.MonkeyPatch, plugin: ModuleType
) -> None:
    allow_all(monkeypatch, plugin)
    request = Mock(return_value={"id": "22", "guild_id": "111", "permission_overwrites": []})
    monkeypatch.setattr(plugin, "_discord_request", request)
    result = json.loads(
        plugin.discord_provisioning_handler(
            {
                "action": "set_channel_permissions",
                "channel_id": "22",
                "target_id": "111",
                "target_type": "role",
                "allow_permissions": ["VIEW_CHANNEL"],
            }
        )
    )
    assert "discord.allow_everyone_permission_grants" in result["error"]
    request.assert_called_once_with("GET", "/channels/22", "test-token")


def test_everyone_deny_is_allowed_without_positive_grant(
    monkeypatch: pytest.MonkeyPatch, plugin: ModuleType
) -> None:
    allow_all(monkeypatch, plugin)
    request = Mock(
        side_effect=[
            {"id": "22", "guild_id": "111", "permission_overwrites": []},
            None,
        ]
    )
    monkeypatch.setattr(plugin, "_discord_request", request)
    result = json.loads(
        plugin.discord_provisioning_handler(
            {
                "action": "set_channel_permissions",
                "channel_id": "22",
                "target_id": "111",
                "target_type": "role",
                "deny_permissions": ["VIEW_CHANNEL"],
            }
        )
    )
    assert result["success"] is True


def test_channel_permissions_reject_overlap(
    monkeypatch: pytest.MonkeyPatch, plugin: ModuleType
) -> None:
    allow_all(monkeypatch, plugin)
    result = json.loads(
        plugin.discord_provisioning_handler(
            {
                "action": "set_channel_permissions",
                "channel_id": "22",
                "target_id": "42",
                "target_type": "member",
                "allow_permissions": ["VIEW_CHANNEL"],
                "deny_permissions": ["VIEW_CHANNEL"],
            }
        )
    )
    assert "overlap" in result["error"].lower()


def test_channel_permissions_reject_administrator(
    monkeypatch: pytest.MonkeyPatch, plugin: ModuleType
) -> None:
    allow_all(monkeypatch, plugin)
    result = json.loads(
        plugin.discord_provisioning_handler(
            {
                "action": "set_channel_permissions",
                "channel_id": "22",
                "target_id": "42",
                "target_type": "role",
                "allow_permissions": ["ADMINISTRATOR"],
            }
        )
    )
    assert "guild-wide" in result["error"]


def test_action_allowlist_is_enforced_at_dispatch(
    monkeypatch: pytest.MonkeyPatch, plugin: ModuleType
) -> None:
    monkeypatch.setattr(plugin, "_get_bot_token", lambda: "test-token")
    monkeypatch.setattr(plugin, "_allowed_actions", lambda: frozenset({"create_role"}))
    request = Mock()
    monkeypatch.setattr(plugin, "_discord_request", request)

    result = json.loads(
        plugin.discord_provisioning_handler(
            {"action": "create_channel", "guild_id": "111", "name": "denied"}
        )
    )
    assert "disabled by discord.server_actions" in result["error"]
    request.assert_not_called()


def test_allowed_actions_shares_config_with_builtin_actions(
    monkeypatch: pytest.MonkeyPatch, plugin: ModuleType
) -> None:
    from hermes_cli import config

    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {"discord": {"server_actions": ["list_guilds", "create_role", "pin_message"]}},
    )
    assert plugin._allowed_actions() == frozenset({"create_role"})


def test_missing_allowlist_fails_closed(
    monkeypatch: pytest.MonkeyPatch, plugin: ModuleType
) -> None:
    from hermes_cli import config

    monkeypatch.setattr(config, "load_config", lambda: {"discord": {}})
    assert plugin._allowed_actions() == frozenset()


def test_invalid_allowlist_type_fails_closed(
    monkeypatch: pytest.MonkeyPatch, plugin: ModuleType
) -> None:
    from hermes_cli import config

    monkeypatch.setattr(config, "load_config", lambda: {"discord": {"server_actions": 42}})
    assert plugin._allowed_actions() == frozenset()


def test_active_profile_secret_resolver_is_used(
    monkeypatch: pytest.MonkeyPatch, plugin: ModuleType
) -> None:
    resolver = Mock(return_value=" scoped-token ")
    monkeypatch.setattr(plugin, "get_secret", resolver)
    assert plugin._get_bot_token() == "scoped-token"
    resolver.assert_called_once_with("DISCORD_BOT_TOKEN", "")


def test_real_hermes_secret_scope_is_honored(
    monkeypatch: pytest.MonkeyPatch, plugin: ModuleType
) -> None:
    from agent.secret_scope import reset_secret_scope, set_secret_scope

    monkeypatch.delenv("DISCORD_BOT_TOKEN", raising=False)
    scope_token = set_secret_scope({"DISCORD_BOT_TOKEN": "profile-scoped-token"})
    try:
        assert plugin._get_bot_token() == "profile-scoped-token"
    finally:
        reset_secret_scope(scope_token)


def test_missing_token_is_clear(plugin: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(plugin, "_get_bot_token", lambda: None)
    result = json.loads(plugin.discord_provisioning_handler({"action": "create_role"}))
    assert "active Hermes profile" in result["error"]


def test_audit_log_reason_is_percent_encoded(
    monkeypatch: pytest.MonkeyPatch, plugin: ModuleType
) -> None:
    response = Mock()
    response.status = 204
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    urlopen = Mock(return_value=response)
    monkeypatch.setattr(plugin.urllib.request, "urlopen", urlopen)

    assert (
        plugin._discord_request(
            "POST",
            "/guilds/111/roles",
            "test-token",
            body={"name": "project"},
            audit_log_reason="Project / launch",
        )
        is None
    )
    request = urlopen.call_args.args[0]
    assert request.get_header("X-audit-log-reason") == "Project%20%2F%20launch"


def test_audit_log_reason_length_is_bounded(
    monkeypatch: pytest.MonkeyPatch, plugin: ModuleType
) -> None:
    allow_all(monkeypatch, plugin)
    request = Mock()
    monkeypatch.setattr(plugin, "_discord_request", request)
    result = json.loads(
        plugin.discord_provisioning_handler(
            {
                "action": "create_role",
                "guild_id": "111",
                "name": "role",
                "audit_log_reason": "x" * 513,
            }
        )
    )
    assert "at most 512" in result["error"]
    request.assert_not_called()


def test_operator_flags_require_literal_booleans(
    monkeypatch: pytest.MonkeyPatch, plugin: ModuleType
) -> None:
    from hermes_cli import config

    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "discord": {
                "allow_administrator_roles": True,
                "allow_everyone_permission_grants": "true",
            }
        },
    )
    assert plugin._administrator_roles_allowed() is True
    assert plugin._everyone_permission_grants_allowed() is False


def test_403_is_enriched(monkeypatch: pytest.MonkeyPatch, plugin: ModuleType) -> None:
    allow_all(monkeypatch, plugin)
    monkeypatch.setattr(
        plugin,
        "_discord_request",
        Mock(side_effect=plugin.DiscordAPIError(403, '{"message":"Missing Permissions"}')),
    )
    result = json.loads(
        plugin.discord_provisioning_handler(
            {"action": "create_role", "guild_id": "111", "name": "role"}
        )
    )
    assert "MANAGE_ROLES" in result["error"]
    assert "403" in result["error"]


def test_schema_is_separate_and_contains_only_provisioning_actions(plugin: ModuleType) -> None:
    schema = plugin.DISCORD_PROVISIONING_SCHEMA
    assert schema["name"] == "discord_provisioning"
    assert schema["parameters"]["properties"]["action"]["enum"] == [
        "create_channel",
        "create_role",
        "set_channel_permissions",
    ]
    assert schema["name"] != "discord_admin"
    properties = schema["parameters"]["properties"]
    assert "permission_bundle" not in properties
    assert "allow_administrator" not in properties
    assert "clear_permissions" in properties
    assert "audit_log_reason" in properties
    assert schema["parameters"]["additionalProperties"] is False


def test_register_uses_isolated_toolset(plugin: ModuleType) -> None:
    context = Mock()
    plugin.register(context)
    context.register_tool.assert_called_once()
    kwargs: dict[str, Any] = context.register_tool.call_args.kwargs
    assert kwargs["name"] == "discord_provisioning"
    assert kwargs["toolset"] == "discord-provisioning"
    assert kwargs.get("override") is not True
    assert kwargs["requires_env"] == ["DISCORD_BOT_TOKEN"]
