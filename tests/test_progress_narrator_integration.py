"""Host integration contracts, tested without posting to real chats."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def plugin():
    name = "tested_progress_narrator"
    spec = importlib.util.spec_from_file_location(name, ROOT / "progress-narrator" / "__init__.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def origin(plugin, platform="matrix", thread="thread-1"):
    return plugin.Origin(
        platform,
        "chat-1",
        thread,
        "message-1",
        "session-key",
        "default",
        "group",
        "scope-1",
        "user-1",
        "parent-1",
    )


class Gateway:
    def __init__(self, success=True, platform="matrix", source_origin=None):
        from gateway.config import Platform
        from gateway.session import SessionSource

        self.calls = []
        self.success = success
        source = SessionSource(
            platform=Platform(source_origin.platform if source_origin else platform),
            chat_id=source_origin.chat_id if source_origin else "chat-1",
            thread_id=(source_origin.thread_id or None) if source_origin else "thread-1",
            chat_type=source_origin.chat_type if source_origin else "group",
            profile="default",
            scope_id="scope-1",
            parent_chat_id="parent-1",
        )
        event = SimpleNamespace(source=source, message_id="message-1", raw_message=None)
        self.state = SimpleNamespace(
            turn=SimpleNamespace(
                agent=SimpleNamespace(_interrupt_requested=False, _current_turn_id="turn"),
                event=event,
            ),
            persistent=SimpleNamespace(run_generation=1),
        )
        self.supports_async_delivery = True

    def _peek_session_state(self, key):
        return self.state

    def _delivery_adapter_for(self, source):
        self.source = source
        return self

    def _thread_metadata_for_source(self, source, message_id):
        return {
            "thread_id": source.thread_id,
            "scope_id": source.scope_id,
            "hermes_profile": source.profile,
            "message_id": message_id,
        }

    async def send(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(success=self.success)


@pytest.mark.parametrize("platform", ["matrix", "telegram", "discord", "slack", "signal"])
def test_shared_sink_preserves_origin(plugin, platform):
    async def run():
        gateway = Gateway(platform=platform)
        sink = plugin.GatewaySink(
            gateway, asyncio.get_running_loop(), origin(plugin, platform), "turn"
        )
        anchor = None if platform == "telegram" else "message-1"
        assert await sink._send("Reading the project configuration.")
        assert gateway.calls == [
            {
                "chat_id": "chat-1",
                "content": "Reading the project configuration.",
                "reply_to": anchor,
                "metadata": {
                    "thread_id": "thread-1",
                    "scope_id": "scope-1",
                    "hermes_profile": "default",
                    "message_id": anchor,
                },
            }
        ]
        assert gateway.source.platform.value == platform
        assert gateway.source.parent_chat_id == "parent-1"

    asyncio.run(run())


@pytest.mark.parametrize("change", ["close", "generation", "idle", "interrupt"])
def test_sink_discards_stale_generation(plugin, change):
    async def run():
        gateway = Gateway()
        sink = plugin.GatewaySink(gateway, asyncio.get_running_loop(), origin(plugin), "turn")
        if change == "close":
            sink.close()
        elif change == "generation":
            gateway.state.persistent.run_generation += 1
        elif change == "idle":
            gateway.state.turn.agent = None
        else:
            gateway.state.turn.agent._interrupt_requested = True
        assert not await sink._send("Must not arrive.")
        assert not gateway.calls

    asyncio.run(run())


def test_sink_failure_does_not_retry_threadless(plugin):
    async def run():
        gateway = Gateway(success=False)
        sink = plugin.GatewaySink(gateway, asyncio.get_running_loop(), origin(plugin), "turn")
        assert not await sink._send("Working.")
        assert len(gateway.calls) == 1
        assert gateway.calls[0]["metadata"]["thread_id"] == "thread-1"

    asyncio.run(run())


def test_capture_uses_task_local_session_key(plugin):
    from gateway.session_context import clear_session_vars, set_session_vars

    tokens = set_session_vars(
        platform="matrix",
        chat_id="room",
        thread_id="thread",
        session_key="actual-key",
        message_id="message",
        profile="default",
        cron_session="",
    )
    try:
        captured = plugin.Origin.capture()
        assert captured and captured.session_key == "actual-key"
        assert captured.thread_id == "thread"
    finally:
        clear_session_vars(tokens)


@pytest.mark.parametrize(
    "platform,cron", [("cli", ""), ("subagent", ""), ("api_server", ""), ("matrix", "1")]
)
def test_unsupported_contexts_are_silent(plugin, platform, cron):
    from gateway.session_context import clear_session_vars, set_session_vars

    tokens = set_session_vars(
        platform=platform, chat_id="room", session_key="key", cron_session=cron
    )
    try:
        assert plugin.Origin.capture() is None
    finally:
        clear_session_vars(tokens)


def test_register_only_observers_and_auxiliary_model(plugin):
    ctx = Mock()
    plugin.register(ctx)
    names = {call.args[0] for call in ctx.register_hook.call_args_list}
    assert {"pre_llm_call", "post_tool_call", "on_session_end", "agent_loop_stopped"} <= names
    assert not ctx.register_tool.called
    assert not ctx.register_middleware.called
    assert not ctx.inject_message.called
    assert ctx.register_auxiliary_task.call_args.args == ("progress_narrator",)
    assert ctx.on_unload.called


def test_stop_closes_matching_origin_only(plugin):
    instance = plugin.Plugin(Mock())
    loop = asyncio.new_event_loop()
    try:
        a = plugin.GatewaySink(Gateway(), loop, origin(plugin), "turn")
        b_origin = plugin.Origin("slack", "other", "", "", "other-key", "default", "dm", "", "", "")
        b = plugin.GatewaySink(Gateway(source_origin=b_origin), loop, b_origin, "turn")
        instance.bindings = {("a", "turn-a"): a, ("b", "turn-b"): b}
        instance.end(session_key="session-key")
        assert not a.active.is_set()
        assert b.active.is_set()
        assert list(instance.bindings) == [("b", "turn-b")]
        instance.close()
        assert not b.active.is_set()
    finally:
        loop.close()


def test_execution_key_survives_session_rotation(plugin):
    instance = plugin.Plugin(Mock())
    instance.bindings = {("old-session", "same-turn"): Mock()}
    assert instance._execution_key("new-session", "same-turn") == ("old-session", "same-turn")
    assert instance._execution_key("new-session", "") == ("new-session", "")


def test_real_loader_discovers_plugin_in_clean_profile(tmp_path, monkeypatch):
    import shutil

    import yaml
    from hermes_cli.plugins import PluginManager

    home = tmp_path / "home"
    shutil.copytree(ROOT / "progress-narrator", home / "plugins" / "progress-narrator")
    (home / "config.yaml").write_text(
        yaml.safe_dump({"plugins": {"enabled": ["progress-narrator"]}}), encoding="utf-8"
    )
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.delenv("HERMES_SAFE_MODE", raising=False)
    manager = PluginManager()
    try:
        manager.discover_and_load()
        loaded = next(p for p in manager.list_plugins() if p["name"] == "progress-narrator")
        assert loaded["enabled"] is True
        assert loaded["error"] is None
        assert loaded["tools"] == 0
        assert loaded["hooks"] == 9
        assert manager.has_hook("post_tool_call")
    finally:
        manager.unload("progress-narrator")


def test_auxiliary_call_uses_registered_task_not_main_loop(plugin):
    ctx = Mock()
    ctx.llm.complete.return_value = SimpleNamespace(
        text="Checking settings.", model="fast", provider="test"
    )
    instance = plugin.Plugin(ctx)
    assert instance.summarize("rules", "evidence") == "Checking settings."
    kwargs = ctx.llm.complete.call_args.kwargs
    assert kwargs["task"] == "progress_narrator"
    assert kwargs["timeout"] == 12
    assert kwargs["max_tokens"] == 160
    assert not ctx.dispatch_tool.called
