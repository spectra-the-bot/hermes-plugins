"""Routing regressions against installed Hermes, without network or model calls.

Only terminal adapter ``send`` is replaced. Gateway delivery, metadata, identity,
reply-anchor, session-state, and session-context methods are the installed ones.
The event gates reproduce hook ordering without depending on arbitrary sleeps.
"""

from __future__ import annotations

import asyncio
import importlib.util
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
SESSION_ID = "routing-session"
SESSION_KEY = "agent:runtime:telegram:dm:chat-1:thread:topic-1"
TURN_ID = "routing-turn"
CONFIG = {
    "plugins": {"entries": {"progress-narrator": {"enabled": True}}},
    "auxiliary": {"progress_narrator": {"model": "never-called-test-model"}},
}


class RecordingAdapter:
    """In-memory endpoint; deliberately has no live client or credentials."""

    supports_async_delivery = True

    def __init__(self, platform):
        self.platform = platform
        self.calls = []

    async def send(self, **kwargs):
        from gateway.platforms.base import SendResult

        self.calls.append(kwargs)
        return SendResult(success=True)


@pytest.fixture
def plugin():
    name = "tested_progress_narrator_routing"
    spec = importlib.util.spec_from_file_location(name, ROOT / "progress-narrator" / "__init__.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def make_rig(plugin, monkeypatch, tmp_path):
    home = tmp_path / "isolated-home"
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_SAFE_MODE", "1")
    from gateway.config import GatewayConfig, Platform
    from gateway.platforms.event import MessageEvent
    from gateway.run import GatewayRunner
    from gateway.session import SessionSource
    from gateway.session_identity import resolve_identity
    from gateway.session_state import SessionState
    from gateway.turn_context import TurnContext

    monkeypatch.setattr(
        "hermes_cli.profiles.get_profile_dir",
        lambda name: home if name == "default" else home / "profiles" / name,
    )
    monkeypatch.setattr("hermes_cli.profiles.profile_exists", lambda name: True)
    load_config = Mock(return_value=CONFIG)
    monkeypatch.setattr("hermes_cli.config.load_config_readonly", load_config)
    instances = []

    def make(*, platform="telegram", receiver="primary", thread_id="topic-1"):
        platform_enum = Platform(platform)
        runner = object.__new__(GatewayRunner)
        runner.config = GatewayConfig(multiplex_profiles=True)
        runner._primary_profile_name = "default"
        primary = RecordingAdapter(platform_enum)
        secondary = RecordingAdapter(platform_enum)
        relay = RecordingAdapter(Platform.RELAY)
        runner.adapters = {platform_enum: primary, Platform.RELAY: relay}
        runner._profile_adapters = {"runtime": {platform_enum: secondary}}
        source = SessionSource(
            platform=platform_enum,
            chat_id="chat-1",
            chat_type="dm" if platform == "telegram" else "group",
            thread_id=thread_id,
            message_id="inbound-message",
            user_id="user-1",
            user_id_alt="alternate-user",
            scope_id="workspace-1",
            parent_chat_id="parent-channel",
            profile="default" if receiver == "secondary" else "runtime",
            delivered_via_upstream_relay=receiver == "relay",
        )
        receiving_adapter = {"primary": primary, "secondary": secondary, "relay": relay}[receiver]
        resolve_identity(source, runner=runner, adapter=receiving_adapter, primary_home=home)
        event = MessageEvent(
            text="Inspect project settings.", source=source, message_id="inbound-message"
        )
        state = SessionState()
        state.turn.agent = SimpleNamespace(_current_turn_id=TURN_ID, _interrupt_requested=False)
        state.turn.event = event
        state.turn.ctx = TurnContext(source=source)
        state.persistent.run_generation = 7
        runner._sessions = {SESSION_KEY: state}
        # Spies invoke, rather than replace, the real resolver and metadata logic.
        runner._delivery_adapter_for = Mock(wraps=runner._delivery_adapter_for)
        runner._thread_metadata_for_source = Mock(wraps=runner._thread_metadata_for_source)
        rig = SimpleNamespace(
            runner=runner,
            source=source,
            event=event,
            state=state,
            primary=primary,
            secondary=secondary,
            relay=relay,
            receiving_adapter=receiving_adapter,
            load_config=load_config,
        )

        @contextmanager
        def bound():
            context = SimpleNamespace(source=source, session_key=SESSION_KEY)
            tokens = runner._set_session_env(context)
            try:
                yield
            finally:
                runner._clear_session_env(tokens)

        def captured_origin():
            with bound():
                result = plugin.Origin.capture()
            assert result is not None
            return result

        def new_plugin():
            ctx = Mock()
            ctx.llm.complete.side_effect = AssertionError("Routing tests must not call a model")
            instance = plugin.Plugin(ctx)
            instance.capture_gateway(gateway=runner)
            instances.append(instance)
            return instance

        def start(instance, turn_id=TURN_ID):
            with bound():
                instance.start(
                    session_id=SESSION_ID,
                    turn_id=turn_id,
                    user_message=event.text,
                    platform=platform,
                )

        rig.origin = captured_origin
        rig.new_plugin = new_plugin
        rig.start = start
        return rig

    yield make
    for instance in instances:
        turns = list(instance.narrator.turns.values()) if instance.narrator is not None else []
        instance.close()
        for turn in turns:
            if turn.thread is not None:
                turn.thread.join(timeout=1)
        instance.ctx.llm.complete.assert_not_called()


def assert_idle(instance):
    assert not instance.bindings
    assert instance.narrator is None or not instance.narrator.turns


def assert_no_sends(rig):
    assert not rig.primary.calls
    assert not rig.secondary.calls
    assert not rig.relay.calls


@contextmanager
def muted(rig, owner):
    from agent.notification_presentation import notification_turn

    if owner == "agent":
        with notification_turn(rig.state.turn.agent, muted=True, session_id=SESSION_ID):
            yield
    else:
        previous = rig.state.turn.ctx.mute_notification_reply
        rig.state.turn.ctx.mute_notification_reply = True
        try:
            yield
        finally:
            rig.state.turn.ctx.mute_notification_reply = previous


@pytest.mark.parametrize("receiver", ["primary", "secondary", "relay"])
def test_source_provenance_reaches_real_gateway_resolver(plugin, make_rig, receiver):
    """Receiving transport wins even when a different runtime owns a live bot."""
    from gateway.session_identity import identity_of

    async def run():
        rig = make_rig(receiver=receiver)
        original = rig.source
        identity = identity_of(original)
        assert identity is not None
        assert identity.transport_profile != identity.runtime_profile
        sink = plugin.GatewaySink(rig.runner, asyncio.get_running_loop(), rig.origin(), TURN_ID)
        # A later mutation of the event source must not rewrite the captured route.
        original.thread_id = "later-topic"
        original.message_id = "later-message"
        assert await sink._send("Checking project settings.")
        captured = rig.runner._delivery_adapter_for.call_args.args[0]
        assert captured is not original
        assert identity_of(captured) is identity
        assert captured._transport_adapter_ref is original._transport_adapter_ref
        assert captured._authorization_profile_home == original._authorization_profile_home
        assert captured.delivered_via_upstream_relay is (receiver == "relay")
        assert captured.user_id_alt == "alternate-user"
        assert captured.thread_id == "topic-1"
        assert captured.message_id == "inbound-message"
        assert rig.runner._delivery_adapter_for(captured) is rig.receiving_adapter
        assert len(rig.receiving_adapter.calls) == 1
        sent = rig.receiving_adapter.calls[0]
        assert sent["chat_id"] == "chat-1"
        assert sent["reply_to"] == "inbound-message"
        assert sent["metadata"]["thread_id"] == "topic-1"
        assert sent["metadata"]["hermes_profile"] == original.profile
        assert sent["metadata"]["scope_id"] == "workspace-1"
        assert sent["metadata"]["parent_chat_id"] == "parent-channel"
        for adapter in (rig.primary, rig.secondary, rig.relay):
            if adapter is not rig.receiving_adapter:
                assert not adapter.calls

    asyncio.run(run())


@pytest.mark.parametrize("defect", ["wrong-turn", "missing-event", "missing-source"])
def test_sink_refuses_unbound_or_mismatched_turn(plugin, make_rig, defect):
    async def run():
        rig = make_rig()
        if defect == "wrong-turn":
            rig.state.turn.agent._current_turn_id = "replacement-turn"
        elif defect == "missing-event":
            rig.state.turn.event = None
        else:
            rig.event.source = None
        with pytest.raises(ValueError):
            plugin.GatewaySink(rig.runner, asyncio.get_running_loop(), rig.origin(), TURN_ID)
        assert_no_sends(rig)

    asyncio.run(run())


@pytest.mark.parametrize("already_started", [False, True])
def test_delayed_start_after_final_cannot_revive_retained_agent(make_rig, already_started):
    """Hermes retains the finished agent in TurnState until the next claim."""

    async def run():
        rig = make_rig()
        instance = rig.new_plugin()
        if already_started:
            rig.start(instance)
            assert (SESSION_ID, TURN_ID) in instance.bindings
        instance.end(session_id=SESSION_ID, turn_id=TURN_ID)
        assert rig.state.turn.agent._current_turn_id == TURN_ID
        rig.start(instance)
        assert_idle(instance)
        assert_no_sends(rig)

    asyncio.run(run())


@pytest.mark.parametrize("reuse_agent", [False, True])
def test_delayed_old_start_does_not_prune_replacement(make_rig, reuse_agent):
    async def run():
        rig = make_rig()
        instance = rig.new_plugin()
        if reuse_agent:
            rig.state.turn.agent._current_turn_id = "replacement-turn"
        else:
            rig.state.turn.agent = SimpleNamespace(
                _current_turn_id="replacement-turn",
                _interrupt_requested=False,
            )
            rig.state.persistent.run_generation += 1
        rig.start(instance, "replacement-turn")
        key = (SESSION_ID, "replacement-turn")
        replacement = instance.bindings[key]
        rig.start(instance, TURN_ID)
        assert instance.bindings == {key: replacement}
        assert replacement.is_current()
        assert set(instance.narrator.turns) == {key}
        assert_no_sends(rig)

    asyncio.run(run())


@pytest.mark.parametrize("boundary", ["final", "replacement", "close"])
def test_start_rechecks_after_slow_configuration(make_rig, boundary):
    """Finalize, replace, or unload while a dispatched start reads configuration."""

    async def run():
        rig = make_rig()
        instance = rig.new_plugin()
        entered, release = threading.Event(), threading.Event()
        first = True

        def blocked_config():
            nonlocal first
            if first:
                first = False
                entered.set()
                assert release.wait(3), "Test did not release the configuration gate"
            return CONFIG

        rig.load_config.side_effect = blocked_config
        pending = asyncio.create_task(asyncio.to_thread(rig.start, instance))
        replacement = None
        try:
            assert await asyncio.to_thread(entered.wait, 2), "Start never reached configuration"
            if boundary == "final":
                instance.end(session_id=SESSION_ID, turn_id=TURN_ID)
            elif boundary == "close":
                instance.close()
            else:
                rig.state.turn.agent = SimpleNamespace(
                    _current_turn_id="replacement-turn",
                    _interrupt_requested=False,
                )
                rig.state.persistent.run_generation += 1
                rig.start(instance, "replacement-turn")
                replacement = instance.bindings[(SESSION_ID, "replacement-turn")]
        finally:
            release.set()
            await asyncio.wait_for(pending, 3)
        if boundary == "replacement":
            assert instance.bindings == {(SESSION_ID, "replacement-turn"): replacement}
            assert replacement is not None
            assert replacement.is_current()
        else:
            assert_idle(instance)
        assert_no_sends(rig)

    asyncio.run(run())


def test_late_callbacks_after_close_cannot_reopen_plugin(make_rig):
    async def run():
        rig = make_rig()
        instance = rig.new_plugin()
        rig.start(instance)
        sink = instance.bindings[(SESSION_ID, TURN_ID)]
        instance.close()
        # These callbacks can already be queued when the loader unloads the plugin.
        instance.capture_gateway(gateway=rig.runner)
        rig.start(instance)
        instance.tool_start(session_id=SESSION_ID, turn_id=TURN_ID, tool_name="read_file")
        instance.tool(session_id=SESSION_ID, turn_id=TURN_ID, tool_name="read_file", result={})
        assert_idle(instance)
        assert not await asyncio.to_thread(sink, "Late worker summary.")
        assert not await sink._send("Already queued delivery.")
        assert_no_sends(rig)

    asyncio.run(run())


@pytest.mark.parametrize("promotion", ["same-turn", "wrong-turn", "new-generation"])
def test_pending_sentinel_waits_for_matching_real_agent(make_rig, promotion):
    from gateway.run import _AGENT_PENDING_SENTINEL

    async def run():
        rig = make_rig()
        real_agent = rig.state.turn.agent
        if promotion == "wrong-turn":
            real_agent._current_turn_id = "replacement-turn"
        rig.state.turn.agent = _AGENT_PENDING_SENTINEL
        instance = rig.new_plugin()
        observed = threading.Event()
        real_peek = rig.runner._peek_session_state

        def observe_pending(key):
            state = real_peek(key)
            if state is not None and state.turn.agent is _AGENT_PENDING_SENTINEL:
                observed.set()
            return state

        rig.runner._peek_session_state = observe_pending
        pending = asyncio.create_task(asyncio.to_thread(rig.start, instance))
        try:
            observed_pending = await asyncio.to_thread(observed.wait, 2)
            assert observed_pending, "Start never observed pending sentinel"
        finally:
            if promotion == "new-generation":
                rig.state.persistent.run_generation += 1
            rig.state.turn.agent = real_agent
            await asyncio.wait_for(pending, 2)
        if promotion == "same-turn":
            sink = instance.bindings[(SESSION_ID, TURN_ID)]
            assert sink.agent is real_agent
            assert sink.is_current()
            assert await sink._send("Attached after promotion.")
            assert len(rig.primary.calls) == 1
        else:
            assert_idle(instance)
            assert_no_sends(rig)

    asyncio.run(run())


def test_pending_sentinel_without_promotion_fails_closed_with_bounded_wait(make_rig):
    from gateway.run import _AGENT_PENDING_SENTINEL

    async def run():
        rig = make_rig()
        rig.state.turn.agent = _AGENT_PENDING_SENTINEL
        instance = rig.new_plugin()
        started = time.monotonic()
        await asyncio.wait_for(asyncio.to_thread(rig.start, instance), 2)
        assert time.monotonic() - started < 1.5
        assert_idle(instance)
        rig.load_config.assert_not_called()
        assert_no_sends(rig)

    asyncio.run(run())


def test_slack_reaction_handoff_keeps_none_anchor_through_real_routing(plugin, make_rig):
    from gateway.platforms.base import _reply_anchor_for_event
    from plugins.platforms.slack.adapter import SlackAdapter

    async def run():
        rig = make_rig(platform="slack", thread_id=None)
        rig.event.raw_message = {"_hermes_no_thread_response": True}
        assert rig.origin().message_id == "inbound-message"
        assert _reply_anchor_for_event(rig.event) is None
        sink = plugin.GatewaySink(rig.runner, asyncio.get_running_loop(), rig.origin(), TURN_ID)
        assert await sink._send("Checking the handoff.")
        source, reply_anchor = rig.runner._thread_metadata_for_source.call_args.args
        assert reply_anchor is None
        assert source.message_id is None, "The gateway must not recover the obsolete message anchor"
        assert rig.source.message_id == "inbound-message", "Snapshot must not mutate ingress"
        sent = rig.primary.calls[0]
        assert sent["reply_to"] is None
        assert "message_id" not in sent["metadata"]
        assert sent["metadata"]["slack_team_id"] == "workspace-1"
        assert sent["metadata"]["user_id"] == "user-1"
        slack = object.__new__(SlackAdapter)
        slack.config = SimpleNamespace(extra={"reply_in_thread": True})
        assert SlackAdapter._resolve_thread_ts(slack, sent["reply_to"], sent["metadata"]) is None
        assert not rig.secondary.calls
        assert not rig.relay.calls

    asyncio.run(run())


@pytest.mark.parametrize("owner", ["agent", "turn-context"])
def test_notification_mute_suppresses_start(make_rig, owner):
    async def run():
        rig = make_rig()
        instance = rig.new_plugin()
        with muted(rig, owner):
            rig.start(instance)
            assert_idle(instance)
            assert_no_sends(rig)

    asyncio.run(run())


@pytest.mark.parametrize("owner", ["agent", "turn-context"])
def test_notification_mute_suppresses_existing_sink_delivery(plugin, make_rig, owner):
    async def run():
        rig = make_rig()
        sink = plugin.GatewaySink(rig.runner, asyncio.get_running_loop(), rig.origin(), TURN_ID)
        assert sink.is_current()
        with muted(rig, owner):
            assert not sink.is_current()
            assert not await asyncio.to_thread(sink, "Queued worker output.")
            assert not await sink._send("Queued gateway output.")
        assert_no_sends(rig)

    asyncio.run(run())


def test_reused_agent_with_new_turn_id_invalidates_existing_sink(plugin, make_rig):
    async def run():
        rig = make_rig()
        sink = plugin.GatewaySink(rig.runner, asyncio.get_running_loop(), rig.origin(), TURN_ID)
        agent, generation = rig.state.turn.agent, rig.state.persistent.run_generation
        rig.state.turn.agent._current_turn_id = "replacement-turn"
        assert rig.state.turn.agent is agent
        assert rig.state.persistent.run_generation == generation
        assert not sink.is_current()
        assert not await asyncio.to_thread(sink, "Late previous-turn result.")
        assert not await sink._send("Previously scheduled send.")
        assert_no_sends(rig)

    asyncio.run(run())


def test_delivery_rechecks_notification_mute_after_resolving_metadata(plugin, make_rig):
    async def run():
        rig = make_rig()
        sink = plugin.GatewaySink(rig.runner, asyncio.get_running_loop(), rig.origin(), TURN_ID)
        real_metadata = rig.runner._thread_metadata_for_source

        def mute_during_metadata(*args):
            metadata = real_metadata(*args)
            rig.state.turn.ctx.mute_notification_reply = True
            return metadata

        rig.runner._thread_metadata_for_source = mute_during_metadata
        assert not await sink._send("Must not escape the final mute check.")
        assert_no_sends(rig)

    asyncio.run(run())
