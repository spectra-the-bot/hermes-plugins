"""Standalone progress narrator. Never modifies core, prompts, or tool results."""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, fields
from typing import Any

from .core import Narrator, Settings

LOG = logging.getLogger(__name__)
TASK = "progress_narrator"
EXCLUDED = {"cli", "tui", "desktop", "api_server", "webhook", "cron", "subagent", "homeassistant"}


@dataclass(frozen=True)
class Origin:
    platform: str
    chat_id: str
    thread_id: str
    message_id: str
    session_key: str
    profile: str
    chat_type: str
    scope_id: str
    user_id: str
    parent_chat_id: str

    @classmethod
    def capture(cls) -> Origin | None:
        from gateway.session_context import async_delivery_supported, get_session_env

        if get_session_env("HERMES_CRON_SESSION") or not async_delivery_supported():
            return None
        values = {
            name: get_session_env(
                "HERMES_SESSION_KEY" if name == "session_key" else "HERMES_SESSION_" + name.upper()
            )
            for name in cls.__dataclass_fields__
        }
        if not values["chat_id"] or not values["session_key"] or not values["platform"]:
            return None
        if values["platform"] in EXCLUDED:
            return None
        return cls(**values)


class GatewaySink:
    """Small compatibility bridge to the host's actual reply routing.

    The adapter send contract is shared; the two routing helpers are internal
    Hermes APIs. Missing helpers disable narration rather than guessing a route.
    No standalone sender or home-channel/threadless fallback is used.
    """

    def __init__(
        self, gateway: Any, loop: asyncio.AbstractEventLoop, origin: Origin, turn_id: str
    ) -> None:
        from gateway.platforms.base import _reply_anchor_for_event
        from gateway.session_identity import replace_source

        self.gateway = gateway
        self.loop = loop
        self.origin = origin
        self.turn_id = turn_id
        self.active = threading.Event()
        self.active.set()
        state = gateway._peek_session_state(origin.session_key)
        self.agent = state.turn.agent if state is not None else None
        self.generation = state.persistent.run_generation if state is not None else None
        self.event = getattr(state.turn, "event", None) if state is not None else None
        source = getattr(self.event, "source", None)
        if (
            not turn_id
            or getattr(self.agent, "_current_turn_id", None) != turn_id
            or source is None
        ):
            raise ValueError("No matching authorized foreground turn")
        if (
            getattr(source.platform, "value", source.platform) != origin.platform
            or str(source.chat_id) != origin.chat_id
            or str(source.thread_id or "") != origin.thread_id
        ):
            raise ValueError("Foreground source differs from the captured origin")
        self.reply_anchor = _reply_anchor_for_event(self.event)
        # Copy the AUTHORIZED source, including wire-invisible receiving-bot identity.
        # Explicit None is meaningful for reaction handoffs and Telegram forum topics.
        self.source = replace_source(source, message_id=self.reply_anchor)
        if not self.is_current():
            raise ValueError("Foreground turn is inactive or muted")

    def is_current(self) -> bool:
        if not self.active.is_set() or self.agent is None:
            return False
        state = self.gateway._peek_session_state(self.origin.session_key)
        return bool(
            state is not None
            and state.turn.agent is self.agent
            and state.persistent.run_generation == self.generation
            and getattr(self.agent, "_current_turn_id", None) == self.turn_id
            and getattr(state.turn, "event", None) is self.event
            and not getattr(self.agent, "_interrupt_requested", False)
            and not getattr(self.agent, "_mute_notification_reply", False)
            and not getattr(getattr(state.turn, "ctx", None), "mute_notification_reply", False)
        )

    def close(self) -> None:
        self.active.clear()

    def __call__(self, text: str) -> bool:
        if not self.is_current() or self.loop.is_closed() or not self.loop.is_running():
            return False
        future = asyncio.run_coroutine_threadsafe(self._send(text), self.loop)
        try:
            return bool(future.result(timeout=8))
        except (TimeoutError, concurrent.futures.CancelledError):
            self.close()
            future.cancel()
            return False

    async def _send(self, text: str) -> bool:
        if not self.is_current():
            return False
        o = self.origin
        adapter = self.gateway._delivery_adapter_for(self.source)
        if adapter is None or not getattr(adapter, "supports_async_delivery", True):
            return False
        metadata = self.gateway._thread_metadata_for_source(self.source, self.reply_anchor)
        if not self.is_current():
            return False
        result = await asyncio.wait_for(
            adapter.send(
                chat_id=o.chat_id,
                content=text,
                reply_to=self.reply_anchor,
                metadata=metadata,
            ),
            timeout=6,
        )
        return bool(result.success)


class Plugin:
    def __init__(self, ctx: Any) -> None:
        self.ctx = ctx
        self.gateway: Any = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.lock = threading.RLock()
        self.bindings: dict[tuple[str, str], GatewaySink] = {}
        self.narrator: Narrator | None = None
        self.closed = threading.Event()
        self.finished: deque[str] = deque(maxlen=256)

    def capture_gateway(self, gateway: Any = None, **kwargs: Any) -> None:
        # This observer runs pre-authorization. It captures transport ONLY, never
        # starts narration or keeps inbound content. pre_llm_call authorizes work.
        if gateway is None or self.closed.is_set():
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        if not all(
            callable(getattr(gateway, name, None))
            for name in (
                "_delivery_adapter_for",
                "_thread_metadata_for_source",
                "_peek_session_state",
            )
        ):
            return
        self.gateway, self.loop = gateway, loop

    @staticmethod
    def _missing_model(error: Exception) -> bool:
        # A generic endpoint 404 must not trigger model hopping.
        if getattr(error, "status_code", None) not in (400, 404):
            return False
        body = getattr(error, "body", None)
        if isinstance(body, dict) and isinstance(body.get("error"), dict):
            body = body["error"]
        message = str(body.get("message", "")) if isinstance(body, dict) else str(error)
        message = message.casefold()
        return "model" in message and any(
            marker in message
            for marker in (
                "does not exist",
                "not found",
                "unknown model",
                "not loaded",
                "model_not_found",
            )
        )

    def summarize(self, instructions: str, evidence: str) -> str:
        request = {
            "messages": [
                {"role": "system", "content": instructions},
                {"role": "user", "content": evidence},
            ],
            "task": TASK,
            "max_tokens": 160,
            "temperature": 0.2,
            "purpose": "progress-narrator.summary",
        }
        try:
            result = self.ctx.llm.complete(**request)
        except Exception as primary_error:
            if not self._missing_model(primary_error):
                raise
            # Host recovery handles transport/capacity failures. Its model-error
            # classifier does not cover every local server's missing-model response.
            from hermes_cli.config import load_config_readonly

            route = load_config_readonly().get("auxiliary", {}).get(TASK, {})
            chain = route.get("fallback_chain", [])
            if not isinstance(chain, list):
                raise
            tried = {(route.get("provider"), route.get("model"))}
            for entry in chain:
                if not isinstance(entry, dict):
                    continue
                provider, model = entry.get("provider"), entry.get("model")
                if not isinstance(provider, str) or not provider.strip():
                    continue
                if not isinstance(model, str) or not model.strip() or (provider, model) in tried:
                    continue
                # The facade cannot override an endpoint/key. Use a named provider
                # for another endpoint rather than silently ignoring route fields.
                if any(entry.get(key) for key in ("base_url", "api_key", "api_mode", "transport")):
                    raise ValueError(
                        "Missing-model fallbacks require named providers without route overrides"
                    ) from None
                tried.add((provider, model))
                fallback = {**request, "provider": provider, "model": model}
                if "timeout" in entry:
                    fallback["timeout"] = entry["timeout"]
                LOG.info(
                    "Progress summary missing model; trying provider=%s model=%s", provider, model
                )
                try:
                    result = self.ctx.llm.complete(**fallback)
                    break
                except Exception as error:
                    if not self._missing_model(error):
                        raise
            else:
                raise primary_error
        # Attribution only. Never log prompts, results, or credentials.
        LOG.info("Progress summary model=%s provider=%s", result.model, result.provider)
        return str(result.text)

    @staticmethod
    def _redact(value: str) -> str:
        from agent.redact import redact_sensitive_text

        return str(redact_sensitive_text(value, force=True, redact_url_credentials=True))

    def _capture_sink(self, origin: Origin, turn_id: str) -> GatewaySink | None:
        # Gateway promotion can lag pre_llm_call by one 50ms scheduler tick.
        # Never adopt the pending sentinel, a newer generation, or another turn.
        state = self.gateway._peek_session_state(origin.session_key)
        if state is None or self.loop is None or not turn_id:
            return None
        generation = state.persistent.run_generation
        deadline = time.monotonic() + 0.5
        while not self.closed.is_set():
            state = self.gateway._peek_session_state(origin.session_key)
            if state is None or state.persistent.run_generation != generation:
                return None
            agent = state.turn.agent
            current = getattr(agent, "_current_turn_id", None)
            if current == turn_id:
                try:
                    return GatewaySink(self.gateway, self.loop, origin, turn_id)
                except (ValueError, ImportError):
                    return None
            if current or agent is None or time.monotonic() >= deadline:
                return None
            time.sleep(0.01)
        return None

    def start(
        self,
        session_id: str = "",
        turn_id: str = "",
        user_message: Any = "",
        platform: str = "",
        parent_session_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        if (
            self.closed.is_set()
            or parent_session_id
            or platform in EXCLUDED
            or self.gateway is None
            or self.loop is None
        ):
            return
        origin = Origin.capture()
        if origin is None:
            return
        sink = self._capture_sink(origin, turn_id)
        if sink is None:
            return
        from hermes_cli.config import load_config_readonly

        config = load_config_readonly()
        entry = config.get("plugins", {}).get("entries", {}).get("progress-narrator", {})
        if not isinstance(entry, dict) or entry.get("enabled", True) is not True:
            return
        allow = entry.get("platforms", [])
        if allow and origin.platform not in allow:
            return
        route = config.get("auxiliary", {}).get(TASK, {})
        if not isinstance(route, dict) or not route.get("model"):
            LOG.warning("Progress narrator idle: configure auxiliary.progress_narrator.model")
            return
        settings = Settings(**{f.name: entry[f.name] for f in fields(Settings) if f.name in entry})
        with self.lock:
            if self.closed.is_set() or turn_id in self.finished or not sink.is_current():
                sink.close()
                return
            if self.narrator is None:
                self.narrator = Narrator(self.summarize, settings, redactor=self._redact)
            # Settings are captured per turn; do not mutate running turns.
            self.narrator.settings = settings
            for key, old in list(self.bindings.items()):
                if (
                    key[0] == session_id
                    or old.origin.session_key == origin.session_key
                    or key not in self.narrator.turns
                    or not old.is_current()
                ):
                    self._end_key(key)
            if self.narrator.begin(session_id, turn_id, str(user_message), sink) is not None:
                self.bindings[(session_id, turn_id)] = sink

    def _execution_key(self, session_id: str, turn_id: str) -> tuple[str, str]:
        # A compression can rotate session_id while retaining the same turn_id.
        # Empty turn IDs never fall back to a session-only match.
        with self.lock:
            if turn_id:
                for key in self.bindings:
                    if key[1] == turn_id:
                        return key
        return session_id, turn_id

    def tool(
        self,
        tool_name: str = "",
        args: Any = None,
        result: Any = None,
        session_id: str = "",
        turn_id: str = "",
        status: str = "completed",
        tool_call_id: str = "",
        **kwargs: Any,
    ) -> None:
        if self.narrator is not None:
            self.narrator.record(
                *self._execution_key(session_id, turn_id),
                tool_name=tool_name,
                args=args,
                result=result,
                status=status,
                tool_call_id=tool_call_id,
            )

    def tool_start(self, **kwargs: Any) -> None:
        if self.narrator is not None:
            self.narrator.record(
                *self._execution_key(kwargs.get("session_id", ""), kwargs.get("turn_id", "")),
                tool_name=kwargs.get("tool_name", ""),
                tool_call_id=kwargs.get("tool_call_id", ""),
                started=True,
            )

    def _end_key(self, key: tuple[str, str]) -> None:
        self.finished.append(key[1])
        sink = self.bindings.pop(key, None)
        if sink is not None:
            sink.close()
        if self.narrator is not None:
            self.narrator.end(*key)

    def end(
        self,
        session_id: str = "",
        turn_id: str = "",
        session_key: str = "",
        old_session_id: str = "",
        **kwargs: Any,
    ) -> None:
        with self.lock:
            if turn_id:
                self.finished.append(turn_id)
            for key, sink in list(self.bindings.items()):
                if turn_id:
                    match = key[1] == turn_id
                else:
                    match = bool(
                        (session_id and key[0] == session_id)
                        or (old_session_id and key[0] == old_session_id)
                        or (session_key and sink.origin.session_key == session_key)
                    )
                if match:
                    self._end_key(key)

    def close(self) -> None:
        self.closed.set()
        with self.lock:
            for key in list(self.bindings):
                self._end_key(key)
            if self.narrator is not None:
                self.narrator.close()


def register(ctx: Any) -> None:
    ctx.register_auxiliary_task(
        TASK,
        display_name="Progress narrator",
        description="Brief tool-activity summaries",
        defaults={"timeout": 12},
    )
    plugin = Plugin(ctx)
    hooks = {
        "pre_gateway_dispatch": plugin.capture_gateway,
        "pre_llm_call": plugin.start,
        "pre_tool_call": plugin.tool_start,
        "post_tool_call": plugin.tool,
        "post_llm_call": plugin.end,
        "on_session_end": plugin.end,
        "agent_loop_stopped": plugin.end,
        "on_session_finalize": plugin.end,
        "on_session_reset": plugin.end,
    }
    for name, callback in hooks.items():
        ctx.register_hook(name, callback)
    ctx.on_unload(plugin.close)
