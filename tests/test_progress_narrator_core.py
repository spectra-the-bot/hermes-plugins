"""Unit tests for the standalone core; all provider responses are test doubles."""

from __future__ import annotations

import contextvars
import importlib.util
import json
import logging
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

CORE_PATH = Path(__file__).resolve().parents[1] / "progress-narrator" / "core.py"
REAL_THREAD_START = threading.Thread.start


@pytest.fixture(scope="module")
def core():
    spec = importlib.util.spec_from_file_location("progress_narrator_core_tests", CORE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    yield module
    sys.modules.pop(spec.name, None)


@pytest.fixture(autouse=True)
def disable_worker_start(monkeypatch):
    """Keep cadence tests deterministic; synchronized tests explicitly start a worker."""
    monkeypatch.setattr(threading.Thread, "start", lambda _thread: None)


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class ScriptedSummary:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, system, evidence):
        self.requests.append((system, json.loads(evidence)))
        assert self.responses, "Unexpected extra summarization request"
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


@pytest.fixture
def make_narrator(core):
    instances = []

    def make(*responses, settings=None, summarize=None, deliver=None, redactor=None):
        clock = FakeClock()
        summary = summarize if summarize is not None else ScriptedSummary(*responses)
        delivered = []

        def capture(text):
            delivered.append(text)
            return True

        narrator = core.Narrator(summary, settings, clock=clock, redactor=redactor)
        instances.append(narrator)
        turn = narrator.begin(
            "session-a",
            "turn-a",
            "Inspect unit-test evidence",
            deliver or capture,
        )
        assert turn is not None
        return SimpleNamespace(
            narrator=narrator,
            turn=turn,
            clock=clock,
            summary=summary,
            delivered=delivered,
        )

    yield make
    for narrator in instances:
        narrator.close()


def record_calls(harness, count=6, *, turn=None, **kwargs):
    active = harness.turn if turn is None else turn
    for _ in range(count):
        harness.narrator.record(*active.key, tool_name="terminal", **kwargs)


def tick_after(harness, seconds):
    harness.clock.advance(seconds)
    harness.narrator._tick(harness.turn)


def test_summary_input_contains_only_tool_activity(make_narrator):
    h = make_narrator("Read files and ran terminal commands.")
    turn = h.narrator.begin(
        "session-a",
        "tool-only-turn",
        "Steve asks whether the plugin is live.",
        lambda _text: True,
    )
    assert turn.task == ""
    record_calls(h, turn=turn)
    h.clock.advance(20)
    h.narrator._tick(turn)
    instructions, payload = h.summary.requests[0]
    assert set(payload) == {
        "recent_activity",
        "currently_running",
        "previous_update",
        "continuation_due",
    }
    assert "Steve" not in json.dumps(payload)
    assert "plugin is live" not in json.dumps(payload)
    assert "Summarize tool activity only" in instructions
    assert "Do not discuss evidence" in instructions
    assert "Do not mention the user" in instructions


def test_default_settings(core):
    settings = core.Settings()
    assert settings.every_calls == 6
    assert settings.min_seconds == 20
    assert settings.max_seconds == 45
    assert settings.max_events == 24
    assert settings.max_updates == 20
    assert settings.include_result_excerpts is False


def test_six_completed_calls_wait_for_twenty_seconds(make_narrator):
    h = make_narrator("Inspected the execution results.")
    record_calls(h, 6)
    assert h.turn.calls == 6
    assert h.summary.requests == []  # Observer callbacks do not call the provider.
    tick_after(h, 19.999)
    assert h.summary.requests == []
    tick_after(h, 0.001)
    assert h.delivered == ["Inspected the execution results."]
    assert h.turn.calls == 0
    assert h.turn.updates == 1


def test_five_calls_at_minimum_wait_until_sixth_call(make_narrator):
    h = make_narrator("The requested checks returned results.")
    record_calls(h, 5)
    tick_after(h, 20)
    assert h.summary.requests == []
    record_calls(h, 1)
    h.narrator._tick(h.turn)
    assert len(h.summary.requests) == 1


def test_single_completion_triggers_at_forty_five_seconds(make_narrator):
    h = make_narrator("An initial check returned a result.")
    record_calls(h, 1)
    tick_after(h, 44.999)
    assert h.summary.requests == []
    tick_after(h, 0.001)
    assert len(h.summary.requests) == 1


def test_running_tool_is_an_attempt_not_a_completed_call(make_narrator):
    h = make_narrator("A check is still running.")
    h.narrator.record(
        *h.turn.key,
        tool_name="terminal",
        tool_call_id="call-1",
        started=True,
        args={"command": "unit-test-command-must-not-leak"},
    )
    assert h.turn.calls == 0
    assert list(h.turn.events) == []
    tick_after(h, 20)
    assert h.summary.requests == []
    tick_after(h, 25)
    evidence = h.summary.requests[0][1]
    assert evidence["currently_running"] == ["terminal"]
    assert evidence["recent_activity"] == []
    assert "unit-test-command-must-not-leak" not in json.dumps(evidence)
    assert "A tool call alone proves only an attempt" in h.summary.requests[0][0]


def test_no_updates_without_new_evidence(make_narrator):
    h = make_narrator("Checked the initial results.")
    tick_after(h, 45)
    assert h.summary.requests == []
    record_calls(h, 1)
    h.narrator._tick(h.turn)
    tick_after(h, 90)
    assert len(h.summary.requests) == 1
    assert len(h.delivered) == 1


def test_cadence_restarts_after_each_attempt(make_narrator):
    h = make_narrator("First useful finding.", "Second useful finding.")
    record_calls(h)
    tick_after(h, 20)
    record_calls(h)
    tick_after(h, 19.999)
    assert len(h.summary.requests) == 1
    tick_after(h, 0.001)
    assert len(h.summary.requests) == 2
    assert h.summary.requests[1][1]["previous_update"] == "First useful finding."


@pytest.mark.parametrize("response", ["SKIP", "skip", " \nSkIp\t", "", " \n\t"])
def test_skip_and_empty_responses_consume_attempt_not_update(make_narrator, response):
    h = make_narrator(response, "A later check found a change.")
    record_calls(h)
    tick_after(h, 20)
    assert h.delivered == []
    assert h.turn.updates == 0
    assert h.turn.previous == ""
    assert h.turn.reported_revision == h.turn.revision
    tick_after(h, 45)
    assert len(h.summary.requests) == 1
    record_calls(h, 1)
    h.narrator._tick(h.turn)
    assert h.delivered == ["A later check found a change."]


def test_case_and_whitespace_normalized_duplicates_are_not_delivered(make_narrator):
    h = make_narrator("Checked  the results.\n", "CHECKED THE RESULTS.", "Found a discrepancy.")
    for _ in range(3):
        record_calls(h)
        tick_after(h, 20)
    assert h.delivered == ["Checked the results.", "Found a discrepancy."]
    assert h.turn.updates == 2
    assert h.summary.requests[2][1]["previous_update"] == "Checked the results."


def test_provider_failure_is_fail_soft_and_not_logged_verbatim(make_narrator, caplog):
    h = make_narrator(RuntimeError("unit-private-provider-detail"), "Recovered on new evidence.")
    record_calls(h)
    with caplog.at_level(logging.WARNING):
        tick_after(h, 20)
    assert h.delivered == []
    assert h.turn.updates == 0
    assert not h.turn.stopped
    assert "unit-private-provider-detail" not in caplog.text
    assert "failed" in caplog.text
    tick_after(h, 45)
    assert len(h.summary.requests) == 1
    record_calls(h, 1)
    h.narrator._tick(h.turn)
    assert h.delivered == ["Recovered on new evidence."]


@pytest.mark.parametrize("failure", [False, RuntimeError("unit-private-delivery-detail")])
def test_failed_delivery_does_not_advance_success_state(make_narrator, caplog, failure):
    attempts = []

    def delivery(text):
        attempts.append(text)
        if len(attempts) == 1:
            if isinstance(failure, Exception):
                raise failure
            return failure
        return True

    h = make_narrator("Checked the result.", "Checked the result.", deliver=delivery)
    record_calls(h)
    with caplog.at_level(logging.WARNING):
        tick_after(h, 20)
    assert h.turn.previous == ""
    assert h.turn.updates == 0
    assert h.turn.calls == 0
    assert not h.turn.stopped
    assert "unit-private-delivery-detail" not in caplog.text
    record_calls(h)
    tick_after(h, 20)
    assert attempts == ["Checked the result.", "Checked the result."]
    assert h.summary.requests[1][1]["previous_update"] == ""
    assert h.turn.updates == 1
    assert h.turn.previous == "Checked the result."


def test_results_returning_after_end_are_discarded(make_narrator):
    def end_during_summary(_system, _evidence):
        h.narrator.end(*h.turn.key)
        return "This result is stale."

    h = make_narrator(summarize=end_during_summary)
    record_calls(h)
    tick_after(h, 20)
    assert h.delivered == []
    assert h.turn.stopped
    assert h.turn.key not in h.narrator.turns


def test_new_evidence_during_summary_survives_for_next_attempt(make_narrator):
    requests = []

    def summarize(_system, evidence):
        requests.append(json.loads(evidence))
        if len(requests) == 1:
            record_calls(h, 1, result={"exit_code": 7})
        return f"Observed evidence batch {len(requests)}."

    h = make_narrator(summarize=summarize)
    record_calls(h)
    tick_after(h, 20)
    assert h.turn.revision != h.turn.reported_revision
    assert h.turn.calls == 1
    tick_after(h, 45)
    assert len(requests) == 2
    assert requests[1]["recent_activity"][-1]["exit_code"] == 7
    assert len(requests[1]["recent_activity"]) == 1


def test_each_summary_sees_only_new_tool_records(make_narrator):
    h = make_narrator("Read the implementation.", "Read the tests.")
    h.narrator.record(*h.turn.key, tool_name="read_file", args={"path": "/src/core.py"})
    tick_after(h, 45)
    assert not h.turn.events
    h.narrator.record(*h.turn.key, tool_name="read_file", args={"path": "/tests/test_core.py"})
    tick_after(h, 45)
    assert [e["target"] for e in h.summary.requests[1][1]["recent_activity"]] == ["test_core.py"]
    assert not h.summary.requests[1][1]["continuation_due"]


def test_identical_records_are_collapsed_in_model_input(make_narrator):
    h = make_narrator("Ran a command.")
    record_calls(h, 6)
    tick_after(h, 20)
    assert len(h.summary.requests[0][1]["recent_activity"]) == 1


def test_changed_activity_does_not_inherit_previous_wording(make_narrator):
    h = make_narrator("Read files.", "Patched the implementation.")
    h.narrator.record(*h.turn.key, tool_name="read_file")
    tick_after(h, 45)
    h.narrator.record(*h.turn.key, tool_name="patch")
    tick_after(h, 180)
    payload = h.summary.requests[1][1]
    assert payload["previous_update"] == ""
    assert payload["continuation_due"] is False


def test_skipped_batch_is_not_replayed(make_narrator):
    h = make_narrator("SKIP", "Applied a patch.")
    h.narrator.record(*h.turn.key, tool_name="read_file", args={"path": "old.py"})
    tick_after(h, 45)
    h.narrator.record(*h.turn.key, tool_name="patch", args={"path": "new.py"})
    tick_after(h, 45)
    assert [e["target"] for e in h.summary.requests[1][1]["recent_activity"]] == ["new.py"]


def test_long_running_tool_gets_spaced_continuation(make_narrator):
    h = make_narrator("Running a command.", "Still running the command.")
    h.narrator.record(*h.turn.key, tool_name="terminal", tool_call_id="long", started=True)
    tick_after(h, 45)
    tick_after(h, 179)
    assert len(h.summary.requests) == 1
    tick_after(h, 1)
    assert len(h.delivered) == 2
    payload = h.summary.requests[1][1]
    assert payload["continuation_due"] is True
    assert payload["currently_running"] == ["terminal"]
    assert payload["recent_activity"] == []
    assert (
        payload["previous_update"] == ""
    )  # Old activity cannot leak into a running-only heartbeat.


def test_heartbeat_does_not_replay_finished_work(make_narrator):
    h = make_narrator("Read files.")
    record_calls(h)
    tick_after(h, 20)
    tick_after(h, 180)
    assert len(h.summary.requests) == 1


def test_heartbeat_uses_last_delivery_not_last_attempt(make_narrator):
    h = make_narrator("Read files.", "SKIP", "Still running a command.")
    record_calls(h)
    tick_after(h, 20)
    record_calls(h)
    tick_after(h, 20)
    h.narrator.record(*h.turn.key, tool_name="terminal", tool_call_id="long", started=True)
    tick_after(h, 160)
    assert h.summary.requests[2][1]["continuation_due"] is True
    assert len(h.delivered) == 2


def test_heartbeat_can_repeat_text_only_after_quiet_interval(make_narrator):
    h = make_narrator("Running a command.", "Running a command.")
    h.narrator.record(*h.turn.key, tool_name="terminal", tool_call_id="long", started=True)
    tick_after(h, 45)
    tick_after(h, 180)
    assert h.delivered == ["Running a command.", "Running a command."]


def test_running_tool_finishing_during_heartbeat_suppresses_stale_update(make_narrator):
    calls = []

    def summarize(_system, payload):
        calls.append(json.loads(payload))
        if len(calls) == 2:
            h.narrator.record(*h.turn.key, tool_name="terminal", tool_call_id="long")
        return "Still running a command."

    h = make_narrator(summarize=summarize)
    h.narrator.record(*h.turn.key, tool_name="terminal", tool_call_id="long", started=True)
    tick_after(h, 45)
    tick_after(h, 180)
    assert len(calls) == 2
    assert len(h.delivered) == 1
    assert len(h.turn.events) == 1


def test_quieter_profile_cadence(core, make_narrator):
    h = make_narrator(
        "Read files.",
        "Ran commands.",
        settings=core.Settings(every_calls=12, min_seconds=90, max_seconds=180),
    )
    record_calls(h, 11)
    tick_after(h, 90)
    assert not h.summary.requests
    record_calls(h, 1)
    h.narrator._tick(h.turn)
    assert len(h.summary.requests) == 1
    record_calls(h, 6)
    tick_after(h, 90)
    assert len(h.summary.requests) == 1
    tick_after(h, 90)
    assert len(h.summary.requests) == 2


@pytest.mark.parametrize("value", [True, "180", 0, 29, 3601, float("nan")])
def test_heartbeat_interval_validation(core, value):
    with pytest.raises((TypeError, ValueError)):
        core.Settings(heartbeat_seconds=value)


def test_begin_replaces_existing_turn_in_same_session(make_narrator):
    h = make_narrator()
    other = h.narrator.begin("session-b", "turn-b", "Other task", lambda _text: True)
    replacement = h.narrator.begin("session-a", "turn-new", "New task", lambda _text: True)
    assert replacement is not None
    assert h.turn.stopped
    assert h.turn.wake.is_set()
    assert not other.stopped
    assert set(h.narrator.turns) == {other.key, replacement.key}
    h.narrator.record(*h.turn.key, tool_name="terminal")
    assert not replacement.events
    assert h.turn.calls == 0


def test_multiple_sessions_keep_evidence_and_destinations_isolated(make_narrator):
    h = make_narrator("First session update.", "Second session update.")
    second_delivered = []

    def deliver_second(text):
        second_delivered.append(text)
        return True

    other = h.narrator.begin("session-b", "turn-b", "Task B only", deliver_second)
    assert other is not None
    h.narrator.record(*h.turn.key, tool_name="read_file", args={"path": "/private/a-only.py"})
    h.narrator.record(*other.key, tool_name="write_file", args={"path": "/private/b-only.py"})
    tick_after(h, 45)
    h.narrator._tick(other)
    first_evidence = json.dumps(h.summary.requests[0][1])
    second_evidence = json.dumps(h.summary.requests[1][1])
    assert "a-only.py" in first_evidence and "b-only.py" not in first_evidence
    assert "b-only.py" in second_evidence and "a-only.py" not in second_evidence
    assert "Task B only" not in first_evidence
    assert h.delivered == ["First session update."]
    assert second_delivered == ["Second session update."]
    h.narrator.end(*h.turn.key)
    assert not other.stopped


def test_event_window_retains_only_latest_events(core, make_narrator):
    h = make_narrator("Recent checks returned results.", settings=core.Settings(max_events=3))
    for number in range(50):
        h.narrator.record(*h.turn.key, tool_name="terminal", result={"exit_code": number})
    assert len(h.turn.events) == 3
    assert h.turn.calls == 50
    tick_after(h, 20)
    activity = h.summary.requests[0][1]["recent_activity"]
    assert [item["exit_code"] for item in activity] == [47, 48, 49]


def test_running_tools_are_bounded_and_removed_by_call_id(make_narrator):
    h = make_narrator()
    for number in range(40):
        h.narrator.record(
            *h.turn.key,
            tool_name="terminal",
            tool_call_id=f"call-{number}",
            started=True,
        )
    assert len(h.turn.running) == 32
    assert h.turn.calls == 0
    h.narrator.record(*h.turn.key, tool_name="terminal", tool_call_id="call-0")
    assert "call-0" not in h.turn.running
    assert "call-1" in h.turn.running
    assert len(h.turn.running) == 31
    assert h.turn.calls == 1
    h.narrator.record(*h.turn.key, tool_name="read_file", tool_call_id="call-next", started=True)
    assert len(h.turn.running) == 32


def test_end_and_close_are_idempotent_and_stop_late_records(make_narrator):
    h = make_narrator()
    other = h.narrator.begin("session-b", "turn-b", "Other task", lambda _text: True)
    assert other is not None
    record_calls(h, 1)
    h.narrator.end(*h.turn.key)
    h.narrator.end(*h.turn.key)
    record_calls(h, 1)
    assert h.turn.calls == 1
    tick_after(h, 45)
    assert h.summary.requests == []
    h.narrator.close()
    h.narrator.close()
    assert h.narrator.turns == {}
    assert other.stopped and other.wake.is_set()


def test_success_limit_stops_additional_provider_requests(core, make_narrator):
    h = make_narrator("One useful update.", settings=core.Settings(max_updates=1))
    record_calls(h)
    tick_after(h, 20)
    record_calls(h)
    tick_after(h, 20)
    assert len(h.summary.requests) == 1
    assert h.turn.stopped


def test_maximum_turn_lifetime_expires_without_provider_request(core, make_narrator):
    h = make_narrator(settings=core.Settings(max_turn_seconds=30))
    record_calls(h)
    tick_after(h, 30)
    assert h.turn.stopped
    assert h.summary.requests == []


@pytest.mark.parametrize("session,turn", [("", "valid"), ("valid", ""), (None, "valid")])
def test_begin_rejects_missing_identifiers(core, session, turn):
    narrator = core.Narrator(ScriptedSummary())
    assert narrator.begin(session, turn, "Task", lambda _text: True) is None
    assert narrator.turns == {}


def test_active_session_limit_allows_replacement_and_slot_reuse(core):
    narrator = core.Narrator(ScriptedSummary())
    try:
        turns = [
            narrator.begin(f"session-{number}", "turn", "Task", lambda _text: True)
            for number in range(32)
        ]
        assert all(turn is not None for turn in turns)
        assert narrator.begin("overflow", "turn", "Task", lambda _text: True) is None
        replacement = narrator.begin("session-0", "new", "Task", lambda _text: True)
        assert replacement is not None and turns[0].stopped
        assert len(narrator.turns) == 32
        narrator.end(*turns[1].key)
        assert narrator.begin("new-session", "turn", "Task", lambda _text: True) is not None
        assert len(narrator.turns) == 32
    finally:
        narrator.close()


@pytest.mark.parametrize(
    "options",
    [
        {"every_calls": 0},
        {"every_calls": 101},
        {"min_seconds": 0},
        {"min_seconds": 46},
        {"max_seconds": 601},
        {"max_seconds": float("nan")},
        {"min_seconds": float("inf")},
        {"max_events": 0},
        {"max_events": 101},
        {"max_updates": 0},
        {"max_updates": 101},
        {"max_turn_seconds": 29},
        {"max_turn_seconds": 7201},
        {"excerpt_chars": -1},
        {"excerpt_chars": 1001},
    ],
)
def test_settings_reject_out_of_range_values(core, options):
    with pytest.raises(ValueError):
        core.Settings(**options)


@pytest.mark.parametrize(
    "options",
    [
        {"every_calls": 6.5},
        {"every_calls": True},
        {"max_events": 1.5},
        {"max_events": True},
        {"max_updates": 1.5},
        {"excerpt_chars": 1.5},
        {"include_result_excerpts": "false"},
        {"include_result_excerpts": 1},
    ],
)
def test_settings_reject_types_that_bypass_safety_bounds(core, options):
    with pytest.raises((TypeError, ValueError)):
        core.Settings(**options)


def test_default_evidence_excludes_commands_arguments_and_raw_result(core):
    event = core.event_from_tool(
        "terminal",
        {"command": "unit-private-command", "query": "unit-private-query"},
        {"stdout": "unit-private-output", "error": "unit-private-error", "exit_code": 1},
        "completed",
        core.Settings(),
    )
    assert event == {"tool": "terminal", "status": "completed", "exit_code": 1, "has_error": True}


@pytest.mark.parametrize("path", ["/private/work/module.py", "C:\\private\\work\\module.py"])
def test_file_evidence_keeps_only_basename(core, path):
    event = core.event_from_tool(
        "read_file",
        {"path": path},
        "private contents",
        "completed",
        core.Settings(),
    )
    assert event == {"tool": "read_file", "status": "completed", "target": "module.py"}


def test_result_metadata_records_false_zero_and_errors_without_claiming_success(core):
    result = {
        "success": False,
        "exit_code": 0,
        "returncode": 2,
        "total_count": 0,
        "verified": False,
        "error": "unit-private-error",
        "output": "unit-private-output",
    }
    expected = {
        "tool": "terminal",
        "status": "completed",
        "success": False,
        "exit_code": 0,
        "returncode": 2,
        "total_count": 0,
        "verified": False,
        "has_error": True,
    }
    for representation in (result, json.dumps(result)):
        event = core.event_from_tool("terminal", {}, representation, "completed", core.Settings())
        assert event == expected
    assert core.event_from_tool("terminal", {}, "done", "completed", core.Settings()) == {
        "tool": "terminal",
        "status": "completed",
    }


def test_result_metadata_does_not_trust_string_success_flags(core):
    event = core.event_from_tool(
        "terminal",
        {},
        {"success": "true", "verified": "yes", "exit_code": "0"},
        "completed",
        core.Settings(),
    )
    assert event == {"tool": "terminal", "status": "completed"}


@pytest.mark.parametrize(
    "name",
    [
        "browser_vault_fill",
        "credential_lookup",
        "password_lookup",
        "secret_sources",
        "oauth_login",
        "memory_search",
        "mcp__honcho__chat",
        "mcp__personal_context__get_item",
    ],
)
def test_sensitive_tools_suppress_identifiers_and_results_even_when_excerpts_enabled(core, name):
    event = core.event_from_tool(
        name,
        {"path": "/unit-private-path"},
        {"output": "unit-private-result", "success": True, "total_count": 12},
        "completed",
        core.Settings(include_result_excerpts=True),
    )
    assert event == {"activity": "accessing protected context", "status": "completed"}


@pytest.mark.parametrize(
    "value,hidden",
    [
        ("Bearer unit-bearer", "unit-bearer"),
        ("api_key=unit-api-value", "unit-api-value"),
        ("password:unit-password-value", "unit-password-value"),
        ("ghp_UNITTESTONLY", "ghp_UNITTESTONLY"),
        ("sk-unit-test-only", "sk-unit-test-only"),
        ("eyJunit.payload.signature", "eyJunit.payload.signature"),
        ("unit-user@example.invalid", "unit-user@example.invalid"),
        ("https://example.invalid/unit-private", "example.invalid"),
    ],
)
def test_clean_redacts_sensitive_markers(core, value, hidden):
    result = core.clean(f"before {value} after", 500)
    assert hidden not in result
    assert result.startswith("before ") and result.endswith(" after")


def test_clean_applies_custom_redactor_before_whitespace_and_length_limit(core):
    seen = []

    def redact(text):
        seen.append(text)
        return text.replace("unit-private-name", "[name]")

    result = core.clean("  unit-private-name\n" + "x" * 2000, 30, redact)
    assert result.startswith("[name] ")
    assert len(result) == 30
    assert len(seen[0]) <= 1024


def test_task_and_provider_output_are_redacted_and_bounded(core, make_narrator):
    h = make_narrator("Bearer unit-bearer " + "x" * 1000)
    task_turn = h.narrator.begin(
        "task-session",
        "task-turn",
        "api_key=unit-key " + "x" * 1000,
        lambda _text: True,
    )
    assert task_turn is not None
    assert "unit-key" not in task_turn.task
    assert len(task_turn.task) <= 600
    record_calls(h)
    tick_after(h, 20)
    assert "unit-bearer" not in h.delivered[0]
    assert len(h.delivered[0]) <= 420


def test_excerpts_are_opt_in_redacted_and_bounded(core):
    result = "Safe result Bearer unit-bearer " + "x" * 1000
    default = core.event_from_tool("terminal", {}, result, "completed", core.Settings())
    opted_in = core.event_from_tool(
        "terminal",
        {},
        result,
        "completed",
        core.Settings(include_result_excerpts=True, excerpt_chars=40),
    )
    assert "excerpt" not in default
    assert opted_in["excerpt"].startswith("Safe result [redacted]")
    assert "unit-bearer" not in opted_in["excerpt"]
    assert len(opted_in["excerpt"]) == 40


def test_opted_in_json_excerpts_redact_quoted_credential_values(core):
    result = {"password": "unit-private-value", "api_key": "unit-api-value"}
    for representation in (result, json.dumps(result)):
        event = core.event_from_tool(
            "terminal",
            {},
            representation,
            "completed",
            core.Settings(include_result_excerpts=True),
        )
        assert "unit-private-value" not in event["excerpt"]
        assert "unit-api-value" not in event["excerpt"]


def test_sensitive_tool_status_is_also_redacted(core):
    event = core.event_from_tool(
        "browser_vault_fill",
        {},
        {},
        "error token=unit-status-value",
        core.Settings(),
    )
    assert "unit-status-value" not in json.dumps(event)


def test_custom_redactor_applies_to_tasks_targets_and_excerpts(core, make_narrator):
    def redact(text):
        return text.replace("unit-private-name", "[name]")

    h = make_narrator(redactor=redact)
    other = h.narrator.begin(
        "redacted-session",
        "redacted-turn",
        "Inspect unit-private-name",
        lambda _text: True,
    )
    assert other.task == ""
    event = core.event_from_tool(
        "read_file",
        {"path": "/private/unit-private-name.txt"},
        "unit-private-name result",
        "completed",
        core.Settings(include_result_excerpts=True),
        redact,
    )
    assert event["target"] == "[name].txt"
    assert event["excerpt"] == "[name] result"


@pytest.mark.parametrize("cancel_all", [False, True])
def test_blocked_provider_does_not_block_recording_or_cancel(make_narrator, cancel_all):
    entered = threading.Event()
    release = threading.Event()

    def blocking_summary(_system, _evidence):
        entered.set()
        if not release.wait(timeout=3):
            raise RuntimeError("unit synchronization timeout")
        return "This result arrived after cancellation."

    h = make_narrator(summarize=blocking_summary)
    record_calls(h)
    h.clock.advance(20)
    worker = h.turn.thread
    assert worker is not None
    REAL_THREAD_START(worker)
    try:
        assert entered.wait(timeout=2)
        record_calls(h, 1)
        if cancel_all:
            h.narrator.close()
        else:
            h.narrator.end(*h.turn.key)
        assert h.turn.stopped
    finally:
        release.set()
        worker.join(timeout=3)
    assert not worker.is_alive()
    assert h.delivered == []
    assert h.narrator.turns == {}


def test_old_worker_cannot_unregister_replacement_with_reused_identifiers(make_narrator):
    entered = threading.Event()
    release = threading.Event()

    def blocking_summary(_system, _evidence):
        entered.set()
        if not release.wait(timeout=3):
            raise RuntimeError("unit synchronization timeout")
        return "This result belongs to the old turn."

    h = make_narrator(summarize=blocking_summary)
    record_calls(h)
    h.clock.advance(20)
    worker = h.turn.thread
    assert worker is not None
    REAL_THREAD_START(worker)
    try:
        assert entered.wait(timeout=2)
        replacement = h.narrator.begin(*h.turn.key, "Replacement task", lambda _text: True)
        assert replacement is not None
        assert h.turn.stopped
    finally:
        release.set()
        worker.join(timeout=3)
    assert not worker.is_alive()
    assert h.delivered == []
    assert not replacement.stopped
    assert h.narrator.turns[replacement.key] is replacement


def test_worker_captures_context_at_turn_registration(make_narrator):
    marker = contextvars.ContextVar("unit_narrator_context", default="unset")
    seen = []

    def summarize(_system, _evidence):
        seen.append(marker.get())
        h.narrator.end(*h.turn.key)
        return "SKIP"

    reset = marker.set("registered-context")
    try:
        h = make_narrator(summarize=summarize)
        marker.set("later-context")
        record_calls(h)
        h.clock.advance(20)
        worker = h.turn.thread
        assert worker is not None
        REAL_THREAD_START(worker)
        worker.join(timeout=3)
        assert not worker.is_alive()
        assert seen == ["registered-context"]
        assert h.narrator.turns == {}
    finally:
        marker.reset(reset)


def test_worker_unregisters_expired_turn(core, make_narrator):
    h = make_narrator(settings=core.Settings(max_turn_seconds=30))
    record_calls(h)
    h.clock.advance(30)
    worker = h.turn.thread
    assert worker is not None
    REAL_THREAD_START(worker)
    worker.join(timeout=3)
    assert not worker.is_alive()
    assert h.turn.stopped
    assert h.narrator.turns == {}
    assert h.summary.requests == []
