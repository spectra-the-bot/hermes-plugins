# Progress Narrator

A standalone Hermes plugin that replaces a stream of tool details with brief,
LLM-generated progress updates. It observes tool activity without modifying tool
results, the system prompt, conversation history, or the main model's behavior.

Example style (illustrative, not a test result):

> Read configuration files and ran terminal commands.

## Behavior

- Uses a separately configured Hermes auxiliary model and host-managed credentials.
- Generates an update after six completed tool calls, with a 20-second minimum interval.
- A 45-second timer can report new activity before six calls complete.
- Each attempt consumes only new tool records; previous file reads are not replayed.
- The model skips more of the same activity instead of paraphrasing the previous update.
- A running tool can receive a brief continuation after 180 seconds without a delivered update.
- An open turn alone never triggers a heartbeat: fresh calls or a running tool are required.
- Emits one short sentence about tool activity only; returns `SKIP` for repetitive activity.
- Runs model and delivery work in a background thread, never inside the tool observer.
- Keeps a bounded event window for each turn; limits concurrent turns and delivered updates.
- Preserves the authorized source's receiving-bot and relay identity.
- Checks the owning agent, turn ID, and gateway generation before delivery.
- Honors the host's muted diagnostic turns and effective reply anchors.
- Allows up to 500 ms for the gateway's pending-agent promotion at turn admission.
- Discards pending updates on available completion, stop, reset, and unload hooks.
- Does not expose tools or grant the summarizer the ability to take actions.

The default input contains tool names, selected file basenames, completion/error
states, and a few numeric result fields. User questions and conversation text are
not retained or sent to the summarizer. It does
**not** include raw commands, search queries, full arguments, file contents, or
raw result text. This makes default summaries primarily activity summaries,
not detailed findings. Sanitized result excerpts are an explicit opt-in.

## Surface support

The implementation uses the originating gateway's shared adapter interface. It
has no Matrix-specific sender, bot token, room ID, or home-channel fallback.
Routing retains the chat, thread, reply anchor, profile, scope, and parent chat.
Contract tests cover Matrix, Telegram, Discord, Slack, and Signal routing.
These tests use recording adapters; they are not live certification of each service.

**CLI, TUI, Desktop, stateless API/webhook, Home Assistant, cron, and delegated
child sessions are intentionally silent.** Hermes currently has no stable,
passive plugin progress-output API shared by those surfaces. `inject_message`
would start or steer conversation turns, so this plugin never uses it.

### Compatibility boundary

The model facade and lifecycle hooks are public plugin APIs. Gateway delivery
currently requires a small bridge to these internal routing/state helpers:

- `GatewayRunner._delivery_adapter_for`
- `GatewayRunner._thread_metadata_for_source`
- `GatewayRunner._peek_session_state`
- `gateway.session_identity.replace_source`
- `gateway.platforms.base._reply_anchor_for_event`

CI pins the tested Hermes 0.21.4 API baseline. The bridge disables itself if the
expected methods are missing. It does not patch or replace any core function. Keep its integration tests in the update
check when upgrading Hermes.

The plugin makes one send attempt and never implements its own threadless
fallback. Underlying adapters can still have their own routing/retry policies.
An already-started network send cannot be recalled. Streaming final answers can
also precede finalization hooks. Generation checks and cancellation reduce late
messages, but **an absolute guarantee of no update after the final answer is not
possible with the current host contract**.

## Install

```sh
hermes plugins install spectra-the-bot/hermes-plugins/progress-narrator --no-enable
hermes plugins doctor progress-narrator --ci
```

Configure a model before enabling the plugin. There is no implicit model default:
without `auxiliary.progress_narrator.model`, the plugin stays idle.

Example using a custom endpoint and an existing host-managed credential:

```sh
hermes config set auxiliary.progress_narrator.provider custom
hermes config set auxiliary.progress_narrator.base_url https://api.venice.ai/api/v1
hermes config set auxiliary.progress_narrator.api_key '${VENICE_API_KEY}'
hermes config set auxiliary.progress_narrator.model gemini-3-5-flash-lite
hermes config set auxiliary.progress_narrator.timeout 12
```

`${VENICE_API_KEY}` is a literal environment reference, not a key value. Keep actual
credentials in the host's secret source or `.env`. The provider is an example,
not a dependency: any working Hermes auxiliary route can be used, including a
local OpenAI-compatible endpoint. Model availability and pricing can change.

`config set` may warn that this auxiliary key is unknown before the plugin is
loaded. The registered task makes the key available to the auxiliary client.

```sh
hermes plugins enable progress-narrator
```

Load it in a new gateway process using your normal supervised restart procedure.
Do not restart a busy gateway just to load the plugin. Existing turns are not
retroactively attached.

Once you have verified narration in your chosen chat, hide raw tool progress:

```sh
# Platform-scoped, recommended for the first rollout:
hermes config set display.platforms.matrix.tool_progress off
# Or, deliberately apply to all gateway surfaces:
# hermes config set display.tool_progress off
```

This plugin never changes display settings automatically. Keep assistant interim
messages enabled if you want the main agent's own updates too; disable them
separately if the two sources become repetitive.

## Configuration

Settings belong under `plugins.entries.progress-narrator`:

```yaml
plugins:
  entries:
    progress-narrator:
      enabled: true
      platforms: []                 # Empty = all eligible messaging adapters
      every_calls: 6
      min_seconds: 20
      max_seconds: 45
      heartbeat_seconds: 180
      max_events: 24
      max_updates: 20
      max_turn_seconds: 1800
      include_result_excerpts: false
      excerpt_chars: 240
```

For a quieter, conversational cadence, use `every_calls: 12`, `min_seconds: 90`,
`max_seconds: 180`, and `heartbeat_seconds: 180`. This allows changed activity at
most once per 90 seconds and a short continuation after about three minutes of
ongoing tool activity. These are eligibility timers, not delivery guarantees:
the model can return `SKIP`, and generation or delivery can fail. Silent model
reasoning without observable tool activity does not generate artificial check-ins.

Settings are captured on each new turn; cadence edits do not require a restart.
Code/prompt upgrades still require a new gateway process. Each summary attempt
consumes its batch even on `SKIP` or failure; new calls during generation remain
queued. Narration is a best-effort activity view, not an audit log.

Use `hermes config set` to update values. For example:

```sh
hermes config set plugins.entries.progress-narrator.every_calls 8
hermes config set plugins.entries.progress-narrator.platforms '["matrix", "slack"]'
```

New turns pick up these settings. Tool-count and time thresholds schedule a
summary attempt, not a guaranteed message. Model latency comes after that
threshold. Exact duplicates, `SKIP`, failures, and canceled turns produce no update.
The selected route follows Hermes' own provider fallback policy; attribution is
logged so operators can verify which provider and model actually answered.

## Privacy and failure behavior

- The summarizer receives only this turn's bounded tool records and previous update.
- Known sensitive tools contribute a generic protected-context label only.
- Host secret redaction runs with `force=True`; additional token/email/URL filtering applies.
- Sanitization is defense in depth, **not a guarantee against arbitrary confidential text**.
- Enabling result excerpts can send private document content to the configured model.
- Use a suitable local/private route when tool metadata or opted-in excerpts are sensitive.
- Prompt injection in evidence is treated as untrusted data; the summarizer has no tools.
- Model errors, missing transport, unsupported contexts, and delivery failures leave the main task running.
- Logs contain model attribution and generic failure messages, not prompts or tool results.
- The plugin stores no transcripts or result excerpts on disk.

Disable with `hermes plugins disable progress-narrator`, then reload through the
normal gateway lifecycle. Pending network calls may finish, but canceled results
are discarded before a new send is initiated where the host permits fencing.

## Development

```sh
HERMES_AGENT_SRC=/path/to/hermes-agent python -m pytest tests/test_progress_narrator_core.py tests/test_progress_narrator_integration.py tests/test_progress_narrator_routing.py
hermes plugins doctor ./progress-narrator --ci
ruff check progress-narrator tests/test_progress_narrator_core.py tests/test_progress_narrator_integration.py tests/test_progress_narrator_routing.py
```

Unit tests use deterministic clocks and explicit model/adapter doubles. Live
auxiliary calls must be tested separately through `ctx.llm`, with actual provider
attribution checked. Do not describe a successful mock delivery as a working
production gateway deployment.
