from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
from agent.secret_sources.base import ErrorKind
from tests.secret_sources.conformance import SecretSourceConformance


def login_item(
    name: str = "OPENAI_API_KEY",
    value: str = "fake-secret",
    *,
    state: str = "Active",
    item_id: str = "1",
    extra=None,
):
    return {
        "id": item_id,
        "state": state,
        "content": {
            "title": name,
            "content": {"Login": {"email": "", "username": "", "password": value, "urls": []}},
            "extra_fields": extra or [],
        },
    }


def custom_item(*fields, item_id: str = "2"):
    return {
        "id": item_id,
        "state": "Active",
        "content": {
            "title": "Custom",
            "content": {
                "Custom": {
                    "sections": [{"section_name": "Runtime", "section_fields": list(fields)}]
                }
            },
            "extra_fields": [],
        },
    }


@pytest.fixture
def fake_cli(tmp_path: Path, monkeypatch, plugin_module):
    """Spy below run_secret_cli while keeping its env/stdin hardening active.

    Patching subprocess.run instead of using a shebang fixture keeps this test
    valid on Windows, where a renamed Python script is not a real .exe.
    """
    binary = tmp_path / ("pass-cli.exe" if os.name == "nt" else "pass-cli")
    binary.write_bytes(b"fake executable placeholder")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    original_validator = plugin_module._validate_binary_path
    monkeypatch.setattr(
        plugin_module,
        "_validate_binary_path",
        lambda candidate: (
            binary.resolve() if candidate == binary else original_validator(candidate)
        ),
    )
    config: dict = {"payload": {"items": []}}
    entries: list[dict] = []

    def completed(argv, returncode=0, stdout="", stderr=""):
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=stderr)

    def fake_run(argv, *, env, capture_output, text, timeout, stdin):
        args = list(argv[1:])
        entries.append(
            {
                "argv": args,
                "env_keys": sorted(env),
                "token_present": "PROTON_PASS_PERSONAL_ACCESS_TOKEN" in env,
                "session_dir": env.get("PROTON_PASS_SESSION_DIR"),
                "home": env.get("HOME"),
                "stdin": "" if stdin == subprocess.DEVNULL else "open",
            }
        )
        assert capture_output is True
        assert text is True
        if (
            config.get("sleep_command") == " ".join(args)
            and float(config.get("sleep", 1)) > timeout
        ):
            raise subprocess.TimeoutExpired(argv, timeout)
        if args == ["--version"]:
            return completed(
                argv,
                int(config.get("version_rc", 0)),
                str(config.get("version", "Proton Pass CLI 2.1.2 (fake)")),
            )

        session = Path(env["PROTON_PASS_SESSION_DIR"])
        marker = session / "fake-login"
        if args == ["login"]:
            if config.get("login_rc", 0):
                return completed(argv, int(config["login_rc"]), stderr="sensitive fake diagnostic")
            if "PROTON_PASS_PERSONAL_ACCESS_TOKEN" not in env:
                return completed(argv, 91)
            session.mkdir(parents=True, exist_ok=True)
            marker.write_text("yes", encoding="utf-8")
            return completed(argv, stdout="logged in")
        if args == ["info", "--output", "json"]:
            if config.get("fresh", True) and not marker.exists():
                return completed(argv, 1)
            identity = config.get("identity", "plain")
            if identity == "agent":
                payload = {"id": "N/A", "personal_access_token_name": "[Agent] fake"}
            elif identity == "human":
                payload = {
                    "id": "user-id",
                    "username": "fake",
                    "email": "fake@example.invalid",
                }
            elif identity == "malformed":
                payload = []
            else:
                payload = {
                    "id": "N/A",
                    "personal_access_token_name": config.get("identity_name", "Runtime PAT"),
                }
            return completed(argv, int(config.get("info_rc", 0)), json.dumps(payload))
        if len(args) >= 2 and args[:2] == ["item", "list"]:
            cache_path = config.get("assert_cache_absent")
            if cache_path is not None:
                assert not Path(cache_path).exists()
            if config.get("list_rc", 0):
                return completed(
                    argv,
                    int(config["list_rc"]),
                    stderr="sensitive fake item diagnostic",
                )
            raw = config.get("raw_output")
            stdout = (
                str(raw) if raw is not None else json.dumps(config.get("payload", {"items": []}))
            )
            return completed(argv, stdout=stdout)
        return completed(argv, 90)

    monkeypatch.setattr("agent.secret_sources.base.subprocess.run", fake_run)

    def configure(**changes):
        config.update(changes)

    def logs():
        return list(entries)

    return binary, configure, logs


@pytest.fixture
def source(plugin_module):
    return plugin_module.ProtonPassSource()


@pytest.fixture
def configured(monkeypatch, fake_cli):
    binary, configure, logs = fake_cli
    monkeypatch.setenv("PROTON_PASS_PERSONAL_ACCESS_TOKEN", "fake-bootstrap-token")
    monkeypatch.setenv("PROTON_PASS_AGENT_TOKEN", "must-not-reach-child")
    monkeypatch.setenv("PROTON_PASS_AGENT_REASON", "must-not-reach-child")
    monkeypatch.setenv("UNRELATED_SECRET", "must-not-reach-child")
    cfg = {"enabled": True, "vault": "Runtime Vault", "binary_path": str(binary)}
    return cfg, configure, logs


class TestProtonPassConformance(SecretSourceConformance):
    @pytest.fixture
    def source(self, plugin_module):
        return plugin_module.ProtonPassSource()


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Proton Pass CLI 2.1.0 (abc)", (2, 1, 0)),
        ("Proton Pass CLI 9.12.3", (9, 12, 3)),
        ("2.0.2", None),
        ("Other Product 2.1.0", None),
        ("prefix Proton Pass CLI 2.1.0", None),
        ("unknown", None),
    ],
)
def test_version_parser(plugin_module, text, expected):
    assert plugin_module._parse_version(text) == expected


@pytest.mark.parametrize("version", ["Proton Pass CLI 2.0.9", "garbage"])
def test_rejects_old_or_malformed_version(source, configured, tmp_path, version):
    cfg, configure, _ = configured
    configure(version=version)
    result = source.fetch(cfg, tmp_path / "home")
    assert result.error_kind == ErrorKind.BINARY_MISSING
    assert not result.secrets


def test_accepts_declared_minimum_version(source, configured, tmp_path):
    cfg, configure, _ = configured
    configure(version="Proton Pass CLI 2.1.0", payload={"items": [login_item()]})
    assert source.fetch(cfg, tmp_path).ok


def test_missing_and_pinned_binary_errors(source, monkeypatch, tmp_path):
    monkeypatch.setenv("PROTON_PASS_PERSONAL_ACCESS_TOKEN", "fake")
    result = source.fetch(
        {"enabled": True, "vault": "v", "binary_path": str(tmp_path / "nope")}, tmp_path
    )
    assert result.error_kind == ErrorKind.BINARY_MISSING


def test_config_schema_and_bootstrap_protection(source):
    schema = source.config_schema()
    assert schema["cache_ttl_seconds"]["default"] == 0
    assert schema["cache_ttl_seconds"]["maximum"] == 30 * 24 * 60 * 60
    assert schema["command_timeout_seconds"]["maximum"] == 300
    assert schema["binary_path"]["default"] == ""
    assert schema["override_existing"]["default"] is False
    assert source.override_existing({}) is False
    assert source.override_existing({"override_existing": True}) is True
    assert source.protected_env_vars({}) == frozenset({"PROTON_PASS_PERSONAL_ACCESS_TOKEN"})
    assert source.shape == "bulk"
    assert source.api_version == 1


def test_happy_path_one_bulk_read_and_minimal_noninteractive_env(source, configured, tmp_path):
    cfg, configure, logs = configured
    configure(payload={"items": [login_item()]})
    result = source.fetch(cfg, tmp_path / "profile")
    assert result.secrets == {"OPENAI_API_KEY": "fake-secret"}
    calls = logs()
    assert [call["argv"] for call in calls] == [
        ["--version"],
        ["info", "--output", "json"],
        ["login"],
        ["info", "--output", "json"],
        ["item", "list", "Runtime Vault", "--output", "json", "--show-secrets"],
    ]
    assert all(call["stdin"] == "" for call in calls)
    assert [call["token_present"] for call in calls] == [False, False, True, False, False]
    assert all("UNRELATED_SECRET" not in call["env_keys"] for call in calls)
    assert all("PROTON_PASS_AGENT_TOKEN" not in call["env_keys"] for call in calls)
    assert all("PROTON_PASS_AGENT_REASON" not in call["env_keys"] for call in calls)
    assert all("item" not in call["argv"] or "view" not in call["argv"] for call in calls)
    # The fake PAT is absent from argv and persisted non-secret logs.
    assert "fake-bootstrap-token" not in json.dumps(calls)


@pytest.mark.parametrize(
    ("identity", "phrase"), [("agent", "Agent"), ("human", "human"), ("malformed", "malformed")]
)
def test_rejects_existing_non_plain_identity_before_item_read(
    source, configured, tmp_path, identity, phrase
):
    cfg, configure, logs = configured
    configure(fresh=False, identity=identity)
    result = source.fetch(cfg, tmp_path)
    assert result.error_kind == ErrorKind.AUTH_FAILED
    assert phrase.lower() in (result.error or "").lower()
    assert not any(call["argv"][:2] == ["item", "list"] for call in logs())


def test_rejects_agent_identity_after_login_and_does_not_fingerprint(source, configured, tmp_path):
    cfg, configure, logs = configured
    configure(identity="agent")
    result = source.fetch(cfg, tmp_path)
    assert result.error_kind == ErrorKind.AUTH_FAILED
    assert not (tmp_path / "state" / "proton-pass" / "session-fingerprint.json").exists()
    assert not any(call["argv"][:2] == ["item", "list"] for call in logs())


def test_missing_fingerprint_and_token_rotation_rebootstrap_session(
    source, configured, monkeypatch, tmp_path
):
    cfg, configure, logs = configured
    configure(payload={"items": [login_item()]})
    assert source.fetch(cfg, tmp_path).ok
    (tmp_path / "state" / "proton-pass" / "session-fingerprint.json").unlink()
    assert source.fetch(cfg, tmp_path).ok
    monkeypatch.setenv("PROTON_PASS_PERSONAL_ACCESS_TOKEN", "rotated-fake-token")
    assert source.fetch(cfg, tmp_path).ok
    assert sum(call["argv"] == ["login"] for call in logs()) == 3


def test_account_identity_change_rebootstraps_session(source, configured, tmp_path):
    cfg, configure, logs = configured
    assert source.fetch(cfg, tmp_path).ok
    configure(identity_name="Other Account PAT")
    assert source.fetch(cfg, tmp_path).ok
    assert sum(call["argv"] == ["login"] for call in logs()) == 2


def test_two_profile_homes_have_isolated_sessions(source, configured, tmp_path):
    cfg, _, logs = configured
    assert source.fetch(cfg, tmp_path / "a").ok
    assert source.fetch(cfg, tmp_path / "b").ok
    sessions = {call["session_dir"] for call in logs() if call["argv"] == ["login"]}
    assert len(sessions) == 2
    assert all(str(tmp_path) in session for session in sessions)


@pytest.mark.skipif(os.name == "nt", reason="ordinary Windows users cannot create symlinks")
def test_symlinked_profile_state_fails_closed(source, configured, tmp_path):
    cfg, _, logs = configured
    profile = tmp_path / "profile"
    outside = tmp_path / "outside"
    profile.mkdir()
    outside.mkdir()
    (profile / "state").symlink_to(outside, target_is_directory=True)
    result = source.fetch(cfg, profile)
    assert result.error_kind == ErrorKind.INTERNAL
    assert not result.secrets
    assert logs() == []


def test_supported_mapping_is_sorted_and_trashed_items_are_ignored(source, configured, tmp_path):
    cfg, configure, _ = configured
    configure(
        payload={
            "items": [
                {"id": "0", "state": "Trashed"},
                login_item(
                    "Z_KEY",
                    "z",
                    item_id="3",
                    extra=[{"name": "EXTRA_KEY", "content": {"Hidden": "extra"}}],
                ),
                custom_item(
                    {"name": "A_KEY", "content": {"Text": "a"}},
                    {"name": "IGNORED_TOTP", "content": {"Totp": "no"}},
                ),
            ]
        }
    )
    result = source.fetch(cfg, tmp_path)
    assert list(result.secrets) == ["A_KEY", "EXTRA_KEY", "Z_KEY"]
    assert "TRASHED" not in result.secrets and "IGNORED_TOTP" not in result.secrets


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"items": {}},
        {"items": [None]},
        {"items": [{}]},
        {"items": [{"state": 1}]},
        {"items": [{"state": "Active", "content": None}]},
    ],
)
def test_malformed_bulk_shapes_fail_closed(source, configured, tmp_path, payload):
    cfg, configure, _ = configured
    configure(payload=payload)
    result = source.fetch(cfg, tmp_path)
    assert result.error_kind == ErrorKind.INTERNAL
    assert not result.secrets


@pytest.mark.parametrize("raw", ["{", '{"items":['])
def test_partial_json_fails_closed_and_is_not_cached(source, configured, tmp_path, raw):
    cfg, configure, logs = configured
    cfg["cache_ttl_seconds"] = 60
    configure(raw_output=raw)
    first = source.fetch(cfg, tmp_path)
    second = source.fetch(cfg, tmp_path)
    assert first.error_kind == second.error_kind == ErrorKind.INTERNAL
    assert sum(call["argv"][:2] == ["item", "list"] for call in logs()) == 2
    assert not (tmp_path / "cache" / "proton_pass_cache.json").exists()


@pytest.mark.parametrize(
    "items",
    [
        [login_item("DUP", "one", item_id="1"), login_item("DUP", "two", item_id="2")],
        [login_item("1INVALID", "one")],
        [login_item("EMPTY", "")],
        [login_item("NOT_STRING", 7)],
    ],
)
def test_duplicate_invalid_and_empty_supported_values_fail_atomically(
    source, configured, tmp_path, items
):
    cfg, configure, _ = configured
    configure(payload={"items": items})
    result = source.fetch(cfg, tmp_path)
    assert result.error_kind == ErrorKind.INTERNAL
    assert result.secrets == {}


def test_valid_empty_vault_response(source, configured, tmp_path):
    cfg, _, _ = configured
    result = source.fetch(cfg, tmp_path)
    assert result.ok and result.secrets == {}


def test_cache_opt_in_hits_after_version_and_identity_preflight(source, configured, tmp_path):
    cfg, configure, logs = configured
    cfg["cache_ttl_seconds"] = 60
    configure(payload={"items": [login_item()]})
    assert source.fetch(cfg, tmp_path).ok
    assert source.fetch(cfg, tmp_path).ok
    calls = logs()
    assert sum(call["argv"] == ["--version"] for call in calls) == 2
    assert sum(call["argv"] == ["info", "--output", "json"] for call in calls) >= 3
    assert sum(call["argv"][:2] == ["item", "list"] for call in calls) == 1
    cache = tmp_path / "cache" / "proton_pass_cache.json"
    assert cache.exists()
    if os.name != "nt":
        assert stat.S_IMODE(cache.stat().st_mode) == 0o600
        assert stat.S_IMODE(cache.parent.stat().st_mode) == 0o700
    assert "fake-bootstrap-token" not in cache.read_text(encoding="utf-8")


def test_cache_disabled_writes_no_secret_store(source, configured, tmp_path):
    cfg, configure, _ = configured
    configure(payload={"items": [login_item()]})
    assert source.fetch(cfg, tmp_path).ok
    assert not (tmp_path / "cache" / "proton_pass_cache.json").exists()


def test_cache_is_bound_to_token_fingerprint(source, configured, monkeypatch, tmp_path):
    cfg, configure, logs = configured
    cfg["cache_ttl_seconds"] = 60
    configure(payload={"items": [login_item(value="first-fake-secret")]})
    assert source.fetch(cfg, tmp_path).secrets == {"OPENAI_API_KEY": "first-fake-secret"}
    monkeypatch.setenv("PROTON_PASS_PERSONAL_ACCESS_TOKEN", "rotated-fake-token")
    configure(payload={"items": [login_item(value="second-fake-secret")]})
    assert source.fetch(cfg, tmp_path).secrets == {"OPENAI_API_KEY": "second-fake-secret"}
    assert sum(call["argv"][:2] == ["item", "list"] for call in logs()) == 2


def test_timeout_and_nonzero_errors_are_mapped_without_diagnostics(source, configured, tmp_path):
    cfg, configure, _ = configured
    cfg["command_timeout_seconds"] = 0.05
    configure(sleep_command="item list Runtime Vault --output json --show-secrets", sleep=0.2)
    timed = source.fetch(cfg, tmp_path)
    assert timed.error_kind == ErrorKind.TIMEOUT
    assert "fake-secret" not in (timed.error or "")

    other_home = tmp_path / "other"
    cfg["command_timeout_seconds"] = 1
    configure(sleep_command="", list_rc=8)
    failed = source.fetch(cfg, other_home)
    assert failed.error_kind == ErrorKind.INTERNAL
    assert "sensitive fake" not in (failed.error or "")


def test_login_error_does_not_expose_token_or_cli_stderr(source, configured, tmp_path):
    cfg, configure, logs = configured
    configure(login_rc=9)
    result = source.fetch(cfg, tmp_path)
    assert result.error_kind == ErrorKind.AUTH_FAILED
    rendered = json.dumps({"error": result.error, "warnings": result.warnings, "logs": logs()})
    assert "fake-bootstrap-token" not in rendered
    assert "sensitive fake" not in rendered


def test_manifest_register_and_config_errors(plugin_module, source, monkeypatch, tmp_path):
    registered = []

    class Context:
        def register_secret_source(self, value):
            registered.append(value)

    plugin_module.register(Context())
    assert len(registered) == 1 and isinstance(registered[0], plugin_module.ProtonPassSource)

    monkeypatch.delenv("PROTON_PASS_PERSONAL_ACCESS_TOKEN", raising=False)
    assert (
        source.fetch({"enabled": True, "vault": "v"}, tmp_path).error_kind
        == ErrorKind.NOT_CONFIGURED
    )
    monkeypatch.setenv("PROTON_PASS_PERSONAL_ACCESS_TOKEN", "fake")
    assert source.fetch({"enabled": True}, tmp_path).error_kind == ErrorKind.NOT_CONFIGURED
    assert (
        source.fetch({"enabled": True, "vault": "--help"}, tmp_path).error_kind
        == ErrorKind.NOT_CONFIGURED
    )
    assert (
        source.fetch({"enabled": True, "vault": "v", "binary_path": []}, tmp_path).error_kind
        == ErrorKind.NOT_CONFIGURED
    )


def test_orchestrator_protects_bootstrap_token(
    plugin_module, source, configured, tmp_path, monkeypatch
):
    from agent.secret_sources import registry

    cfg, configure, _ = configured
    configure(payload={"items": [login_item("SAFE_RUNTIME_VALUE", "vault-copy")]})
    registry._reset_registry_for_tests()
    monkeypatch.setattr(registry, "_ensure_builtin_sources", lambda: None)
    assert registry.register_source(source)
    env = {"PROTON_PASS_PERSONAL_ACCESS_TOKEN": "bootstrap"}
    report = registry.apply_all({"proton_pass": cfg}, tmp_path, environ=env)
    assert env["PROTON_PASS_PERSONAL_ACCESS_TOKEN"] == "bootstrap"  # noqa: S105
    assert env["SAFE_RUNTIME_VALUE"] == "vault-copy"  # noqa: S105
    assert source.protected_env_vars(cfg) == frozenset({"PROTON_PASS_PERSONAL_ACCESS_TOKEN"})
    assert report.sources[0].skipped_protected == []
    registry._reset_registry_for_tests()


@pytest.mark.parametrize(
    "name",
    [
        "Path",
        "pythonPath",
        "ld_preload",
        "DyLd_Insert_Libraries",
        "git_Ssh_Command",
        "Ssh_AskPass",
        "HgRcPath",
        "Svn_Editor",
        "P4Config",
        "java_tool_options",
        "_JaVa_OpTiOnS",
        "all_proxy",
        "https_proxy",
        "ComSpec",
        "PathExt",
        "xdg_config_home",
        "Hermes_Config",
        "proton_pass_session_dir",
        "npm_config_prefix",
        "Yarn_Cache_Folder",
        "OpenSSL_Conf",
        "Curl_Home",
        "WgetRc",
        "Docker_Host",
        "KubeConfig",
        "Home",
        "TmpDir",
        "Shell",
        "Editor",
        "Pager",
    ],
)
def test_runtime_control_destination_names_are_rejected(plugin_module, name):
    with pytest.raises(ValueError, match="reserved runtime-control"):
        plugin_module._parse_items(json.dumps({"items": [login_item(name, "value")]}))


@pytest.mark.parametrize(
    "name", ["AWS_ACCESS_KEY_ID", "OPENAI_API_KEY", "DATABASE_URL", "some_service_token"]
)
def test_ordinary_api_secret_destinations_remain_supported(plugin_module, name):
    assert plugin_module._parse_items(json.dumps({"items": [login_item(name, "value")]})) == {
        name: "value"
    }


@pytest.mark.parametrize("override_existing", [False, True])
def test_orchestrator_never_applies_git_ssh_command(
    source, configured, tmp_path, monkeypatch, override_existing
):
    from agent.secret_sources import registry

    cfg, configure, _ = configured
    cfg["override_existing"] = override_existing
    configure(payload={"items": [login_item("GIT_SSH_COMMAND", "fake-executable")]})
    registry._reset_registry_for_tests()
    monkeypatch.setattr(registry, "_ensure_builtin_sources", lambda: None)
    assert registry.register_source(source)
    env: dict[str, str] = {}
    report = registry.apply_all({"proton_pass": cfg}, tmp_path, environ=env)
    assert "GIT_SSH_COMMAND" not in env
    assert report.sources[0].result.error_kind == ErrorKind.INTERNAL
    registry._reset_registry_for_tests()


def test_hostile_name_after_valid_item_fails_atomically_without_cache(source, configured, tmp_path):
    cfg, configure, _ = configured
    cfg["cache_ttl_seconds"] = 60
    configure(
        payload={
            "items": [
                login_item("SAFE_NAME", "safe", item_id="1"),
                login_item("PATH", "hostile", item_id="2"),
            ]
        }
    )
    result = source.fetch(cfg, tmp_path)
    assert result.error_kind == ErrorKind.INTERNAL
    assert result.secrets == {}
    assert not (tmp_path / "cache" / "proton_pass_cache.json").exists()


def test_unknown_state_after_valid_item_fails_atomically_without_cache(
    source, configured, tmp_path
):
    cfg, configure, _ = configured
    cfg["cache_ttl_seconds"] = 60
    configure(
        payload={
            "items": [
                login_item("SAFE_NAME", "safe", item_id="1"),
                login_item("UNKNOWN", "value", item_id="2", state="Deleted"),
            ]
        }
    )
    result = source.fetch(cfg, tmp_path)
    assert result.error_kind == ErrorKind.INTERNAL
    assert result.secrets == {}
    assert not (tmp_path / "cache" / "proton_pass_cache.json").exists()


@pytest.mark.parametrize("setting", ["command_timeout_seconds", "cache_ttl_seconds"])
@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), "nan", "inf"])
def test_nonfinite_config_is_rejected(source, configured, tmp_path, setting, value):
    cfg, _, logs = configured
    cfg[setting] = value
    result = source.fetch(cfg, tmp_path)
    assert result.error_kind == ErrorKind.NOT_CONFIGURED
    assert not result.secrets
    assert logs() == []


@pytest.mark.parametrize("setting", ["command_timeout_seconds", "cache_ttl_seconds"])
@pytest.mark.parametrize("value", [1e308, 10**1000])
def test_huge_finite_config_is_rejected(source, configured, tmp_path, setting, value):
    cfg, _, logs = configured
    cfg[setting] = value
    result = source.fetch(cfg, tmp_path)
    assert result.error_kind == ErrorKind.NOT_CONFIGURED
    assert not result.secrets
    assert logs() == []


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_fetch_budget_rejects_nonfinite_values_with_finite_default(source, value):
    budget = source.fetch_timeout_seconds({"command_timeout_seconds": value})
    assert budget == source.fetch_timeout_seconds({"command_timeout_seconds": 30})
    assert budget < float("inf")


def test_fetch_budget_rejects_huge_finite_value_with_finite_default(source):
    budget = source.fetch_timeout_seconds({"command_timeout_seconds": 1e308})
    assert budget == source.fetch_timeout_seconds({"command_timeout_seconds": 30})
    assert budget < float("inf")


def test_not_configured_remediation_uses_plugin_keys(source):
    remediation = source.remediation(ErrorKind.NOT_CONFIGURED, {})
    assert "secrets.proton_pass.vault" in remediation
    assert "PROTON_PASS_PERSONAL_ACCESS_TOKEN" in remediation
    assert "ProtonPass" not in remediation


def test_inherited_path_is_not_used_for_discovery(plugin_module, source, monkeypatch, tmp_path):
    hostile = tmp_path / "hostile-bin"
    hostile.mkdir()
    binary = hostile / ("pass-cli.exe" if os.name == "nt" else "pass-cli")
    binary.write_bytes(b"hostile")
    binary.chmod(0o700)
    monkeypatch.setenv("PATH", str(hostile))
    monkeypatch.setenv("PROTON_PASS_PERSONAL_ACCESS_TOKEN", "fake")
    monkeypatch.setattr(plugin_module, "_standard_binary_candidates", lambda: ())
    result = source.fetch({"enabled": True, "vault": "v", "binary_path": ""}, tmp_path)
    assert result.error_kind == ErrorKind.BINARY_MISSING


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership and mode policy")
def test_binary_validator_rejects_insecure_file_and_ancestor(plugin_module):
    repository = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(dir=repository) as temporary:
        root = Path(temporary)
        insecure_file = root / "insecure-file"
        insecure_file.write_bytes(b"fake")
        insecure_file.chmod(0o720)
        assert plugin_module._validate_binary_path(insecure_file) is None

        insecure_parent = root / "insecure-parent"
        insecure_parent.mkdir(mode=0o700)
        candidate = insecure_parent / "pass-cli"
        candidate.write_bytes(b"fake")
        candidate.chmod(0o700)
        insecure_parent.chmod(0o770)
        assert plugin_module._validate_binary_path(candidate) is None


@pytest.mark.skipif(os.name == "nt", reason="ordinary Windows users cannot create symlinks")
def test_binary_validator_accepts_safe_symlink_to_trusted_target(plugin_module):
    repository = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(dir=repository) as temporary:
        root = Path(temporary)
        target = root / "pass-cli-target"
        target.write_bytes(b"fake")
        target.chmod(0o700)
        link = root / "pass-cli"
        link.symlink_to(target)
        assert plugin_module._validate_binary_path(link) == target.resolve()


def test_untrusted_product_version_never_receives_token(source, configured, tmp_path):
    cfg, configure, logs = configured
    configure(version="Unrelated CLI 9.9.9")
    result = source.fetch(cfg, tmp_path)
    assert result.error_kind == ErrorKind.BINARY_MISSING
    assert [entry["argv"] for entry in logs()] == [["--version"]]
    assert logs()[0]["token_present"] is False


@pytest.mark.skipif(os.name == "nt", reason="ordinary Windows users cannot create symlinks")
@pytest.mark.parametrize("name", ["runtime.lock", "session-fingerprint.json"])
def test_symlinked_state_files_fail_before_cli(source, configured, tmp_path, name):
    cfg, _, logs = configured
    root = tmp_path / "state" / "proton-pass"
    root.mkdir(parents=True)
    outside = tmp_path / "outside-file"
    outside.write_text("outside", encoding="utf-8")
    (root / name).symlink_to(outside)
    result = source.fetch(cfg, tmp_path)
    assert result.error_kind == ErrorKind.INTERNAL
    assert result.secrets == {}
    assert logs() == []


@pytest.mark.skipif(os.name == "nt", reason="ordinary Windows users cannot create symlinks")
def test_symlinked_profile_root_fails_before_cli(source, configured, tmp_path):
    cfg, _, logs = configured
    outside = tmp_path / "outside"
    outside.mkdir()
    profile = tmp_path / "profile-link"
    profile.symlink_to(outside, target_is_directory=True)
    result = source.fetch(cfg, profile)
    assert result.error_kind == ErrorKind.INTERNAL
    assert logs() == []


@pytest.mark.skipif(os.name == "nt", reason="ordinary Windows users cannot create symlinks")
def test_symlinked_session_directory_fails_before_cli(source, configured, tmp_path):
    cfg, _, logs = configured
    root = tmp_path / "state" / "proton-pass"
    root.mkdir(parents=True)
    outside = tmp_path / "outside-session"
    outside.mkdir()
    (root / "session").symlink_to(outside, target_is_directory=True)
    result = source.fetch(cfg, tmp_path)
    assert result.error_kind == ErrorKind.INTERNAL
    assert logs() == []


@pytest.mark.skipif(os.name == "nt", reason="ordinary Windows users cannot create symlinks")
@pytest.mark.parametrize("link_file", [False, True])
def test_symlinked_cache_parent_or_file_fails_closed(source, configured, tmp_path, link_file):
    cfg, configure, logs = configured
    cfg["cache_ttl_seconds"] = 60
    outside = tmp_path / "outside-cache"
    outside.mkdir()
    cache_dir = tmp_path / "cache"
    if link_file:
        cache_dir.mkdir()
        target = outside / "cache.json"
        target.write_text("{}", encoding="utf-8")
        (cache_dir / "proton_pass_cache.json").symlink_to(target)
    else:
        cache_dir.symlink_to(outside, target_is_directory=True)
    configure(payload={"items": [login_item()]})
    result = source.fetch(cfg, tmp_path)
    assert result.error_kind == ErrorKind.INTERNAL
    assert result.secrets == {}
    assert not any(entry["argv"][:2] == ["item", "list"] for entry in logs())


def test_same_name_session_tree_replacement_reauthenticates(source, configured, tmp_path):
    cfg, _, logs = configured
    assert source.fetch(cfg, tmp_path).ok
    marker = tmp_path / "state" / "proton-pass" / "session" / "fake-login"
    marker.write_text("replacement-session", encoding="utf-8")
    assert source.fetch(cfg, tmp_path).ok
    assert sum(entry["argv"] == ["login"] for entry in logs()) == 2


def test_session_tree_entry_limit_fails_before_unbounded_walk(plugin_module, tmp_path, monkeypatch):
    session = tmp_path / "session"
    session.mkdir()
    for index in range(3):
        (session / f"entry-{index}").write_bytes(b"x")
    monkeypatch.setattr(plugin_module, "_MAX_SESSION_ENTRIES", 2)
    with pytest.raises(RuntimeError, match="entry limit"):
        plugin_module._session_tree_digest(session)


def test_session_tree_byte_limit_rejects_small_fixture(plugin_module, tmp_path, monkeypatch):
    session = tmp_path / "session"
    session.mkdir()
    (session / "oversized").write_bytes(b"12345")
    monkeypatch.setattr(plugin_module, "_MAX_SESSION_FILE_BYTES", 4)
    with pytest.raises(RuntimeError, match="byte limit"):
        plugin_module._session_tree_digest(session)


@pytest.mark.parametrize(
    "mutation",
    ["malformed_member", "missing_sentinel", "malformed_sentinel", "altered_value"],
)
def test_cache_integrity_failures_are_total_misses(source, configured, tmp_path, mutation):
    cfg, configure, logs = configured
    cfg["cache_ttl_seconds"] = 60
    configure(payload={"items": [login_item(value="first-value")]})
    assert source.fetch(cfg, tmp_path).secrets == {"OPENAI_API_KEY": "first-value"}
    cache = tmp_path / "cache" / "proton_pass_cache.json"
    payload = json.loads(cache.read_text(encoding="utf-8"))
    sentinel = next(name for name in payload["secrets"] if name.startswith("\0"))
    if mutation == "malformed_member":
        payload["secrets"]["OPENAI_API_KEY"] = 7
    elif mutation == "missing_sentinel":
        del payload["secrets"][sentinel]
    elif mutation == "malformed_sentinel":
        payload["secrets"][sentinel] = 7
    else:
        payload["secrets"]["OPENAI_API_KEY"] = "tampered-value"
    cache.write_text(json.dumps(payload), encoding="utf-8")

    configure(payload={"items": [login_item(value="fresh-value")]})
    result = source.fetch(cfg, tmp_path)
    assert result.secrets == {"OPENAI_API_KEY": "fresh-value"}
    assert sum(entry["argv"][:2] == ["item", "list"] for entry in logs()) == 2


def _rewrite_cache(cache: Path, transform) -> None:
    payload = json.loads(cache.read_text(encoding="utf-8"))
    transform(payload)
    cache.write_text(json.dumps(payload), encoding="utf-8")


def test_malformed_extra_cache_member_disk_cache_would_drop_is_total_miss(
    source, configured, tmp_path, plugin_module, monkeypatch
):
    cfg, configure, logs = configured
    cfg["cache_ttl_seconds"] = 60
    configure(payload={"items": [login_item(value="first-value")]})
    assert source.fetch(cfg, tmp_path).ok
    cache = tmp_path / "cache" / "proton_pass_cache.json"
    _rewrite_cache(cache, lambda payload: payload["secrets"].update({"EXTRA": 7}))
    monkeypatch.setattr(
        plugin_module._DISK_CACHE,
        "read",
        lambda *args, **kwargs: pytest.fail("DiskCache.read ran before raw validation"),
    )
    configure(payload={"items": [login_item(value="fresh-value")]})
    assert source.fetch(cfg, tmp_path).secrets == {"OPENAI_API_KEY": "fresh-value"}
    assert sum(entry["argv"][:2] == ["item", "list"] for entry in logs()) == 2


def test_extra_top_level_cache_key_is_total_miss(source, configured, tmp_path):
    cfg, configure, logs = configured
    cfg["cache_ttl_seconds"] = 60
    configure(payload={"items": [login_item(value="first-value")]})
    assert source.fetch(cfg, tmp_path).ok
    cache = tmp_path / "cache" / "proton_pass_cache.json"
    _rewrite_cache(cache, lambda payload: payload.update({"unexpected": "member"}))
    configure(payload={"items": [login_item(value="fresh-value")]})
    assert source.fetch(cfg, tmp_path).secrets == {"OPENAI_API_KEY": "fresh-value"}
    assert sum(entry["argv"][:2] == ["item", "list"] for entry in logs()) == 2


def test_duplicate_cache_keys_are_total_miss(source, configured, tmp_path):
    cfg, configure, logs = configured
    cfg["cache_ttl_seconds"] = 60
    configure(payload={"items": [login_item(value="first-value")]})
    assert source.fetch(cfg, tmp_path).ok
    cache = tmp_path / "cache" / "proton_pass_cache.json"
    raw = cache.read_text(encoding="utf-8")
    cache.write_text(raw.replace('{"key":', '{"key":"duplicate","key":', 1), encoding="utf-8")
    configure(payload={"items": [login_item(value="fresh-value")]})
    assert source.fetch(cfg, tmp_path).secrets == {"OPENAI_API_KEY": "fresh-value"}
    assert sum(entry["argv"][:2] == ["item", "list"] for entry in logs()) == 2


@pytest.mark.parametrize("timestamp", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_cache_timestamp_is_total_miss(source, configured, tmp_path, timestamp):
    cfg, configure, logs = configured
    cfg["cache_ttl_seconds"] = 60
    configure(payload={"items": [login_item(value="first-value")]})
    assert source.fetch(cfg, tmp_path).ok
    cache = tmp_path / "cache" / "proton_pass_cache.json"
    _rewrite_cache(cache, lambda payload: payload.update({"fetched_at": timestamp}))
    configure(payload={"items": [login_item(value="fresh-value")]})
    assert source.fetch(cfg, tmp_path).secrets == {"OPENAI_API_KEY": "fresh-value"}
    assert sum(entry["argv"][:2] == ["item", "list"] for entry in logs()) == 2


def test_future_cache_timestamp_is_total_miss(source, configured, tmp_path):
    cfg, configure, logs = configured
    cfg["cache_ttl_seconds"] = 60
    configure(payload={"items": [login_item(value="first-value")]})
    assert source.fetch(cfg, tmp_path).ok
    cache = tmp_path / "cache" / "proton_pass_cache.json"
    _rewrite_cache(cache, lambda payload: payload.update({"fetched_at": time.time() + 3600}))
    configure(payload={"items": [login_item(value="fresh-value")]})
    assert source.fetch(cfg, tmp_path).secrets == {"OPENAI_API_KEY": "fresh-value"}
    assert sum(entry["argv"][:2] == ["item", "list"] for entry in logs()) == 2


def test_altered_cache_timestamp_breaks_integrity_envelope(source, configured, tmp_path):
    cfg, configure, logs = configured
    cfg["cache_ttl_seconds"] = 60
    configure(payload={"items": [login_item(value="first-value")]})
    assert source.fetch(cfg, tmp_path).ok
    cache = tmp_path / "cache" / "proton_pass_cache.json"
    _rewrite_cache(cache, lambda payload: payload.update({"fetched_at": payload["fetched_at"] - 1}))
    configure(payload={"items": [login_item(value="fresh-value")]})
    assert source.fetch(cfg, tmp_path).secrets == {"OPENAI_API_KEY": "fresh-value"}
    assert sum(entry["argv"][:2] == ["item", "list"] for entry in logs()) == 2


def test_ttl_zero_clears_preexisting_plaintext_before_fetch(source, configured, tmp_path):
    cfg, configure, _ = configured
    cache = tmp_path / "cache" / "proton_pass_cache.json"
    cache.parent.mkdir(parents=True)
    cache.write_text('{"old":"plaintext"}', encoding="utf-8")
    configure(
        payload={"items": [login_item()]},
        assert_cache_absent=cache,
    )
    assert source.fetch(cfg, tmp_path).ok
    assert not cache.exists()


def test_rotation_clears_old_cache_before_replacement(source, configured, monkeypatch, tmp_path):
    cfg, configure, _ = configured
    cfg["cache_ttl_seconds"] = 60
    configure(payload={"items": [login_item(value="old-value")]})
    assert source.fetch(cfg, tmp_path).ok
    cache = tmp_path / "cache" / "proton_pass_cache.json"
    assert cache.exists()
    monkeypatch.setenv("PROTON_PASS_PERSONAL_ACCESS_TOKEN", "rotated-token")
    configure(
        payload={"items": [login_item(value="new-value")]},
        assert_cache_absent=cache,
    )
    result = source.fetch(cfg, tmp_path)
    assert result.secrets == {"OPENAI_API_KEY": "new-value"}


def test_oversized_captured_output_is_rejected_without_cache(
    plugin_module, source, configured, monkeypatch, tmp_path
):
    cfg, configure, _ = configured
    cfg["cache_ttl_seconds"] = 60
    monkeypatch.setattr(plugin_module, "_MAX_OUTPUT_BYTES", 32)
    configure(payload={"items": [login_item(value="long-value")]})
    result = source.fetch(cfg, tmp_path)
    assert result.error_kind == ErrorKind.INTERNAL
    assert not (tmp_path / "cache" / "proton_pass_cache.json").exists()


def test_decoded_item_limit_is_rejected_without_cache(
    plugin_module, source, configured, monkeypatch, tmp_path
):
    cfg, configure, _ = configured
    cfg["cache_ttl_seconds"] = 60
    monkeypatch.setattr(plugin_module, "_MAX_ITEMS", 1)
    configure(payload={"items": [login_item(item_id="1"), login_item("OTHER", item_id="2")]})
    result = source.fetch(cfg, tmp_path)
    assert result.error_kind == ErrorKind.INTERNAL
    assert not (tmp_path / "cache" / "proton_pass_cache.json").exists()


def test_decoded_field_limit_is_rejected_without_cache(
    plugin_module, source, configured, monkeypatch, tmp_path
):
    cfg, configure, _ = configured
    cfg["cache_ttl_seconds"] = 60
    monkeypatch.setattr(plugin_module, "_MAX_FIELDS", 1)
    configure(
        payload={
            "items": [
                custom_item(
                    {"name": "ONE", "content": {"Text": "one"}},
                    {"name": "TWO", "content": {"Text": "two"}},
                )
            ]
        }
    )
    result = source.fetch(cfg, tmp_path)
    assert result.error_kind == ErrorKind.INTERNAL
    assert not (tmp_path / "cache" / "proton_pass_cache.json").exists()


@pytest.mark.parametrize("limit_name", ["name", "value"])
def test_decoded_name_and_value_limits_are_rejected_without_cache(
    plugin_module, source, configured, monkeypatch, tmp_path, limit_name
):
    cfg, configure, _ = configured
    cfg["cache_ttl_seconds"] = 60
    if limit_name == "name":
        monkeypatch.setattr(plugin_module, "_MAX_NAME_CHARS", 3)
        item = login_item("LONG_NAME", "ok")
    else:
        monkeypatch.setattr(plugin_module, "_MAX_VALUE_CHARS", 3)
        item = login_item("KEY", "long-value")
    configure(payload={"items": [item]})
    result = source.fetch(cfg, tmp_path)
    assert result.error_kind == ErrorKind.INTERNAL
    assert not (tmp_path / "cache" / "proton_pass_cache.json").exists()
