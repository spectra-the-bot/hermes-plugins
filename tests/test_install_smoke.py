from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_subdirectory_identifier_and_manifest_contract():
    from hermes_cli.plugins_cmd import _resolve_git_url

    url, subdir = _resolve_git_url("spectra-the-bot/hermes-plugins/proton-pass")
    assert url == "https://github.com/spectra-the-bot/hermes-plugins.git"
    assert subdir == "proton-pass"

    manifest = yaml.safe_load((ROOT / "proton-pass" / "plugin.yaml").read_text())
    assert manifest["name"] == "proton-pass"
    assert manifest["version"] == "1.0.0"
    assert manifest["platforms"] == ["linux", "macos", "windows"]
    assert manifest["requires_env"][0]["name"] == "PROTON_PASS_PERSONAL_ACCESS_TOKEN"
    assert manifest["requires_env"][0]["secret"] is True


def test_clean_temp_home_plugin_discovery_and_secret_registration(tmp_path, monkeypatch):
    from agent.secret_sources import registry
    from hermes_cli.plugins import PluginManager
    from hermes_cli.plugins_cmd import _install_plugin_core

    home = tmp_path / "hermes-home"
    repository = tmp_path / "artifact-repository"
    shutil.copytree(
        ROOT / "proton-pass",
        repository / "proton-pass",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    git = shutil.which("git")
    assert git is not None

    def run_git(*args: str) -> None:
        subprocess.run([git, *args], check=True)  # noqa: S603 -- fixed test inputs

    run_git("init", "-q", str(repository))
    run_git("-C", str(repository), "add", "proton-pass")
    run_git(
        "-C",
        str(repository),
        "-c",
        "user.name=Plugin Test",
        "-c",
        "user.email=plugin-test@example.invalid",
        "commit",
        "-qm",
        "test: build plugin artifact",
    )

    monkeypatch.setenv("HERMES_HOME", str(home))
    destination, manifest, installed_name = _install_plugin_core(
        f"{repository.as_uri()}#proton-pass", force=False
    )
    assert installed_name == "proton-pass"
    assert manifest["name"] == "proton-pass"
    assert destination == home / "plugins" / "proton-pass"
    (home / "config.yaml").write_text(
        yaml.safe_dump({"plugins": {"enabled": ["proton-pass"]}}), encoding="utf-8"
    )
    monkeypatch.delenv("HERMES_SAFE_MODE", raising=False)
    registry._reset_registry_for_tests()
    monkeypatch.setattr(registry, "_ensure_builtin_sources", lambda: None)

    manager = PluginManager()
    manager.discover_and_load()
    loaded = manager.list_plugins()
    proton = next(entry for entry in loaded if entry["name"] == "proton-pass")
    assert proton["enabled"] is True
    assert proton["error"] is None
    assert registry.get_source("proton_pass").name == "proton_pass"

    artifact_files = {
        path.relative_to(destination).as_posix()
        for path in destination.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }
    assert artifact_files == {"README.md", "after-install.md", "plugin.yaml", "__init__.py"}
    registry._reset_registry_for_tests()
