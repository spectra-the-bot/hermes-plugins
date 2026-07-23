"""Runtime-only Proton Pass secret source for Hermes Agent.

This plugin deliberately supports only a plain, narrowly scoped Proton Pass
personal access token and one bulk, read-only item-list operation.  It does not
implement Agent identities, interactive credential access, or item mutation.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, NamedTuple

from agent.secret_sources._cache import CachedFetch, DiskCache
from agent.secret_sources.base import (
    ErrorKind,
    FetchResult,
    SecretSource,
    is_valid_env_name,
    run_secret_cli,
)

TOKEN_ENV = "PROTON_PASS_PERSONAL_ACCESS_TOKEN"  # noqa: S105 -- environment variable name
_MIN_VERSION = (2, 1, 0)
_DEFAULT_TIMEOUT = 30.0
_CACHE_FORMAT = "proton-pass-runtime-v1"
_PRIVILEGE_MODE = "read-only-vault"
_VERSION_RE = re.compile(r"\b(\d+)\.(\d+)\.(\d+)\b")
_AGENT_PREFIX = "[Agent] "


class _Paths(NamedTuple):
    root: Path
    session: Path
    home: Path
    fingerprint: Path
    lock: Path


_CacheKey = tuple[str, str, str]


def _cache_key_string(key: _CacheKey) -> str:
    return "|".join(key)


_DISK_CACHE: DiskCache[_CacheKey] = DiskCache(
    "proton_pass_cache.json", key_serializer=_cache_key_string
)


def _result_error(message: str, kind: ErrorKind, binary: Path | None = None) -> FetchResult:
    return FetchResult(error=message, error_kind=kind, binary_path=binary)


def _parse_positive_float(value: Any, default: float, *, allow_zero: bool = False) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    if parsed > 0 or (allow_zero and parsed == 0):
        return parsed
    return default


def _find_binary(configured: str) -> Path | None:
    """Resolve a configured executable exactly, or discover pass-cli on PATH."""
    if configured:
        candidate = Path(configured).expanduser()
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.resolve()
        return None
    found = shutil.which("pass-cli")
    return Path(found).resolve() if found else None


def _parse_version(text: str) -> tuple[int, int, int] | None:
    match = _VERSION_RE.search(text or "")
    if not match:
        return None
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def _paths(home_path: Path) -> _Paths:
    # Normalize without resolving symlinks: _prepare_paths must see and reject a
    # symlinked profile state directory instead of silently following it.
    normalized_home = Path(os.path.abspath(os.fspath(Path(home_path).expanduser())))
    root = normalized_home / "state" / "proton-pass"
    return _Paths(
        root=root,
        session=root / "session",
        home=root / "home",
        fingerprint=root / "session-fingerprint.json",
        lock=root / "runtime.lock",
    )


def _ensure_private_dir(path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError(f"refusing symlinked Proton Pass state directory: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise RuntimeError(f"refusing symlinked Proton Pass state directory: {path}")
    if os.name != "nt":
        os.chmod(path, 0o700)


def _prepare_paths(paths: _Paths) -> None:
    # Check the profile-owned parent explicitly: mkdir(path/to/root) would
    # otherwise follow an attacker-created `state` directory symlink.
    _ensure_private_dir(paths.root.parent)
    _ensure_private_dir(paths.root)
    _ensure_private_dir(paths.home)
    if paths.session.is_symlink():
        raise RuntimeError(f"refusing symlinked Proton Pass session directory: {paths.session}")
    _ensure_private_dir(paths.session)


def _reset_session(paths: _Paths) -> None:
    """Reset only this plugin's profile-scoped pass-cli session state."""
    if paths.session.is_symlink():
        raise RuntimeError(f"refusing symlinked Proton Pass session directory: {paths.session}")
    if paths.session.exists():
        shutil.rmtree(paths.session)
    _ensure_private_dir(paths.session)
    try:
        paths.fingerprint.unlink()
    except FileNotFoundError:
        pass


def _child_env(paths: _Paths, *, token: str | None = None) -> dict[str, str]:
    """Return pass-cli's isolated state environment; token is login-only."""
    env = {
        "PROTON_PASS_SESSION_DIR": str(paths.session),
        "PROTON_PASS_KEY_PROVIDER": "fs",
        "HOME": str(paths.home),
        "USERPROFILE": str(paths.home),
        "XDG_CONFIG_HOME": str(paths.home / "config"),
        "XDG_DATA_HOME": str(paths.home / "data"),
        "XDG_CACHE_HOME": str(paths.home / "cache"),
    }
    if token is not None:
        env[TOKEN_ENV] = token
    return env


def _run(
    binary: Path,
    args: list[str],
    paths: _Paths,
    timeout: float,
    *,
    token: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return run_secret_cli(
        [str(binary), *args],
        extra_env=_child_env(paths, token=token),
        timeout=timeout,
    )


def _identity(stdout: str) -> tuple[str, str | None]:
    """Classify structured info output as plain PAT, Agent, human, or malformed."""
    try:
        payload = json.loads(stdout)
    except (TypeError, json.JSONDecodeError):
        return "malformed", None
    if not isinstance(payload, dict):
        return "malformed", None
    name = payload.get("personal_access_token_name")
    if payload.get("id") == "N/A" and isinstance(name, str) and name.strip():
        clean = name.strip()
        if clean.startswith(_AGENT_PREFIX):
            return "agent", clean
        return "plain_pat", clean
    if (
        isinstance(payload.get("id"), str)
        and any(key in payload for key in ("username", "email"))
        and "personal_access_token_name" not in payload
    ):
        return "human", None
    return "malformed", None


def _session_fingerprint(token: str, identity_name: str) -> str:
    # A PAT is account-bound; hashing it together with the structured session
    # identity and the plugin's privilege mode prevents stale session reuse.
    material = f"{_CACHE_FORMAT}\0plain-pat\0{_PRIVILEGE_MODE}\0{identity_name}\0{token}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _read_fingerprint(path: Path) -> str | None:
    if path.is_symlink():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    value = payload.get("fingerprint") if isinstance(payload, dict) else None
    return value if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) else None


def _write_fingerprint(path: Path, fingerprint: str) -> None:
    """Atomically persist only the non-secret SHA-256 session binding."""
    _ensure_private_dir(path.parent)
    fd, temporary = tempfile.mkstemp(prefix=".session-fingerprint-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({"version": 1, "fingerprint": fingerprint}, handle)
        if os.name != "nt":
            os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


@contextmanager
def _state_lock(path: Path, wait_seconds: float) -> Iterator[None]:
    """Serialize access to the profile-owned pass-cli session and cache.

    Hermes can start gateway children concurrently.  An advisory lock prevents one
    process from replacing the isolated session while another process is reading it.
    The lock contains no data and is released automatically if a process exits.
    """
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, stat.S_IRUSR | stat.S_IWUSR)
        if os.name != "nt":
            os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as exc:
        raise RuntimeError("Could not open the Proton Pass runtime lock.") from exc

    acquired = False
    deadline = time.monotonic() + wait_seconds
    try:
        while not acquired:
            try:
                if os.name == "nt":
                    import msvcrt

                    if os.fstat(fd).st_size == 0:
                        os.write(fd, b"\0")
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)  # type: ignore[attr-defined]
                else:
                    import fcntl

                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except OSError as exc:
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        "Timed out waiting for another Proton Pass runtime fetch."
                    ) from exc
                time.sleep(0.05)
        yield
    finally:
        if acquired:
            try:
                if os.name == "nt":
                    import msvcrt

                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]
                else:
                    import fcntl

                    fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(fd)


def _verified_identity(
    binary: Path, paths: _Paths, timeout: float
) -> tuple[str, str | None, str | None]:
    """Return (class, name, safe_error) from pass-cli's structured info."""
    try:
        proc = _run(binary, ["info", "--output", "json"], paths, timeout)
    except RuntimeError as exc:
        return "unavailable", None, str(exc)
    if proc.returncode != 0:
        return "unavailable", None, None
    kind, name = _identity(proc.stdout)
    if kind == "agent":
        return (
            kind,
            name,
            "Agent personal access tokens are not supported by this runtime-only source.",
        )
    if kind == "human":
        return (
            kind,
            None,
            "The isolated Proton Pass state contains a human session; "
            "only a plain PAT is accepted.",
        )
    if kind != "plain_pat":
        return kind, None, "pass-cli returned malformed or unrecognized structured identity data."
    return kind, name, None


def _ensure_plain_pat_session(
    binary: Path, paths: _Paths, token: str, timeout: float
) -> tuple[str | None, FetchResult | None]:
    """Validate/rebootstrap the owned session and return its account-bound hash."""
    existing_kind, existing_name, existing_error = _verified_identity(binary, paths, timeout)
    if existing_kind in {"agent", "human", "malformed"}:
        return None, _result_error(
            existing_error or "Unsupported Proton Pass identity.", ErrorKind.AUTH_FAILED, binary
        )

    if existing_kind == "plain_pat" and existing_name is not None:
        candidate = _session_fingerprint(token, existing_name)
        if _read_fingerprint(paths.fingerprint) == candidate:
            return candidate, None

    try:
        _reset_session(paths)
        login = _run(binary, ["login"], paths, timeout, token=token)
    except RuntimeError as exc:
        return None, _result_error(
            str(exc),
            ErrorKind.TIMEOUT if "timed out" in str(exc) else ErrorKind.BINARY_MISSING,
            binary,
        )
    if login.returncode != 0:
        return None, _result_error(
            f"pass-cli login failed with exit code {login.returncode}; no secret values were read.",
            ErrorKind.AUTH_FAILED,
            binary,
        )

    kind, name, error = _verified_identity(binary, paths, timeout)
    if kind != "plain_pat" or name is None:
        # Do not leave an Agent/human/unknown identity in this runtime-owned state.
        try:
            _reset_session(paths)
        except RuntimeError:
            pass
        return None, _result_error(
            error or "The login did not produce a verified plain-PAT session.",
            ErrorKind.AUTH_FAILED,
            binary,
        )

    fingerprint = _session_fingerprint(token, name)
    try:
        _write_fingerprint(paths.fingerprint, fingerprint)
    except OSError:
        return None, _result_error(
            "Could not securely persist the Proton Pass session fingerprint.",
            ErrorKind.INTERNAL,
            binary,
        )
    return fingerprint, None


def _add_secret(target: dict[str, str], name: Any, value: Any) -> None:
    if not isinstance(name, str) or not is_valid_env_name(name):
        raise ValueError("a supported secret field has an invalid environment-variable name")
    if not isinstance(value, str) or value == "":
        raise ValueError(f"supported field {name!r} has an empty or non-string value")
    if name in target:
        raise ValueError(f"duplicate environment-variable name {name!r}")
    target[name] = value


def _field_value(field: Any) -> tuple[Any, Any, bool]:
    if not isinstance(field, dict):
        raise ValueError("field entry is not an object")
    name = field.get("name")
    content = field.get("content")
    if not isinstance(content, dict) or len(content) != 1:
        raise ValueError("field content is not an object")
    kind, value = next(iter(content.items()))
    if kind not in {"Hidden", "Text"}:
        return name, None, False
    return name, value, True


def _parse_items(stdout: str) -> dict[str, str]:
    """Strictly parse one complete `item list --show-secrets` response."""
    try:
        payload = json.loads(stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("bulk item output is not complete JSON") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        raise ValueError("bulk item output must be an object containing an items array")

    found: dict[str, str] = {}
    # Sort by stable metadata so duplicate detection and diagnostics are deterministic.
    items = payload["items"]
    for item in sorted(
        items, key=lambda value: str(value.get("id", "")) if isinstance(value, dict) else ""
    ):
        if not isinstance(item, dict):
            raise ValueError("item entry is not an object")
        if not isinstance(item.get("id"), str) or not item["id"]:
            raise ValueError("item id is missing or malformed")
        state = item.get("state")
        if not isinstance(state, str):
            raise ValueError("item state is missing or malformed")
        if state != "Active":
            continue
        outer = item.get("content")
        if not isinstance(outer, dict):
            raise ValueError("item content is missing or malformed")
        title = outer.get("title")
        inner = outer.get("content")
        extra = outer.get("extra_fields")
        if not isinstance(title, str) or not isinstance(inner, dict) or not isinstance(extra, list):
            raise ValueError("item has malformed title, content, or extra_fields")
        if len(inner) != 1 or not isinstance(next(iter(inner)), str):
            raise ValueError("item content must contain exactly one typed variant")

        login = inner.get("Login")
        if login is not None:
            if not isinstance(login, dict) or "password" not in login:
                raise ValueError("Login item is missing its password field")
            _add_secret(found, title, login.get("password"))

        custom = inner.get("Custom")
        if custom is not None:
            if not isinstance(custom, dict) or not isinstance(custom.get("sections"), list):
                raise ValueError("Custom item sections are malformed")
            for section in custom["sections"]:
                if not isinstance(section, dict) or not isinstance(
                    section.get("section_fields"), list
                ):
                    raise ValueError("Custom item section_fields are malformed")
                for field in section["section_fields"]:
                    name, value, supported = _field_value(field)
                    if supported:
                        _add_secret(found, name, value)

        for field in extra:
            name, value, supported = _field_value(field)
            if supported:
                _add_secret(found, name, value)

    return dict(sorted(found.items()))


class ProtonPassSource(SecretSource):
    """Bulk runtime source backed by the official Proton Pass CLI."""

    name = "proton_pass"
    label = "Proton Pass"
    shape = "bulk"

    def override_existing(self, cfg: dict[str, Any]) -> bool:
        return bool(isinstance(cfg, dict) and cfg.get("override_existing", True))

    def protected_env_vars(self, cfg: dict[str, Any]) -> frozenset[str]:
        return frozenset({TOKEN_ENV})

    def config_schema(self) -> dict[str, dict[str, Any]]:
        return {
            "enabled": {"description": "Master switch", "default": False},
            "vault": {"description": "Exact vault name to bulk-read", "default": ""},
            "binary_path": {
                "description": "Absolute pass-cli path (empty = PATH discovery)",
                "default": "",
            },
            "command_timeout_seconds": {
                "description": "Timeout for each noninteractive CLI operation",
                "default": _DEFAULT_TIMEOUT,
            },
            "cache_ttl_seconds": {
                "description": "Plaintext DiskCache TTL; 0 disables all secret-value caching",
                "default": 0,
            },
            "override_existing": {
                "description": "Vault values overwrite .env/shell values",
                "default": True,
            },
        }

    def fetch(self, cfg: dict[str, Any], home_path: Path) -> FetchResult:
        """Fetch without allowing an unexpected local failure to escape startup."""
        try:
            return self._fetch(cfg, home_path)
        except Exception:
            return _result_error(
                "The Proton Pass source failed safely before applying any values.",
                ErrorKind.INTERNAL,
            )

    def _fetch(self, cfg: dict[str, Any], home_path: Path) -> FetchResult:
        cfg = cfg if isinstance(cfg, dict) else {}
        token = os.environ.get(TOKEN_ENV, "")
        if not token:
            return _result_error(
                f"secrets.proton_pass.enabled is true but {TOKEN_ENV} is not set.",
                ErrorKind.NOT_CONFIGURED,
            )
        vault = cfg.get("vault")
        if not isinstance(vault, str) or not vault.strip():
            return _result_error(
                "secrets.proton_pass.vault must be a non-empty vault name.",
                ErrorKind.NOT_CONFIGURED,
            )
        vault = vault.strip()
        if vault.startswith("-"):
            return _result_error(
                "secrets.proton_pass.vault must not begin with '-' because pass-cli "
                "parses the vault as a positional argument.",
                ErrorKind.NOT_CONFIGURED,
            )

        configured = cfg.get("binary_path", "")
        if not isinstance(configured, str):
            return _result_error(
                "secrets.proton_pass.binary_path must be a string.", ErrorKind.NOT_CONFIGURED
            )
        if configured and not Path(configured).expanduser().is_absolute():
            return _result_error(
                "secrets.proton_pass.binary_path must be an absolute path.",
                ErrorKind.NOT_CONFIGURED,
            )
        binary = _find_binary(configured)
        if binary is None:
            missing_message = (
                "The configured pass-cli binary is not executable."
                if configured
                else "pass-cli was not found on PATH; install Proton Pass CLI >= 2.1.0 "
                "or set secrets.proton_pass.binary_path."
            )
            return _result_error(
                missing_message,
                ErrorKind.BINARY_MISSING,
            )

        timeout = _parse_positive_float(cfg.get("command_timeout_seconds"), _DEFAULT_TIMEOUT)
        ttl = _parse_positive_float(cfg.get("cache_ttl_seconds"), 0.0, allow_zero=True)
        paths = _paths(home_path)
        try:
            _prepare_paths(paths)
        except RuntimeError as exc:
            return _result_error(str(exc), ErrorKind.INTERNAL, binary)
        try:
            version_proc = _run(binary, ["--version"], paths, timeout)
        except RuntimeError as exc:
            return _result_error(
                str(exc),
                ErrorKind.TIMEOUT if "timed out" in str(exc) else ErrorKind.BINARY_MISSING,
                binary,
            )
        if version_proc.returncode != 0:
            return _result_error("pass-cli --version failed.", ErrorKind.BINARY_MISSING, binary)
        version = _parse_version(version_proc.stdout)
        if version is None or version < _MIN_VERSION:
            return _result_error(
                "Proton Pass CLI 2.1.0 or newer is required.", ErrorKind.BINARY_MISSING, binary
            )

        try:
            with _state_lock(paths.lock, timeout):
                return self._fetch_locked(binary, paths, home_path, token, vault, timeout, ttl)
        except RuntimeError as exc:
            return _result_error(
                str(exc),
                ErrorKind.TIMEOUT if "Timed out" in str(exc) else ErrorKind.INTERNAL,
                binary,
            )

    def _fetch_locked(
        self,
        binary: Path,
        paths: _Paths,
        home_path: Path,
        token: str,
        vault: str,
        timeout: float,
        ttl: float,
    ) -> FetchResult:
        fingerprint, failure = _ensure_plain_pat_session(binary, paths, token, timeout)
        if failure is not None:
            return failure
        assert fingerprint is not None

        cache_key: _CacheKey = (fingerprint, vault, _CACHE_FORMAT)
        cached = _DISK_CACHE.read(cache_key, ttl, home_path)
        if cached is not None:
            return FetchResult(secrets=dict(cached.secrets), binary_path=binary)

        try:
            proc = _run(
                binary,
                ["item", "list", vault, "--output", "json", "--show-secrets"],
                paths,
                timeout,
            )
        except RuntimeError as exc:
            return _result_error(
                str(exc),
                ErrorKind.TIMEOUT if "timed out" in str(exc) else ErrorKind.BINARY_MISSING,
                binary,
            )
        if proc.returncode != 0:
            return _result_error(
                f"pass-cli bulk item list failed with exit code {proc.returncode}; "
                "no partial values were applied.",
                ErrorKind.AUTH_FAILED,
                binary,
            )
        try:
            secrets = _parse_items(proc.stdout)
        except ValueError as exc:
            return _result_error(
                f"Rejected Proton Pass bulk output: {exc}.", ErrorKind.INTERNAL, binary
            )

        # Cache only a complete, successfully parsed bulk response.
        _DISK_CACHE.write(
            cache_key,
            CachedFetch(secrets=secrets, fetched_at=time.time()),
            ttl,
            home_path,
        )
        return FetchResult(secrets=secrets, binary_path=binary)

    def remediation(self, kind: ErrorKind | None, cfg: dict[str, Any]) -> str:
        if kind == ErrorKind.BINARY_MISSING:
            return "Install Proton Pass CLI 2.1.0 or newer, or set secrets.proton_pass.binary_path."
        if kind in (ErrorKind.AUTH_FAILED, ErrorKind.AUTH_EXPIRED):
            return (
                "Provide a plain, read-only Proton Pass PAT; "
                "Agent and human sessions are intentionally rejected."
            )
        return super().remediation(kind, cfg)

    def fetch_timeout_seconds(self, cfg: dict[str, Any]) -> float:
        """Budget for lock contention plus the bounded noninteractive subprocesses."""
        timeout = _parse_positive_float(
            (cfg or {}).get("command_timeout_seconds"), _DEFAULT_TIMEOUT
        )
        return max(super().fetch_timeout_seconds(cfg), timeout * 6 + 15)


def register(ctx: Any) -> None:
    ctx.register_secret_source(ProtonPassSource())
