"""Runtime-only Proton Pass secret source for Hermes Agent.

This plugin deliberately supports only a plain, narrowly scoped Proton Pass
personal access token and one bulk, read-only item-list operation.  It does not
implement Agent identities, interactive credential access, or item mutation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import shutil
import stat
import subprocess  # nosec B404
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, NamedTuple, cast

from agent.secret_sources._cache import CachedFetch, DiskCache
from agent.secret_sources.base import (
    ErrorKind,
    FetchResult,
    SecretSource,
    is_valid_env_name,
    run_secret_cli,
)

TOKEN_ENV = "PROTON_PASS_PERSONAL_ACCESS_TOKEN"  # noqa: S105  # nosec B105
_MIN_VERSION = (2, 1, 0)
_DEFAULT_TIMEOUT = 30.0
_CACHE_FORMAT = "proton-pass-runtime-v1"
_PRIVILEGE_MODE = "read-only-vault"
_VERSION_RE = re.compile(r"^Proton Pass CLI (\d+)\.(\d+)\.(\d+)(?: \([^\r\n()]+\))?\s*$")
_AGENT_PREFIX = "[Agent] "
_CACHE_SENTINEL = "\0PROTON_PASS_CACHE_INTEGRITY\0"
_MAX_OUTPUT_BYTES = 8 * 1024 * 1024
_MAX_ITEMS = 10_000
_MAX_FIELDS = 50_000
_MAX_NAME_CHARS = 256
_MAX_VALUE_CHARS = 1024 * 1024
_BLOCKED_ENV_NAMES = frozenset(
    {
        "PATH",
        "PYTHONPATH",
        "PYTHONHOME",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "NODE_OPTIONS",
        "RUBYOPT",
        "PERL5OPT",
        "BASH_ENV",
        "ENV",
        "ZDOTDIR",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
    }
)
_BLOCKED_ENV_PREFIXES = ("DYLD_", "HERMES_", "PROTON_PASS_")


class _Paths(NamedTuple):
    root: Path
    session: Path
    home: Path
    fingerprint: Path
    lock: Path


_CacheKey = tuple[str, str, str]


class _SessionBinding(NamedTuple):
    fingerprint: str
    identity_name: str


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
    except (OverflowError, TypeError, ValueError):
        return default
    if math.isfinite(parsed) and (parsed > 0 or (allow_zero and parsed == 0)):
        return parsed
    return default


def _is_nonfinite_number(value: Any) -> bool:
    try:
        return not math.isfinite(float(value))
    except OverflowError:
        return True
    except (TypeError, ValueError):
        return False


def _standard_binary_candidates() -> tuple[Path, ...]:
    """Return fixed documented locations; inherited PATH is never trusted."""
    if os.name == "nt":
        # Proton does not currently document one stable system-wide Windows
        # install location. Windows operators must configure binary_path.
        return ()
    return (
        Path.home() / ".local" / "bin" / "pass-cli",
        Path("/opt/homebrew/bin/pass-cli"),
        Path("/usr/local/bin/pass-cli"),
        Path("/usr/bin/pass-cli"),
    )


def _validate_binary_path(candidate: Path) -> Path | None:
    """Canonicalize and validate one executable before it crosses the PAT boundary."""
    try:
        target = candidate.resolve(strict=True)
        target_stat = target.stat()
    except (OSError, RuntimeError):
        return None
    if not stat.S_ISREG(target_stat.st_mode) or not os.access(target, os.X_OK):
        return None
    if os.name == "nt":
        return target

    allowed_owners = {os.geteuid(), 0}
    current = target
    while True:
        try:
            metadata = current.stat()
        except OSError:
            return None
        if metadata.st_uid not in allowed_owners:
            return None
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return None
        if current.parent == current:
            break
        current = current.parent
    return target


def _find_binary(configured: str) -> Path | None:
    """Resolve a trusted configured path or a trusted fixed-location installation."""
    candidates = (Path(configured).expanduser(),) if configured else _standard_binary_candidates()
    for candidate in candidates:
        trusted = _validate_binary_path(candidate)
        if trusted is not None:
            return trusted
    return None


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


def _validate_path_components(path: Path, *, final_directory: bool = True) -> None:
    """Reject symlinks and non-directory ancestors in every existing component."""
    if not path.is_absolute():
        raise RuntimeError("Proton Pass state paths must be absolute.")
    current = Path(path.anchor)
    components = path.parts[1:]
    for index, component in enumerate(components):
        current /= component
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise RuntimeError("Could not validate the Proton Pass state path.") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise RuntimeError("Refusing a symlinked Proton Pass state or cache path.")
        is_final = index == len(components) - 1
        if (not is_final or final_directory) and not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError("A Proton Pass state path component is not a directory.")


def _validate_regular_file(path: Path) -> bool:
    """Return whether a regular file exists; reject links and special files."""
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise RuntimeError("Could not validate a Proton Pass state file.") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError("Refusing a linked or non-regular Proton Pass state file.")
    return True


def _ensure_private_dir(path: Path) -> None:
    _validate_path_components(path)
    try:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as exc:
        raise RuntimeError("Could not create the private Proton Pass state directory.") from exc
    _validate_path_components(path)
    if os.name != "nt":
        try:
            os.chmod(path, 0o700, follow_symlinks=False)
        except (NotImplementedError, OSError) as exc:
            raise RuntimeError("Could not secure the Proton Pass state directory.") from exc


def _prepare_paths(paths: _Paths) -> None:
    _validate_path_components(paths.root.parents[1])
    _ensure_private_dir(paths.root.parent)
    _ensure_private_dir(paths.root)
    _ensure_private_dir(paths.home)
    _ensure_private_dir(paths.session)
    _validate_regular_file(paths.fingerprint)
    _validate_regular_file(paths.lock)


def _cache_file(home_path: Path) -> Path:
    return cast(Path, _DISK_CACHE.path(Path(os.path.abspath(os.fspath(home_path.expanduser())))))


def _prepare_cache(home_path: Path, *, create_parent: bool) -> Path:
    cache_file = _cache_file(home_path)
    _validate_path_components(cache_file.parent)
    if create_parent:
        _ensure_private_dir(cache_file.parent)
    _validate_regular_file(cache_file)
    return cache_file


def _clear_cache(home_path: Path) -> None:
    cache_file = _prepare_cache(home_path, create_parent=False)
    if cache_file.exists():
        try:
            cache_file.unlink()
        except OSError as exc:
            raise RuntimeError("Could not clear the Proton Pass plaintext cache.") from exc


def _reset_session(paths: _Paths) -> None:
    """Reset only this plugin's profile-scoped pass-cli session state."""
    _validate_path_components(paths.root)
    _validate_path_components(paths.session)
    fingerprint_exists = _validate_regular_file(paths.fingerprint)
    if fingerprint_exists:
        try:
            paths.fingerprint.unlink()
        except OSError as exc:
            raise RuntimeError("Could not remove the Proton Pass session fingerprint.") from exc

    retired: Path | None = None
    if paths.session.exists():
        for suffix in range(100):
            candidate = paths.root / f".session-retired-{os.getpid()}-{time.time_ns()}-{suffix}"
            if not candidate.exists() and not candidate.is_symlink():
                retired = candidate
                break
        if retired is None:
            raise RuntimeError("Could not reserve a safe Proton Pass session reset path.")
        try:
            os.replace(paths.session, retired)
        except OSError as exc:
            raise RuntimeError("Could not atomically retire the Proton Pass session.") from exc
    _ensure_private_dir(paths.session)
    if retired is not None:
        try:
            shutil.rmtree(retired)
        except OSError as exc:
            raise RuntimeError("Could not remove the retired Proton Pass session.") from exc


def _child_env(paths: _Paths, *, token: str | None = None) -> dict[str, str]:
    """Return pass-cli's isolated state environment; token is login-only."""
    env = {
        "PROTON_PASS_SESSION_DIR": str(paths.session),
        "PROTON_PASS_KEY_PROVIDER": "fs",  # nosec B105
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
    return cast(
        subprocess.CompletedProcess[str],
        run_secret_cli(
            [str(binary), *args],
            extra_env=_child_env(paths, token=token),
            timeout=timeout,
        ),
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


def _hash_component(digest: Any, value: str | bytes) -> None:
    encoded = value.encode("utf-8") if isinstance(value, str) else value
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)


def _session_tree_digest(path: Path) -> str:
    """Hash the isolated session tree and reject links or special entries."""
    _validate_path_components(path)
    digest = hashlib.sha256()
    _hash_component(digest, "proton-pass-session-tree-v1")
    try:
        root_metadata = os.lstat(path)
    except OSError as exc:
        raise RuntimeError("Could not inspect the isolated Proton Pass session.") from exc
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise RuntimeError("Refusing linked or non-directory Proton Pass session data.")
    for value in (
        stat.S_IMODE(root_metadata.st_mode),
        root_metadata.st_dev,
        root_metadata.st_ino,
        root_metadata.st_mtime_ns,
    ):
        _hash_component(digest, str(value))

    def visit(directory: Path, relative: Path) -> None:
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError as exc:
            raise RuntimeError("Could not inspect the isolated Proton Pass session.") from exc
        for entry in entries:
            child_relative = relative / entry.name
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise RuntimeError("Could not inspect isolated Proton Pass session data.") from exc
            relative_name = child_relative.as_posix()
            if stat.S_ISLNK(metadata.st_mode):
                raise RuntimeError("Refusing symlinked Proton Pass session data.")
            if stat.S_ISDIR(metadata.st_mode):
                _hash_component(digest, "directory")
                _hash_component(digest, relative_name)
                _hash_component(digest, str(stat.S_IMODE(metadata.st_mode)))
                _hash_component(digest, str(metadata.st_dev))
                _hash_component(digest, str(metadata.st_ino))
                _hash_component(digest, str(metadata.st_mtime_ns))
                visit(Path(entry.path), child_relative)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise RuntimeError("Refusing non-regular Proton Pass session data.")

            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                fd = os.open(entry.path, flags)
            except OSError as exc:
                raise RuntimeError("Could not safely open Proton Pass session data.") from exc
            try:
                opened = os.fstat(fd)
                if not stat.S_ISREG(opened.st_mode):
                    raise RuntimeError("Refusing non-regular Proton Pass session data.")
                if os.name != "nt" and (opened.st_dev, opened.st_ino) != (
                    metadata.st_dev,
                    metadata.st_ino,
                ):
                    raise RuntimeError("Proton Pass session data changed while it was inspected.")
                _hash_component(digest, "file")
                _hash_component(digest, relative_name)
                _hash_component(digest, str(stat.S_IMODE(opened.st_mode)))
                _hash_component(digest, str(opened.st_dev))
                _hash_component(digest, str(opened.st_ino))
                _hash_component(digest, str(opened.st_size))
                _hash_component(digest, str(opened.st_mtime_ns))
                while True:
                    chunk = os.read(fd, 128 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
            finally:
                os.close(fd)

    visit(path, Path())
    return digest.hexdigest()


def _session_fingerprint(token: str, identity_name: str, session_digest: str) -> str:
    digest = hashlib.sha256()
    for component in (
        _CACHE_FORMAT,
        "plain-pat",
        _PRIVILEGE_MODE,
        identity_name,
        session_digest,
        token,
    ):
        _hash_component(digest, component)
    return digest.hexdigest()


def _read_fingerprint(path: Path) -> str | None:
    if not _validate_regular_file(path):
        return None
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise RuntimeError("Refusing a non-regular Proton Pass fingerprint file.")
            payload = json.load(handle)
    except json.JSONDecodeError:
        return None
    except OSError as exc:
        raise RuntimeError("Could not safely read the Proton Pass session fingerprint.") from exc
    value = payload.get("fingerprint") if isinstance(payload, dict) else None
    return value if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) else None


def _write_fingerprint(path: Path, fingerprint: str) -> None:
    """Atomically persist only the non-secret SHA-256 session binding."""
    _ensure_private_dir(path.parent)
    _validate_regular_file(path)
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
    _validate_path_components(path.parent)
    _validate_regular_file(path)
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, stat.S_IRUSR | stat.S_IWUSR)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("runtime lock is not a regular file")
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
) -> tuple[_SessionBinding | None, FetchResult | None]:
    """Validate/rebootstrap the owned session and return its session-tree binding."""
    before_info_digest = _session_tree_digest(paths.session)
    existing_kind, existing_name, existing_error = _verified_identity(binary, paths, timeout)
    if existing_kind in {"agent", "human", "malformed"}:
        return None, _result_error(
            existing_error or "Unsupported Proton Pass identity.", ErrorKind.AUTH_FAILED, binary
        )

    if existing_kind == "plain_pat" and existing_name is not None:
        after_info_digest = _session_tree_digest(paths.session)
        before_candidate = _session_fingerprint(token, existing_name, before_info_digest)
        after_candidate = _session_fingerprint(token, existing_name, after_info_digest)
        stored = _read_fingerprint(paths.fingerprint)
        if stored in {before_candidate, after_candidate}:
            if stored != after_candidate:
                _write_fingerprint(paths.fingerprint, after_candidate)
            return _SessionBinding(after_candidate, existing_name), None

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

    fingerprint = _session_fingerprint(token, name, _session_tree_digest(paths.session))
    try:
        _write_fingerprint(paths.fingerprint, fingerprint)
    except (OSError, RuntimeError):
        return None, _result_error(
            "Could not securely persist the Proton Pass session fingerprint.",
            ErrorKind.INTERNAL,
            binary,
        )
    return _SessionBinding(fingerprint, name), None


def _refresh_session_binding(paths: _Paths, token: str, identity_name: str) -> _SessionBinding:
    fingerprint = _session_fingerprint(token, identity_name, _session_tree_digest(paths.session))
    _write_fingerprint(paths.fingerprint, fingerprint)
    return _SessionBinding(fingerprint, identity_name)


def _add_secret(target: dict[str, str], name: Any, value: Any) -> None:
    if not isinstance(name, str) or len(name) > _MAX_NAME_CHARS or not is_valid_env_name(name):
        raise ValueError("a supported secret field has an invalid environment-variable name")
    if name in _BLOCKED_ENV_NAMES or name.startswith(_BLOCKED_ENV_PREFIXES):
        raise ValueError("a supported field uses a reserved runtime-control destination name")
    if not isinstance(value, str) or value == "":
        raise ValueError("a supported field has an empty or non-string value")
    if len(value) > _MAX_VALUE_CHARS:
        raise ValueError("a supported field value exceeds the decoded size limit")
    if name in target:
        raise ValueError("duplicate environment-variable name")
    target[name] = value


def _field_value(field: Any) -> tuple[Any, Any, bool]:
    if not isinstance(field, dict):
        raise ValueError("field entry is not an object")
    name = field.get("name")
    if not isinstance(name, str) or len(name) > _MAX_NAME_CHARS:
        raise ValueError("field name is missing, malformed, or oversized")
    content = field.get("content")
    if not isinstance(content, dict) or len(content) != 1:
        raise ValueError("field content is not an object")
    kind, value = next(iter(content.items()))
    if isinstance(value, str) and len(value) > _MAX_VALUE_CHARS:
        raise ValueError("field value exceeds the decoded size limit")
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
    if len(items) > _MAX_ITEMS:
        raise ValueError("bulk item output exceeds the decoded item limit")
    field_count = 0
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
        if state == "Trashed":
            continue
        if state != "Active":
            raise ValueError("item state is unknown")
        outer = item.get("content")
        if not isinstance(outer, dict):
            raise ValueError("item content is missing or malformed")
        title = outer.get("title")
        inner = outer.get("content")
        extra = outer.get("extra_fields")
        if not isinstance(title, str) or not isinstance(inner, dict) or not isinstance(extra, list):
            raise ValueError("item has malformed title, content, or extra_fields")
        if len(title) > _MAX_NAME_CHARS:
            raise ValueError("item title exceeds the decoded name limit")
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
                field_count += len(section["section_fields"])
                if field_count > _MAX_FIELDS:
                    raise ValueError("bulk item output exceeds the decoded field limit")
                for field in section["section_fields"]:
                    name, value, supported = _field_value(field)
                    if supported:
                        _add_secret(found, name, value)

        field_count += len(extra)
        if field_count > _MAX_FIELDS:
            raise ValueError("bulk item output exceeds the decoded field limit")
        for field in extra:
            name, value, supported = _field_value(field)
            if supported:
                _add_secret(found, name, value)

    return dict(sorted(found.items()))


def _cache_integrity(key: _CacheKey, secrets: dict[str, str]) -> str:
    digest = hashlib.sha256()
    _hash_component(digest, "proton-pass-cache-envelope-v1")
    _hash_component(digest, _cache_key_string(key))
    for name, value in sorted(secrets.items()):
        _hash_component(digest, name)
        _hash_component(digest, value)
    return digest.hexdigest()


def _cache_envelope(key: _CacheKey, secrets: dict[str, str]) -> dict[str, str]:
    envelope = dict(secrets)
    envelope[_CACHE_SENTINEL] = _cache_integrity(key, secrets)
    return envelope


def _verified_cached_secrets(key: _CacheKey, cached: CachedFetch) -> dict[str, str] | None:
    integrity = cached.secrets.get(_CACHE_SENTINEL)
    if not isinstance(integrity, str) or not re.fullmatch(r"[0-9a-f]{64}", integrity):
        return None
    verified: dict[str, str] = {}
    try:
        for name, value in cached.secrets.items():
            if name == _CACHE_SENTINEL:
                continue
            _add_secret(verified, name, value)
    except ValueError:
        return None
    if not hmac.compare_digest(integrity, _cache_integrity(key, verified)):
        return None
    return dict(sorted(verified.items()))


class ProtonPassSource(SecretSource):  # type: ignore[misc]
    """Bulk runtime source backed by the official Proton Pass CLI."""

    name = "proton_pass"
    label = "Proton Pass"
    shape = "bulk"
    api_version = 1

    def override_existing(self, cfg: dict[str, Any]) -> bool:
        return bool(isinstance(cfg, dict) and cfg.get("override_existing", False))

    def protected_env_vars(self, cfg: dict[str, Any]) -> frozenset[str]:
        return frozenset({TOKEN_ENV})

    def config_schema(self) -> dict[str, dict[str, Any]]:
        return {
            "enabled": {"description": "Master switch", "default": False},
            "vault": {"description": "Exact vault name to bulk-read", "default": ""},
            "binary_path": {
                "description": "Absolute pass-cli path (empty = fixed-location discovery)",
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
                "default": False,
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

        for setting in ("command_timeout_seconds", "cache_ttl_seconds"):
            if _is_nonfinite_number(cfg.get(setting)):
                return _result_error(
                    f"secrets.proton_pass.{setting} must be finite.",
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
                else "A trusted pass-cli was not found in a standard location; install "
                "Proton Pass CLI >= 2.1.0 or set secrets.proton_pass.binary_path."
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
        if ttl == 0:
            _clear_cache(home_path)

        binding, failure = _ensure_plain_pat_session(binary, paths, token, timeout)
        if failure is not None:
            return failure
        if binding is None:
            return _result_error(
                "The Proton Pass session could not be bound safely.", ErrorKind.INTERNAL, binary
            )

        cache_key: _CacheKey = (binding.fingerprint, vault, _CACHE_FORMAT)
        if ttl > 0:
            _prepare_cache(home_path, create_parent=False)
            cached = _DISK_CACHE.read(cache_key, ttl, home_path)
            if cached is not None:
                verified = _verified_cached_secrets(cache_key, cached)
                if verified is not None:
                    return FetchResult(secrets=verified, binary_path=binary)
            # Expired, mismatched, malformed, and absent envelopes all remove
            # any old plaintext before the fresh bulk request begins.
            _clear_cache(home_path)

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
                ErrorKind.TIMEOUT if "timed out" in str(exc) else ErrorKind.INTERNAL,
                binary,
            )
        if proc.returncode != 0:
            return _result_error(
                f"pass-cli bulk item list failed with exit code {proc.returncode}; "
                "no partial values were applied.",
                ErrorKind.INTERNAL,
                binary,
            )
        if len(proc.stdout.encode("utf-8")) > _MAX_OUTPUT_BYTES:
            return _result_error(
                "Rejected Proton Pass bulk output because it exceeds the capture size limit.",
                ErrorKind.INTERNAL,
                binary,
            )
        try:
            secrets = _parse_items(proc.stdout)
        except ValueError as exc:
            return _result_error(
                f"Rejected Proton Pass bulk output: {exc}.", ErrorKind.INTERNAL, binary
            )

        # Cache only a complete, successfully parsed bulk response, bound to
        # the final tree in case a legitimate CLI read updated session data.
        binding = _refresh_session_binding(paths, token, binding.identity_name)
        cache_key = (binding.fingerprint, vault, _CACHE_FORMAT)
        if ttl > 0:
            _prepare_cache(home_path, create_parent=True)
            _DISK_CACHE.write(
                cache_key,
                CachedFetch(secrets=_cache_envelope(cache_key, secrets), fetched_at=time.time()),
                ttl,
                home_path,
            )
        return FetchResult(secrets=secrets, binary_path=binary)

    def remediation(self, kind: ErrorKind | None, cfg: dict[str, Any]) -> str:
        if kind == ErrorKind.NOT_CONFIGURED:
            return (
                "Set secrets.proton_pass.vault, provide PROTON_PASS_PERSONAL_ACCESS_TOKEN, "
                "and enable secrets.proton_pass."
            )
        if kind == ErrorKind.BINARY_MISSING:
            return "Install Proton Pass CLI 2.1.0 or newer, or set secrets.proton_pass.binary_path."
        if kind in (ErrorKind.AUTH_FAILED, ErrorKind.AUTH_EXPIRED):
            return (
                "Provide a plain, read-only Proton Pass PAT; "
                "Agent and human sessions are intentionally rejected."
            )
        return cast(str, super().remediation(kind, cfg))

    def fetch_timeout_seconds(self, cfg: dict[str, Any]) -> float:
        """Budget for lock contention plus the bounded noninteractive subprocesses."""
        timeout = _parse_positive_float(
            (cfg or {}).get("command_timeout_seconds"), _DEFAULT_TIMEOUT
        )
        return max(cast(float, super().fetch_timeout_seconds(cfg)), timeout * 6 + 15)


def register(ctx: Any) -> None:
    ctx.register_secret_source(ProtonPassSource())
