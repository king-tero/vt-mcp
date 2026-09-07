"""An opt-in Linux guard for one exact, isolated Python command shape.

This is a host hook adapter and data-snapshot runner, not an MCP tool or sandbox.
Only the main script bytes are checked; imports and later actions are not covered.
"""

import argparse
import errno
import hashlib
import json
import os
import re
import shlex
import stat
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import anyio

from vt_mcp.reports import VTAIError
from vt_mcp.vtai_client import ConfigurationError, Settings, VTAIClient

PYTHON = "/usr/bin/python3"
MAX_SCRIPT_BYTES = 8 * 1024 * 1024
MAX_HOOK_BYTES = 64 * 1024
MAX_POLICY_BYTES = 16 * 1024
PREPARATION_SECONDS = 3.0
MFD_NOEXEC_SEAL = 0x0008  # Linux UAPI; not exposed by every supported Python.
# Linux UAPI include/uapi/linux/fcntl.h, independent of CPython build headers.
# F_LINUX_SPECIFIC_BASE is 1024; the seal commands use offsets 9 and 10.
F_ADD_SEALS = 1033
F_GET_SEALS = 1034
F_SEAL_SEAL = 0x0001
F_SEAL_SHRINK = 0x0002
F_SEAL_GROW = 0x0004
F_SEAL_WRITE = 0x0008
F_SEAL_EXEC = 0x0020
PATH_PATTERN = r"/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+"
COMMAND_PATTERN = re.compile(r"/usr/bin/python3 -I (" + PATH_PATTERN + r"\.py)")
POLICY_KEYS = {
    "schema_version",
    "mode",
    "token_file",
    "base_url",
    "minimum_completed_engines",
    "maximum_analysis_age_days",
}
REPORT_ERRORS = {
    "not_found",
    "access_denied",
    "upstream_access_denied",
    "rate_limited",
    "timeout",
    "upstream_error",
    "unavailable",
    "invalid_response",
    "response_too_large",
}


class GuardError(Exception):
    """Internal closed reason code; never wrap an exception's text or a pathname."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class Policy:
    mode: str
    token_file: str
    base_url: str
    minimum_completed_engines: int
    maximum_analysis_age_days: int


@dataclass(frozen=True)
class Snapshot:
    fd: int
    sha256: str


@dataclass(frozen=True)
class CheckResult:
    reason: str
    analysis_date: str | None = None
    engines: int | None = None


def _preparation_checkpoint(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise GuardError("preparation_timeout")


def _path(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= 4096
        and re.fullmatch(PATH_PATTERN, value) is not None
        and not {".", ".."}.intersection(value.split("/"))
    )


def covered_script(command: Any) -> str | None:
    if not isinstance(command, str):
        return None
    match = COMMAND_PATTERN.fullmatch(command)
    return match[1] if match and _path(match[1]) else None


def _stamp(info: os.stat_result) -> tuple[int, int, int]:
    return info.st_size, info.st_mtime_ns, info.st_ctime_ns


@contextmanager
def _regular(path: str, limit: int) -> Iterator[tuple[int, os.stat_result]]:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= limit:
            raise GuardError("invalid_file")
        yield fd, info
    finally:
        os.close(fd)


def _read_regular(path: str, limit: int) -> bytes:
    deadline = time.monotonic() + PREPARATION_SECONDS
    with _regular(path, limit) as (fd, before):
        parts = bytearray()
        while True:
            _preparation_checkpoint(deadline)
            part = os.read(fd, min(65536, limit + 1 - len(parts)))
            _preparation_checkpoint(deadline)
            if not part:
                break
            parts.extend(part)
            if len(parts) > limit:
                raise GuardError("invalid_file")
        if _stamp(before) != _stamp(os.fstat(fd)) or len(parts) != before.st_size:
            raise GuardError("source_changed")
    result = bytes(parts)
    _preparation_checkpoint(deadline)
    return result


def _unique_object(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _invalid_constant(value: str) -> Any:
    raise ValueError("non-finite JSON number")


def load_policy(path: str, expected_sha256: str) -> Policy:
    try:
        if not _path(path) or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
            raise ValueError
        raw = _read_regular(path, MAX_POLICY_BYTES)
        if hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise GuardError("policy_changed")
        data = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
        if not isinstance(data, dict) or data.keys() != POLICY_KEYS:
            raise ValueError
        if type(data["schema_version"]) is not int or data["schema_version"] != 1:
            raise ValueError
        if data["mode"] not in ("control", "observe") or not _path(data["token_file"]):
            raise ValueError
        for key, maximum in (
            ("minimum_completed_engines", 10000),
            ("maximum_analysis_age_days", 365),
        ):
            if type(data[key]) is not int or not 1 <= data[key] <= maximum:
                raise ValueError
        if not isinstance(data["base_url"], str):
            raise ValueError
        # Reuse endpoint validation without consulting the environment or opening HTTP.
        Settings("guard-policy-validation", data["base_url"])
        return Policy(**{key: value for key, value in data.items() if key != "schema_version"})
    except GuardError as exc:
        if exc.reason == "policy_changed":
            raise
        raise GuardError("invalid_policy") from None
    except (OSError, ValueError, TypeError, RecursionError):
        raise GuardError("invalid_policy") from None


def _seals() -> tuple[Any, int]:
    if sys.platform != "linux":
        raise GuardError("unsupported_platform")
    try:
        import fcntl

        required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL
        return fcntl, required
    except ImportError:
        raise GuardError("unsupported_platform") from None


def _new_memfd() -> int:
    try:
        if sys.platform != "linux" or not os.access(PYTHON, os.X_OK):
            raise GuardError("unsupported_platform")
        fd = os.memfd_create(
            "vt-mcp-checked-script", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL
        )
        if fd < 3:
            try:
                fcntl, _ = _seals()
                return fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 3)
            finally:
                os.close(fd)
        return fd
    except (OSError, AttributeError):
        raise GuardError("unsupported_platform") from None


def _seal(fd: int) -> None:
    fcntl, required = _seals()
    fcntl.fcntl(fd, F_ADD_SEALS, required)
    if (
        fcntl.fcntl(fd, F_GET_SEALS) & (required | F_SEAL_EXEC) != required | F_SEAL_EXEC
        or os.fstat(fd).st_mode & 0o111
    ):
        raise GuardError("unsupported_platform")
    # Python must be able to reopen the data descriptor as its script.
    with open(f"/proc/self/fd/{fd}", "rb"):
        pass


@contextmanager
def snapshot(path: str) -> Iterator[Snapshot]:
    deadline = time.monotonic() + PREPARATION_SECONDS
    if not _path(path) or not path.endswith(".py"):
        raise GuardError("invalid_file")
    target = None
    try:
        target = _new_memfd()
        _preparation_checkpoint(deadline)
        with _regular(path, MAX_SCRIPT_BYTES) as (source, before):
            count = 0
            while True:
                _preparation_checkpoint(deadline)
                part = os.read(source, min(65536, MAX_SCRIPT_BYTES + 1 - count))
                _preparation_checkpoint(deadline)
                if not part:
                    break
                count += len(part)
                if count > MAX_SCRIPT_BYTES:
                    raise GuardError("invalid_file")
                offset = 0
                while offset < len(part):
                    _preparation_checkpoint(deadline)
                    written = os.write(target, part[offset:])
                    _preparation_checkpoint(deadline)
                    if written <= 0:
                        raise GuardError("preparation_failed")
                    offset += written
            if _stamp(before) != _stamp(os.fstat(source)) or count != before.st_size:
                raise GuardError("source_changed")
        _preparation_checkpoint(deadline)
        _seal(target)
        _preparation_checkpoint(deadline)
        os.lseek(target, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        while True:
            _preparation_checkpoint(deadline)
            part = os.read(target, 65536)
            _preparation_checkpoint(deadline)
            if not part:
                break
            digest.update(part)
        os.lseek(target, 0, os.SEEK_SET)
        checked = Snapshot(target, digest.hexdigest())
        _preparation_checkpoint(deadline)
        yield checked
    except OSError:
        raise GuardError("preparation_failed") from None
    finally:
        if target is not None:
            os.close(target)


def report_reason(report: dict[str, Any], sha256: str, policy: Policy, now: datetime) -> str:
    """Use only explicit counts and dated evidence; no detection prose or defaults."""
    try:
        data = report["data"]
        if report["status"] != "found" or data["id"].lower() != sha256:
            return "invalid_response"
        stats = data["last_analysis_stats"]
        if any(
            type(stats.get(key)) is int and stats[key] > 0 for key in ("malicious", "suspicious")
        ):
            return "flagged"
        counts = [stats[key] for key in ("malicious", "suspicious", "harmless", "undetected")]
        if any(type(value) is not int or value < 0 for value in counts):
            return "insufficient_evidence"
        engines = report["coverage"]["engines"]
        if (
            type(engines) is not int
            or engines < policy.minimum_completed_engines
            or counts[2] + counts[3] < policy.minimum_completed_engines
        ):
            return "insufficient_evidence"
        date = report["analysis_date"]
        if not isinstance(date, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)", date
        ):
            return "insufficient_evidence"
        age = now - datetime.fromisoformat(date)
        if not timedelta(0) <= age <= timedelta(days=policy.maximum_analysis_age_days):
            return "insufficient_evidence"
        return "policy_satisfied"
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        return "insufficient_evidence"


def _settings(policy: Policy) -> Settings:
    try:
        token = _read_regular(policy.token_file, 514).decode("ascii").strip()
        return Settings.from_env(
            {"VTAI_TOKEN": token, "VTAI_BASE_URL": policy.base_url, "VTAI_TIMEOUT": "15"}
        )
    except (GuardError, OSError, UnicodeError, ConfigurationError):
        raise GuardError("credential_unavailable") from None


async def _check(policy: Policy, sha256: str) -> CheckResult:
    try:
        async with VTAIClient(_settings(policy)) as client:
            report = await client.get_file_report(sha256)
        reason = report_reason(report, sha256, policy, datetime.now(UTC))
        if (
            report.get("status") != "found"
            or report.get("data", {}).get("id", "").lower() != sha256
        ):
            return CheckResult(reason)
        date = report.get("analysis_date")
        try:
            if not isinstance(date, str) or not re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)", date
            ):
                date = None
            else:
                date = datetime.fromisoformat(date).isoformat()
        except (ValueError, TypeError, OverflowError):
            date = None
        coverage = report.get("coverage")
        engines = coverage.get("engines") if isinstance(coverage, dict) else None
        if type(engines) is not int or engines < 0:
            engines = None
        return CheckResult(reason, date, engines)
    except VTAIError as exc:
        code = exc.error.get("code")
        return CheckResult(code if code in REPORT_ERRORS else "check_failed")
    except GuardError as exc:
        return CheckResult(exc.reason)
    except Exception:
        # Cancellation is a BaseException, and must never turn into observe-and-run.
        return CheckResult("check_failed")


def _emit(**fields: Any) -> None:
    payload = {"component": "vt-mcp-guard", **fields}
    encoded = json.dumps(payload, separators=(",", ":"))
    if len(encoded.encode("utf-8")) + 1 > 2048:
        # Counters can be valid yet too large for a concise status line.
        payload.update(coverage={"engines": None}, coverage_omitted=True)
        encoded = json.dumps(payload, separators=(",", ":"))
    if len(encoded.encode("utf-8")) + 1 > 2048:
        raise GuardError("status_too_large")
    print(
        encoded,
        file=sys.stderr,
        flush=True,
    )


def _execute(checked: Snapshot) -> None:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("VTAI_")}
    # Do not inherit host-supplied extra descriptors, even if marked inheritable.
    for name in os.listdir("/proc/self/fd"):
        fd = int(name)
        if fd > 2 and fd != checked.fd:
            try:
                os.set_inheritable(fd, False)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
    os.set_inheritable(checked.fd, True)
    try:
        os.execve(PYTHON, [PYTHON, "-I", f"/proc/self/fd/{checked.fd}"], environment)
    except OSError:
        raise GuardError("execution_failed") from None


def run(policy: Policy, path: str) -> int:
    with snapshot(path) as checked:
        result = anyio.run(_check, policy, checked.sha256)
        proceed = result.reason == "policy_satisfied" or policy.mode == "observe"
        _emit(
            mode=policy.mode,
            decision="starting" if proceed else "blocked",
            reason=result.reason,
            sha256=checked.sha256,
            source="VirusTotal via VTAI",
            analysis_date=result.analysis_date,
            coverage={"engines": result.engines},
        )
        if not proceed:
            return 77
        _execute(checked)
    return 78  # Only reachable if an injected test executor returns.


def _deny() -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                "VTAI guard could not prepare this command. Execution denied."
            ),
        }
    }


def hook(raw: bytes, policy_path: str, policy_sha256: str) -> dict[str, Any]:
    if len(raw) > MAX_HOOK_BYTES:
        return _deny()
    try:
        event = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
        if not isinstance(event, dict):
            raise ValueError
        if event.get("hook_event_name") != "PreToolUse" or event.get("tool_name") != "Bash":
            return {}
        tool_input = event["tool_input"]
        if not isinstance(tool_input, dict) or not isinstance(tool_input.get("command"), str):
            raise ValueError
        path = covered_script(tool_input["command"])
        if path is None:
            return {}
        load_policy(policy_path, policy_sha256)
        rewritten = shlex.join(
            [
                sys.executable,
                "-I",
                "-m",
                "vt_mcp",
                "guard",
                "run",
                "--policy",
                policy_path,
                "--policy-sha256",
                policy_sha256,
                "--",
                path,
            ]
        )
        result = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "updatedInput": {**tool_input, "command": rewritten},
            }
        }
        if len(json.dumps(result, ensure_ascii=True).encode("ascii")) + 1 > MAX_HOOK_BYTES:
            return _deny()
        return result
    except (GuardError, ValueError, TypeError, KeyError, RecursionError):
        return _deny()


def doctor(policy: Policy) -> None:
    fd = _new_memfd()
    try:
        os.write(fd, b"# Local capability check; no script is executed.\n")
        _seal(fd)
    finally:
        os.close(fd)
    _settings(policy)
    print(
        json.dumps(
            {
                "component": "vt-mcp-guard",
                "status": "local_checks_passed",
                "mode": policy.mode,
                "host_activation": "unverified",
                "network": "not_checked",
                "access": "not_checked",
            },
            separators=(",", ":"),
        )
    )


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise GuardError("invalid_arguments")


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    is_hook = arguments[:1] == ["hook"]
    parser = _Parser(description="Opt-in guard for /usr/bin/python3 -I /absolute/script.py")
    parser.add_argument("action", choices=("hook", "run", "doctor"))
    parser.add_argument("--policy", required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("script", nargs="?")
    try:
        args = parser.parse_intermixed_args(arguments)
        is_hook = args.action == "hook"
        if (args.action == "run") != (args.script is not None):
            raise GuardError("invalid_arguments")
        if is_hook:
            result = hook(
                sys.stdin.buffer.read(MAX_HOOK_BYTES + 1), args.policy, args.policy_sha256
            )
            print(json.dumps(result, ensure_ascii=True))
            return 0
        policy = load_policy(args.policy, args.policy_sha256)
        if args.action == "doctor":
            doctor(policy)
            return 0
        return run(policy, args.script)
    except KeyboardInterrupt:
        if is_hook:
            print(json.dumps(_deny()))
        else:
            _emit(decision="blocked", reason="cancelled")
        return 130
    except Exception as exc:
        if is_hook:
            print(json.dumps(_deny()))
            return 0
        _emit(
            decision="blocked", reason=exc.reason if isinstance(exc, GuardError) else "guard_failed"
        )
        return 78
