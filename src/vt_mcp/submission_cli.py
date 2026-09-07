"""Explicit local consent, durable recovery and bounded analysis waiting."""

import argparse
import hashlib
import json
import math
import os
import stat
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

import anyio

from vt_mcp.analyses import (
    MAX_SUBMISSION_BYTES,
    AnalysisError,
    unknown_submission,
    validate_analysis_id,
    validate_sha256,
)
from vt_mcp.client import AnalysisClient
from vt_mcp.vtai_client import ConfigurationError, Settings

COPY_SECONDS = 15.0
_CLI_ERRORS = {
    "invalid_arguments": "Invalid command arguments. Use --help for the supported syntax.",
    "invalid_file": "Provide a readable regular file within the submission size limit.",
    "snapshot_changed": "The source changed while copying. No submission was started.",
    "snapshot_timeout": "The local copy exceeded its preparation budget.",
    "consent_required": "Standard submission requires explicit consent for the copied SHA256.",
    "confirmation_declined": "Submission was not confirmed. No bytes were sent.",
    "local_state_unavailable": (
        "Durable private recovery state could not be confirmed. No POST was started."
    ),
    "configuration_error": "VTAI configuration is unavailable or invalid.",
    "cancelled": "Local activity was interrupted. This does not withdraw an accepted submission.",
    "local_failure": "The local operation could not be completed.",
}


class CLIError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code if code in _CLI_ERRORS else "local_failure"
        super().__init__(_CLI_ERRORS[self.code])


@dataclass(frozen=True)
class Snapshot:
    file: BinaryIO
    sha256: str
    size: int


@contextmanager
def copy_snapshot(path: str) -> Iterator[Snapshot]:
    source = None
    prepared = False
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        source = os.open(path, flags | getattr(os, "O_NOFOLLOW", 0))
        before = os.fstat(source)
        if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= MAX_SUBMISSION_BYTES:
            raise CLIError("invalid_file")
        with tempfile.TemporaryFile("w+b") as copied:
            digest, size = hashlib.sha256(), 0
            deadline = time.monotonic() + COPY_SECONDS
            while True:
                if time.monotonic() >= deadline:
                    raise CLIError("snapshot_timeout")
                part = os.read(source, min(65536, MAX_SUBMISSION_BYTES + 1 - size))
                if not part:
                    break
                size += len(part)
                if size > MAX_SUBMISSION_BYTES:
                    raise CLIError("invalid_file")
                copied.write(part)
                digest.update(part)
            after = os.fstat(source)

            def stamp(value):
                return value.st_size, value.st_mtime_ns, value.st_ctime_ns

            if stamp(before) != stamp(after) or size != before.st_size:
                raise CLIError("snapshot_changed")
            copied.flush()
            copied.seek(0)
            if time.monotonic() >= deadline:
                raise CLIError("snapshot_timeout")
            os.close(source)
            source = None
            prepared = True
            yield Snapshot(copied, digest.hexdigest(), size)
    except OSError:
        if prepared:
            raise
        raise CLIError("invalid_file") from None
    finally:
        if source is not None:
            os.close(source)


def _directory(parent: int, name: str, *, private: bool) -> int:
    try:
        os.mkdir(name, 0o700, dir_fd=parent)
    except FileExistsError:
        pass
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        info = os.fstat(fd)
        if private and (info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise CLIError("local_state_unavailable")
        # Visibility does not prove durability: another process or an earlier
        # failed attempt may have created this entry without syncing its parent.
        os.fsync(fd)
        os.fsync(parent)
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def _state_directory(path: Path) -> Iterator[int]:
    if not path.is_absolute() or len(path.parts) < 2 or ".." in path.parts:
        raise CLIError("local_state_unavailable")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for index, part in enumerate(path.parts[1:]):
            child = _directory(fd, part, private=index == len(path.parts) - 2)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def state_path(override: str | None) -> Path:
    if override is not None:
        return Path(override)
    configured = os.environ.get("XDG_STATE_HOME")
    base = (
        Path(configured)
        if configured and Path(configured).is_absolute()
        else Path.home() / ".local/state"
    )
    return base / "vt-mcp"


def persist_reference(settings: Settings, sha256: str, directory: Path) -> bool:
    """Return True only for this confirmed creator. Existing state never permits POST."""
    validate_sha256(sha256)
    service = settings.base_url.rstrip("/")
    if settings.token in service:
        raise CLIError("configuration_error")
    reference = {"schema_version": 1, "service": service, "mode": "standard", "sha256": sha256}
    raw = json.dumps(reference, separators=(",", ":")).encode("utf-8")
    if len(raw) > 4096:
        raise CLIError("local_state_unavailable")
    service_key = hashlib.sha256(service.encode()).hexdigest()
    identity_key = hashlib.sha256(
        b"vt-mcp-submission-identity-v1\0" + service.encode() + b"\0" + settings.token.encode()
    ).hexdigest()
    try:
        with _state_directory(directory) as root:
            parent = _directory(root, service_key, private=True)
            try:
                actor = _directory(parent, identity_key, private=True)
                try:
                    name = sha256 + ".json"
                    try:
                        fd = os.open(
                            name,
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                            0o600,
                            dir_fd=actor,
                        )
                    except FileExistsError:
                        fd = os.open(
                            name,
                            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                            dir_fd=actor,
                        )
                        try:
                            info = os.fstat(fd)
                            if (
                                not stat.S_ISREG(info.st_mode)
                                or info.st_uid != os.getuid()
                                or info.st_mode & 0o077
                                or info.st_size != len(raw)
                            ):
                                raise CLIError("local_state_unavailable")
                            if os.read(fd, len(raw) + 1) != raw:
                                raise CLIError("local_state_unavailable")
                        finally:
                            os.close(fd)
                        return False
                    try:
                        offset = 0
                        while offset < len(raw):
                            written = os.write(fd, raw[offset:])
                            if written <= 0:
                                raise CLIError("local_state_unavailable")
                            offset += written
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    os.fsync(actor)
                    return True
                finally:
                    os.close(actor)
            finally:
                os.close(parent)
    except (OSError, ValueError, AttributeError):
        raise CLIError("local_state_unavailable") from None


def confirm(snapshot: Snapshot, *, accepted: bool, expected: str | None, service: str) -> None:
    if expected is not None:
        if validate_sha256(expected) != snapshot.sha256:
            raise AnalysisError("hash_mismatch")
    if accepted:
        if expected is None:
            raise CLIError("consent_required")
        return
    if not sys.stdin.isatty():
        raise CLIError("consent_required")
    print(
        "Standard submission sends the copied file to VirusTotal through VTAI. "
        "This is not confidential: reports are shared with the community and content may be "
        "shared with security partners and customers. Stopping locally does not withdraw an "
        "accepted file.\n"
        f"Service: {service}\nMode: standard\nSHA256: {snapshot.sha256}\nBytes: {snapshot.size}\n"
        "Type SUBMIT to authorize only this copy: ",
        file=sys.stderr,
        end="",
        flush=True,
    )
    answer = sys.stdin.readline(64)
    if answer.strip() != "SUBMIT":
        raise CLIError("confirmation_declined")


async def wait_analysis(client: AnalysisClient, analysis_id: str, seconds: float) -> dict:
    if not math.isfinite(seconds) or not 0 < seconds <= 300:
        raise CLIError("invalid_arguments")
    validate_analysis_id(analysis_id)
    latest, last_error, interval = None, None, 5.0
    with anyio.move_on_after(seconds):
        while True:
            delay = interval
            try:
                result = await client.get_analysis(analysis_id)
                latest, last_error = result, None
                if result["status"] == "completed":
                    return {**result, "wait": {"status": "completed", "last_error": None}}
                delay = max(delay, result["next_poll_after_seconds"])
            except AnalysisError as exc:
                if not exc.error["retryable"]:
                    raise
                last_error = exc
                delay = max(delay, exc.error["retry_after_seconds"] or 0)
            await anyio.sleep(delay)
            interval = min(interval * 2, 30)
    if latest is not None:
        return {
            **latest,
            "wait": {
                "status": "budget_exhausted",
                "last_error": last_error.error if last_error else None,
            },
        }
    raise last_error or AnalysisError("timeout")


async def _read(settings: Settings, action: str, identifier: str, wait: float = 0) -> dict:
    async with AnalysisClient(settings) as client:
        if action == "submission":
            return await client.get_submission(identifier)
        if wait:
            return await wait_analysis(client, identifier, wait)
        return await client.get_analysis(identifier)


async def _submit(settings: Settings, snapshot: Snapshot, new_reference: bool) -> dict:
    async with AnalysisClient(settings) as client:
        if new_reference:
            return await client.submit(snapshot.file, snapshot.sha256, snapshot.size)
        return await client.get_submission(snapshot.sha256)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CLIError("invalid_arguments")


def main(argv: list[str]) -> int:
    parser = _Parser(description="Explicit standard submission and actor-owned analysis reads")
    sub = parser.add_subparsers(dest="action", required=True)
    submit = sub.add_parser(
        "submit", help="Submit only an explicitly authorized private local copy"
    )
    submit.add_argument("path")
    submit.add_argument("--mode", choices=("standard",), required=True)
    submit.add_argument("--accept-standard", action="store_true")
    submit.add_argument("--expected-sha256")
    submit.add_argument("--state-dir")
    receipt = sub.add_parser(
        "submission", help="Read the current account's receipt without uploading"
    )
    receipt.add_argument("sha256")
    analysis = sub.add_parser(
        "analysis", help="Read one registered analysis, optionally wait up to300s"
    )
    analysis.add_argument("analysis_id")
    analysis.add_argument("--wait", type=float, default=0)
    recovery, started = None, False
    try:
        args = parser.parse_args(argv)
        if args.action == "analysis":
            if not math.isfinite(args.wait) or not 0 <= args.wait <= 300:
                raise CLIError("invalid_arguments")
            validate_analysis_id(args.analysis_id)
        elif args.action == "submission":
            validate_sha256(args.sha256)
        settings = Settings.from_env()
        if settings.token in settings.base_url:
            raise CLIError("configuration_error")
        if args.action == "submit":
            with copy_snapshot(args.path) as snapshot:
                confirm(
                    snapshot,
                    accepted=args.accept_standard,
                    expected=args.expected_sha256,
                    service=settings.base_url.rstrip("/"),
                )
                created = persist_reference(settings, snapshot.sha256, state_path(args.state_dir))
                recovery = unknown_submission(snapshot.sha256, snapshot.size)
                started = created
                result = anyio.run(_submit, settings, snapshot, created)
        else:
            identifier = args.sha256 if args.action == "submission" else args.analysis_id
            result = anyio.run(_read, settings, args.action, identifier, getattr(args, "wait", 0))
        print(json.dumps(result, ensure_ascii=True))
        return 3 if result["status"] == "submission_unknown" else 0
    except AnalysisError as exc:
        result = {"status": "error", "error": exc.error}
        if exc.submission is not None or recovery is not None:
            result["submission"] = exc.submission or recovery
        code = 3 if exc.error["code"] == "submission_unknown" else 2
    except KeyboardInterrupt:
        result = (
            recovery
            if started
            else {
                "status": "error",
                "error": {
                    "code": "cancelled",
                    "message": _CLI_ERRORS["cancelled"],
                    "retryable": False,
                },
            }
        )
        code = 130
    except (CLIError, ConfigurationError) as exc:
        reason = exc.code if isinstance(exc, CLIError) else "configuration_error"
        result = {
            "status": "error",
            "error": {"code": reason, "message": _CLI_ERRORS[reason], "retryable": False},
        }
        code = 2
    except Exception:
        if started:
            error = AnalysisError("submission_unknown", submission=recovery)
            result = {"status": "error", "error": error.error, "submission": recovery}
            code = 3
        else:
            result = {
                "status": "error",
                "error": {
                    "code": "local_failure",
                    "message": _CLI_ERRORS["local_failure"],
                    "retryable": False,
                },
            }
            code = 2
    print(json.dumps(result, ensure_ascii=True))
    return code
