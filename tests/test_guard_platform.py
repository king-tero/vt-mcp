"""Linux capability checks do not depend on CPython's exposed header macros."""

import builtins
import errno
import fcntl
import hashlib
import os
import subprocess
import sys

import pytest

from vt_mcp import guard

SEAL_NAMES = (
    "F_ADD_SEALS",
    "F_GET_SEALS",
    "F_SEAL_SEAL",
    "F_SEAL_SHRINK",
    "F_SEAL_GROW",
    "F_SEAL_WRITE",
)


@pytest.mark.parametrize("missing", [*SEAL_NAMES, "all"])
def test_absent_python_macros_still_require_immutable_nonexec_bytes(tmp_path, monkeypatch, missing):
    removed = SEAL_NAMES if missing == "all" else (missing,)
    for name in removed:
        monkeypatch.delattr(fcntl, name, raising=False)
    script = tmp_path / "inert.py"
    body = b'print("checked-inert-copy")\n'
    script.write_bytes(body)
    before = set(os.listdir("/proc/self/fd"))
    with guard.snapshot(str(script)) as checked:
        assert checked.sha256 == hashlib.sha256(body).hexdigest()
        assert fcntl.fcntl(checked.fd, 1034) & 0x2F == 0x2F
        assert not os.get_inheritable(checked.fd)
        assert not os.fstat(checked.fd).st_mode & 0o111
        for operation in (
            lambda: os.pwrite(checked.fd, b"x", 0),
            lambda: os.ftruncate(checked.fd, 0),
            lambda: os.ftruncate(checked.fd, len(body) + 1),
            lambda: os.fchmod(checked.fd, 0o700),
            lambda: fcntl.fcntl(checked.fd, 1033, 0x10),
        ):
            with pytest.raises(OSError) as caught:
                operation()
            assert caught.value.errno == errno.EPERM
        script.write_bytes(b'print("unchecked-replacement")\n')
        child = subprocess.run(
            [guard.PYTHON, "-I", f"/proc/self/fd/{checked.fd}"],
            pass_fds=(checked.fd,),
            capture_output=True,
            timeout=3,
            env={"PATH": "/usr/bin:/bin"},
        )
        assert child.returncode == 0 and child.stdout == b"checked-inert-copy\n"
        assert child.stderr == b"" and os.pread(checked.fd, len(body), 0) == body
    assert set(os.listdir("/proc/self/fd")) == before
    assert all(not hasattr(fcntl, name) for name in removed)


@pytest.mark.parametrize("mode", ["control", "observe"])
@pytest.mark.parametrize(
    "failure",
    [
        "add_error",
        "get_error",
        "ignored_add",
        "seal",
        "shrink",
        "grow",
        "write",
        "exec",
        "mode",
        "proc",
    ],
)
def test_missing_kernel_capability_blocks_before_query_or_execution(
    tmp_path, monkeypatch, mode, failure
):
    script = tmp_path / "inert.py"
    script.write_bytes(b"pass\n")
    policy = guard.Policy(mode, str(tmp_path / "unused-token"), "http://localhost/api/v3", 1, 30)
    original_fcntl, original_stat, original_open = fcntl.fcntl, os.fstat, builtins.open
    target = [None]
    removed_bit = {"seal": 1, "shrink": 2, "grow": 4, "write": 8, "exec": 32}.get(failure)

    def syscall(fd, command, argument=0):
        if command == 1033:
            target[0] = fd
            if failure == "add_error":
                raise OSError(errno.EINVAL, "private-kernel-detail")
            if failure == "ignored_add":
                return 0
        if command == 1034 and failure == "get_error":
            raise OSError(errno.EINVAL, "private-kernel-detail")
        result = original_fcntl(fd, command, argument)
        return result & ~removed_bit if command == 1034 and removed_bit else result

    def fstat(fd):
        result = original_stat(fd)
        if failure == "mode" and fd == target[0]:
            return os.stat_result((result.st_mode | 0o100, *result[1:]))
        return result

    def open_file(path, *args, **kwargs):
        if failure == "proc" and str(path).startswith("/proc/self/fd/"):
            raise OSError(errno.EACCES, "private-proc-detail")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(fcntl, "fcntl", syscall)
    monkeypatch.setattr(os, "fstat", fstat)
    monkeypatch.setattr(builtins, "open", open_file)
    monkeypatch.setattr(guard, "VTAIClient", lambda *_: pytest.fail("Queried before capability"))
    monkeypatch.setattr(guard, "_execute", lambda *_: pytest.fail("Executed before capability"))
    before = set(os.listdir("/proc/self/fd"))
    with pytest.raises(guard.GuardError) as caught:
        guard.run(policy, str(script))
    assert caught.value.reason in {"unsupported_platform", "preparation_failed"}
    assert "private-" not in str(caught.value)
    assert set(os.listdir("/proc/self/fd")) == before


@pytest.mark.parametrize("missing", ["linux", "fcntl"])
def test_non_linux_or_absent_fcntl_remains_unsupported(monkeypatch, missing):
    if missing == "linux":
        monkeypatch.setattr(sys, "platform", "darwin")
    else:
        monkeypatch.setitem(sys.modules, "fcntl", None)
    with pytest.raises(guard.GuardError, match="unsupported_platform"):
        guard._seals()
