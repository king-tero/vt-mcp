"""Bounded Registry operations for the two reviewed remote-only identities."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
import re
import stat
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote

REGISTRY = "https://registry.modelcontextprotocol.io"
OFFICIAL = "io.modelcontextprotocol.registry/official"
# Canonical JSON hashes pin the entire manifest, including the secret header
# template. The corporate remote-only manifest deliberately has no repository.
IDENTITIES = {
    "VirusTotal/virustotal-mcp": {
        "id": 1361592455,
        "oidc_subject": "repo:VirusTotal@7701252/virustotal-mcp@1361592455:ref:refs/heads/main",
        "name": "io.github.VirusTotal/virustotal-mcp",
        "version": "0.8.2",
        "manifest_sha256": "294e3daa8f45e8f6b6050ab7cce140489272844c911afe6e3aca60843b0aa0e8",
    },
    "king-tero/vt-mcp": {
        "id": 1359828317,
        "oidc_subject": "repo:king-tero@4201239/vt-mcp@1359828317:ref:refs/heads/main",
        "name": "io.github.king-tero/vt-mcp",
        "version": "0.8.0",
        "manifest_sha256": "86c09dc2d84b540291e56813f13e6747cc6ae0f138adb9e4d5575d769f0a155d",
    },
}
OPERATIONS = {"verify-identity", "publish", "retire", "restore"}
RETIRE_MESSAGES = {
    "king-tero/vt-mcp": "Moved to io.github.VirusTotal/virustotal-mcp.",
    "VirusTotal/virustotal-mcp": "Temporarily retired for Registry identity recovery.",
}
LIMIT = 1024 * 1024


class Rejected(Exception):
    """Only fixed diagnostic codes may reach logs or the result artifact."""


def require(condition, code):
    if not condition:
        raise Rejected(code)


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def identity(environ):
    repository = environ.get("GITHUB_REPOSITORY")
    require(repository in IDENTITIES, "repository_not_allowed")
    selected = IDENTITIES[repository]
    require(environ.get("GITHUB_REPOSITORY_ID") == str(selected["id"]), "repository_id_mismatch")
    return repository, selected


def manifest_contract(manifest, selected):
    require(digest(manifest) == selected["manifest_sha256"], "manifest_contract_mismatch")


def context(environ):
    repository, selected = identity(environ)
    sha = environ.get("GITHUB_SHA", "")
    operation = environ.get("REGISTRY_OPERATION", "verify-identity")
    require(operation in OPERATIONS, "invalid_operation")
    require(
        re.fullmatch(r"[a-f0-9]{40}", sha)
        and environ.get("REVIEWED_SHA") == sha
        and environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and environ.get("GITHUB_REF") == "refs/heads/main"
        and environ.get("GITHUB_WORKFLOW_REF")
        == f"{repository}/.github/workflows/mcp-registry.yml@refs/heads/main",
        "reviewed_main_required",
    )
    return {"repository": repository, "sha": sha, "operation": operation, **selected}


def child_env(environ, *, oidc=False):
    keys = ["PATH", "HOME", "SSL_CERT_FILE", "SSL_CERT_DIR"]
    keys += (
        ["ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"] if oidc else ["GH_TOKEN"]
    )
    # No inherited debug, shell tracing, pagers, alternate GH host or proxy options.
    return {
        **{k: environ[k] for k in keys if k in environ},
        "GH_PROMPT_DISABLED": "1",
        "GH_PAGER": "cat",
        "NO_COLOR": "1",
    }


def command(args, environ, *, timeout=90):
    try:
        result = subprocess.run(
            args,
            env=environ,
            capture_output=True,
            timeout=timeout,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise Rejected("command_unavailable_or_timed_out") from None
    require(result.returncode == 0, "command_failed")
    return result.stdout


def github(path, environ):
    raw = command(
        ["gh", "api", "--hostname", "github.com", "--method", "GET", path],
        child_env(environ),
        timeout=30,
    )
    require(len(raw) <= LIMIT, "github_response_too_large")
    return json.loads(raw)


def github_preflight(current, environ):
    prefix = f"repos/{current['repository']}"
    repository = github(prefix, environ)  # No trailing slash on the repository root.
    require(
        type(repository.get("id")) is int
        and repository["id"] == current["id"]
        and repository.get("full_name") == current["repository"]
        and type(repository.get("private")) is bool,
        "github_repository_mismatch",
    )
    # Only the pinned corporate remote-only contract may omit a public repository.
    require(not repository["private"] or current["id"] == 1361592455, "private_repository_rejected")
    main = github(prefix + "/git/ref/heads/main", environ)
    require(main.get("object", {}).get("sha") == current["sha"], "main_has_changed")
    runs = github(
        prefix + "/actions/workflows/ci.yml/runs"
        f"?head_sha={current['sha']}&event=push&branch=main&per_page=100",
        environ,
    )["workflow_runs"]
    require(isinstance(runs, list), "invalid_ci_response")
    require(
        any(
            r.get("head_sha") == current["sha"]
            and r.get("head_branch") == "main"
            and r.get("event") == "push"
            and r.get("status") == "completed"
            and r.get("conclusion") == "success"
            and r.get("path") == ".github/workflows/ci.yml"
            and r.get("repository", {}).get("id") == current["id"]
            and r.get("head_repository", {}).get("id") == current["id"]
            for r in runs
        ),
        "successful_main_ci_required",
    )


def registry_get(path):
    connection = http.client.HTTPSConnection("registry.modelcontextprotocol.io", timeout=30)
    try:
        connection.request(
            "GET", path, headers={"Accept": "application/json", "Cache-Control": "no-cache"}
        )
        response = connection.getresponse()
        if response.status == 404:
            return None
        require(response.status == 200, "registry_read_failed")
        require(
            response.getheader("Content-Encoding", "identity") == "identity", "compressed_response"
        )
        raw = response.read(LIMIT + 1)
        require(len(raw) <= LIMIT, "registry_response_too_large")
        return json.loads(raw)
    finally:
        connection.close()


def public_entry(value, selected):
    if value is None:
        return {"name": selected["name"], "version": selected["version"], "status": "absent"}
    manifest_contract(value["server"], selected)
    official = value["_meta"][OFFICIAL]
    status = official.get("status")
    require(status in {"active", "deprecated", "deleted"}, "invalid_registry_status")
    message = official.get("statusMessage")
    require(
        message is None or (isinstance(message, str) and len(message) <= 500),
        "invalid_status_message",
    )
    require(status != "active" or message is None, "active_status_has_message")
    return {
        "name": selected["name"],
        "version": selected["version"],
        "status": status,
        "manifest_sha256": selected["manifest_sha256"],
        "status_message_sha256": digest(message) if message is not None else None,
    }


def snapshot():
    observed = {}
    for repository, selected in IDENTITIES.items():
        prefix = "/v0.1/servers/" + quote(selected["name"], safe="") + "/versions"
        listing = registry_get(prefix + "?include_deleted=true")
        listed = None
        if listing is not None:
            rows, metadata = listing["servers"], listing["metadata"]
            # This specific endpoint returns all versions, not a paginated search.
            require(isinstance(rows, list) and len(rows) <= 1, "unexpected_registry_versions")
            require(
                type(metadata.get("count")) is int
                and metadata["count"] == len(rows)
                and not any(metadata.get(k) for k in ("nextCursor", "next_cursor", "cursor")),
                "incomplete_registry_versions",
            )
            if rows:
                listed = public_entry(rows[0], selected)
        exact = public_entry(
            registry_get(prefix + "/" + selected["version"] + "?include_deleted=true"), selected
        )
        require((listed or public_entry(None, selected)) == exact, "registry_views_disagree")
        observed[repository] = exact
    return observed


def action(current, before):
    own = before[current["repository"]]["status"]
    operation = current["operation"]
    if operation == "verify-identity":
        return None
    if operation in {"publish", "restore"}:
        require(
            all(
                s["status"] in {"absent", "deleted"}
                for r, s in before.items()
                if r != current["repository"]
            ),
            "counterpart_reserves_remote_url",
        )
    if operation == "publish":
        require(own in {"absent", "active"}, "existing_version_requires_restore")
        return ["publish", "server.json"] if own == "absent" else None
    require(own != "absent", "own_version_missing")
    if operation == "retire":
        return (
            [
                "status",
                "--status",
                "deleted",
                "--message",
                RETIRE_MESSAGES[current["repository"]],
                current["name"],
                current["version"],
            ]
            if own != "deleted"
            else None
        )
    return (
        ["status", "--status", "active", current["name"], current["version"]]
        if own != "active"
        else None
    )


def credential_paths():
    home = Path.home()
    return [
        home / ".config/mcp-publisher/token.json",
        home / ".mcp_publisher_token",
        home / ".mcpregistry_github_token",
        home / ".mcpregistry_registry_token",
        Path.cwd() / ".mcpregistry_github_token",
        Path.cwd() / ".mcpregistry_registry_token",
    ]


def fresh_credentials():
    paths = credential_paths()
    require(not any(p.exists() or p.is_symlink() for p in paths), "preexisting_credentials")
    for parent in (paths[0].parent, paths[0].parent.parent):
        require(
            not parent.is_symlink() and (not parent.exists() or parent.is_dir()),
            "unsafe_credential_directory",
        )
    return paths[0]


def check_credential(path, current):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            require(
                stat.S_ISREG(info.st_mode)
                and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_uid == os.getuid()
                and info.st_nlink == 1
                and info.st_size <= 16384,
                "credential_rejected",
            )
            saved = json.loads(os.read(descriptor, 16385))
        finally:
            os.close(descriptor)
        require(
            saved["method"] == "github-oidc" and saved["registry"] == REGISTRY,
            "credential_rejected",
        )
        parts = saved["token"].split(".")
        require(
            len(parts) == 3 and all(re.fullmatch(r"[A-Za-z0-9_-]+", p) for p in parts),
            "credential_rejected",
        )

        def decode(part):
            return json.loads(
                base64.b64decode(part + "=" * (-len(part) % 4), altchars=b"-_", validate=True)
            )

        header, claims = decode(parts[0]), decode(parts[1])
        now = time.time()
        # The trusted HTTPS exchange authenticates this new token; this decoding
        # checks the expected claims, not a separate local signature verification.
        require(
            header["alg"] == "EdDSA"
            and claims["iss"] == "mcp-registry"
            and claims["auth_method"] == "github-oidc",
            "credential_rejected",
        )
        require(
            claims.get("auth_method_sub") == current["oidc_subject"],
            "credential_subject_mismatch",
        )
        require(
            claims.get("permissions")
            == [{"action": "publish", "resource": current["name"].split("/")[0] + "/*"}],
            "credential_permissions_mismatch",
        )
        require(
            all(type(claims.get(k)) is int for k in ("iat", "nbf", "exp"))
            and now - 300 <= claims["iat"] <= now + 60
            and claims["nbf"] <= now + 60 < claims["exp"]
            and claims["iat"] < claims["exp"],
            "credential_time_invalid",
        )
    except (KeyError, ValueError, TypeError, AttributeError, OSError):
        raise Rejected("credential_rejected") from None


@contextmanager
def authenticated(publisher, current, environ, result):
    credential = fresh_credentials()
    env = child_env(environ, oidc=True)
    try:
        command([publisher, "login", "github-oidc"], env)
        check_credential(credential, current)
        result["identity_verified"] = True
        yield
    finally:
        try:
            command([publisher, "logout"], env, timeout=10)
        except Rejected:
            pass
        finally:
            try:
                credential.unlink(missing_ok=True)
                require(
                    not credential.exists() and not credential.is_symlink(),
                    "credential_cleanup_failed",
                )
                result["credential_cleanup"] = "removed"
            except OSError:
                raise Rejected("credential_cleanup_failed") from None


def write_json(path, value, *, exclusive=False):
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | (os.O_EXCL if exclusive else os.O_TRUNC)
    with os.fdopen(os.open(path, flags, 0o600), "w") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    if exclusive:
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def operate(environ, result):
    current = context(environ)
    result.update({k: current[k] for k in ("repository", "id", "sha", "operation")})
    manifest_contract(json.loads(Path("server.json").read_text()), current)
    result["phase"] = "github_preflight"
    github_preflight(current, environ)  # Must pass before requesting OIDC.
    publisher = str(Path(environ["RUNNER_TEMP"]) / "mcp-publisher")
    result["phase"] = "authentication"
    with authenticated(publisher, current, environ, result):
        result["phase"] = "registry_preflight"
        result["before"] = before = snapshot()
        args = action(current, before)
        if args is None:
            result["after"] = snapshot()
            require(result["after"] == before, "registry_changed_without_mutation")
            result["status"] = "verified" if current["operation"] == "verify-identity" else "noop"
            return
        result["phase"] = "mutation"
        write_json(
            Path(environ["RUNNER_TEMP"]) / "registry-mutation-intent.json",
            {
                "operation": current["operation"],
                "sha": current["sha"],
                "before": before,
                "state": "may_have_been_applied_reconcile_before_another_attempt",
            },
            exclusive=True,
        )
        result["mutation_attempted"] = True
        command([publisher, *args], child_env(environ, oidc=True))  # Exactly one, never retried.
        result["phase"] = "postcondition"
        result["after"] = after = snapshot()
        own = after[current["repository"]]
        expected = "deleted" if current["operation"] == "retire" else "active"
        require(own["status"] == expected, "postcondition_failed")
        if expected == "deleted":
            require(
                own["status_message_sha256"] == digest(RETIRE_MESSAGES[current["repository"]]),
                "postcondition_failed",
            )
        require(
            all(after[r] == value for r, value in before.items() if r != current["repository"]),
            "counterpart_changed",
        )
        result["status"] = "completed"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "run"), default="run", nargs="?")
    args = parser.parse_args(argv)
    result = {
        "status": "error",
        "phase": "context",
        "identity_verified": False,
        "mutation_attempted": False,
        "credential_cleanup": "not_started",
    }
    path = Path(os.environ["RUNNER_TEMP"]) / "registry-result.json"
    try:
        write_json(path, result, exclusive=True)
    except OSError:
        print(json.dumps({"status": "error", "error": "result_already_exists_or_unwritable"}))
        return 1
    try:
        if args.command == "validate":
            _, selected = identity(os.environ)
            manifest_contract(json.loads(Path("server.json").read_text()), selected)
            fresh_credentials()  # validate may otherwise read a saved registry URL.
            command(
                [str(Path(os.environ["RUNNER_TEMP"]) / "mcp-publisher"), "validate", "server.json"],
                child_env(os.environ, oidc=True),
            )
            result.update(status="validated", phase="manifest_validation")
        else:
            operate(os.environ, result)
    except (Exception, KeyboardInterrupt) as error:
        result["status"] = "error"
        result["error"] = str(error) if isinstance(error, Rejected) else "operation_failed"
        result["reconciliation_required"] = result["mutation_attempted"]
    write_json(path, result)
    print(json.dumps(result, sort_keys=True))  # Only closed diagnostics and pinned public metadata.
    return 1 if result["status"] == "error" else 0


if __name__ == "__main__":
    raise SystemExit(main())
