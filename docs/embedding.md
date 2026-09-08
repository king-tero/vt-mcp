# Embed report, analysis and submission tools in VTAI

The factory introduced in `0.3.0` exposes four report tools through a host-supplied reader. Version `0.5.0` adds an optional analysis reader; `0.8.0` adds an optional submission reader. The CLI remains stdio and `create_server(settings, transport=...)` remains compatible. The embedding host supplies authentication and owns its HTTP deployment; this factory alone does not provide either.

`vt_mcp.server.create_report_server(*, lifespan, bind_reports, bind_analyses=None, bind_submissions=None)` returns an SDK `MCPServer`. The first two arguments are required:

- `lifespan` accepts the server and returns an async context manager yielding shared resources. The resource owner opens and closes them once; a VTAI host may lend resources that its own application lifespan already manages.
- `bind_reports(ctx)` is synchronous and returns a `vt_mcp.reports.ReportReader` for the current tool call. The SDK context is `mcp.server.mcpserver.Context`. Its `request_context.lifespan_context` contains shared resources; for HTTP calls, `request_context.request` contains that request's Starlette `Request`.

The factory calls the binder anew inside each tool invocation. It neither caches readers nor falls back to lifespan resources after a missing or failed binding. Discovery and malformed argument shapes do not invoke it. The existing local wrapper deliberately binds its single configured HTTP client; a remote host must instead read an authenticated actor from the current request and return an adapter bound only to that actor. Never store actors or per-request credentials in shared resources, server attributes or mutable middleware fields.

`ReportReader` has four asynchronous methods, each returning the current structured report dictionary or raising `VTAIError`:

| Method | Argument |
|---|---|
| `get_file_report(file_hash)` | Hash string |
| `get_url_report(url)` | URL string |
| `get_domain_report(domain)` | Domain string |
| `get_ip_report(ip)` | IP string |

The reader invokes VTAI's authorized query service. Authentication, revalidation, quotas, normalization, deadlines and upstream access remain that service's responsibility. A direct reader must not call a privileged upstream client while bypassing the shared admission service. No credential is a tool argument.

The pure helpers in `vt_mcp.reports` give HTTP and direct readers the same presentation:

- `format_file_report(raw, file_hash, *, retrieved_at, forbidden_values=())`
- `format_indicator_report(raw, kind, *, retrieved_at, forbidden_values=())`, with kind `url`, `domain` or `ip`.
- `report_http_error(status, kind, *, retry_after_seconds=None, upstream_access_denied=False)` returns a `VTAIError` for a semantic HTTP status. Kind `file` is accepted as an alias for `hash` when constructing `invalid_hash`.

For both formatters, `raw` is the JSON-compatible object inside the REST `data` envelope. Convert backend Pydantic models using `model_dump(mode="json")` before passing their data. `retrieved_at` is an explicit timezone-aware `datetime`, converted to UTC without reading a clock inside the formatter. Analysis dates remain upstream UTC strings or null; they are never replaced with retrieval time. The functions validate and minimize the data without mutating it, preserve missing legacy file metadata, and reject oversized data instead of truncating it. The size check uses the compact UTF-8 JSON `{"data": raw}` envelope and the same 256 KiB ceiling; HTTP additionally bounds the actual received body.

The optional `forbidden_values` tuple rejects known credentials occurring in report strings. It is a defense at an adapter boundary, not authorization or a way to accept secrets from tool arguments. Backend services must already exclude credentials from reports. Data containing invalid Unicode, invalid dates, inconsistent report links or invalid statistics produces a controlled error.

`VTAIError.error` retains `code`, `message`, `retryable`, `http_status` and `retry_after_seconds`. It is also importable from `vt_mcp.vtai_client` for compatibility. HTTP adapters parse their own transport headers and bodies before using `report_http_error`; direct adapters pass typed service failures. The legacy `upstream_access_denied` flag distinguishes provider failures from rejected VTAI credentials. Retry delays must be nonnegative integers within the existing eight-digit limit. Unknown binder or reader exceptions become a sanitized `unavailable` tool result. Cancellation still propagates.

The VTAI host owns SDK HTTP transport settings, host/origin policy, ASGI mounting and session-manager lifecycle. Its tests must exercise authentication before dispatch, fresh request context, shared quotas, prefixed routes and clean resource shutdown. The [validation matrix](clients.md#validation-levels) distinguishes package protocol tests from service and client workflows.

## Bind analysis lookups

Pass `bind_analyses(ctx)` to expose `get_analysis(analysis_id)`. Without that argument the embedded factory keeps its original four report tools. With the analysis reader it exposes five; the optional submission reader adds two more. The local 0.8 `create_server` supplies all readers and its local-file tool for eight tools.

The synchronous binder returns `vt_mcp.analyses.AnalysisReader`, with one asynchronous method `get_analysis(analysis_id) -> dict`. It resolves the authenticated actor on every call and invokes the shared VTAI analysis service. VTAI owns receipt visibility, revalidation, quota admission and upstream access. That binder grants only selected-analysis reads; submission and receipt tools use the separate binder below.

`format_analysis_response(raw, analysis_id, *, forbidden_values=())` validates the complete JSON-compatible analysis response, including its selected ID, file identity, pending/completed state and evidence. This response does not use the report `data` envelope. For Pydantic models, use `model_dump(mode="json")`. Keep the upstream analysis date and VTAI retrieval time; do not substitute a later file report.

`analysis_http_error(status, *, code=None, retry_after_seconds=None, submission=None)` creates a closed, sanitized `AnalysisError`, a subclass of `VTAIError`. Direct readers map typed backend errors rather than exposing raw messages. As with report readers, unexpected exceptions are sanitized and cancellation propagates. Do not place credentials or actors in the shared lifespan.

## Bind autonomous submission and recovery

`bind_submissions(ctx)` is an optional synchronous per-call binder returning
`vt_mcp.analyses.SubmissionReader`:

```python
async def submit_file(self, sha256: str, content_base64: str) -> dict: ...
async def get_submission(self, sha256: str) -> dict: ...
```

Providing this binder adds `submit_file` and `get_submission` together. Omitting
it preserves the four/five-tool embedding surface. With both optional binders,
the embedded server has seven tools. The local `create_server` additionally
registers `submit_local_file(path, expected_sha256: str | None = None)`, for eight;
that local-path tool is not exposed by the remote embedding factory.

Bind the authenticated actor afresh and invoke VTAI's existing shared submission
and receipt services. Do not use HTTP loopback inside VTAI or bypass its current
identity checks, per-account reservation, quotas, deadlines or analysis ownership.
Submission has no consent argument or interactive confirmation; standard-sharing
authority comes from the assigned task and host policy. This does not change VTAI
rights. No token is a tool argument and no actor belongs in shared lifespan state.

The inline contract accepts at most 24,000,000 decoded bytes and verifies their
SHA-256. The remote host must bound the full JSON request, including base64
expansion; the VTAI 0.8 integration uses 32,065,536 bytes. The local/binary path keeps
32,000,000 bytes. A remote reader must never interpret an input as a path on the
client machine or fetch an arbitrary URL to obtain it.

Return the existing validated submission response states and closed error with
recovery metadata. `exists` is an existing report; `submitted` registers an ID;
`submission_unknown` may remain uncertain. Never automatically retry a POST or
replace selected-analysis evidence with the newest file report. Cancellation must
propagate while retaining any durable recovery state. Version 0.8 binding, limits
and native-client workflows require their own validation; prior five-tool evidence
is historical.
