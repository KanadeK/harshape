# HarShape

[![CI](https://github.com/KanadeK/harshape/actions/workflows/ci.yml/badge.svg)](https://github.com/KanadeK/harshape/actions/workflows/ci.yml)
[简体中文](README.zh-CN.md) · [MIT](LICENSE)

Create a **performance-only HAR skeleton** before sharing a network capture. Keep timings, statuses, byte sizes and repeated-endpoint groups; replace hosts and path components with file-local keyed pseudonyms, shift timestamps, and discard headers, cookies, bodies and unknown extensions.

Useful when a support engineer needs the shape of a slow waterfall but does not need account URLs, payloads or browser identity. All processing is local. No API, browser extension, server or runtime dependency is needed.

## Install, run, remove

Python 3.11+ is required. From this repository:

```console
python -m venv .venv
# Activate .venv, then:
python -m pip install .
harshape original.har --output share.har
python examples/demo.py
```

Activate in PowerShell with `.venv\Scripts\Activate.ps1`, or in POSIX shells with `. .venv/bin/activate`. Alternatively download `harshape-0.1.0-py3-none-any.whl` from [Releases](https://github.com/KanadeK/harshape/releases) and run `python -m pip install ./harshape-0.1.0-py3-none-any.whl`. Source builds may download setuptools. This project is not claimed to be on PyPI.

`share.har` must be a new path; HarShape never overwrites an existing file, including the original. Exit 0 means a complete projection was written. Exit 2 means invalid input, a resource limit or an I/O error. Console JSON reports entry/origin/endpoint counts, status counts and output size without source names or URLs. `python -m harshape` is equivalent.

Uninstall with `python -m pip uninstall harshape`. There is no tool configuration or cache to clean. Remove original/projected captures and unused virtual environments yourself when appropriate. The example generates synthetic input in a temporary directory, verifies removal of its canaries and cleans up.

## Exact projection policy

The output is rebuilt from a fixed allowlist. The original object is never copied and edited in place.

| Original information | Result |
|---|---|
| HTTP(S) origin (scheme/host/port) | A keyed `h-….invalid` hostname; all output URLs use HTTPS |
| HTTP(S) path | Each nonempty slash-separated segment is a keyed `p-…` token, scoped to its origin and parent path; empty separators stay empty |
| Query, fragment, URL username/password | Omitted, including parameter names |
| Other absolute schemes, including data/blob/file/ws | Opaque keyed URL under a synthetic `.invalid` host; original scheme/payload/path is not copied |
| Start timestamps | Earliest entry becomes `2000-01-01T00:00:00Z`; relative offsets survive to microsecond precision; entry order stays unchanged |
| Total and phase durations, status, byte sizes, optional compression | Validated finite numeric metadata is retained |
| Method, HTTP version, MIME type | Only fixed standard allowlisted values survive; others become `OTHER`, `unknown` or `application/octet-stream`; MIME parameters are dropped |
| Headers, cookies, query arrays | Empty arrays |
| Request body, response body text/encoding, redirect URL | Body fields omitted; redirect URL empty |
| Pages, browser/creator identity, IP, connection, comments, initiators, cache details, vendor/future extensions | Omitted or empty; creator becomes HarShape |

HMAC-SHA256 tokens use a fresh random 256-bit key for each projection and retain 128 bits per token. The key and mapping are never written. Identical HTTP(S) endpoints with different query values group together inside one output. New projections receive unrelated pseudonyms; there is no reproducible-key option or reversible mapping.

For example, two requests to `https://account.example/api/users/123?token=…` remain the same synthetic endpoint in the output, while their host, segment text and query values disappear. Common prefixes remain recognizable as common prefixes without retaining their names.

## Security boundary and limits

This is a deliberately reduced derivative for performance discussion. It cannot replay requests, inspect payloads or debug authentication/redirect/header behavior. **Performance metadata can still identify an application or person**: timing, lengths, counts, statuses and graph structure remain. Review the result before sharing. Keyed pseudonyms do not establish statistical anonymity, and the tool does not promise to detect every possible encoding of private information inside retained numeric metadata.

Accepted input is a stable, UTF-8 HAR 1.2 JSON file; a UTF-8 BOM is supported. Required entry fields are `startedDateTime` with timezone, finite nonnegative `time`, `request.url`, `response.status`, `response.content.size`, and a timings object. Status must be 0 (aborted) or 100–599; byte sizes must be integers; optional header/body sizes and missing timing phases become `-1`. Times are milliseconds and must be nonnegative up to 10¹², or exactly -1 for an unknown phase (total duration must be nonnegative). Bytes are at most 2⁵³−1. Original total/phase inconsistencies are not repaired.

- Default input byte cap: 32 MiB; `--max-input-bytes N` can set 1 byte–256 MiB.
- At most 10,000 entries, 8,192 characters per URL, 128 slash-separated path fields (including empty fields), and 200,000 aggregate URL fields. A capture can span at most 366 days.
- Output cap: 64 MiB, checked after serialization. The JSON document, projected objects and serialized output are held in memory; these caps are **not a total-memory limit**.
- Duplicate JSON object keys, nesting beyond 128 containers, nonstandard NaN/Infinity, unsupported numeric values and malformed required fields fail the entire operation. Unknown fields are dropped, not sanitized selectively.
- New output requests mode 0600 on POSIX. Windows inherits the destination ACL. Ordinary write failures remove only the newly created output; forced termination can leave a partial file. No encryption, live-file snapshot, hostile-filesystem sandbox or power-loss guarantee is provided.

A reference-schema structural check is recorded in [validation](docs/validation.md). Browser/viewer import compatibility has not been tested; use a viewer that accepts reduced HAR 1.2 or process the output as JSON. No universal viewer support is claimed.

## Development and alternatives

[CONTRIBUTING.md](CONTRIBUTING.md) has reproducible lint, unit/integration, demo and build commands. [Design](docs/design.md) explains the acceptance boundary and research.

[Cloudflare har-sanitizer](https://github.com/cloudflare/har-sanitizer) and [har-anonymizer](https://github.com/ErikApption/har-anonymizer) retain more information for other support/debugging workflows. HarShape instead rebuilds a performance projection and pseudonymizes **every** HTTP(S) hostname/path segment. It intentionally trades debugging detail for a smaller sharing surface; prefer those tools when you need selective retention.
