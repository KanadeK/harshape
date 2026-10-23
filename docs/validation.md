# Validation record — 0.1.0

Executed on Windows/Python 3.13.16 on 2026-10-23:

- 30 discovered tests: 29 passed, with one POSIX-only permission test skipped on Windows. The permission test executes on Linux/macOS CI.
- Statement coverage: 97.77%; Ruff lint and formatting passed.
- Unit/integration coverage includes canaries in standard and unknown fields, nonmutation, URL/parent/origin grouping, fresh random keys, opaque schemes, timestamp offsets, status/numeric validation, explicit nesting limits, UTF-8 BOM, no-clobber output, write cleanup, source-change detection and CLI behavior.
- Built the wheel/source archive, installed the wheel in a fresh virtual environment outside the checkout without index access or dependencies, ran installed help/version and the privacy/performance demo, then uninstalled it.
- An additional independent experiment projected 200 entries carrying 200 distinct synthetic canaries, confirmed all original canaries absent and source unchanged, and validated that output plus an empty capture against the local, pinned [har-schema reference](https://github.com/ahmadnassri/har-schema/tree/c01b2e49edc33cd2cd22c980c57681be57bbb1f6) using jsonschema Draft6Validator. The ISC reference license was preserved with the local research copy; no reference schema or validator is bundled in this project. This checks structure against a permissive reference, not statistical anonymity or browser import behavior.
- Runtime dependency metadata is empty and licensing is MIT. Publishable-source token/private-key/machine-path patterns were checked; this limited scan does not prove arbitrary private information is absent.

Independent review reconstructed the full output allowlist rather than checking only recognized secret names. It examined ephemeral HMAC scope, query/userinfo removal, numeric/string boundaries, fixed timestamp anchoring, resource limits and exclusive output ownership. Review also tightened negative phase values to nonnegative or exactly -1, checked explicit port 0 grouping, added the fixed JSON nesting bound, and aligned UTF-8 BOM behavior with the HAR reference. A synthetic privacy-test constant was marked as a deliberate canary for Ruff; no real credential was introduced.

The six-job CI matrix covers Linux/macOS/Windows on Python 3.11/3.13. Check the README badge for the exact remote result. No browser/viewer import testing, replay, general HAR validator, total-RSS cap, anonymous-sharing guarantee, snapshot consistency or secure-erasure guarantee is claimed.
