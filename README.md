# VulnIntel CI Client (v1)

**English** | [한국어](README.ko.md) | [简体中文](README.zh-CN.md)

A thin client that uploads an existing lockfile or SBOM to the VulnIntel server, receives a verdict, and turns that verdict into a CI exit code.
It consists of one GitHub Action (`action.yml`, composite) and one `vulnintel_scan.py` that runs inside it.

> **Container images are not supported. Application dependencies only.**
> VulnIntel does not collect deb/rpm/apk advisories. If you upload an SBOM generated with `syft <image>`, most components
> are classified as unsupported ecosystems, and the client returns `exit 2` (indeterminate) instead of PASS. Upload a source tree (`syft dir:.`) or a lockfile.

- The script uses only the Python 3 standard library (no pip or jq required). It also runs standalone on GitLab CI and Jenkins via `python3 vulnintel_scan.py`.
- Each run uploads exactly one file. For multiple lockfiles, split them into separate steps with a matrix.

## Usage

GitHub Actions:

```yaml
- uses: actions/checkout@v4
- uses: vulnintel/scan-action@v1
  with:
    api-key: ${{ secrets.VULNINTEL_API_KEY }}
    fail-on-kev: true
    max-cvss: 9.0
```

GitLab CI / Jenkins (inputs are CLI arguments or `INPUT_*` environment variables; arguments take precedence):

```bash
curl -fsSLo vulnintel_scan.py https://raw.githubusercontent.com/vulnintel/scan-action/v1/vulnintel_scan.py
export INPUT_API_KEY="$VULNINTEL_API_KEY"     # Pass the key as an environment variable, not an argument (avoids exposure in the process list)
python3 vulnintel_scan.py --file package-lock.json --max-high 5
```

`v1` in the URL is a moving tag. In production pipelines, pin to a release tag (`v1.0.0`) or a commit SHA.

Environment variable names are the input key in uppercase with `-` replaced by `_` (`max-cvss` → `INPUT_MAX_CVSS`).
An environment variable or argument whose value is an empty string is treated as "empty" (e.g., `--max-cvss ""` creates no CVSS rule).

## Inputs

| Key | Default | Description |
|---|---|---|
| `api-key` | Required | `X-Api-Key` header. If missing, `exit 4`. |
| `api-url` | `https://api.vulnintelapp.com/api/v1` | Base URL. Only `https://` is allowed (`http://` only for localhost). Redirects are not followed. |
| `path` | `.` | Auto-discovery root. Checks **top level only** (no recursion into subdirectories). |
| `file` | empty | If set, skips auto-discovery and syft and uploads only this file. |
| `syft` | `auto` | `auto`: if syft is on PATH, uploads the output of `syft dir:<path> -o cyclonedx-json` (on failure, warns and falls back to lockfile discovery). `off`: lockfile discovery only. |
| `scan-depth` | `basic` | `basic` / `precise`. |
| `fail-on` | `policy` | `policy` / `never`. See the suppression mapping below. |
| `fail-on-kev` | `true` | `{type: kev_present, action: fail}` |
| `max-cvss` | `9.0` | `{type: cvss_threshold, min_score: <value>, max_count: 0, action: fail}`. Empty means no rule. Vulnerabilities without a CVSS score are not caught by this rule. |
| `max-critical` | `0` | `{type: severity_threshold, severity: CRITICAL, max_count: <value>, action: fail}`. Catches CRITICAL findings without a CVSS score. Empty means no rule. |
| `max-high` | empty | Same as above, for `HIGH`. |
| `max-unknown` | empty | Same as above, for `UNKNOWN` (severity unknown). Not the same as "unresolved" (impact unknown) described below. |
| `ignore` | empty | `CVE-YYYY-NNNN` / `GHSA-xxxx-xxxx-xxxx` separated by commas, spaces, or newlines → `{type: ignore_list, cve_ids: [...]}`. Invalid format or more than 500 entries → `exit 4` before sending. |
| `policy-json` | empty | Sends the policy JSON as is. When set, all policy keys above are ignored (one-line warning). |
| `unsupported-ratio-threshold` | `0.20` | Coverage gate. If exceeded, `exit 2`. `1.0` effectively disables it. |
| `no-cache` | `false` | Requests a bypass of the server's 24h result cache. |
| `timeout` | `360` | Total wait from upload to verdict (seconds). Values below 310 are raised to 310 with a warning (server job hard timeout is 300 seconds). |
| `sbom-output` | empty | If set, saves the job's CycloneDX SBOM to this path. Failure here does not change the verdict. |

If you turn off all policy keys (`fail-on-kev: false`, `max-cvss` and `max-critical` empty, etc.), the client sends a single non-failing `warn` rule.
This is because the server applies its default policy (fail on KEV or CVSS 9+) when it receives a policy with no rules.

Auto-discovery targets (files the server parsers read): `package-lock.json`, `go.sum`, `requirements.txt`, `Cargo.lock`, `Gemfile.lock`,
`composer.lock`, `packages.lock.json`, CycloneDX/SPDX JSON. If there are zero candidates or two or more, `exit 4`.
`pnpm-lock.yaml`, `yarn.lock`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `pom.xml`, and `build.gradle` have no parser and are excluded from candidates (covered when using syft).

## Outputs

| Output | Content |
|---|---|
| `job-id` | Scan job UUID |
| `passed` | Raw value of `result.policy.passed` (`true`/`false`) |
| `verdict` | `pass` / `policy_failed` / `indeterminate` / `service_error` / `usage_error` — the verdict before `fail-on` suppression |
| `total-packages` / `total-vulnerabilities` / `kev-count` | Values from `result.summary` |
| `unsupported-ratio` | Ratio of unsupported packages (3 decimal places) |
| `data-freshness` | `result.data_freshness.internal_db_synced_at` |

Outputs are written only when `$GITHUB_OUTPUT` exists. The console shows the DB sync time, cache hit status, counts by severity (including `UNKNOWN`), the number of unresolved vulnerabilities,
the full `warnings`, and `rule` / `count` / `samples` for each violated rule. If `$GITHUB_STEP_SUMMARY` exists, the same content is appended to it once.

## Exit codes

| code | Meaning | Condition |
|---|---|---|
| 0 | PASS | Coverage gate passed **and** 0 unresolved **and** `policy.passed == true` |
| 1 | Policy violation | `policy.passed == false` (when 0 unresolved) |
| 2 | Indeterminate | Coverage below threshold · `total_packages == 0` · 1 or more unresolved vulnerabilities (`summary.unknown_vulnerabilities > 0`; still 2 even when mixed with confirmed violations) · job `failed` · upload rejected with 400/413/422 · 429 `upload_budget_exceeded` · 402 `monthly_quota_exceeded` · input over 10MB |
| 3 | Service unreachable | Network failure · 5xx (after 4 upload retries, or 5 consecutive polling failures) · 429 retries exceed the total timeout · total timeout exceeded |
| 4 | Usage error | Missing `api-key` · 401 · input file not found · auto-discovery found 0 or multiple files · invalid input format · `api-url` error (3xx/404) |

Evaluation order is `total_packages == 0` → coverage gate → unresolved gate → `policy.passed`. Even if an earlier stage returns 2,
all policy violations (`rule` / `count` / `samples`) are printed to the console and STEP_SUMMARY first, so confirmed violations are never hidden.
`unsupported_ratio = unsupported / total_packages`. `unsupported` uses `result.summary.unsupported_packages` first;
if that value is missing (older cached result), it sums N from `unsupported_ecosystem: eco(N), eco2(M)` in `warnings`. `missing_version` is not counted
(for packages with an unknown version, the server includes every vulnerability with a matching name in policy evaluation, so they cannot taint a PASS. Versionless entries in an SBOM take the same path.
Name-only entries whose ecosystem cannot be determined are counted as `unsupported`).

**Unresolved gate**: `result.summary.unknown_vulnerabilities` is the number of vulnerabilities where a version is present but range comparison failed, so impact could not be determined
(ones the policy could not evaluate, excluding those suppressed by `ignore` or VEX). If greater than 0, `exit 2` regardless of `policy.passed`.
After review, adding them to `ignore` clears the gate. Results without this field (older cache) skip this gate.

`fail-on` suppression mapping (the `verdict` output keeps the pre-suppression value):

| `fail-on` | 1 | 2 | 3 | 4 |
|---|---|---|---|---|
| `policy` (default) | 1 | 2 | 0 + warning | 4 |
| `never` | 0 + warning | 0 + warning | 0 + warning | 4 |

## Endpoints used

Every request sends `X-Api-Key: <key>` and `User-Agent: vulnintel-scan-action/<version>`.
The server error body is `{"error": <detail>, "message": <detail>, "request_id": ...}`, where `<detail>` is a string or a `{error: <code>, ...}` object
(e.g., `{"error": {"error": "upload_budget_exceeded", "retry_after_seconds": 3600}, ...}`). The client handles both this format and a top-level `detail` (422 / legacy format),
and prints the raw body if parsing fails.

### `POST /scan/jobs`

`multipart/form-data`: `file` (required), `kind` (`sbom`|`lockfile`; `sbom` for CycloneDX/SPDX JSON), `policy` (JSON string), `scan_depth`, `no_cache`.

| Response | Client behavior |
|---|---|
| `202 {job_id, status, status_url}` | If `status == "completed"`, it is a cache hit — fetches the result once without polling |
| Network error · 5xx | Retries up to 4 times with 1→2→4→8 second backoff; `exit 3` when exhausted |
| `429` `rate_limit_exceeded` · `active_job_limit_exceeded` | Waits for `Retry-After` (or `detail.retry_after_seconds` if absent), then retries, within the total timeout |
| `429` `upload_budget_exceeded` | `exit 2` without retry |
| `402` `monthly_quota_exceeded` | `exit 2` without retry or wait; prints `plan` / `limit` / `used` / `reset_at` / `upgrade_url` |
| `400` | `exit 2`; prints the full policy JSON that was sent |
| `413` · `422` · other 4xx | `exit 2` |
| `401` · `404` · `405` · 3xx | `exit 4` (check the key or `api-url`) |

### `GET /scan/jobs/{job_id}`

Polls every 3 seconds. Stops when `status` becomes `completed`/`failed`.
Network errors and 5xx are deferred to the next cycle; 5 in a row → `exit 3`. On `429`, waits for `Retry-After`. On `failed`, prints `error.code` and `error.message` and returns `exit 2`.
Fields used for the verdict: `result.summary.{total_packages, total_vulnerabilities, kev_count, by_severity, unsupported_packages, unknown_vulnerabilities}`,
`result.policy.{passed, violations[].{rule, count, samples}}`, `result.warnings[]`, `result.data_freshness.internal_db_synced_at`.

### `GET /scan/jobs/{job_id}/sbom`

When `sbom-output` is set, called once to save the CycloneDX JSON.

## Security

- **Version pinning**: `@v1` moves with new releases. To reduce supply chain risk, pin to a commit SHA.
  ```yaml
  - uses: vulnintel/scan-action@<40-char commit SHA>  # v1.0.0
  ```
- **API key**: Pass it only through GitHub Secrets, such as `secrets.VULNINTEL_API_KEY`. Never write it in plain text in a workflow file.
  On GitHub Actions the client applies `::add-mask::` to the key, and on other CI systems it also masks the key as `***` in output.
- **Data sent**: Only the contents of the one selected lockfile or SBOM file (the syft-generated SBOM when using syft) and the policy settings.
  Source code is not sent.
- **Transport**: Uses `https://` only (except localhost), verifies TLS certificates, and does not follow redirects (so the key cannot leak to another host).
- **Output handling**: Strings from the server or lockfile are printed inside a `::stop-commands::` block so they are not executed as workflow commands.
- To report a vulnerability, follow [SECURITY.md](SECURITY.md).

## Tests

```bash
python3 -m pip install pytest && python3 -m pytest tests -q
```

Tests spin up a fake server (`http.server`) and verify behavior over real HTTP paths. Only the tests use pytest; the script itself uses only the standard library.
