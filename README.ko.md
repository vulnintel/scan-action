# VulnIntel CI 클라이언트 (v1)

[English](README.md) | **한국어** | [简体中文](README.zh-CN.md)

이미 있는 lockfile 또는 SBOM을 VulnIntel 서버에 올려 판정을 받고, 그 판정을 CI exit code로 바꾸는 얇은 클라이언트다.
GitHub Action(`action.yml`, composite) 1개와 그 안에서 도는 `vulnintel_scan.py` 1개로 구성된다.

> **컨테이너 이미지는 지원하지 않는다. 애플리케이션 의존성 전용이다.**
> VulnIntel은 deb/rpm/apk advisory를 수집하지 않는다. `syft <image>`로 만든 SBOM을 올리면 대부분의 컴포넌트가
> 평가 불가 생태계로 분류되고, 클라이언트는 PASS 대신 `exit 2`(판정 불가)를 낸다. 소스 트리(`syft dir:.`)나 lockfile을 올린다.

- 스크립트는 Python 3 표준 라이브러리만 쓴다(pip·jq 불필요). GitLab CI·Jenkins에서도 `python3 vulnintel_scan.py`로 단독 실행된다.
- 실행 1회에 파일 1개만 올린다. 여러 lockfile은 matrix로 스텝을 나눠 돌린다.

## 사용 예

GitHub Actions:

```yaml
- uses: actions/checkout@v4
- uses: vulnintel/scan-action@v1
  with:
    api-key: ${{ secrets.VULNINTEL_API_KEY }}
    fail-on-kev: true
    max-cvss: 9.0
```

GitLab CI / Jenkins (입력은 CLI 인자 또는 `INPUT_*` 환경변수, 인자가 우선):

```bash
curl -fsSLo vulnintel_scan.py https://raw.githubusercontent.com/vulnintel/scan-action/v1/vulnintel_scan.py
export INPUT_API_KEY="$VULNINTEL_API_KEY"     # 키는 인자보다 환경변수로 넘긴다(프로세스 목록 노출 방지)
python3 vulnintel_scan.py --file package-lock.json --max-high 5
```

URL의 `v1`은 움직이는 태그다. 운영 파이프라인에서는 릴리스 태그(`v1.0.0`)나 커밋 SHA로 고정한다.

환경변수 이름은 입력 키를 대문자로 바꾸고 `-`를 `_`로 바꾼 것이다(`max-cvss` → `INPUT_MAX_CVSS`).
값이 빈 문자열인 환경변수/인자는 "빈값"으로 취급한다(예: `--max-cvss ""`는 CVSS 규칙을 만들지 않는다).

## 입력

| 키 | 기본값 | 의미 |
|---|---|---|
| `api-key` | 필수 | `X-Api-Key` 헤더. 없으면 `exit 4`. |
| `api-url` | `https://api.vulnintelapp.com/api/v1` | 베이스 URL. `https://`만 허용(로컬호스트만 `http://` 허용). 리다이렉트는 따르지 않는다. |
| `path` | `.` | 자동탐색 루트. **직하위만** 본다(하위 디렉터리 재귀 없음). |
| `file` | 빈값 | 지정 시 자동탐색·syft를 건너뛰고 이 파일만 올린다. |
| `syft` | `auto` | `auto`: PATH에 syft가 있으면 `syft dir:<path> -o cyclonedx-json` 결과를 올린다(실패 시 경고 후 lockfile 탐색). `off`: lockfile 탐색만. |
| `scan-depth` | `basic` | `basic` / `precise`. |
| `fail-on` | `policy` | `policy` / `never`. 아래 억제 매핑. |
| `fail-on-kev` | `true` | `{type: kev_present, action: fail}` |
| `max-cvss` | `9.0` | `{type: cvss_threshold, min_score: <값>, max_count: 0, action: fail}`. 빈값이면 규칙 없음. CVSS가 없는 취약점은 이 규칙에 걸리지 않는다. |
| `max-critical` | `0` | `{type: severity_threshold, severity: CRITICAL, max_count: <값>, action: fail}`. CVSS 없는 CRITICAL을 막는다. 빈값이면 규칙 없음. |
| `max-high` | 빈값 | 위와 같음, `HIGH`. |
| `max-unknown` | 빈값 | 위와 같음, `UNKNOWN`(심각도 미상). 아래 "미확정 게이트"(영향 여부 미상)와 다른 개념이다. |
| `ignore` | 빈값 | 콤마/공백/개행 구분 `CVE-YYYY-NNNN`·`GHSA-xxxx-xxxx-xxxx` → `{type: ignore_list, cve_ids: [...]}`. 형식 위반·500개 초과는 전송 전에 `exit 4`. |
| `policy-json` | 빈값 | 정책 JSON을 그대로 전송. 설정 시 위 정책 키 전부 무시(경고 1줄). |
| `unsupported-ratio-threshold` | `0.20` | 커버리지 게이트. 초과 시 `exit 2`. `1.0`이면 사실상 비활성. |
| `no-cache` | `false` | 서버 24h 결과 캐시 우회 요청. |
| `timeout` | `360` | 업로드~판정 총 대기(초). 310 미만은 310으로 올리고 경고(서버 job 하드 타임아웃 300초). |
| `sbom-output` | 빈값 | 지정 시 job의 CycloneDX SBOM을 이 경로에 저장. 실패해도 판정은 바뀌지 않는다. |

정책 키를 전부 끄면(`fail-on-kev: false`, `max-cvss`·`max-critical` 빈값 등) 클라이언트는 실패하지 않는 `warn` 규칙 1개를 보낸다.
서버는 규칙이 빈 정책을 받으면 기본 정책(KEV·CVSS 9+ 실패)을 적용하기 때문이다.

자동탐색 대상(서버 파서가 읽는 파일): `package-lock.json`, `go.sum`, `requirements.txt`, `Cargo.lock`, `Gemfile.lock`,
`composer.lock`, `packages.lock.json`, CycloneDX/SPDX JSON. 후보가 0개 또는 2개 이상이면 `exit 4`.
`pnpm-lock.yaml`·`yarn.lock`·`poetry.lock`·`uv.lock`·`Pipfile.lock`·`pom.xml`·`build.gradle`은 파서가 없어 후보에서 빠진다(syft 사용 시 커버됨).

## 출력

| 출력 | 내용 |
|---|---|
| `job-id` | 스캔 job UUID |
| `passed` | `result.policy.passed` 원값(`true`/`false`) |
| `verdict` | `pass` / `policy_failed` / `indeterminate` / `service_error` / `usage_error` — `fail-on` 억제 전 판정 |
| `total-packages` / `total-vulnerabilities` / `kev-count` | `result.summary` 값 |
| `unsupported-ratio` | 평가 불가 패키지 비율(소수 3자리) |
| `data-freshness` | `result.data_freshness.internal_db_synced_at` |

출력은 `$GITHUB_OUTPUT`이 있을 때만 기록한다. 콘솔에는 DB 동기 시각, 캐시 적중 여부, 심각도별 건수(`UNKNOWN` 포함), 미확정 취약점 수,
`warnings` 전문, 위반 규칙별 `rule`·`count`·`samples`, 정책 위반 시 업그레이드 안내를 출력하고, `$GITHUB_STEP_SUMMARY`가 있으면 같은 내용을 1회 append한다.

업그레이드 안내는 보낸 정책의 `fail` 규칙을 위반한 취약점을 패키지별로 묶어 한 줄씩 출력한다(`samples`는 규칙당 최대 5개라 클라이언트가 `result.packages`에 규칙을 다시 적용한다).
권장 버전은 그 취약점들의 수정 버전 중 최댓값이며, 모든 값이 점으로 구분된 숫자일 때만 숫자로 비교하고 아니면 ID별 수정 버전을 나열한다.
수정 버전이 없는 취약점은 `no fixed version yet`로 표시한다. 최대 20개 패키지까지 출력하고 나머지는 `... and N more package(s)`로 줄인다. 이 필드가 없는 결과는 안내를 출력하지 않는다.

```text
Policy: FAILED
  - rule=cvss_threshold count=3 samples=CVE-2025-64459, CVE-2024-53908, CVE-2026-4277
Fix by upgrading:
  django 4.2.16 → upgrade to >= 4.2.30 (CVE-2024-53908, CVE-2025-64459, CVE-2026-4277)
```

## exit code

| code | 의미 | 조건 |
|---|---|---|
| 0 | PASS | 커버리지 게이트 통과 **그리고** 미확정 0 **그리고** `policy.passed == true` |
| 1 | 정책 위반 | `policy.passed == false` (미확정 0일 때) |
| 2 | 판정 불가 | 커버리지 미달 · `total_packages == 0` · 미확정 취약점 1건 이상(`summary.unknown_vulnerabilities > 0`, 확정 위반과 섞여도 2) · job `failed` · 업로드 거부 400/413/422 · 429 `upload_budget_exceeded` · 402 `monthly_quota_exceeded` · 10MB 초과 입력 |
| 3 | 서비스 도달 실패 | 네트워크 실패 · 5xx(업로드 4회 재시도 후, 폴링 연속 5회 실패) · 429 재시도가 총 timeout을 넘김 · 총 timeout 초과 |
| 4 | 사용법 오류 | `api-key` 없음 · 401 · 입력 파일 없음 · 자동탐색 0개/다중 · 입력값 형식 위반 · `api-url` 오류(3xx/404) |

평가 순서는 `total_packages == 0` → 커버리지 게이트 → 미확정 게이트 → `policy.passed`다. 앞 단계에서 2가 나도
콘솔·STEP_SUMMARY에는 그 전에 정책 위반 내역(`rule`·`count`·`samples`)을 전부 출력하므로 확정 위반이 가려지지 않는다.
`unsupported_ratio = unsupported / total_packages`이며 `unsupported`는 `result.summary.unsupported_packages`를 우선 쓰고,
값이 없으면(구 캐시 결과) `warnings`의 `unsupported_ecosystem: eco(N), eco2(M)`에서 N을 합산한다. `missing_version`은 세지 않는다
(버전 미상 패키지는 서버가 이름이 같은 취약점을 전부 정책 평가에 넣으므로 PASS를 오염시키지 않는다. SBOM의 버전 없는 항목도 같은 경로다.
생태계를 알 수 없는 이름만 있는 항목은 `unsupported`로 집계된다).

**미확정 게이트**: `result.summary.unknown_vulnerabilities`는 버전이 있는데 범위 비교가 안 돼 영향 여부를 확정하지 못한 취약점 수다
(정책이 평가하지 못한 것, `ignore`·VEX로 억제한 건 제외). 0보다 크면 `policy.passed`와 무관하게 `exit 2`.
검토 후 `ignore`에 넣으면 풀린다. 필드가 없는(구 캐시) 결과는 이 게이트를 건너뛴다.

`fail-on` 억제 매핑 (`verdict` 출력은 억제 전 값을 유지한다):

| `fail-on` | 1 | 2 | 3 | 4 |
|---|---|---|---|---|
| `policy` (기본) | 1 | 2 | 0 + 경고 | 4 |
| `never` | 0 + 경고 | 0 + 경고 | 0 + 경고 | 4 |

`fail-on: policy`에서도 exit 3을 0으로 바꾸는 것은 의도된 동작이다. VulnIntel 장애로 고객의 빌드·배포를 막지 않으며(fail-open), 판정이 없다는 사실은 경고와 `verdict` 출력(`service_error`)으로 남는다.
VulnIntel에 도달하지 못했을 때 job을 실패시키려면 다음 스텝에서 `steps.<id>.outputs.verdict == 'service_error'`를 검사한다:

```yaml
- uses: vulnintel/scan-action@v1
  id: vulnintel
  with:
    api-key: ${{ secrets.VULNINTEL_API_KEY }}
- if: steps.vulnintel.outputs.verdict == 'service_error'
  run: exit 1
```

## 사용하는 엔드포인트

모든 요청에 `X-Api-Key: <키>`, `User-Agent: vulnintel-scan-action/<버전>`을 보낸다.
서버 에러 바디는 `{"error": <detail>, "message": <detail>, "request_id": ...}`이고 `<detail>`은 문자열 또는 `{error: <코드>, ...}` 객체다
(예: `{"error": {"error": "upload_budget_exceeded", "retry_after_seconds": 3600}, ...}`). 클라이언트는 이 형식과 최상위 `detail`(422·구 형식)을
모두 처리하고, 파싱이 안 되면 원문을 출력한다.

### `POST /scan/jobs`

`multipart/form-data`: `file`(필수), `kind`(`sbom`|`lockfile`, CycloneDX/SPDX JSON이면 `sbom`), `policy`(JSON 문자열), `scan_depth`, `no_cache`.

| 응답 | 클라이언트 동작 |
|---|---|
| `202 {job_id, status, status_url}` | `status == "completed"`면 캐시 적중 — 폴링 없이 결과 1회 조회 |
| 네트워크 오류 · 5xx | 1→2→4→8초 백오프로 최대 4회 재시도, 소진 시 `exit 3` |
| `429` `rate_limit_exceeded` · `active_job_limit_exceeded` | `Retry-After`(없으면 `detail.retry_after_seconds`)만큼 대기 후 재시도, 총 timeout 내 |
| `429` `upload_budget_exceeded` | 재시도 없이 `exit 2` |
| `402` `monthly_quota_exceeded` | 재시도·대기 없이 `exit 2`, `plan`·`limit`·`used`·`reset_at`·`upgrade_url` 출력 |
| `400` | `exit 2`, 전송한 정책 JSON 전문을 출력 |
| `413` · `422` · 기타 4xx | `exit 2` |
| `401` · `404` · `405` · 3xx | `exit 4` (키 또는 `api-url` 확인) |

### `GET /scan/jobs/{job_id}`

3초 간격으로 폴링한다. `status`가 `completed`/`failed`가 되면 종료.
네트워크 오류·5xx는 다음 주기로 넘기고 연속 5회면 `exit 3`. `429`는 `Retry-After`만큼 대기. `failed`면 `error.code`·`error.message`를 출력하고 `exit 2`.
판정에 쓰는 필드: `result.summary.{total_packages, total_vulnerabilities, kev_count, by_severity, unsupported_packages, unknown_vulnerabilities}`,
`result.policy.{passed, violations[].{rule, count, samples}}`, `result.warnings[]`, `result.data_freshness.internal_db_synced_at`.
업그레이드 안내에 쓰는 필드: `result.packages[].{purl, name, version, vulnerabilities[].{id, aliases, kev, severity, cvss.score, fixed_versions}}`.

### `GET /scan/jobs/{job_id}/sbom`

`sbom-output` 지정 시 1회 호출해 CycloneDX JSON을 저장한다.

## 보안

- **버전 고정**: `@v1`은 새 릴리스를 따라 움직인다. 공급망 위험을 줄이려면 커밋 SHA로 고정한다.
  ```yaml
  - uses: vulnintel/scan-action@<40자리 커밋 SHA>  # v1.0.0
  ```
- **API 키**: `secrets.VULNINTEL_API_KEY` 같은 GitHub Secrets로만 넘긴다. 워크플로 파일에 평문으로 쓰지 않는다.
  클라이언트는 GitHub Actions에서 키에 `::add-mask::`를 적용하고, 다른 CI에서도 출력 속 키를 `***`로 가린다.
- **보내는 데이터**: 선택된 lockfile 또는 SBOM 파일 1개의 내용(syft 사용 시 syft가 만든 SBOM)과 정책 설정만 보낸다.
  소스 코드는 보내지 않는다.
- **전송**: `https://`만 쓰고(로컬호스트 제외) TLS 인증서를 검증하며, 리다이렉트를 따르지 않는다(키가 다른 호스트로 새지 않게).
- **출력 처리**: 서버·lockfile에서 온 문자열은 `::stop-commands::` 구간 안에서 출력해 워크플로 명령으로 실행되지 않게 한다.
- 취약점 제보는 [SECURITY.md](SECURITY.md)를 따른다.

## 테스트

```bash
python3 -m pip install pytest && python3 -m pytest tests -q
```

가짜 서버(`http.server`)를 띄워 실제 HTTP 경로로 검증한다. 테스트만 pytest를 쓰고 스크립트 본체는 표준 라이브러리만 쓴다.
