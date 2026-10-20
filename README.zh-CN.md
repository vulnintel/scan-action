# VulnIntel CI 客户端 (v1)

[English](README.md) | [한국어](README.ko.md) | **简体中文**

一个轻量客户端：将现有的 lockfile 或 SBOM 上传到 VulnIntel 服务器获取判定结果，并将该判定转换为 CI 退出码（exit code）。
由 1 个 GitHub Action（`action.yml`，composite）和在其中运行的 1 个 `vulnintel_scan.py` 组成。

> **不支持容器镜像，仅适用于应用依赖。**
> VulnIntel 不收集 deb/rpm/apk 安全公告。如果上传用 `syft <image>` 生成的 SBOM，大部分组件会
> 被归类为无法评估的生态系统，客户端会返回 `exit 2`（无法判定）而不是 PASS。请上传源码树（`syft dir:.`）或 lockfile。

- 脚本仅使用 Python 3 标准库（无需 pip、jq）。在 GitLab CI、Jenkins 中也可以通过 `python3 vulnintel_scan.py` 独立运行。
- 每次运行只上传 1 个文件。多个 lockfile 请用 matrix 拆分为多个步骤运行。

## 使用示例

GitHub Actions：

```yaml
- uses: actions/checkout@v4
- uses: vulnintel/scan-action@v1
  with:
    api-key: ${{ secrets.VULNINTEL_API_KEY }}
    fail-on-kev: true
    max-cvss: 9.0
```

GitLab CI / Jenkins（输入通过 CLI 参数或 `INPUT_*` 环境变量传入，参数优先）：

```bash
curl -fsSLo vulnintel_scan.py https://raw.githubusercontent.com/vulnintel/scan-action/v1/vulnintel_scan.py
export INPUT_API_KEY="$VULNINTEL_API_KEY"     # 密钥通过环境变量而不是参数传入（避免在进程列表中暴露）
python3 vulnintel_scan.py --file package-lock.json --max-high 5
```

URL 中的 `v1` 是移动标签。生产流水线中请固定到发布标签（`v1.0.0`）或提交 SHA。

环境变量名是将输入键转为大写并把 `-` 替换为 `_`（`max-cvss` → `INPUT_MAX_CVSS`）。
值为空字符串的环境变量/参数视为“空值”（例如 `--max-cvss ""` 不会创建 CVSS 规则）。

## 输入

| 键 | 默认值 | 说明 |
|---|---|---|
| `api-key` | 必填 | `X-Api-Key` 请求头。缺失时 `exit 4`。 |
| `api-url` | `https://api.vulnintelapp.com/api/v1` | 基础 URL。仅允许 `https://`（仅 localhost 允许 `http://`）。不跟随重定向。 |
| `path` | `.` | 自动发现的根目录。**只查看直接下级**（不递归子目录）。 |
| `file` | 空值 | 指定后跳过自动发现和 syft，只上传该文件。 |
| `syft` | `auto` | `auto`：PATH 中有 syft 时，上传 `syft dir:<path> -o cyclonedx-json` 的结果（失败时警告并改为查找 lockfile）。`off`：仅查找 lockfile。 |
| `scan-depth` | `basic` | `basic` / `precise`。 |
| `fail-on` | `policy` | `policy` / `never`。见下方抑制映射。 |
| `fail-on-kev` | `true` | `{type: kev_present, action: fail}` |
| `max-cvss` | `9.0` | `{type: cvss_threshold, min_score: <值>, max_count: 0, action: fail}`。空值表示不创建规则。没有 CVSS 的漏洞不会触发此规则。 |
| `max-critical` | `0` | `{type: severity_threshold, severity: CRITICAL, max_count: <值>, action: fail}`。用于拦截没有 CVSS 的 CRITICAL。空值表示不创建规则。 |
| `max-high` | 空值 | 同上，对应 `HIGH`。 |
| `max-unknown` | 空值 | 同上，对应 `UNKNOWN`（严重程度未知）。与下文的“未确定判定”（是否受影响未知）是不同概念。 |
| `ignore` | 空值 | 以逗号/空格/换行分隔的 `CVE-YYYY-NNNN`、`GHSA-xxxx-xxxx-xxxx` → `{type: ignore_list, cve_ids: [...]}`。格式错误或超过 500 个时，在发送前 `exit 4`。 |
| `policy-json` | 空值 | 原样发送策略 JSON。设置后忽略上述所有策略键（输出 1 行警告）。 |
| `unsupported-ratio-threshold` | `0.20` | 覆盖率门禁。超过时 `exit 2`。设为 `1.0` 实际上等于禁用。 |
| `no-cache` | `false` | 请求绕过服务器 24h 结果缓存。 |
| `timeout` | `360` | 从上传到判定的总等待时间（秒）。小于 310 时提升为 310 并警告（服务器 job 硬超时为 300 秒）。 |
| `sbom-output` | 空值 | 指定后将 job 的 CycloneDX SBOM 保存到该路径。保存失败不影响判定。 |

如果关闭所有策略键（`fail-on-kev: false`、`max-cvss` 和 `max-critical` 为空值等），客户端会发送 1 条不会导致失败的 `warn` 规则。
这是因为服务器收到规则为空的策略时会应用默认策略（KEV、CVSS 9+ 判为失败）。

自动发现目标（服务器解析器可读取的文件）：`package-lock.json`、`go.sum`、`requirements.txt`、`Cargo.lock`、`Gemfile.lock`、
`composer.lock`、`packages.lock.json`、CycloneDX/SPDX JSON。候选为 0 个或 2 个以上时 `exit 4`。
`pnpm-lock.yaml`、`yarn.lock`、`poetry.lock`、`uv.lock`、`Pipfile.lock`、`pom.xml`、`build.gradle` 没有解析器，不在候选之列（使用 syft 时可覆盖）。

## 输出

| 输出 | 内容 |
|---|---|
| `job-id` | 扫描 job UUID |
| `passed` | `result.policy.passed` 原始值（`true`/`false`） |
| `verdict` | `pass` / `policy_failed` / `indeterminate` / `service_error` / `usage_error` —— `fail-on` 抑制前的判定 |
| `total-packages` / `total-vulnerabilities` / `kev-count` | `result.summary` 中的值 |
| `unsupported-ratio` | 无法评估的包所占比例（保留 3 位小数） |
| `data-freshness` | `result.data_freshness.internal_db_synced_at` |

仅当存在 `$GITHUB_OUTPUT` 时才写入输出。控制台会打印 DB 同步时间、是否命中缓存、按严重程度统计的数量（含 `UNKNOWN`）、未确定漏洞数、
`warnings` 全文，以及每条违规规则的 `rule`、`count`、`samples`；如果存在 `$GITHUB_STEP_SUMMARY`，会将相同内容追加 1 次。

## 退出码

| code | 含义 | 条件 |
|---|---|---|
| 0 | PASS | 通过覆盖率门禁 **且** 未确定为 0 **且** `policy.passed == true` |
| 1 | 策略违规 | `policy.passed == false`（未确定为 0 时） |
| 2 | 无法判定 | 覆盖率不足 · `total_packages == 0` · 未确定漏洞 1 个以上（`summary.unknown_vulnerabilities > 0`，即使与已确认违规同时存在也返回 2） · job `failed` · 上传被拒 400/413/422 · 429 `upload_budget_exceeded` · 402 `monthly_quota_exceeded` · 输入超过 10MB |
| 3 | 无法连接服务 | 网络故障 · 5xx（上传重试 4 次后、轮询连续 5 次失败） · 429 重试超出总 timeout · 超出总 timeout |
| 4 | 用法错误 | 缺少 `api-key` · 401 · 输入文件不存在 · 自动发现 0 个/多个 · 输入值格式错误 · `api-url` 错误（3xx/404） |

评估顺序为 `total_packages == 0` → 覆盖率门禁 → 未确定门禁 → `policy.passed`。即使前面的阶段返回 2，
也会先在控制台和 STEP_SUMMARY 中完整打印策略违规明细（`rule`、`count`、`samples`），因此已确认的违规不会被掩盖。
`unsupported_ratio = unsupported / total_packages`，其中 `unsupported` 优先使用 `result.summary.unsupported_packages`，
若该值不存在（旧缓存结果），则从 `warnings` 的 `unsupported_ecosystem: eco(N), eco2(M)` 中累加 N。不统计 `missing_version`
（对于版本未知的包，服务器会把同名漏洞全部纳入策略评估，因此不会污染 PASS。SBOM 中没有版本的条目也走同样的路径。
无法确定生态系统、只有名称的条目计入 `unsupported`）。

**未确定门禁**：`result.summary.unknown_vulnerabilities` 是有版本但无法进行范围比较、因而无法确定是否受影响的漏洞数
（即策略无法评估的部分，不含通过 `ignore`、VEX 抑制的）。大于 0 时，无论 `policy.passed` 如何都 `exit 2`。
审查后将其加入 `ignore` 即可解除。没有该字段的（旧缓存）结果会跳过此门禁。

`fail-on` 抑制映射（`verdict` 输出保留抑制前的值）：

| `fail-on` | 1 | 2 | 3 | 4 |
|---|---|---|---|---|
| `policy`（默认） | 1 | 2 | 0 + 警告 | 4 |
| `never` | 0 + 警告 | 0 + 警告 | 0 + 警告 | 4 |

## 使用的端点

所有请求都会发送 `X-Api-Key: <密钥>`、`User-Agent: vulnintel-scan-action/<版本>`。
服务器错误响应体为 `{"error": <detail>, "message": <detail>, "request_id": ...}`，`<detail>` 为字符串或 `{error: <代码>, ...}` 对象
（例如 `{"error": {"error": "upload_budget_exceeded", "retry_after_seconds": 3600}, ...}`）。客户端同时处理此格式和顶层 `detail`（422、旧格式），
无法解析时打印原文。

### `POST /scan/jobs`

`multipart/form-data`：`file`（必填）、`kind`（`sbom`|`lockfile`，CycloneDX/SPDX JSON 为 `sbom`）、`policy`（JSON 字符串）、`scan_depth`、`no_cache`。

| 响应 | 客户端行为 |
|---|---|
| `202 {job_id, status, status_url}` | `status == "completed"` 表示命中缓存 —— 不轮询，直接查询 1 次结果 |
| 网络错误 · 5xx | 以 1→2→4→8 秒退避最多重试 4 次，用尽后 `exit 3` |
| `429` `rate_limit_exceeded` · `active_job_limit_exceeded` | 等待 `Retry-After`（没有则用 `detail.retry_after_seconds`）后重试，在总 timeout 内 |
| `429` `upload_budget_exceeded` | 不重试，`exit 2` |
| `402` `monthly_quota_exceeded` | 不重试也不等待，`exit 2`，打印 `plan`、`limit`、`used`、`reset_at`、`upgrade_url` |
| `400` | `exit 2`，打印所发送策略 JSON 的全文 |
| `413` · `422` · 其他 4xx | `exit 2` |
| `401` · `404` · `405` · 3xx | `exit 4`（检查密钥或 `api-url`） |

### `GET /scan/jobs/{job_id}`

每 3 秒轮询一次。`status` 变为 `completed`/`failed` 时结束。
网络错误、5xx 推迟到下一周期，连续 5 次则 `exit 3`。`429` 时等待 `Retry-After`。`failed` 时打印 `error.code`、`error.message` 并 `exit 2`。
判定使用的字段：`result.summary.{total_packages, total_vulnerabilities, kev_count, by_severity, unsupported_packages, unknown_vulnerabilities}`、
`result.policy.{passed, violations[].{rule, count, samples}}`、`result.warnings[]`、`result.data_freshness.internal_db_synced_at`。

### `GET /scan/jobs/{job_id}/sbom`

指定 `sbom-output` 时调用 1 次，保存 CycloneDX JSON。

## 安全

- **版本固定**：`@v1` 会随新版本发布而移动。为降低供应链风险，请固定到提交 SHA。
  ```yaml
  - uses: vulnintel/scan-action@<40 位提交 SHA>  # v1.0.0
  ```
- **API 密钥**：只通过 GitHub Secrets（如 `secrets.VULNINTEL_API_KEY`）传入。不要以明文写在工作流文件中。
  客户端在 GitHub Actions 中会对密钥应用 `::add-mask::`，在其他 CI 中也会将输出中的密钥替换为 `***`。
- **发送的数据**：只发送所选的 1 个 lockfile 或 SBOM 文件的内容（使用 syft 时为 syft 生成的 SBOM）以及策略设置。
  不发送源代码。
- **传输**：仅使用 `https://`（localhost 除外），验证 TLS 证书，且不跟随重定向（防止密钥泄露到其他主机）。
- **输出处理**：来自服务器、lockfile 的字符串在 `::stop-commands::` 区段内输出，避免被当作工作流命令执行。
- 漏洞报告请遵循 [SECURITY.md](SECURITY.md)。

## 测试

```bash
python3 -m pip install pytest && python3 -m pytest tests -q
```

启动假服务器（`http.server`），通过真实 HTTP 路径进行验证。只有测试使用 pytest，脚本本体只使用标准库。
