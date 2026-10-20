"""vulnintel_scan.py 회귀 테스트 — http.server 가짜 서버로 실제 HTTP 경로를 검증한다."""

from __future__ import annotations

import json
import sys
import threading
from email.parser import BytesParser
from email.policy import default as email_policy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vulnintel_scan as vs  # noqa: E402

JOB_ID = "3f2b8c1e-0000-4000-8000-000000000001"


def _result(
    *,
    passed: bool = True,
    total: int = 10,
    unsupported: int | None = 0,
    warnings: list[str] | None = None,
    violations: list[dict[str, Any]] | None = None,
    unknown: int | None = None,
    packages: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """완료 job 응답 바디를 만든다. unknown=None 이면 필드 없는 구 결과."""
    return {
        "job_id": JOB_ID,
        "status": "completed",
        "progress": {"phase": "completed", "percent": 100},
        "error": None,
        "result": {
            "summary": {
                "total_packages": total,
                "affected_packages": 0,
                "total_vulnerabilities": 1 if violations else 0,
                "by_severity": {"CRITICAL": 0, "HIGH": 0, "UNKNOWN": 2},
                "kev_count": 0,
                "unsupported_packages": unsupported,
                **({} if unknown is None else {"unknown_vulnerabilities": unknown}),
            },
            "packages": packages or [],
            "policy": {"passed": passed, "violations": violations or []},
            "data_freshness": {"internal_db_synced_at": "2026-10-14T01:02:03+00:00"},
            "warnings": warnings or [],
            "sbom_url": f"/api/v1/scan/jobs/{JOB_ID}/sbom",
        },
    }


def _resp(status: int, body: Any, headers: dict[str, str] | None = None) -> tuple:
    """가짜 서버 응답 1개."""
    return status, body, headers or {}


def _envelope(detail: Any) -> dict[str, Any]:
    """서버의 실제 오류 바디 형태 — 구조화 detail 은 최상위 error/message 아래에 중첩된다."""
    return {"error": detail, "message": detail, "request_id": "req-1"}


ACCEPTED = _resp(202, {"job_id": JOB_ID, "status": "queued"})
CACHED = _resp(202, {"job_id": JOB_ID, "status": "completed"})


class FakeServer:
    """라우트별 응답 큐를 가진 가짜 VulnIntel API. 큐의 마지막 응답은 반복된다."""

    def __init__(self) -> None:
        """서버를 띄우고 요청 기록을 준비한다."""
        self.routes: dict[str, list[tuple]] = {}
        self.requests: list[dict[str, Any]] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                path = self.path.removeprefix("/api/v1")
                key = f"{self.command} {path}"
                fake.requests.append(
                    {"key": key, "headers": dict(self.headers), "body": body}
                )
                queue = fake.routes.get(key) or [_resp(404, {"detail": "not found"})]
                status, payload, headers = queue.pop(0) if len(queue) > 1 else queue[0]
                raw = (
                    payload
                    if isinstance(payload, bytes)
                    else json.dumps(payload).encode()
                )
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            do_GET = do_POST = _handle

            def log_message(self, *args: Any) -> None:
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/api/v1"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def count(self, key: str) -> int:
        """해당 라우트 요청 수."""
        return sum(1 for r in self.requests if r["key"] == key)

    def form(self) -> dict[str, Any]:
        """첫 업로드 요청의 multipart 필드를 파싱한다."""
        req = next(r for r in self.requests if r["key"] == "POST /scan/jobs")
        msg = BytesParser(policy=email_policy).parsebytes(
            f"Content-Type: {req['headers']['Content-Type']}\r\n\r\n".encode()
            + req["body"]
        )
        return {
            p.get_param("name", header="content-disposition"): p.get_content()
            for p in msg.iter_parts()
        }


POST = "POST /scan/jobs"
GET = f"GET /scan/jobs/{JOB_ID}"


@pytest.fixture
def server():
    """요청마다 새 가짜 서버."""
    srv = FakeServer()
    yield srv
    srv.httpd.shutdown()
    srv.httpd.server_close()


@pytest.fixture
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """sleep 을 기록만 하도록 바꾼다."""
    calls: list[float] = []
    monkeypatch.setattr(vs, "sleep", calls.append)
    return calls


@pytest.fixture
def run(server: FakeServer, sleeps: list[float], tmp_path: Path, monkeypatch):
    """package-lock.json 1개가 있는 작업 디렉터리에서 main 을 실행한다."""
    for k in list(vs.os.environ):
        if k.startswith(("INPUT_", "GITHUB_")):
            monkeypatch.delenv(k)
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {}}'
    )
    outputs = tmp_path / "gh_output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(outputs))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "gh_summary"))

    def _run(*args: str, **env: str) -> tuple[int, dict[str, str]]:
        for k, v in env.items():
            monkeypatch.setenv(f"INPUT_{k.upper()}", v)
        argv = [
            "--api-key",
            "vk_test",
            "--api-url",
            server.url,
            "--path",
            str(tmp_path),
        ]
        argv += ["--syft", "off"]  # 개발 머신에 syft 가 있어도 결과가 같게
        code = vs.main(argv + list(args))
        out = dict(
            line.split("=", 1)
            for line in outputs.read_text().splitlines()
            if "=" in line
        )
        outputs.write_text("")
        return code, out

    return _run


# ── 정상·정책 ─────────────────────────────────────────────


def test_no_cache_input_sends_no_cache_true(run, server, sleeps):
    server.routes = {POST: [ACCEPTED], GET: [_resp(200, _result())]}
    code, _ = run(no_cache="true")
    assert code == 0
    assert server.form()["no_cache"] == "true"


def test_pass_sends_flat_policy_and_writes_outputs(run, server, sleeps):
    server.routes = {
        POST: [ACCEPTED],
        GET: [_resp(200, {"status": "running"}), _resp(200, _result())],
    }
    code, out = run()
    assert code == 0
    assert (
        out["verdict"] == "pass" and out["passed"] == "true" and out["job-id"] == JOB_ID
    )
    assert out["unsupported-ratio"] == "0.000"
    assert out["data-freshness"] == "2026-10-14T01:02:03+00:00"
    assert sleeps == [vs.POLL_INTERVAL]  # running → 3초 후 재조회
    form = server.form()
    assert form["kind"] == "lockfile" and form["scan_depth"] == "basic"
    assert form["no_cache"] == "false"
    assert json.loads(form["policy"])["rules"] == [
        {"type": "kev_present", "action": "fail"},
        {"type": "cvss_threshold", "min_score": 9.0, "max_count": 0, "action": "fail"},
        {
            "type": "severity_threshold",
            "severity": "CRITICAL",
            "max_count": 0,
            "action": "fail",
        },
    ]
    headers = server.requests[0]["headers"]
    assert headers["X-Api-Key"] == "vk_test"
    assert headers["User-Agent"].startswith("vulnintel-scan-action/")


def test_policy_violation_exit_1_with_details(run, server, capsys):
    viol = [{"rule": "kev_present", "count": 1, "samples": ["CVE-2024-3094"]}]
    server.routes = {
        POST: [ACCEPTED],
        GET: [_resp(200, _result(passed=False, violations=viol))],
    }
    code, out = run()
    assert code == 1 and out["verdict"] == "policy_failed" and out["passed"] == "false"
    text = capsys.readouterr().out
    assert "rule=kev_present count=1 samples=CVE-2024-3094" in text
    assert "2026-10-14T01:02:03" in text


def test_fail_on_never_suppresses_policy_violation(run, server):
    server.routes = {POST: [ACCEPTED], GET: [_resp(200, _result(passed=False))]}
    code, out = run(fail_on="never")
    assert code == 0 and out["verdict"] == "policy_failed"


def test_flat_keys_map_unknown_high_and_ignore(run, server):
    server.routes = {POST: [ACCEPTED], GET: [_resp(200, _result())]}
    run(
        "--max-unknown",
        "0",
        "--max-high",
        "3",
        "--max-cvss",
        "",
        "--ignore",
        "CVE-2024-0001, CVE-2024-0002\nGHSA-abcd-efgh-ijkl",
    )
    rules = json.loads(server.form()["policy"])["rules"]
    assert {
        "type": "severity_threshold",
        "severity": "UNKNOWN",
        "max_count": 0,
        "action": "fail",
    } in rules
    assert {
        "type": "severity_threshold",
        "severity": "HIGH",
        "max_count": 3,
        "action": "fail",
    } in rules
    assert not any(r["type"] == "cvss_threshold" for r in rules)
    assert {
        "type": "ignore_list",
        "cve_ids": ["CVE-2024-0001", "CVE-2024-0002", "GHSA-abcd-efgh-ijkl"],
    } in rules


def test_all_rules_disabled_sends_warn_rule_not_empty_list():
    cfg = dict(
        vs.INPUTS, **{"fail-on-kev": "false", "max-cvss": "", "max-critical": ""}
    )
    assert json.loads(vs.build_policy(cfg)) == {
        "rules": [{"type": "kev_present", "action": "warn"}]
    }


# ── 커버리지 게이트 ─────────────────────────────────────────


def test_coverage_gate_runs_before_policy_passed_from_warnings(run, server, capsys):
    """구 캐시(필드 없음) → warnings 파싱. passed=true 여도 exit 2."""
    body = _result(
        total=10, unsupported=None, warnings=["unsupported_ecosystem: deb(6), apk(2)"]
    )
    server.routes = {POST: [ACCEPTED], GET: [_resp(200, body)]}
    code, out = run()
    assert code == 2 and out["passed"] == "true" and out["unsupported-ratio"] == "0.800"
    assert "Container images are not supported" in capsys.readouterr().out
    code, out = run(fail_on="never")  # never 는 2를 0으로 만들 뿐 verdict 는 남는다
    assert code == 0 and out["verdict"] == "indeterminate"


def test_coverage_gate_prefers_summary_field(run, server):
    body = _result(total=10, unsupported=8, warnings=[])
    server.routes = {POST: [ACCEPTED], GET: [_resp(200, body)]}
    code, out = run()
    assert code == 2 and out["unsupported-ratio"] == "0.800"


def test_coverage_threshold_1_disables_gate(run, server):
    body = _result(
        total=10, unsupported=10, warnings=["unsupported_ecosystem: deb(10)"]
    )
    server.routes = {POST: [ACCEPTED], GET: [_resp(200, body)]}
    assert run("--unsupported-ratio-threshold", "1.0")[0] == 0


def test_zero_packages_is_indeterminate(run, server):
    server.routes = {
        POST: [ACCEPTED],
        GET: [_resp(200, _result(total=0, unsupported=0))],
    }
    code, out = run()
    assert code == 2 and out["unsupported-ratio"] == ""


def test_missing_version_is_not_counted_as_unsupported(run, server, capsys):
    body = _result(total=10, unsupported=None, warnings=["missing_version: 7"])
    server.routes = {POST: [ACCEPTED], GET: [_resp(200, body)]}
    assert run()[0] == 0
    assert "missing_version: 7" in capsys.readouterr().out


# ── 미확정(unknown) 판정 ───────────────────────────────


def test_unknown_only_is_indeterminate_not_pass(run, server, capsys):
    """확정 취약점 0·unsupported 0 이어도 미확정이 있으면 PASS 가 아니라 exit 2."""
    body = _result(passed=True, unknown=2)
    server.routes = {POST: [ACCEPTED], GET: [_resp(200, body)]}
    code, out = run()
    assert code == 2 and out["verdict"] == "indeterminate" and out["passed"] == "true"
    assert "could not be confirmed" in capsys.readouterr().out
    assert run(fail_on="never")[0] == 0  # 억제 매핑은 기존 표 그대로


def test_safe_only_with_zero_unknown_passes(run, server):
    server.routes = {POST: [ACCEPTED], GET: [_resp(200, _result(unknown=0))]}
    code, out = run()
    assert code == 0 and out["verdict"] == "pass"


def test_violation_and_unknown_mix_is_2_and_still_prints_violations(
    run, server, capsys
):
    """혼합은 exit 2(판정 불가 우선) — 확정 위반 내역도 가리지 않고 출력한다."""
    viol = [{"rule": "kev_present", "count": 1, "samples": ["CVE-2024-3094"]}]
    body = _result(passed=False, violations=viol, unknown=1)
    server.routes = {POST: [ACCEPTED], GET: [_resp(200, body)]}
    code, out = run()
    assert code == 2 and out["verdict"] == "indeterminate" and out["passed"] == "false"
    text = capsys.readouterr().out
    assert "rule=kev_present count=1 samples=CVE-2024-3094" in text
    assert "policy also FAILED" in text


def test_old_result_without_unknown_field_keeps_previous_behaviour(run, server):
    """구 캐시 결과(필드 없음)는 기존 판정 그대로."""
    server.routes = {POST: [ACCEPTED], GET: [_resp(200, _result(unknown=None))]}
    assert run()[0] == 0


# ── 업그레이드 안내 ─────────────────────────────────────


def _vuln(vid: str, fixed: list[str], score: float = 9.8, **extra: Any) -> dict:
    """result.packages[].vulnerabilities 원소."""
    sev = "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM"
    return {
        "id": vid,
        "severity": sev,
        "cvss": {"score": score},
        "fixed_versions": fixed,
        **extra,
    }


def _pkg(name: str, version: str | None, *vulns: dict) -> dict:
    """result.packages 원소."""
    return {
        "purl": f"pkg:pypi/{name}@{version}",
        "name": name,
        "version": version,
        "vulnerabilities": list(vulns),
    }


VIOL = [{"rule": "cvss_threshold", "count": 3, "samples": ["CVE-2025-64459"]}]


def test_fix_lines_group_by_package_with_numeric_max(run, server, capsys, tmp_path):
    """패키지별 한 줄, 수정 버전은 숫자 튜플 최댓값(문자열 비교면 4.2.9 가 이긴다)."""
    django = _pkg(
        "django",
        "4.2.16",
        _vuln("CVE-2026-4277", ["4.2.30"]),
        _vuln("CVE-2024-53908", ["4.2.9"]),
        _vuln("CVE-2025-64459", ["4.2.26"]),
    )
    low = _pkg("idna", "3.6", _vuln("CVE-2024-3651", ["3.7"], score=6.2))
    body = _result(passed=False, violations=VIOL, packages=[django, low])
    server.routes = {POST: [ACCEPTED], GET: [_resp(200, body)]}
    assert run()[0] == 1
    line = (
        "  django 4.2.16 → upgrade to >= 4.2.30 "
        "(CVE-2024-53908, CVE-2025-64459, CVE-2026-4277)"
    )
    text = capsys.readouterr().out
    assert f"Fix by upgrading:\n{line}\n" in text
    assert "idna" not in text  # 정책을 넘지 않은 취약점은 안내하지 않는다
    assert line in (tmp_path / "gh_summary").read_text(encoding="utf-8")


def test_fix_lines_no_fixed_version_and_non_numeric(run, server, capsys):
    """수정 버전 없음은 `no fixed version yet`, 숫자가 아닌 버전은 CVE별로 나열한다."""
    pkgs = [
        _pkg("a", "1.0", _vuln("CVE-2024-0001", []), _vuln("CVE-2024-0002", ["1.1"])),
        _pkg("b", None, _vuln("CVE-2024-0003", [])),
        _pkg("c", "2.0", _vuln("CVE-2024-0004", ["2.1rc1"])),
    ]
    body = _result(passed=False, violations=VIOL, packages=pkgs)
    server.routes = {POST: [ACCEPTED], GET: [_resp(200, body)]}
    run()
    text = capsys.readouterr().out
    assert (
        "  a 1.0 → upgrade to >= 1.1 (CVE-2024-0002); "
        "no fixed version yet (CVE-2024-0001)"
    ) in text
    assert "  b (version unknown) → no fixed version yet (CVE-2024-0003)" in text
    assert "  c 2.0 → CVE-2024-0004 fixed in 2.1rc1" in text


def test_fix_lines_follow_sent_policy_rules_and_ignore(run, server, capsys):
    """KEV·severity 규칙도 서버 평가와 같게, ignore 한 ID·한도 이하 규칙은 제외한다."""
    pkgs = [
        _pkg("kevpkg", "1.0", _vuln("CVE-2024-0010", ["1.2"], score=5.0, kev=True)),
        _pkg("ignored", "1.0", _vuln("CVE-2024-0011", ["1.1"])),
        _pkg("high", "1.0", _vuln("CVE-2024-0012", ["1.3"], score=7.5)),
    ]
    body = _result(passed=False, violations=VIOL, packages=pkgs)
    server.routes = {POST: [ACCEPTED], GET: [_resp(200, body)]}
    run("--max-high", "1", "--ignore", "CVE-2024-0011")
    text = capsys.readouterr().out
    assert "  kevpkg 1.0 → upgrade to >= 1.2 (CVE-2024-0010)" in text
    assert "ignored 1.0 →" not in text and "high 1.0 →" not in text


def test_fix_lines_are_capped(run, server, capsys):
    pkgs = [
        _pkg(f"p{i}", "1.0", _vuln(f"CVE-2024-{i:04d}", ["1.1"])) for i in range(25)
    ]
    body = _result(passed=False, violations=VIOL, packages=pkgs)
    server.routes = {POST: [ACCEPTED], GET: [_resp(200, body)]}
    run()
    text = capsys.readouterr().out
    assert text.count(" → upgrade to >= 1.1") == vs.MAX_FIX_PACKAGES
    assert "  ... and 5 more package(s)" in text


def test_old_result_without_fixed_versions_or_packages(run, server, capsys):
    """필드 없는 구 응답 — 판정·출력은 기존 그대로, 안내만 빠지거나 `no fixed`."""
    server.routes = {POST: [ACCEPTED], GET: [_resp(200, _result(passed=False))]}
    del server.routes[GET][0][1]["result"]["packages"]
    assert run()[0] == 1
    assert "Fix by upgrading" not in capsys.readouterr().out
    old = _pkg("django", "4.2.16", _vuln("CVE-2025-64459", []))
    del old["vulnerabilities"][0]["fixed_versions"]
    body = _result(passed=False, violations=VIOL, packages=[old])
    server.routes = {POST: [ACCEPTED], GET: [_resp(200, body)]}
    assert run()[0] == 1
    assert "django 4.2.16 → no fixed version yet" in capsys.readouterr().out


# ── 업로드 오류·재시도 ─────────────────────────────────────


def test_402_quota_exceeded_exits_2_without_retry(run, server, sleeps, capsys):
    detail = {
        "error": "monthly_quota_exceeded",
        "plan": "free",
        "limit": 50,
        "used": 50,
        "reset_at": "2026-11-01T00:00:00+00:00",
        "upgrade_url": "https://www.vulnintelapp.com/pricing",
    }
    server.routes = {POST: [_resp(402, {"detail": detail})]}
    code, out = run()
    assert code == 2 and out["verdict"] == "indeterminate"
    assert server.count(POST) == 1 and sleeps == []
    text = capsys.readouterr().out
    for piece in (
        "plan=free",
        "limit=50",
        "used=50",
        "reset_at=2026-11-01",
        "vulnintelapp.com/pricing",
    ):
        assert piece in text


def test_429_active_job_limit_waits_retry_after_then_retries(run, server, sleeps):
    busy = _resp(
        429,
        {"detail": {"error": "active_job_limit_exceeded", "limit": 1, "active": 1}},
        {"Retry-After": "15"},
    )
    server.routes = {POST: [busy, ACCEPTED], GET: [_resp(200, _result())]}
    assert run()[0] == 0
    assert server.count(POST) == 2 and sleeps == [15]


def test_429_upload_budget_exceeded_exits_2_without_retry(run, server, sleeps):
    detail = {"error": "upload_budget_exceeded", "retry_after_seconds": 3600}
    server.routes = {POST: [_resp(429, {"detail": detail}, {"Retry-After": "3600"})]}
    assert run()[0] == 2
    assert server.count(POST) == 1 and sleeps == []


def test_429_upload_budget_real_envelope_exits_2_without_retry(run, server, sleeps):
    """실제 서버 envelope(error 객체)의 예산 초과도 재시도 없이 exit 2."""
    detail = {"error": "upload_budget_exceeded", "retry_after_seconds": 3600}
    server.routes = {
        POST: [_resp(429, _envelope(detail), {"Retry-After": "3600"}), ACCEPTED],
        GET: [_resp(200, _result())],
    }
    code, out = run()
    assert code == 2 and out["verdict"] == "indeterminate"
    assert server.count(POST) == 1 and sleeps == []


def test_402_real_envelope_exits_2_with_plan_details(run, server, sleeps, capsys):
    detail = {
        "error": "monthly_quota_exceeded",
        "plan": "free",
        "limit": 50,
        "used": 50,
        "reset_at": "2026-11-01T00:00:00+00:00",
        "upgrade_url": "https://www.vulnintelapp.com/pricing",
    }
    server.routes = {POST: [_resp(402, _envelope(detail))]}
    assert run()[0] == 2
    assert server.count(POST) == 1 and sleeps == []
    text = capsys.readouterr().out
    assert "plan=free limit=50 used=50 reset_at=2026-11-01" in text
    assert "Upgrade: https://www.vulnintelapp.com/pricing" in text


def test_429_active_job_real_envelope_retries(run, server, sleeps):
    busy = _resp(
        429,
        _envelope({"error": "active_job_limit_exceeded", "limit": 1, "active": 1}),
        {"Retry-After": "15"},
    )
    server.routes = {POST: [busy, ACCEPTED], GET: [_resp(200, _result())]}
    assert run()[0] == 0
    assert server.count(POST) == 2 and sleeps == [15]


def test_5xx_upload_backoff_then_exit_3_suppressed(run, server, sleeps):
    server.routes = {POST: [_resp(503, b"bad gateway")]}
    code, out = run()
    assert (
        code == 0 and out["verdict"] == "service_error"
    )  # 3 → 0 + 경고(fail-on=policy)
    assert server.count(POST) == 5 and sleeps == [1, 2, 4, 8]


def test_400_policy_error_prints_policy_json(run, server, capsys):
    server.routes = {
        POST: [_resp(400, {"detail": "invalid policy JSON: validation failed"})]
    }
    assert run()[0] == 2
    text = capsys.readouterr().out
    assert "invalid policy JSON" in text and '"kev_present"' in text


def test_401_is_usage_error_even_with_fail_on_never(run, server):
    server.routes = {POST: [_resp(401, {"detail": {"error": "invalid_api_key"}})]}
    code, out = run(fail_on="never")
    assert code == 4 and out["verdict"] == "usage_error"


# ── 폴링 ────────────────────────────────────────────────


def test_cache_hit_skips_polling_loop(run, server, sleeps, capsys):
    server.routes = {POST: [CACHED], GET: [_resp(200, _result())]}
    assert run()[0] == 0
    assert server.count(GET) == 1 and sleeps == []
    assert "Cache hit" in capsys.readouterr().out


def test_failed_job_exits_2_with_error_code(run, server, capsys):
    failed = {
        "job_id": JOB_ID,
        "status": "failed",
        "error": {"code": "parse_error", "message": "too many components"},
    }
    server.routes = {POST: [ACCEPTED], GET: [_resp(200, failed)]}
    assert run()[0] == 2
    assert "parse_error" in capsys.readouterr().out


def test_five_consecutive_poll_failures_exit_3(run, server, sleeps):
    server.routes = {POST: [ACCEPTED], GET: [_resp(500, b"boom")]}
    code, out = run()
    assert code == 0 and out["verdict"] == "service_error"
    assert server.count(GET) == 5


def test_poll_failure_counter_resets_on_success(run, server):
    flaky = (
        [_resp(500, b"x")] * 4
        + [_resp(200, {"status": "running"})]
        + [_resp(500, b"x")] * 4
    )
    server.routes = {POST: [ACCEPTED], GET: flaky + [_resp(200, _result())]}
    assert run()[0] == 0


# ── 사용법 오류 ──────────────────────────────────────────


def test_missing_api_key_exit_4(run, server):
    code = vs.main(["--api-url", server.url, "--fail-on", "never"])
    assert code == 4 and server.requests == []


def test_501_ignore_ids_exit_4_without_request(run, server):
    ids = ",".join(f"CVE-2024-{i:05d}" for i in range(501))
    assert run("--ignore", ids)[0] == 4
    assert server.requests == []


def test_timeout_below_floor_is_raised_to_310(run, server, capsys):
    server.routes = {POST: [ACCEPTED], GET: [_resp(200, _result())]}
    assert run(timeout="30")[0] == 0
    assert "using 310s" in capsys.readouterr().out


def test_plain_http_to_remote_host_is_rejected(run):
    assert (
        vs.main(["--api-key", "k", "--api-url", "http://api.example.com/api/v1"]) == 4
    )


def test_discovery_multiple_hits_and_unparsed_only(tmp_path: Path):
    (tmp_path / "go.sum").write_text("x")
    (tmp_path / "requirements.txt").write_text("x")
    with pytest.raises(vs.Exit) as exc:
        vs.discover(str(tmp_path))
    assert exc.value.code == 4 and "go.sum" in exc.value.message

    only = tmp_path / "pnpm"
    only.mkdir()
    (only / "pnpm-lock.yaml").write_text("x")
    with pytest.raises(vs.Exit) as exc:
        vs.discover(str(only))
    assert exc.value.code == 4 and "syft" in exc.value.message


def test_sbom_json_is_discovered_and_sent_as_sbom(run, server, tmp_path: Path):
    (tmp_path / "package-lock.json").unlink()
    (tmp_path / "bom.json").write_text(
        '{"bomFormat": "CycloneDX", "specVersion": "1.6"}'
    )
    (tmp_path / "package.json").write_text('{"name": "x"}')
    server.routes = {POST: [ACCEPTED], GET: [_resp(200, _result())]}
    assert run("--syft", "off")[0] == 0
    assert server.form()["kind"] == "sbom"


def test_oversized_file_exit_2_without_request(run, server, tmp_path: Path):
    big = tmp_path / "big.json"
    big.write_bytes(b"x" * (vs.MAX_UPLOAD_BYTES + 1))
    assert run("--file", str(big))[0] == 2
    assert server.requests == []


def test_action_yml_inputs_match_script_defaults():
    """action.yml 입력 키·기본값이 스크립트 INPUTS 와 어긋나지 않는다(외부 계약)."""
    text = (Path(vs.__file__).parent / "action.yml").read_text(encoding="utf-8")
    block = text.split("\ninputs:\n", 1)[1].split("\noutputs:\n", 1)[0]
    found: dict[str, str] = {}
    for line in block.splitlines():
        if line.startswith("  ") and not line.startswith("   ") and line.endswith(":"):
            name = line.strip()[:-1]
            found[name] = ""
        elif line.strip().startswith("default:"):
            found[name] = line.split(":", 1)[1].strip().strip('"')
    assert found == vs.INPUTS
    for key in vs.OUTPUT_KEYS:
        assert f"  {key}:\n" in text


# ── 보안 ────────────────────────────────────────────────


def test_gha_masks_key_and_fences_untrusted_output(run, server, capsys, monkeypatch):
    """GitHub Actions: 키 마스킹 → stop-commands 안에서만 서버 문자열 출력 → 마지막에 해제."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    evil = "::add-mask::x\n##[error]forged\nkey=vk_test"
    body = _result(warnings=[evil], unknown=1)
    server.routes = {POST: [ACCEPTED], GET: [_resp(200, body)]}
    assert run()[0] == 2
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "::add-mask::vk_test"
    token = lines[1].removeprefix("::stop-commands::")
    assert len(token) == 32 and lines[-1] == f"::{token}::"
    inside = lines[2:-1]
    # 출력된 서버 문자열은 모두 stop-commands 가 켜진 구간에 있다
    active = True
    for line in inside:
        if line == f"::{token}::":
            active = False
        elif line == f"::stop-commands::{token}":
            active = True
        elif line.strip() in ("- ::add-mask::x", "##[error]forged"):
            assert active
        elif not active:
            assert line.startswith("::error::")  # 해제 구간에는 우리 주석 1줄만
    assert "##[error]forged" in inside and "  - ::add-mask::x" in inside
    assert not any("vk_test" in line for line in inside)
    assert "key=***" in "\n".join(inside)


def test_api_key_with_newline_is_rejected_without_echo(
    run, server, capsys, monkeypatch
):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    code = vs.main(["--api-key", "vk_a\n::error::x", "--api-url", server.url])
    assert code == 4 and server.requests == []
    text = capsys.readouterr().out
    assert "vk_a" not in text and "::add-mask::" not in text


def test_api_url_with_credentials_is_rejected_without_echo(run, capsys):
    code = vs.main(["--api-key", "k", "--api-url", "https://u:secret@api.example.com"])
    assert code == 4 and "secret" not in capsys.readouterr().out


def test_redirect_is_not_followed(run, server):
    other = FakeServer()
    try:
        server.routes = {
            POST: [_resp(302, b"", {"Location": other.url + "/scan/jobs"})]
        }
        assert run()[0] == 4
        assert other.requests == []
    finally:
        other.httpd.shutdown()
        other.httpd.server_close()


def test_oversized_response_is_treated_as_network_error(run, server, monkeypatch):
    monkeypatch.setattr(vs, "MAX_RESPONSE_BYTES", 100)
    server.routes = {POST: [_resp(202, {"job_id": JOB_ID, "pad": "x" * 200})]}
    code, out = run()
    assert out["verdict"] == "service_error" and server.count(POST) == 5


def test_server_newline_cannot_forge_github_output(run, server):
    body = _result(passed=False)
    body["result"]["data_freshness"]["internal_db_synced_at"] = "x\npassed=true\r"
    server.routes = {POST: [ACCEPTED], GET: [_resp(200, body)]}
    code, out = run()
    assert code == 1 and out["passed"] == "false"
    assert out["data-freshness"] == "x passed=true "


def test_backticks_cannot_close_step_summary_fence(run, server, tmp_path: Path):
    body = _result(warnings=["```\n[click](https://evil.example)\n```"])
    server.routes = {POST: [ACCEPTED], GET: [_resp(200, body)]}
    assert run()[0] == 0
    summary = (tmp_path / "gh_summary").read_text()
    fence = summary.splitlines()[2]
    assert fence == "````" and summary.rstrip().endswith(fence)
