#!/usr/bin/env python3
"""VulnIntel CI scan client (v1) - Python 3 stdlib only.

Uploads one lockfile/SBOM to VulnIntel, waits for the verdict and maps it to an exit code:
0 pass · 1 policy failed · 2 indeterminate · 3 service unreachable · 4 usage error.
Inputs come from CLI flags (``--max-cvss 9.0``) or ``INPUT_*`` env vars (``INPUT_MAX_CVSS``).
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
import uuid
from email.message import Message
from time import monotonic, sleep
from typing import Any
from urllib.parse import urlparse

VERSION = "1.0.0"
USER_AGENT = f"vulnintel-scan-action/{VERSION}"
DEFAULT_API_URL = "https://api.vulnintelapp.com/api/v1"

MIN_TIMEOUT = (
    310  # 서버 하드 타임아웃 300초보다 커야 워커의 자체 실패 표기를 볼 수 있다
)
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 서버 업로드 상한
MAX_RESPONSE_BYTES = 64 * 1024 * 1024  # 응답 바디 상한(SBOM 다운로드 포함)
MAX_IGNORE_IDS = 500  # 서버 ignore_list 상한
UPLOAD_BACKOFF = (1, 2, 4, 8)  # 네트워크·5xx 재시도 간격(초)
POLL_INTERVAL = 3  # 서버 조회 리미터 60/60s 대비 20회/분
MAX_POLL_FAILURES = 5
REQUEST_TIMEOUT = 60
DEFAULT_RETRY_AFTER = 10
ID_RE = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$")

INPUTS = {
    "api-key": "",
    "api-url": DEFAULT_API_URL,
    "path": ".",
    "file": "",
    "syft": "auto",
    "scan-depth": "basic",
    "fail-on": "policy",
    "fail-on-kev": "true",
    "max-cvss": "9.0",
    "max-critical": "0",
    "max-high": "",
    "max-unknown": "",
    "ignore": "",
    "policy-json": "",
    "unsupported-ratio-threshold": "0.20",
    "no-cache": "false",
    "timeout": "360",
    "sbom-output": "",
}
OUTPUT_KEYS = (
    "job-id",
    "passed",
    "verdict",
    "total-packages",
    "total-vulnerabilities",
    "kev-count",
    "unsupported-ratio",
    "data-freshness",
)
VERDICTS = {
    0: "pass",
    1: "policy_failed",
    2: "indeterminate",
    3: "service_error",
    4: "usage_error",
}

# 서버 파서가 읽는 파일명.
LOCKFILES = (
    "package-lock.json",
    "go.sum",
    "requirements.txt",
    "Cargo.lock",
    "Gemfile.lock",
    "composer.lock",
    "packages.lock.json",
)
# 파서가 없는 흔한 lockfile — 발견 시 syft 안내만 한다.
UNPARSED = (
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
)
NETWORK_ERRORS = (OSError, http.client.HTTPException)  # URLError ⊂ OSError


class Exit(Exception):
    """판정 결과(exit code)와 사유를 들고 main 으로 빠져나온다."""

    def __init__(self, code: int, message: str) -> None:
        """exit code 와 메시지를 저장한다."""
        super().__init__(message)
        self.code = code
        self.message = message


class _Parser(argparse.ArgumentParser):
    """인자 오류를 argparse 기본값(exit 2) 대신 exit 4 로 돌린다."""

    def error(self, message: str) -> None:  # type: ignore[override]
        """인자 오류를 사용법 오류로 변환한다."""
        raise Exit(4, f"invalid arguments: {message}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """리다이렉트를 따르지 않는다 — X-Api-Key 가 다른 호스트로 전달되는 것을 막는다."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        """리다이렉트 요청을 만들지 않아 3xx 를 HTTPError 로 남긴다."""
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)
_LOG: list[str] = []
_SECRET = ""  # 출력에서 가릴 API 키
_GUARD: str | None = None  # GitHub Actions 에서 켠 ::stop-commands:: 토큰


def _gha() -> bool:
    """GitHub Actions 러너에서 실행 중인가."""
    return os.environ.get("GITHUB_ACTIONS") == "true"


def say(msg: str, level: str | None = None) -> None:
    """콘솔에 출력하고 step summary 용으로 모은다. level 은 warning/error.

    서버·lockfile 문자열이 섞이므로, GitHub Actions 에서는 main 이 켠 stop-commands 안에서
    출력해 워크플로 명령(::add-mask:: 등)으로 해석되지 않게 하고, 주석(annotation)만 잠깐 푼다.
    """
    text = str(msg).replace(_SECRET, "***") if _SECRET else str(msg)
    for i, line in enumerate(text.splitlines() or [""]):
        if level and i == 0 and _gha():
            note = f"::{level}::{line.replace('%', '%25')}"
            if _GUARD:
                note = f"::{_GUARD}::\n{note}\n::stop-commands::{_GUARD}"
            print(note, flush=True)
        else:
            print(line, flush=True)
        _LOG.append(f"{level.upper()}: {line}" if level and i == 0 else line)


def _protect(api_key: str) -> None:
    """키를 출력에서 가리고, GitHub Actions 면 이후 출력의 워크플로 명령 해석을 끈다."""
    global _SECRET, _GUARD
    if any(c.isspace() or not c.isprintable() for c in api_key):
        # 개행이 섞인 키는 ::add-mask:: 줄과 HTTP 헤더를 깨뜨린다. 메시지에 키를 넣지 않는다.
        raise Exit(4, "api-key must not contain whitespace or control characters.")
    _SECRET = api_key
    if _gha():
        if api_key:  # secrets 대신 평문으로 넘긴 경우에도 로그에서 가려지게
            print(f"::add-mask::{api_key}", flush=True)
        _GUARD = uuid.uuid4().hex
        print(f"::stop-commands::{_GUARD}", flush=True)


# ───────────────────────────── 입력 ─────────────────────────────


def read_inputs(argv: list[str] | None) -> dict[str, str]:
    """CLI 인자 > INPUT_* 환경변수 > 기본값 순으로 입력을 모은다."""
    parser = _Parser(description=__doc__)
    for name in INPUTS:
        parser.add_argument(f"--{name}", dest=name)
    args = vars(parser.parse_args(argv))
    cfg = {}
    for name, default in INPUTS.items():
        env = "INPUT_" + name.upper().replace("-", "_")
        value = args[name] if args[name] is not None else os.environ.get(env, default)
        cfg[name] = value.strip()
    return cfg


def _choice(cfg: dict[str, str], name: str, allowed: tuple[str, ...]) -> str:
    """열거형 입력을 검증한다."""
    if cfg[name] not in allowed:
        raise Exit(4, f"{name} must be one of {'/'.join(allowed)}, got {cfg[name]!r}")
    return cfg[name]


def _bool(cfg: dict[str, str], name: str) -> bool:
    """true/false 입력을 bool 로 바꾼다."""
    value = cfg[name].lower()
    if value in ("true", "1", "yes"):
        return True
    if value in ("false", "0", "no", ""):
        return False
    raise Exit(4, f"{name} must be true or false, got {cfg[name]!r}")


def _num(cfg: dict[str, str], name: str, cast: type, lo: float, hi: float) -> Any:
    """숫자 입력을 범위 검증해 돌려준다. 빈값은 None(규칙 미생성)."""
    raw = cfg[name]
    if raw == "":
        return None
    try:
        value = cast(raw)
    except ValueError:
        raise Exit(4, f"{name} must be a {cast.__name__}, got {raw!r}") from None
    if not lo <= value <= hi:
        raise Exit(4, f"{name} must be between {lo} and {hi}, got {raw!r}")
    return value


def parse_ignore(raw: str) -> list[str]:
    """콤마·공백·개행 구분 ID 목록을 서버와 같은 규칙으로 검증한다."""
    ids = list(dict.fromkeys(t for t in re.split(r"[,\s]+", raw) if t))
    bad = [t for t in ids if not ID_RE.match(t)]
    if bad:
        raise Exit(
            4,
            f"ignore: invalid IDs {bad[:5]} "
            "(expected CVE-YYYY-NNNN or GHSA-xxxx-xxxx-xxxx, lowercase GHSA body)",
        )
    if len(ids) > MAX_IGNORE_IDS:
        raise Exit(4, f"ignore: {len(ids)} IDs exceeds the limit of {MAX_IGNORE_IDS}")
    return ids


def build_policy(cfg: dict[str, str]) -> str:
    """플랫 입력 키를 서버 PolicySpec JSON 문자열로 조립한다."""
    if cfg["policy-json"]:
        try:
            parsed = json.loads(cfg["policy-json"])
        except ValueError as exc:
            raise Exit(4, f"policy-json is not valid JSON: {exc}") from None
        if not isinstance(parsed, dict):
            raise Exit(4, "policy-json must be a JSON object")
        say("policy-json is set; flat policy inputs are ignored.", "warning")
        return cfg["policy-json"]

    rules: list[dict[str, Any]] = []
    if _bool(cfg, "fail-on-kev"):
        rules.append({"type": "kev_present", "action": "fail"})
    max_cvss = _num(cfg, "max-cvss", float, 0.0, 10.0)
    if max_cvss is not None:
        rules.append(
            {
                "type": "cvss_threshold",
                "min_score": max_cvss,
                "max_count": 0,
                "action": "fail",
            }
        )
    for name, severity in (
        ("max-critical", "CRITICAL"),
        ("max-high", "HIGH"),
        ("max-unknown", "UNKNOWN"),
    ):
        count = _num(cfg, name, int, 0, 10**9)
        if count is not None:
            rules.append(
                {
                    "type": "severity_threshold",
                    "severity": severity,
                    "max_count": count,
                    "action": "fail",
                }
            )
    ids = parse_ignore(cfg["ignore"])
    if ids:
        rules.append({"type": "ignore_list", "cve_ids": ids})
    if not rules:
        # 서버는 rules 가 비면 기본 정책(KEV·CVSS 9+ fail)으로 폴백한다.
        # "규칙 없음"을 지키려고 무해한 warn 규칙 1개를 넣는다.
        rules.append({"type": "kev_present", "action": "warn"})
    return json.dumps({"rules": rules})


# ───────────────────────────── 입력 파일 ─────────────────────────────


def _is_sbom(content: bytes) -> bool:
    """CycloneDX/SPDX JSON 이면 True."""
    try:
        data = json.loads(content)
    except ValueError:
        return False
    return isinstance(data, dict) and (
        data.get("bomFormat") == "CycloneDX" or isinstance(data.get("spdxVersion"), str)
    )


def _read(path: str) -> bytes:
    """파일을 읽는다. 크기 초과는 서버 왕복 없이 판정 불가."""
    size = os.path.getsize(path)
    if size > MAX_UPLOAD_BYTES:
        raise Exit(
            2,
            f"{path} is {size} bytes; the server accepts at most {MAX_UPLOAD_BYTES} "
            "bytes. Upload a smaller lockfile/SBOM via `file:`.",
        )
    with open(path, "rb") as fh:
        return fh.read()


def discover(root: str) -> str:
    """root 직하위에서 서버 파서가 읽는 파일을 정확히 1개 찾는다."""
    names = sorted(os.listdir(root))
    found = []
    for name in names:
        full = os.path.join(root, name)
        if not os.path.isfile(full):
            continue
        if name in LOCKFILES:
            found.append(name)
        elif name.endswith(".json") and os.path.getsize(full) <= MAX_UPLOAD_BYTES:
            with open(full, "rb") as fh:
                if _is_sbom(fh.read()):
                    found.append(name)
    unparsed = [n for n in names if n in UNPARSED]
    if len(found) == 1:
        if unparsed:
            say(
                f"Also found {', '.join(unparsed)} (no server parser); syft covers them."
            )
        return os.path.join(root, found[0])
    lines = [
        (
            f"No supported lockfile/SBOM found in {root!r}."
            if not found
            else f"Found {len(found)} candidate files in {root!r}: {', '.join(found)}."
        ),
        f"Supported: {', '.join(LOCKFILES)}, CycloneDX/SPDX JSON.",
    ]
    if unparsed:
        lines.append(
            f"Found {', '.join(unparsed)}, which have no server parser - "
            "install syft on the runner so it can generate an SBOM that covers them."
        )
    lines.append(
        "Set `file:` to the one file to scan (use a matrix for several), "
        "or install syft."
    )
    raise Exit(4, "\n".join(lines))


def select_input(cfg: dict[str, str]) -> tuple[str, bytes, str]:
    """업로드할 (파일명, 내용, kind)를 정한다: file → syft → lockfile 자동탐색."""
    if cfg["file"]:
        path = cfg["file"]
        if not os.path.isfile(path):
            raise Exit(4, f"file not found: {path}")
    else:
        root = cfg["path"]
        if not os.path.isdir(root):
            raise Exit(4, f"path is not a directory: {root}")
        syft = shutil.which("syft") if cfg["syft"] == "auto" else None
        if syft:
            say(f"Generating a CycloneDX SBOM with syft (dir:{root}).")
            try:
                proc = subprocess.run(
                    [syft, "-q", f"dir:{root}", "-o", "cyclonedx-json"],
                    capture_output=True,
                    timeout=int(cfg["timeout"] or MIN_TIMEOUT),
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    content = proc.stdout
                    if len(content) > MAX_UPLOAD_BYTES:
                        raise Exit(
                            2,
                            f"syft SBOM is {len(content)} bytes (> {MAX_UPLOAD_BYTES}); "
                            "narrow `path` or set `file:`.",
                        )
                    return "syft-sbom.cdx.json", content, "sbom"
                say(
                    f"syft failed (exit {proc.returncode}); falling back to "
                    "lockfile discovery.",
                    "warning",
                )
            except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
                say(
                    f"syft failed ({exc}); falling back to lockfile discovery.",
                    "warning",
                )
        path = discover(root)
    content = _read(path)
    return os.path.basename(path), content, "sbom" if _is_sbom(content) else "lockfile"


# ───────────────────────────── HTTP ─────────────────────────────


def _request(
    method: str,
    url: str,
    api_key: str,
    deadline: float,
    body: bytes | None = None,
    content_type: str | None = None,
) -> tuple[int, Message, bytes]:
    """HTTP 요청 1회. 4xx/5xx 도 (status, headers, body)로 돌려주고 네트워크 오류만 raise."""
    headers = {"X-Api-Key": api_key, "User-Agent": USER_AGENT, "Accept": "*/*"}
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    timeout = max(1.0, min(REQUEST_TIMEOUT, deadline - monotonic()))
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            return resp.status, resp.headers, _read_body(resp, deadline)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, _read_body(exc.fp, deadline) if exc.fp else b""


def _read_body(resp: Any, deadline: float) -> bytes:
    """응답 바디를 상한·마감 안에서 읽는다. 넘으면 네트워크 오류로 취급한다.

    read1 은 수신된 만큼만 돌려주므로 조금씩 흘려보내는 서버도 마감에서 끊긴다.
    """
    chunks: list[bytes] = []
    size = 0
    while chunk := resp.read1(65536):
        size += len(chunk)
        if size > MAX_RESPONSE_BYTES:
            raise http.client.HTTPException(
                f"response body exceeds {MAX_RESPONSE_BYTES} bytes"
            )
        if monotonic() > deadline:
            raise http.client.HTTPException("timed out while reading the response")
        chunks.append(chunk)
    return b"".join(chunks)


def _detail(raw: bytes) -> Any:
    """에러 바디에서 오류 정보(문자열 또는 dict)를 꺼낸다. 실패 시 None.

    서버는 구조화 detail 을 최상위 `error` 객체로,
    문자열 detail 은 `error`/`message` 문자열로 감싼다. 422·FastAPI 기본 형식은 `detail`.
    """
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    if "detail" in data:
        return data["detail"]
    error = data.get("error")
    return error if isinstance(error, dict) else data.get("message", error)


def _describe(status: int | None, raw: bytes) -> str:
    """에러 응답을 사람이 읽을 한 줄로 만든다 — 파싱 실패 시 원문."""
    detail = _detail(raw)
    if isinstance(detail, str):
        text = detail
    elif detail is not None:
        text = json.dumps(detail)
    else:
        text = raw.decode("utf-8", errors="replace")[:2000]
    return f"HTTP {status}: {text}" if status else f"network error: {text}"


def _retry_after(headers: Message | None, detail: Any) -> int:
    """Retry-After 헤더(없으면 detail.retry_after_seconds)를 초로 돌려준다."""
    hint = detail.get("retry_after_seconds") if isinstance(detail, dict) else None
    candidates: tuple[Any, ...] = (
        headers.get("Retry-After") if headers else None,
        hint,
    )
    for value in candidates:
        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            continue
    return DEFAULT_RETRY_AFTER


def _wait(seconds: float, deadline: float, what: str) -> None:
    """총 timeout 안에서만 대기한다. 넘으면 우리 장애(exit 3)."""
    if monotonic() + seconds > deadline:
        raise Exit(3, f"timeout reached while {what}.")
    sleep(seconds)


def _json(raw: bytes) -> dict[str, Any]:
    """성공 응답 바디를 JSON 객체로 파싱한다."""
    try:
        data = json.loads(raw)
    except ValueError:
        data = None
    if not isinstance(data, dict):
        raise Exit(3, f"server returned a non-JSON body: {raw[:200]!r}")
    return data


def _multipart(
    fields: dict[str, str], filename: str, content: bytes
) -> tuple[bytes, str]:
    """multipart/form-data 바디를 만든다."""
    boundary = uuid.uuid4().hex
    safe_name = re.sub(r'[\r\n"\\]', "_", filename)
    parts = [
        f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
        for k, v in fields.items()
    ]
    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
        f'filename="{safe_name}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode()
        + content
        + b"\r\n"
    )
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def upload(
    base: str,
    api_key: str,
    fields: dict[str, str],
    filename: str,
    content: bytes,
    deadline: float,
) -> dict[str, Any]:
    """POST /scan/jobs. 네트워크·5xx 는 백오프 재시도, 429 는 Retry-After 대기."""
    body, ctype = _multipart(fields, filename, content)
    retries = 0
    while True:
        try:
            status, headers, raw = _request(
                "POST", f"{base}/scan/jobs", api_key, deadline, body, ctype
            )
        except NETWORK_ERRORS as exc:
            status, headers, raw = 0, None, str(exc).encode()
        if 200 <= status < 300:
            return _json(raw)
        if status == 0 or status >= 500:
            if retries >= len(UPLOAD_BACKOFF):
                raise Exit(
                    3,
                    f"upload failed after {retries} retries ({_describe(status, raw)}).",
                )
            say(f"Upload failed ({_describe(status, raw)}); retrying.", "warning")
            _wait(UPLOAD_BACKOFF[retries], deadline, "retrying the upload")
            retries += 1
            continue
        detail = _detail(raw)
        error = detail.get("error") if isinstance(detail, dict) else None
        if status == 429 and error != "upload_budget_exceeded":
            wait = _retry_after(headers, detail)
            say(
                f"Rate limited ({error or 'HTTP 429'}); retrying in {wait}s.", "warning"
            )
            _wait(wait, deadline, f"rate limited ({error or 'HTTP 429'})")
            continue
        raise _upload_error(status, detail, raw, fields["policy"])


def _upload_error(status: int, detail: Any, raw: bytes, policy: str) -> Exit:
    """재시도하지 않는 업로드 거부를 exit code 로 분류한다."""
    error = detail.get("error") if isinstance(detail, dict) else None
    if status == 401:
        return Exit(4, f"API key rejected ({_describe(status, raw)}). Check `api-key`.")
    if 300 <= status < 400 or status in (404, 405):
        return Exit(
            4, f"Unexpected response ({_describe(status, raw)}). Check `api-url`."
        )
    if status == 402 and error == "monthly_quota_exceeded":
        return Exit(
            2,
            "Monthly judgment quota exceeded (402 monthly_quota_exceeded): "
            f"plan={detail.get('plan')} limit={detail.get('limit')} "
            f"used={detail.get('used')} reset_at={detail.get('reset_at')}\n"
            f"Upgrade: {detail.get('upgrade_url')}",
        )
    if error == "upload_budget_exceeded":
        return Exit(
            2,
            f"Daily upload budget exceeded ({_describe(status, raw)}); "
            f"resets in {_retry_after(None, detail)}s.",
        )
    if status == 400:
        say(f"Policy JSON sent:\n{policy}")
    return Exit(2, f"Upload rejected ({_describe(status, raw)}).")


def wait_for_result(
    base: str, api_key: str, job_id: str, deadline: float
) -> dict[str, Any]:
    """GET /scan/jobs/{id} 를 3초 간격으로 폴링해 completed/failed job 을 돌려준다."""
    failures = 0
    while True:
        try:
            status, headers, raw = _request(
                "GET", f"{base}/scan/jobs/{job_id}", api_key, deadline
            )
        except NETWORK_ERRORS as exc:
            status, headers, raw = 0, None, str(exc).encode()
        wait: float = POLL_INTERVAL
        if status == 200:
            failures = 0
            job = _json(raw)
            if job.get("status") in ("completed", "failed"):
                return job
        elif status == 0 or status >= 500:
            failures += 1
            if failures >= MAX_POLL_FAILURES:
                raise Exit(
                    3,
                    f"status polling failed {failures} times in a row "
                    f"({_describe(status, raw)}).",
                )
        elif status == 429:
            wait = _retry_after(headers, _detail(raw))
        elif status == 401:
            raise Exit(
                4, f"API key rejected ({_describe(status, raw)}). Check `api-key`."
            )
        else:
            raise Exit(2, f"Status request rejected ({_describe(status, raw)}).")
        _wait(wait, deadline, f"waiting for job {job_id}")


def save_sbom(base: str, api_key: str, job_id: str, path: str, deadline: float) -> None:
    """SBOM 을 저장한다. 실패해도 판정은 바꾸지 않고 경고만 남긴다."""
    try:
        status, _, raw = _request(
            "GET",
            f"{base}/scan/jobs/{job_id}/sbom",
            api_key,
            max(deadline, monotonic() + 30),
        )
        if status != 200:
            raise OSError(_describe(status, raw))
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(raw)
        say(f"SBOM saved to {path}.")
    except NETWORK_ERRORS as exc:
        say(f"Could not save SBOM to {path}: {exc}", "warning")


# ───────────────────────────── 판정 ─────────────────────────────


def unsupported_from_warnings(warnings: list[str]) -> int:
    """`unsupported_ecosystem: eco(N), eco2(M)` 경고에서 N 합계를 구한다(구 캐시 폴백)."""
    return sum(
        int(n)
        for w in warnings
        if w.startswith("unsupported_ecosystem:")
        for n in re.findall(r"\((\d+)\)", w)
    )


def judge(job: dict[str, Any], threshold: float, out: dict[str, str]) -> None:
    """결과를 출력하고 판정한다 — 커버리지·미확정 게이트를 policy.passed 보다 먼저 본다.

    순서: total 0 → 커버리지 → 미확정(unknown_vulnerabilities) → policy.passed.
    판정 불가(2)가 정책 위반(1)보다 앞서지만, 위반 내역은 그 전에 전부 출력한다.
    """
    if job.get("status") == "failed":
        err = job.get("error") or {}
        raise Exit(
            2,
            f"Scan job failed: {err.get('code')}: {err.get('message')}",
        )
    result = job.get("result")
    if not isinstance(result, dict):
        raise Exit(2, "Scan job completed without a result.")

    summary = result.get("summary") or {}
    policy = result.get("policy") or {}
    warnings = [str(w) for w in result.get("warnings") or []]
    freshness = (result.get("data_freshness") or {}).get("internal_db_synced_at")
    total = int(summary.get("total_packages") or 0)
    unsupported = summary.get("unsupported_packages")
    if not isinstance(unsupported, int) or isinstance(unsupported, bool):
        unsupported = unsupported_from_warnings(warnings)
    ratio = unsupported / total if total else None
    unknown = summary.get("unknown_vulnerabilities")
    if not isinstance(unknown, int) or isinstance(unknown, bool):
        unknown = None  # 필드 없는 구 캐시 결과 — 기존 판정으로 폴백
    passed = policy.get("passed")

    out.update(
        {
            "passed": "true" if passed is True else "false" if passed is False else "",
            "total-packages": str(total),
            "total-vulnerabilities": str(summary.get("total_vulnerabilities", "")),
            "kev-count": str(summary.get("kev_count", "")),
            "unsupported-ratio": f"{ratio:.3f}" if ratio is not None else "",
            "data-freshness": str(freshness or ""),
        }
    )
    sev = summary.get("by_severity") or {}
    say(f"Vulnerability DB synced at: {freshness or 'unknown'}")
    say(
        f"Packages: {total}  Vulnerabilities: {summary.get('total_vulnerabilities')}  "
        f"KEV: {summary.get('kev_count')}"
    )
    say(
        "By severity: "
        + " ".join(
            f"{k}={sev.get(k, 0)}"
            for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
        )
    )
    say(
        f"Unsupported packages: {unsupported}/{total} "
        f"(ratio {out['unsupported-ratio'] or 'n/a'}, threshold {threshold})"
    )
    if unknown is not None:
        say(f"Unconfirmed vulnerabilities (needs review): {unknown}")
    if warnings:
        say("Warnings:")
        for w in warnings:
            say(f"  - {w}")
    violations = policy.get("violations") or []
    say(f"Policy: {'passed' if passed else 'FAILED'}")
    for v in violations:
        say(
            f"  - rule={v.get('rule')} count={v.get('count')} "
            f"samples={', '.join(v.get('samples') or [])}"
        )

    if total == 0:
        raise Exit(
            2,
            "No packages were parsed from the input, so nothing was checked. "
            "Check that the file is a supported lockfile/SBOM.",
        )
    if ratio is not None and ratio > threshold:
        ecos = next((w for w in warnings if w.startswith("unsupported_ecosystem:")), "")
        raise Exit(
            2,
            f"Coverage too low: {unsupported}/{total} packages ({ratio:.1%}) are in "
            f"ecosystems VulnIntel cannot assess (threshold {threshold:.0%}). {ecos}\n"
            "Container images are not supported - VulnIntel checks application "
            "dependencies only. If this SBOM came from `syft <image>`, scan the "
            "source tree instead (`syft dir:.`) or upload the lockfile. "
            "Adjust `unsupported-ratio-threshold` only if this is expected.",
        )
    if unknown:
        raise Exit(
            2,
            f"{unknown} vulnerability finding(s) could not be confirmed as affected or "
            "not (the version could not be compared or the range data is incomplete), "
            "so this is not a PASS. "
            + (
                "The policy also FAILED - confirmed violations are listed above. "
                if passed is not True
                else ""
            )
            + "Review them in the VulnIntel scan result, then pin a comparable version "
            "or add the reviewed IDs to `ignore`.",
        )
    if passed is not True:
        raise Exit(1, "Policy violated.")


# ───────────────────────────── main ─────────────────────────────


def run(cfg: dict[str, str], out: dict[str, str]) -> None:
    """입력 검증 → 업로드 → 폴링 → 판정. 정상 PASS 면 그냥 반환한다."""
    api_key = cfg["api-key"]
    if not api_key:
        raise Exit(4, "api-key is required (set it from a repository secret).")
    base = cfg["api-url"].rstrip("/")
    url = urlparse(base)
    if url.username is not None or url.password is not None:
        # URL 을 메시지에 넣지 않는다 — userinfo 에 비밀값이 있을 수 있다
        raise Exit(4, "api-url must not contain credentials (user:pass@).")
    local = url.hostname in ("localhost", "127.0.0.1", "::1")
    if not url.hostname or not (
        url.scheme == "https" or (url.scheme == "http" and local)
    ):
        raise Exit(4, f"api-url must be an https:// URL, got {cfg['api-url']!r}")
    _choice(cfg, "syft", ("auto", "off"))
    scan_depth = _choice(cfg, "scan-depth", ("basic", "precise"))
    no_cache = _bool(cfg, "no-cache")
    threshold = _num(cfg, "unsupported-ratio-threshold", float, 0.0, 1.0)
    if threshold is None:
        raise Exit(4, "unsupported-ratio-threshold must not be empty.")
    timeout = _num(cfg, "timeout", int, 1, 10**6) or MIN_TIMEOUT
    if timeout < MIN_TIMEOUT:
        say(
            f"timeout {timeout}s is below the server's 300s job limit; using {MIN_TIMEOUT}s.",
            "warning",
        )
        timeout = MIN_TIMEOUT
    cfg["timeout"] = str(timeout)
    policy = build_policy(cfg)

    filename, content, kind = select_input(cfg)
    say(f"Uploading {filename} ({kind}, {len(content)} bytes) to {base}.")
    deadline = monotonic() + timeout
    fields = {
        "kind": kind,
        "policy": policy,
        "scan_depth": scan_depth,
        "no_cache": "true" if no_cache else "false",
    }
    created = upload(base, api_key, fields, filename, content, deadline)
    job_id = str(created.get("job_id", ""))
    try:
        uuid.UUID(job_id)
    except ValueError:
        raise Exit(3, f"server returned an invalid job_id: {job_id!r}") from None
    out["job-id"] = job_id
    say(f"Scan job: {job_id}")

    cache_hit = created.get("status") == "completed"
    if cache_hit:
        say(
            "Cache hit: this result may be up to 24h old. "
            "Set `no-cache: true` for a fresh scan."
        )
    job = wait_for_result(base, api_key, job_id, deadline)
    if cfg["sbom-output"] and job.get("status") == "completed":
        save_sbom(base, api_key, job_id, cfg["sbom-output"], deadline)
    judge(job, threshold, out)


def _append(env: str, text: str) -> None:
    """GitHub 파일 명령($GITHUB_OUTPUT 등)이 있을 때만 append 한다."""
    path = os.environ.get(env)
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(text)


def _output_line(key: str, value: str) -> str:
    """$GITHUB_OUTPUT 의 `k=v` 한 줄. 서버 값의 개행으로 다른 출력을 위조하지 못하게 한다."""
    return key + "=" + re.sub(r"[\r\n]", " ", value) + "\n"


def main(argv: list[str] | None = None) -> int:
    """실행 진입점. fail-on 억제 매핑을 적용한 최종 exit code 를 돌려준다."""
    global _SECRET, _GUARD
    _LOG.clear()
    _SECRET, _GUARD = "", None
    try:
        return _main(argv)
    finally:
        if _GUARD:  # 다음 스텝의 워크플로 명령이 막히지 않게 반드시 푼다
            print(f"::{_GUARD}::", flush=True)
        _SECRET, _GUARD = "", None


def _main(argv: list[str] | None) -> int:
    """입력 → 실행 → 판정 출력·파일 명령 기록."""
    out = dict.fromkeys(OUTPUT_KEYS, "")
    fail_on = "policy"
    code, message = 0, "Policy passed and coverage gate passed."
    try:
        cfg = read_inputs(argv)
        _protect(cfg["api-key"])
        fail_on = _choice(cfg, "fail-on", ("policy", "never"))
        run(cfg, out)
    except Exit as exc:
        code, message = exc.code, exc.message

    out["verdict"] = VERDICTS[code]
    if code == 4 or (code in (1, 2) and fail_on == "policy"):
        final = code
    else:
        final = 0
    if code == 0:
        say(f"PASS: {message}")
    elif final == 0:
        say(
            f"{message}\n(verdict {out['verdict']}, exit {code} suppressed to 0 by "
            f"fail-on={fail_on})",
            "warning",
        )
    else:
        say(message, "error")
    say(f"Verdict: {out['verdict']} (exit {final})")

    _append("GITHUB_OUTPUT", "".join(_output_line(k, v) for k, v in out.items()))
    body = "\n".join(_LOG)
    # 서버 문자열의 ``` 가 코드 블록을 닫고 마크다운을 주입하지 못하게 더 긴 펜스를 쓴다
    fence = "`" * max(3, 1 + max(map(len, re.findall(r"`+", body)), default=0))
    _append(
        "GITHUB_STEP_SUMMARY",
        f"### VulnIntel scan: {out['verdict']}\n\n{fence}\n{body}\n{fence}\n",
    )
    return final


if __name__ == "__main__":
    # Windows 러너 콘솔(cp1252 등)에서 비ASCII 서버 문자열로 죽지 않게
    sys.stdout.reconfigure(errors="backslashreplace")  # type: ignore[union-attr]
    sys.exit(main())
