#!/usr/bin/env python3
"""Verify that the published Reading Trainer page and v2 API are both mounted."""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request


BASE_URL = "https://kimdu.site/reading-trainer"
USER_AGENT = "ReadingTrainerDeploymentCheck/1.0"


def request(path: str) -> tuple[int, str, bytes]:
    request = urllib.request.Request(
        BASE_URL + path,
        headers={"User-Agent": USER_AGENT, "Cache-Control": "no-cache"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return response.status, response.headers.get_content_type(), response.read()


def main() -> int:
    try:
        page_status, page_type, page_body = request("/")
        api_status, api_type, api_body = request("/api/v2/bootstrap")
        payload = json.loads(api_body)
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        print(f"FAIL: 生产环境请求失败：{error}", file=sys.stderr)
        return 1

    errors: list[str] = []
    if page_status != 200 or page_type != "text/html" or not page_body:
        errors.append(f"网页异常：HTTP {page_status}, Content-Type {page_type}")
    if api_status != 200 or api_type != "application/json":
        errors.append(f"API 异常：HTTP {api_status}, Content-Type {api_type}")
    if payload.get("api_version") != 2 or payload.get("success") is not True:
        errors.append("bootstrap 未返回有效的 API v2 状态")
    if "state" not in payload or "authenticated" not in payload:
        errors.append("bootstrap 响应缺少必要字段")

    if errors:
        print("FAIL: Reading Trainer 生产部署不完整：", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print("PASS: 正式网页与 /reading-trainer/api/v2/bootstrap 均正常。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
