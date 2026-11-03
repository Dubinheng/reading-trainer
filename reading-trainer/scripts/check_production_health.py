#!/usr/bin/env python3
"""Check the entry link, reader page, and startup API independently."""

from __future__ import annotations

import argparse
import gzip
import http.client
import json
import sys
import time
import urllib.error
import urllib.request


BASE_URL = "https://kimdu.site/reading-trainer"
USER_AGENT = "ReadingTrainerDeploymentCheck/1.0"


def request(path: str) -> tuple[int, str, bytes]:
    request = urllib.request.Request(
        BASE_URL + path,
        headers={"User-Agent": USER_AGENT, "Cache-Control": "no-cache", "Accept-Encoding": "gzip"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        body = response.read()
        if response.headers.get("Content-Encoding", "").lower() == "gzip":
            body = gzip.decompress(body)
        return response.status, response.headers.get_content_type(), body


def validate(path: str, content_type: str, body: bytes) -> str | None:
    if path == "/api/v2/bootstrap":
        if content_type != "application/json":
            return "启动接口未返回 JSON"
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return "启动接口返回无效 JSON"
        if not isinstance(payload, dict) or payload.get("api_version") != 2 or payload.get("success") is not True:
            return "启动接口未返回有效的 API v2 状态"
        if "state" not in payload or "authenticated" not in payload:
            return "启动接口响应缺少必要字段"
        return None
    if content_type != "text/html" or not body:
        return "网页未返回有效 HTML"
    if path == "/" and b"ielts-toefl-reader.html" not in body and b'id="itr-app"' not in body:
        return "入口缺少阅读页链接"
    if path != "/" and b'id="itr-app"' not in body:
        return "阅读页缺少应用入口"
    return None


def check(label: str, path: str) -> bool:
    start = time.monotonic()
    try:
        status, content_type, body = request(path)
        problem = validate(path, content_type, body) if status == 200 else f"HTTP {status}"
    except urllib.error.HTTPError as error:
        problem = f"HTTP {error.code}"
    except (OSError, EOFError, http.client.HTTPException) as error:
        problem = f"连接失败 ({error})"
    elapsed = time.monotonic() - start
    if problem:
        print(f"FAIL {label} {elapsed:.2f}s — {problem}", file=sys.stderr)
        return False
    print(f"PASS {label} HTTP 200 {elapsed:.2f}s", flush=True)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=1, help="number of checks for each endpoint")
    args = parser.parse_args()
    if not 1 <= args.samples <= 20:
        parser.error("--samples must be between 1 and 20")
    endpoints = (
        ("正式入口", "/"),
        ("阅读页", "/ielts-toefl-reader.html"),
        ("启动接口", "/api/v2/bootstrap"),
    )
    healthy = True
    for sample in range(args.samples):
        if args.samples > 1:
            print(f"样本 {sample + 1}/{args.samples}", flush=True)
        for label, path in endpoints:
            if not check(label, path):
                healthy = False
    return 0 if healthy else 1


if __name__ == "__main__":
    raise SystemExit(main())
