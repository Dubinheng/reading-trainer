#!/usr/bin/env python3
"""Fail fast if Reading Trainer regresses to browser-local persistence."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "ielts-toefl-reader.html"
BACKEND = ROOT / "server" / "reading_trainer_backend.py"


def check_contract() -> list[str]:
    errors: list[str] = []
    frontend = FRONTEND.read_text(encoding="utf-8")
    backend = BACKEND.read_text(encoding="utf-8")

    forbidden_frontend = {
        "localStorage 写入": r"(?:window\.)?localStorage\s*\.\s*setItem\s*\(",
        "sessionStorage 写入": r"(?:window\.)?sessionStorage\s*\.\s*setItem\s*\(",
        "sessionStorage 业务存储": r"(?:window\.)?sessionStorage\s*\.\s*(?:getItem|removeItem|clear)\s*\(",
        "IndexedDB": r"\bindexedDB\s*\.",
        "Cache Storage": r"\bcaches\s*\.\s*open\s*\(",
        "JavaScript 持久 Cookie": r"\bdocument\s*\.\s*cookie\s*=",
        "前端直连飞书": r"https://open\.feishu\.cn/",
        "前端 Authorization 头": r"\bAuthorization\s*:",
    }
    for label, pattern in forbidden_frontend.items():
        if re.search(pattern, frontend, flags=re.IGNORECASE):
            errors.append(f"前端出现禁止项：{label}")

    local_ops = re.findall(
        r"(?:window\.)?localStorage\s*\.\s*([A-Za-z_$][\w$]*)\s*\(", frontend
    )
    unexpected_ops = sorted(set(local_ops) - {"getItem", "removeItem"})
    if unexpected_ops:
        errors.append("localStorage 只允许旧数据迁移读取/删除，发现：" + ", ".join(unexpected_ops))

    fetch_calls = re.findall(r"\bfetch\s*\(\s*([^\n,]+)", frontend)
    for expression in fetch_calls:
        if not expression.strip().startswith("API_V2 +"):
            errors.append(f"前端网络请求没有经过 API v2：fetch({expression.strip()})")

    required_frontend = {
        "API v2 入口": "var API_V2 = '/reading-trainer/api/v2';",
        "服务器全局数据写入": "function persistGlobal(section, value)",
        "服务器用户数据写入": "function persistUserData(section, ownerId, value)",
        "同源安全 Cookie 请求": "credentials:'same-origin'",
    }
    for label, marker in required_frontend.items():
        if marker not in frontend:
            errors.append(f"缺少必要的前端服务器化标记：{label}")

    required_backend = {
        "独立数据库": 'DB_FILENAME = "reading_trainer.db"',
        "禁止复用 resumes.db": 'if self.db_path.name.lower() == "resumes.db"',
        "服务端管理员密码": '"READING_TRAINER_ADMIN_PASSWORD"',
        "飞书幂等计划": "def build_feishu_sync_plan(",
        "飞书敏感字段过滤": "def _is_sensitive_key(",
    }
    for label, marker in required_backend.items():
        if marker not in backend:
            errors.append(f"缺少必要的后端数据保护：{label}")

    return errors


def main() -> int:
    errors = check_contract()
    if errors:
        print("Reading Trainer 数据持久化契约检查失败：", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("PASS: 腾讯服务器主库、飞书同步副本、浏览器无业务持久化写入。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
