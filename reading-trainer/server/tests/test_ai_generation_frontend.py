import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from server.reading_trainer_backend import (
    AI_TIMEOUT_DEFAULT_SECONDS,
    AI_TIMEOUT_MAX_SECONDS,
)


ROOT = Path(__file__).resolve().parents[2]
FRONTEND = ROOT / "ielts-toefl-reader.html"


def _function_source(source: str, name: str, next_name: str) -> str:
    start = source.index(f"function {name}(")
    end = source.index(f"function {next_name}(", start)
    return source[start:end].strip()


def test_generation_timeout_keeps_browser_later_than_backend():
    source = FRONTEND.read_text(encoding="utf-8")
    timeout = int(re.search(r"GENERATION_REQUEST_TIMEOUT_MS\s*=\s*(\d+)", source).group(1))
    batch_source = _function_source(source, "apiGenerateBatch", "apiGenerate")

    assert AI_TIMEOUT_DEFAULT_SECONDS == 110
    assert AI_TIMEOUT_MAX_SECONDS == 300
    assert timeout == 310000
    assert timeout > AI_TIMEOUT_MAX_SECONDS * 1000
    assert "60000" not in batch_source
    assert "clearTimeout(timer)" in batch_source


def test_default_six_questions_are_two_ordered_batches():
    if shutil.which("node") is None:
        pytest.skip("Node.js is required to execute the embedded frontend batch function")
    source = FRONTEND.read_text(encoding="utf-8")
    batch_builder = _function_source(source, "buildGenerationBatches", "generationMaxTokens")
    question_types = [
        "multiple-choice",
        "true-false-notgiven",
        "fill-blank",
        "vocabulary",
        "matching",
        "headings",
    ]
    harness = f"""
const MAX_GENERATION_BATCH_SIZE = 3;
function clampQuestionCount(value, fallback) {{
  let n = parseInt(value, 10);
  if (!Number.isFinite(n)) n = fallback || 6;
  return Math.max(1, Math.min(20, n));
}}
function canonicalQuestionTypes(types) {{ return types.slice(); }}
function allocationTotal(allocation) {{
  return Object.keys(allocation || {{}}).reduce((sum, type) => sum + (parseInt(allocation[type], 10) || 0), 0);
}}
function getGenerationAllocation() {{ throw new Error('valid allocation unexpectedly discarded'); }}
{batch_builder}
const types = ['multiple-choice', 'true-false-notgiven', 'fill-blank', 'vocabulary', 'matching', 'headings'];
const allocation = Object.fromEntries(types.map(type => [type, 1]));
process.stdout.write(JSON.stringify(buildGenerationBatches(6, types, allocation)));
"""
    result = subprocess.run(
        ["node", "-e", harness],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    batches = json.loads(result.stdout)

    assert [batch["count"] for batch in batches] == [3, 3]
    assert sum(batch["count"] for batch in batches) == 6
    assert all(batch["count"] <= 3 for batch in batches)
    merged = {}
    for batch in batches:
        for question_type, count in batch["allocation"].items():
            merged[question_type] = merged.get(question_type, 0) + count
    assert merged == {question_type: 1 for question_type in question_types}

    api_generate = _function_source(source, "apiGenerate", "apiExplain")
    assert "batches.reduce" in api_generate
    assert "apiGenerateBatch" in api_generate
    assert "q.id = i + 1" in api_generate
