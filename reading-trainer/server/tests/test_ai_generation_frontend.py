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


def test_heading_option_objects_are_rendered_as_text_not_object_object():
    if shutil.which("node") is None:
        pytest.skip("Node.js is required to execute the embedded frontend helpers")
    source = FRONTEND.read_text(encoding="utf-8")
    start = source.index("function headingOptionText(")
    end = source.index("function badge(", start)
    helpers = source[start:end]
    harness = f"""
{helpers}
const values = [
  headingOptionText('i. Moon exploration'),
  headingOptionText({{label: 'ii', text: 'The problem of no air'}}),
  headingOptionText({{id: 'iii', heading: 'Radiation danger'}}),
  headingOptionValue({{value: 'iv', text: 'Extreme temperatures'}})
];
process.stdout.write(JSON.stringify(values));
"""
    result = subprocess.run(
        ["node", "-e", harness],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(result.stdout) == [
        "i. Moon exploration",
        "The problem of no air",
        "Radiation danger",
        "iv",
    ]
    headings_source = _function_source(source, "renderQuestion", "checkQuestion")
    assert "headingOptionValue(h)" in headings_source
    assert "headingOptionText(h)" in headings_source


def test_assignment_flow_exposes_per_question_check_and_full_report():
    source = FRONTEND.read_text(encoding="utf-8")
    render_source = _function_source(source, "renderQuestion", "checkQuestion")
    result_source = _function_source(source, "renderAssignmentResult", "collectAssignmentAnswer")
    report_source = _function_source(source, "buildPracticeReportMarkup", "gradeAll")
    grade_source = _function_source(source, "gradeAll", "assignmentResponseResult")
    assert "itr-assignment-check" in render_source
    assert "itr-assignment-showans" in render_source
    assert "itr-assignment-explain" in render_source
    assert "sharedByType" in result_source
    assert "sharedByExam" in result_source
    assert "buildPracticeReportMarkup" in result_source
    assert "错题与解析" in report_source
    assert "能力分析与学习建议" in report_source
    assert "分项统计" in report_source
    assert "buildPracticeReportMarkup" in grade_source
