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


def test_assignment_send_requires_server_ack_and_all_recipients():
    if shutil.which("node") is None:
        pytest.skip("Node.js is required to execute the embedded frontend helper")
    source = FRONTEND.read_text(encoding="utf-8")
    start = source.index("function assignmentSendResponseConfirmed(")
    end = source.index("function confirmAssignmentAfterTransportError(", start)
    helper = source[start:end]
    harness = f"""
function assignmentId(a) {{ return a && (a.id != null ? a.id : (a.assignmentId != null ? a.assignmentId : a.assignment_id)); }}
function assignmentObjectFromResponse(res) {{ return res && (res.assignment || res.item || null); }}
{helper}
const cases = [
  assignmentSendResponseConfirmed({{ok:true, assignment:{{id:'asgn_1', status:'sent', studentIds:['s1','s2']}}}}, 'asgn_1', ['s1','s2']),
  assignmentSendResponseConfirmed({{ok:true, assignment:{{id:'asgn_1', status:'sent', studentIds:['s1']}}}}, 'asgn_1', ['s1','s2']),
  assignmentSendResponseConfirmed({{ok:true, assignment:{{id:'asgn_1', status:'draft', studentIds:['s1']}}}}, 'asgn_1', ['s1']),
  assignmentSendResponseConfirmed({{ok:false, assignment:{{id:'asgn_1', status:'sent', studentIds:['s1']}}}}, 'asgn_1', ['s1'])
];
process.stdout.write(JSON.stringify(cases));
"""
    result = subprocess.run(["node", "-e", harness], cwd=ROOT, capture_output=True, text=True, check=True)
    assert json.loads(result.stdout) == [True, False, False, False]


def test_assignment_vocabulary_reuses_server_book_and_source_article():
    source = FRONTEND.read_text(encoding="utf-8")
    render_source = _function_source(source, "renderAssignmentAnswer", "openAssignment")
    add_source = _function_source(source, "addAssignmentSelection", "renderAssignmentAnswer")
    persist_source = _function_source(source, "addVocabToBook", "renderVBook")
    assert "itr-assignment-vocab-extract" in render_source
    assert "itr-assignment-vocab-add" in render_source
    assert "itr-assignment-source-text" in render_source
    assert "assignmentSelectionFromArticle" in render_source
    assert "assignmentVocabMetadata" in add_source
    assert "sourceType: 'assignment'" in source
    assert "assignmentId: assignmentId(detail)" in source
    assert "apiV2('/vbook/items'" in persist_source
    assert "res.ok !== true" in persist_source
    assert "服务器未确认生词保存" in persist_source


def test_assignment_article_selection_keeps_phrase_context():
    if shutil.which("node") is None:
        pytest.skip("Node.js is required to execute the embedded selection helper")
    source = FRONTEND.read_text(encoding="utf-8")
    selection_source = _function_source(source, "assignmentSelectionFromArticle", "assignmentVocabMetadata")
    harness = f"""
var assignmentState = {{ vocabSelection: null }};
var fakeNode = {{ nodeType: 1 }};
var sourceEl = {{ contains: function (node) {{ return node === fakeNode; }} }};
var window = {{ getSelection: function () {{ return {{
  rangeCount: 1,
  isCollapsed: false,
  toString: function () {{ return 'valuable knowledge'; }},
  getRangeAt: function () {{ return {{ commonAncestorContainer: fakeNode }}; }}
}}; }} }};
function splitSentences(text) {{ return text.match(/[^.!?]+[.!?]+/g).map(function (item) {{ return item.trim(); }}); }}
{selection_source}
var result = assignmentSelectionFromArticle(sourceEl, [{{
  text: 'Students preserve valuable knowledge. Another sentence follows.',
  articleIndex: 2
}}]);
process.stdout.write(JSON.stringify(result));
"""
    result = subprocess.run(["node", "-e", harness], cwd=ROOT, capture_output=True, text=True, check=True)
    assert json.loads(result.stdout) == {
        "word": "valuable knowledge",
        "ctx": "Students preserve valuable knowledge.",
        "articleIndex": 2,
        "invalid": False,
    }


def test_assignment_wrong_book_uses_server_confirmed_idempotent_item_api():
    source = FRONTEND.read_text(encoding="utf-8")
    add_source = _function_source(source, "addAssignmentWrongToBook", "renderAssignmentQuestionFeedback")
    feedback_source = _function_source(source, "renderAssignmentQuestionFeedback", "checkAssignmentQuestion")
    submit_source = _function_source(source, "submitAssignmentAnswers", "assignmentArticleEntries")
    assert "apiV2('/wbook/items'" in add_source
    assert "sourceType: 'assignment'" in add_source
    assert "res.ok !== true" in add_source
    assert "服务器未确认错题保存" in add_source
    assert "applyServerState(res.state)" in add_source
    assert "itr-assignment-wrong-add" in feedback_source
    assert "addAssignmentWrongToBook" in feedback_source
    assert "applyServerState(res.state)" in submit_source


def test_student_personal_diagnosis_uses_shared_grade_dimensions():
    source = FRONTEND.read_text(encoding="utf-8")
    diagnosis_source = _function_source(source, "renderStudentDiagnosis", "renderStats")
    render_source = _function_source(source, "renderStats", "exportScorePDF")
    grade_source = _function_source(source, "gradeAll", "assignmentResponseResult")
    assert "学生个人诊断" in diagnosis_source
    assert "近 10 次" in diagnosis_source
    assert "能力与题型" in diagnosis_source
    assert "练习记录" in diagnosis_source
    assert "currentUser.role === 'student'" in render_source
    assert "renderStudentDiagnosis(panel, currentUser.id" in render_source
    assert "DIAGNOSIS_ABILITIES" in source
    assert "证据定位" in source
    assert "source: 'practice'" in grade_source
    assert "byType: cloneData(byType" in grade_source
    assert "byExam: cloneData(examDetail" in grade_source


def test_student_personal_diagnosis_aggregates_assignment_and_practice_records():
    if shutil.which("node") is None:
        pytest.skip("Node.js is required to execute the embedded diagnosis helpers")
    source = FRONTEND.read_text(encoding="utf-8")
    start = source.index('var studentDiagnosisState =')
    end = source.index('function renderStudentDiagnosis(', start)
    helpers = source[start:end]
    harness = f"""
function normType(value) {{ return value; }}
function escapeHtml(value) {{ return String(value == null ? '' : value); }}
function typeLabel(value) {{ return value; }}
var TYPE_ADVICE = {{}};
{helpers}
const records = [
  {{ts:1, source:'practice', total:6, right:4, unanswered:1, byType:{{'fill-blank':{{total:3,right:2}},headings:{{total:3,right:2}}}}, byExam:{{IELTS:{{total:6,right:4}}}}}},
  {{ts:2, source:'assignment', assignmentId:'a1', total:4, right:3, unanswered:0, byType:{{headings:{{total:2,right:2}},vocabulary:{{total:2,right:1}}}}, byExam:{{TOEFL:{{total:4,right:3}}}}}}
];
studentDiagnosisState.period = 'all';
const totals = diagnosisTotals(diagnosisFilteredRecords(records));
const types = diagnosisAggregateTypes(diagnosisFilteredRecords(records));
const abilities = diagnosisAbilityData(types);
studentDiagnosisState.source = 'assignment';
const assignmentOnly = diagnosisFilteredRecords(records);
process.stdout.write(JSON.stringify({{totals,types,abilities,assignmentOnly:assignmentOnly.length}}));
"""
    result = subprocess.run(["node", "-e", harness], cwd=ROOT, capture_output=True, text=True, check=True)
    data = json.loads(result.stdout)
    assert data["totals"] == {"total": 10, "right": 7, "unanswered": 1, "pct": 70}
    assert data["types"]["headings"] == {"right": 4, "total": 5, "unanswered": 0, "pct": 80}
    assert next(item for item in data["abilities"] if item["name"] == "主旨与结构")["pct"] == 80
    assert data["assignmentOnly"] == 1


def test_pdf_export_has_watermark_controls_and_no_heading_answer_leak():
    source = FRONTEND.read_text(encoding="utf-8")
    worksheet_source = _function_source(source, "worksheetQuestion", "worksheetAnswerSheet")
    assert "itr-paper-watermark" in source
    assert "opacity: .3" in source
    assert "itr-pdf-export-modal" in source
    assert "导出 A4 PDF" in source
    assert "发送答题作业" in source
    assert re.search(r"MAX_PDF_ANSWER_SLOTS\s*=\s*60", source)
    assert "请减少题目或拆分试卷" in source
    assert "escapeHtml(it.heading)" not in worksheet_source
    assert "headingOptionValue(q.answer" not in worksheet_source


def test_vocab_selection_is_shared_and_server_confirmed():
    source = FRONTEND.read_text(encoding="utf-8")
    assert "function normalizeVocabSelection(" in source
    assert "selectionFromArticleSource" in source
    assert "practiceVocabOwnerIds" in source
    assert "POST /vbook/items" in source
    assert "res.ok !== true" in _function_source(source, "addVocabToBook", "renderVBook")
    assert "getTargetStudentIds()" not in _function_source(source, "addSelectionToVBook", "doVocabExtract")


def test_teacher_and_student_top_tabs_have_role_scoped_defs():
    source = FRONTEND.read_text(encoding="utf-8")
    build = _function_source(source, "buildTabs", "switchTab")
    teacher_block, student_block = build.split("} else {", 1)
    assert 'currentRole === "teacher"' in build
    assert 'pane: "teacher"' in teacher_block
    assert 'pane: "grades"' not in teacher_block
    assert 'pane: "wbook"' not in teacher_block
    assert 'pane: "vbook"' not in teacher_block
    assert 'pane: "library"' in teacher_block
    assert 'id: "itr-teacher-tab"' in teacher_block
    assert 'pane: "grades"' in student_block
    assert 'pane: "wbook"' in student_block
    assert 'pane: "vbook"' in student_block
    assert 'pane: "assignments"' in student_block
    assert 'pane: "library"' in student_block
    student_order = [
        student_block.index('pane: "practice"'),
        student_block.index('pane: "assignments"'),
        student_block.index('pane: "wbook"'),
        student_block.index('pane: "library"'),
        student_block.index('pane: "vbook"'),
        student_block.index('pane: "grades"'),
    ]
    assert student_order == sorted(student_order)
    # Teacher navigation is intentionally a short, dedicated set.
    assert 'defs = [' in build and 'pane: "library"' in build
    assert 'tabGroup.className = "itr-tab-main"' in build
    assert "tabGroup.appendChild(b);" in build
    assert "#itr-app .itr-tab-main { display: flex; gap: 8px;" in source


def test_teacher_practice_has_no_vocab_or_wrongbook_controls():
    source = FRONTEND.read_text(encoding="utf-8")
    render_question = _function_source(source, "renderQuestion", "checkQuestion")
    render_cards = _function_source(source, "renderCards", "renderWorksheet")
    grade = _function_source(source, "gradeAll", "assignmentResponseResult")
    assert 'data-itr-role="teacher"' in source
    assert 'id="itr-vocab-btn"' in source
    assert 'id="itr-add-sel-vocab"' in source
    assert "options.hideVocab ? ''" in render_question
    assert 'hideVocab: !!(currentUser && currentUser.role === "teacher")' in render_cards
    assert "if (!currentUser || currentUser.role !== 'teacher') wrongs.forEach" in grade
    assert "enableWrongBook: !currentUser || currentUser.role !== 'teacher'" in grade


def test_teacher_detail_tabs_use_scoped_ids_and_bind_once():
    source = FRONTEND.read_text(encoding="utf-8")
    assert 'data-tc-tab="score"' in source
    assert 'data-tc-tab="wrong"' in source
    assert 'data-tc-tab="vocab"' in source
    assert 'data-tc-tab="tasks"' in source
    detail = _function_source(source, "selectTeacherStudent", "renderTCScorePanel")
    assert "data-bound" in detail
    assert "tabsContainer.parentNode.querySelectorAll" in detail
    assert "tc-panel-' + t.getAttribute('data-tc-tab')" in detail


def test_teacher_score_uses_pct_and_ts_and_wrong_book_user_answer():
    source = FRONTEND.read_text(encoding="utf-8")
    score = _function_source(source, "renderTCScorePanel", "renderTCWrongPanel")
    wrong = _function_source(source, "renderTCWrongPanel", "renderTCVocabPanel")
    assert "renderStudentDiagnosis(panel, studentId, { readonly: true })" in score
    assert "g.score" not in score
    assert "g.date" not in score
    assert "item.userAnswer" in wrong
    assert "data-tc-wrong" in wrong
    assert "data-tc-vocab" in _function_source(source, "renderTCVocabPanel", "renderTCTasksPanel")


def test_wrong_review_posts_server_review_and_no_local_box_mutation():
    source = FRONTEND.read_text(encoding="utf-8")
    wrong = _function_source(source, "wrongReview", "getStudents")
    assert "/wbook/items/" in wrong
    assert "/review" in wrong
    assert "masteryStreak" in wrong
    assert "answered" in wrong
    assert "res && res.correct === true" in wrong
    assert "res && res.answered != null" in wrong
    assert "saveWBook" not in source
    assert "item.box =" in _function_source(source, "vocabReview", "bookKey")


def test_wrong_book_groups_by_article_and_opens_article_review():
    source = FRONTEND.read_text(encoding="utf-8")
    render = _function_source(source, "renderWBook", "renderWrongArticle")
    detail = _function_source(source, "renderWrongArticle", "wrongReview")
    review = _function_source(source, "wrongReview", "getStudents")
    assert "wrongArticleGroups(book, 'pending')" in render
    assert "待巩固文章" in render and "已掌握文章" in render
    assert "查看并重做本篇错题" in render
    assert "重做本篇错题" in detail
    assert "group.items.map" in detail
    assert 'class="itr-article itr-warticle-passage"' in detail
    assert "details.itr-warticle-passage { width:100%; max-width:none;" in source
    assert ".itr-warticle-passage .itr-article { width:100%; max-width:none;" in source
    assert "正确率 " in review
    assert "newlyMastered" in review and "byType" in review


def test_review_assignment_submit_and_vocabulary_report_contract():
    source = FRONTEND.read_text(encoding="utf-8")
    review_question = _function_source(source, "assignmentReviewQuestion", "assignmentIsReview")
    assert "question.id = reviewId" in review_question
    assert "question.questionId = reviewId" in review_question
    assert "assignmentType" in source
    assert "reviewItems" in source
    assert "viewedVocabIds" in _function_source(source, "submitAssignmentAnswers", "assignmentArticleEntries")
    render_answer = _function_source(source, "renderAssignmentAnswer", "openAssignment")
    assert "completedViewedIds" in render_answer
    assert "viewed ? '已查看' : '未查看'" in render_answer
    report = _function_source(source, "renderAssignmentResult", "collectAssignmentAnswer")
    assert "vocabulary" in report
    assert "sharedTotal === 0" in report
    assert "不计入阅读题正确率或成绩趋势" in report
    assert "未查看" in source
    composer = _function_source(source, "openTeacherReviewComposer", "getWBookForStudent")
    assert "apiV2('/assignments/review'" in composer
    assert "sourceStudentId" in composer and "wrongItemIds" in composer and "vocabItemIds" in composer
    assert "reviewRequestId = uid('review')" in composer
    assert "assignmentSendResponseConfirmed(res, reviewRequestId, ids)" in composer
    assert "sourceClass ? getStudentsByTeacher" in composer


def test_practice_attempt_id_and_server_wrong_item_payload():
    source = FRONTEND.read_text(encoding="utf-8")
    grade = _function_source(source, "gradeAll", "assignmentResponseResult")
    add = _function_source(source, "addWrongToBook", "wrongItemId")
    assert "practiceAttemptId" in grade
    assert "attemptId" in add
    assert "userAnswer" in add
    assert "apiV2('/wbook/items'" in add
