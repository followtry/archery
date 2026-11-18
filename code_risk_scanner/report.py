# -*- coding: utf-8 -*-
"""报告校验、告警正文。不发网络请求，除非调用方明确传入 webhook。"""

import json
import os
import urllib.request

_SEVERITY = {"Critical", "Warning", "Suggestion"}
_MIDDLEWARE = {"TDDL", "Lindorm", "Redis", "ES", "Java", "Go", "Env", "Security"}
_MODES = {"FULL_PERIODIC", "INCREMENTAL_MR"}
_FINDING_KEYS = [
    "rule_id", "severity", "middleware", "file_path", "line_range",
    "code_snippet", "cause", "harm", "risk_analysis", "remediation_suggestion",
]


def validate(report):
    """对照输出契约做门禁自检。不合规直接抛 ValueError，避免把坏报告送进流水线。"""
    if not isinstance(report, dict):
        raise ValueError("报告必须是对象")
    for key in ("scan_metadata", "gate_status", "summary", "findings"):
        if key not in report:
            raise ValueError("缺少字段 {0}".format(key))
    meta = report["scan_metadata"]
    for key in ("repo_name", "branch", "commit_id", "scan_mode", "scanned_files_count"):
        if key not in meta:
            raise ValueError("scan_metadata 缺少 {0}".format(key))
    if meta["scan_mode"] not in _MODES:
        raise ValueError("scan_mode 不合法")
    if not isinstance(meta["scanned_files_count"], int) or meta["scanned_files_count"] < 0:
        raise ValueError("scanned_files_count 必须是非负整数")
    if report["gate_status"] not in ("PASS", "BLOCK"):
        raise ValueError("gate_status 不合法")
    summary = report["summary"]
    counts = {}
    for name, field in (
        ("Critical", "critical_count"),
        ("Warning", "warning_count"),
        ("Suggestion", "suggestion_count"),
    ):
        value = summary.get(field)
        if not isinstance(value, int) or value < 0:
            raise ValueError("{0} 必须是非负整数".format(field))
        counts[name] = value
    if not isinstance(report["findings"], list):
        raise ValueError("findings 必须是数组")
    seen = {"Critical": 0, "Warning": 0, "Suggestion": 0}
    for finding in report["findings"]:
        for key in _FINDING_KEYS:
            if not finding.get(key) and finding.get(key) != 0:
                raise ValueError("{0} 缺少或为空: {1}".format(finding.get("rule_id"), key))
        if finding["severity"] not in _SEVERITY:
            raise ValueError("severity 不合法")
        if finding["middleware"] not in _MIDDLEWARE:
            raise ValueError("middleware 不合法")
        parts = finding["line_range"].split("-")
        if len(parts) != 2 or not all(part.isdigit() for part in parts):
            raise ValueError("line_range 必须是 起-止")
        if finding["cause"] not in finding["risk_analysis"] or finding["harm"] not in finding["risk_analysis"]:
            raise ValueError("{0} 的 risk_analysis 没有同时写上原因和危害".format(finding["rule_id"]))
        if finding["severity"] == "Suggestion" and "需人工复核" not in finding["risk_analysis"]:
            raise ValueError("{0} 是 Suggestion 但没有标注需人工复核".format(finding["rule_id"]))
        seen[finding["severity"]] += 1
    for name, field in (
        ("Critical", "critical_count"),
        ("Warning", "warning_count"),
        ("Suggestion", "suggestion_count"),
    ):
        if counts[name] != seen[name]:
            raise ValueError("{0} 与明细不一致".format(field))
    expect = "BLOCK" if counts["Critical"] else "PASS"
    if report["gate_status"] != expect:
        raise ValueError("gate_status 应为 {0}".format(expect))
    return report


def render_alert(report):
    """给人读的告警正文：每条都有原因、危害、修复。"""
    summary = report["summary"]
    meta = report["scan_metadata"]
    lines = [
        "# 代码隐患巡检 {0}".format(report["gate_status"]),
        "",
        "- 仓库：{0}  分支：{1}  提交：{2}".format(meta.get("repo_name", ""), meta.get("branch", ""), meta.get("commit_id", "")),
        "- 模式：{0}  扫描文件：{1}  时间：{2}".format(
            meta.get("scan_mode", ""), meta.get("scanned_files_count", 0), meta.get("generated_at", "")
        ),
        "- Critical {0} / Warning {1} / Suggestion {2}".format(
            summary["critical_count"], summary["warning_count"], summary["suggestion_count"]
        ),
    ]
    if meta.get("scan_note"):
        lines.append("- 说明：{0}".format(meta["scan_note"]))
    if report["gate_status"] == "BLOCK":
        lines.append("- 门禁：存在 Critical，MR 模式应拦截合入。周期巡检只告警，不因本报告失败。")
    else:
        lines.append("- 门禁：没有 Critical，允许合入。Warning 和 Suggestion 仍要看。")
    lines.append("")
    if not report["findings"]:
        lines.append("没有命中。")
        return "\n".join(lines) + "\n"
    for finding in report["findings"]:
        lines.append("## [{severity}] {rule_id} {title}".format(**finding))
        lines.append("")
        owner = finding.get("owner")
        where = "{0}:{1}".format(finding["file_path"], finding["line_range"])
        lines.append("- 位置：{0}".format(where if not owner else where + "  最近修改：" + owner))
        lines.append("- 原因：{0}".format(finding["cause"]))
        lines.append("- 危害：{0}".format(finding["harm"]))
        if finding.get("incident"):
            lines.append("- 历史故障：{0}".format(finding["incident"]))
        lines.append("- 代码：")
        lines.append("")
        lines.append("```")
        lines.append(finding["code_snippet"])
        lines.append("```")
        lines.append("")
        lines.append(finding["remediation_suggestion"])
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def dingtalk_payload(report):
    text = render_alert(report)
    if len(text) > 15000:
        text = text[:15000] + "\n\n（正文已截断，完整结果看扫描报告文件）"
    return {
        "msgtype": "markdown",
        "markdown": {
            "title": "代码隐患巡检 {0}".format(report["gate_status"]),
            "text": text,
        },
    }


def notify_dingtalk(report, webhook):
    payload = json.dumps(dingtalk_payload(report), ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        webhook,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return response.read().decode("utf-8", errors="replace")


def load_report(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def dump_report(report, path):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
