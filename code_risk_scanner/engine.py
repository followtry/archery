# -*- coding: utf-8 -*-
"""把范围过滤、检测和报告串起来。"""

import json
import os
import subprocess

from code_risk_scanner import __version__
from code_risk_scanner.catalog import DEFAULT_SHARD_KEYS, RULES, SLA, rule
from code_risk_scanner.detectors import downgrade_background, scan_text
from code_risk_scanner.scope import in_business_scope, is_excluded, iter_source_files
from code_risk_scanner.source import Source

MODES = ("FULL_PERIODIC", "INCREMENTAL_MR")


def scan(repo_path, scan_mode="FULL_PERIODIC", diff_base=None, blame=False,
         sharding_keys=None, skill_dir=None):
    repo = os.path.abspath(repo_path)
    if scan_mode not in MODES:
        raise ValueError("scan_mode 只能是 FULL_PERIODIC 或 INCREMENTAL_MR")
    config = _load_config(repo)
    keys = _shard_keys(sharding_keys, config)
    suppress_rules = {item.upper() for item in config.get("suppress_rules", [])}
    suppress_paths = [item.strip("/") for item in config.get("suppress_paths", []) if item]
    note = ""
    if scan_mode == "INCREMENTAL_MR":
        base = diff_base or "HEAD~1"
        changed = _changed_files(repo, base)
        if changed is None:
            files = list(iter_source_files(repo))
            note = "增量基线 {0} 不可用，已退回全量扫描。".format(base)
        else:
            files = []
            for rel in changed:
                rel = rel.replace("\\", "/").lstrip("./")
                if is_excluded(rel) or not in_business_scope(rel):
                    continue
                if os.path.isfile(os.path.join(repo, rel)):
                    files.append(rel)
    else:
        files = list(iter_source_files(repo))
    files = [rel for rel in files if not _suppressed_path(rel, suppress_paths)]

    findings = []
    errors = []
    for rel in files:
        full = os.path.join(repo, rel)
        try:
            text = _read(full)
            for raw in scan_text(rel, text, keys):
                if raw["rule_id"].upper() in suppress_rules:
                    continue
                findings.append(_materialize(repo, rel, text, raw, blame))
        except Exception as exc:  # 一个文件解析失败不应该让整次巡检没有报告
            errors.append({"file": rel, "error": str(exc)})

    findings.sort(key=lambda item: (
        {"Critical": 0, "Warning": 1, "Suggestion": 2}[item["severity"]],
        item["file_path"],
        item["line_range"],
    ))
    return _report(repo, scan_mode, files, findings, errors, note, skill_dir)


def decide_exit(scan_mode, gate_status):
    """周期巡检只告警，退出码保持 0。MR 模式有 Critical 才拦截。"""
    if scan_mode == "INCREMENTAL_MR" and gate_status == "BLOCK":
        return 1
    return 0


def _materialize(repo, rel, text, raw, blame):
    item = rule(raw["rule_id"])
    source = Source(rel, text)
    line_start = source.line_of(raw["start"])
    line_end = source.line_of(raw["end"])
    if line_end < line_start:
        line_end = line_start
    severity = raw.get("severity") or item["severity"]
    severity, notes = downgrade_background(text, line_start, severity)
    needs_review = bool(raw.get("needs_review") or item["review"] or severity == "Suggestion")
    if needs_review and not any("需人工复核" in note for note in notes):
        notes.append("需人工复核。")
    evidence = raw.get("evidence") or ""
    risk = "原因：{cause} 证据：{evidence} 危害：{harm} 历史故障：{incident}".format(
        cause=item["cause"],
        evidence=evidence,
        harm=item["harm"],
        incident=item["incident"],
    )
    if notes:
        risk = risk + " " + " ".join(notes)
    finding = {
        "rule_id": item["id"],
        "title": item["title"],
        "severity": severity,
        "middleware": item["middleware"],
        "file_path": rel,
        "line_range": "{0}-{1}".format(line_start, line_end),
        "code_snippet": source.snippet(line_start, line_end) or evidence,
        "cause": item["cause"],
        "harm": item["harm"],
        "incident": item["incident"],
        "risk_analysis": risk,
        "remediation_suggestion": SLA[severity] + "\n" + item["remediation"].strip(),
        "needs_review": needs_review,
    }
    if blame:
        owner = _blame(repo, rel, line_start, line_end)
        if owner:
            finding["owner"] = owner
    return finding


def _report(repo, scan_mode, files, findings, errors, note, skill_dir):
    from datetime import datetime, timedelta, timezone

    counts = {"Critical": 0, "Warning": 0, "Suggestion": 0}
    for finding in findings:
        counts[finding["severity"]] += 1
    branch, commit = _git_identity(repo)
    metadata = {
        "repo_name": os.path.basename(repo.rstrip(os.sep)) or repo,
        "branch": branch,
        "commit_id": commit,
        "scan_mode": scan_mode,
        "scanned_files_count": len(files),
        "scanner_version": __version__,
        "generated_at": datetime.now(timezone(timedelta(hours=8))).isoformat(timespec="seconds"),
    }
    if note:
        metadata["scan_note"] = note
    if skill_dir:
        metadata["skill_dir"] = skill_dir
    if errors:
        metadata["scan_errors"] = errors
    return {
        "scan_metadata": metadata,
        "gate_status": "BLOCK" if counts["Critical"] else "PASS",
        "summary": {
            "critical_count": counts["Critical"],
            "warning_count": counts["Warning"],
            "suggestion_count": counts["Suggestion"],
        },
        "findings": findings,
    }


def _shard_keys(cli_keys, config):
    if cli_keys:
        return [item.strip() for item in cli_keys if item.strip()]
    configured = config.get("sharding_keys")
    if configured:
        return list(configured)
    return list(DEFAULT_SHARD_KEYS)


def _load_config(repo):
    path = os.path.join(repo, ".code-risk.json")
    if not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(".code-risk.json 必须是对象")
    return data


def _suppressed_path(rel, prefixes):
    for prefix in prefixes:
        if rel == prefix or rel.startswith(prefix + "/"):
            return True
    return False


def _read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def _git_identity(repo):
    branch = _git(repo, ["rev-parse", "--abbrev-ref", "HEAD"]) or "unknown"
    commit = _git(repo, ["rev-parse", "HEAD"]) or "unknown"
    return branch, commit


def _changed_files(repo, base):
    """返回相对扫描根目录的变更文件。拿不到基线时返回 None，调用方退回全量。"""
    top = _git(repo, ["rev-parse", "--show-toplevel"])
    if not top:
        return None
    try:
        out = subprocess.check_output(
            ["git", "diff", "--name-only", "--diff-filter=ACMRT", "{0}...HEAD".format(base)],
            cwd=top,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
        )
    except (subprocess.CalledProcessError, OSError, subprocess.TimeoutExpired):
        return None
    prefix = os.path.relpath(os.path.abspath(repo), top).replace("\\", "/")
    names = []
    for line in out.splitlines():
        path = line.strip().replace("\\", "/")
        if not path:
            continue
        if prefix == ".":
            names.append(path)
            continue
        if path == prefix:
            continue
        if path.startswith(prefix + "/"):
            names.append(path[len(prefix) + 1:])
    return names


def _blame(repo, rel, start, end):
    try:
        out = subprocess.check_output(
            ["git", "log", "-n", "1", "--pretty=format:%an <%ae>", "-L", "{0},{1}:{2}".format(start, end, rel)],
            cwd=repo,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=15,
        )
    except (subprocess.CalledProcessError, OSError, subprocess.TimeoutExpired):
        return ""
    line = out.strip().splitlines()
    return line[0].strip() if line else ""


def _git(repo, args):
    try:
        return subprocess.check_output(
            ["git"] + args, cwd=repo, stderr=subprocess.DEVNULL, text=True, timeout=10
        ).strip()
    except (subprocess.CalledProcessError, OSError, subprocess.TimeoutExpired):
        return ""


def known_rule_ids():
    return list(RULES)
