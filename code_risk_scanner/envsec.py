# -*- coding: utf-8 -*-
"""环境隔离和安全防护。只认连接串、密钥字面量和同一方法里的写入口。"""

import os
import re

_ENDPOINT = re.compile(
    r"(?i)(?:jdbc:[a-z0-9:+]+//|redis://|rediss://|https?://)[^\s\"'`\\]{3,180}"
)
_SECRET_LINE = re.compile(
    r"(?i)\b(password|passwd|secret_key|secretkey|access_key|accesskey|app_secret|appsecret)\b\s*[:=]\s*(.+)$"
)
_SECRET_CALL = re.compile(
    r"(?i)set(?:Password|Secret|AccessKey)\s*\(\s*(['\"])([^'\"]{4,})\1"
)
_USER_COLS = {
    "user_id", "uid", "buyer_id", "seller_id", "member_id", "account_id", "customer_id",
}
_SKIP_SECRET = {"null", "none", "false", "true", "changeme", "your_password", "password", "secret"}


def scan(path, text):
    hits = []
    hits.extend(_environments(path, text))
    hits.extend(_secrets(text))
    hits.extend(_missing_sign(text))
    hits.extend(_cross_user_write(text))
    return hits


def _hit(rule_id, start, end, evidence):
    return {
        "rule_id": rule_id,
        "start": start,
        "end": max(start, end),
        "evidence": evidence,
        "needs_review": False,
    }


def _environments(path, text):
    declared = _declared_env(path)
    found = []
    for match in _ENDPOINT.finditer(text):
        url = match.group(0)
        if "${" in url:
            continue
        env = _endpoint_env(url)
        if env:
            found.append((match.start(), match.end(), env, url))
    hits = []
    distinct = []
    for start, end, env, url in found:
        if env not in distinct:
            distinct.append(env)
        if declared and env != declared:
            hits.append(_hit(
                "ENV-002", start, end,
                "文件声明的是{0}，连接串指向{1}：{2}".format(_label(declared), _label(env), url),
            ))
        elif not declared:
            hits.append(_hit(
                "ENV-001", start, end,
                "连接串写死了{0}地址，没有按环境切换：{1}".format(_label(env), url),
            ))
    if not declared and len(distinct) >= 2:
        hits.append(_hit(
            "ENV-003", found[0][0], found[0][1],
            "同一份默认配置里同时有{0}。".format("、".join(_label(item) for item in distinct)),
        ))
    return hits


def _secrets(text):
    hits = []
    for index, line in enumerate(text.splitlines()):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        match = _SECRET_LINE.search(line)
        if not match:
            continue
        value = _clean_secret(match.group(2))
        if value is None:
            continue
        start = text.find(line)
        if start < 0:
            start = 0
        hits.append(_hit("SEC-001", start, start + len(line), "密钥以明文写在源码或配置里。"))
    for match in _SECRET_CALL.finditer(text):
        value = match.group(2)
        if value.startswith("${") or value.startswith("ENC("):
            continue
        hits.append(_hit("SEC-001", match.start(), match.end(), "setPassword/setSecret 传入了明文。"))
    return hits


def _missing_sign(text):
    from code_risk_scanner.source import Source

    hits = []
    source = Source(path_of(text), text)
    for method in source.methods():
        around = method.header + method.text
        if not re.search(r"(?i)notify|callback|验签", around):
            continue
        if not re.search(r"(?i)\b(update|delete|insert|save)\s*\(|\b(update|delete)\s+\w+", method.text):
            continue
        if re.search(r"(?i)checkSign|verifySign|signature|验签|\.verify\s*\(|\bhmac\b|\brsa\b", around):
            continue
        hits.append(_hit(
            "SEC-002", method.start, method.end,
            "通知或回调入口改了数据，方法里没有验签。",
        ))
    return hits


def _cross_user_write(text):
    from code_risk_scanner.detectors import _sql_spans, _where_columns
    from code_risk_scanner.source import Source

    hits = []
    source = Source(path_of(text), text)
    for method in source.methods():
        around = method.header + method.text
        if not re.search(
            r"(?i)getParameter\s*\(\s*['\"](?:orderId|bizOrderId|refundId|id)['\"]"
            r"|@RequestParam\b[^)\n]{0,80}\b(?:orderId|bizOrderId|refundId)\b",
            around,
        ):
            continue
        if re.search(r"(?i)checkOwner|checkUser|verifyUser|hasPermission|getCurrentUser|getLoginUser|鉴权", method.text):
            continue
        for start, end, sql in _sql_spans(text):
            if start < method.start or start >= method.end:
                continue
            if not re.match(r"(?is)\s*(update|delete)\b", sql):
                continue
            cols = _where_columns(sql) or set()
            if cols & _USER_COLS:
                continue
            hits.append(_hit(
                "SEC-003", start, end,
                "按外部传入的单号更新或删除，WHERE 没有用户归属列，方法里也没有归属校验。",
            ))
    return hits


def _declared_env(path):
    name = os.path.basename(path).lower()
    if any(token in name for token in ("production", "online", "-prod", ".prod", "_prod")):
        return "prod"
    if "gray" in name or "grey" in name:
        return "gray"
    if "prepub" in name or "-pre" in name or ".pre" in name or "_pre" in name:
        return "pre"
    if "daily" in name or "-dev" in name:
        return "daily"
    return None


def _endpoint_env(url):
    if re.search(r"(?i)(?:\.|//)daily(?:\.|/|:|$)|//daily-", url):
        return "daily"
    if re.search(r"(?i)(?:\.|//)(?:prepub|pre)(?:\.|/|:|$)|//pre-", url):
        return "pre"
    if re.search(r"(?i)(?:\.|//)(?:gray|grey)(?:\.|/|:|$)|//(?:gray|grey)-", url):
        return "gray"
    if re.search(r"(?i)(?:\.|//)(?:online|prod|production)(?:\.|/|:|$)", url):
        return "prod"
    return None


def _label(env):
    return {"daily": "日常", "pre": "预发", "gray": "灰度", "prod": "生产"}[env]


def _clean_secret(raw):
    value = raw.strip().strip(",").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        value = value[1:-1].strip()
    if not value or value.startswith("${") or value.startswith("ENC(") or value.startswith("<"):
        return None
    if value.lower() in _SKIP_SECRET or len(value) < 4 or set(value) <= {"*"}:
        return None
    return value


def path_of(text):
    return "<mem>"
