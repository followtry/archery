# -*- coding: utf-8 -*-
"""源码窗口与括号配对。ponytail: 只跳过字符串，不跳过注释；注释里的括号会带偏配对。升级路径是换 tree-sitter。"""

import re

_METHOD_REJECT = re.compile(
    r"\b(if|else|for|while|switch|catch|try|do)\b[^{]*$"
)


class Method(object):
    def __init__(self, start, end, text, header):
        self.start = start
        self.end = end
        self.text = text
        self.header = header


class Source(object):
    def __init__(self, path, text):
        self.path = path.replace("\\", "/")
        self.text = text
        self.lines = text.splitlines()
        self._methods = None

    def line_of(self, index):
        if index <= 0:
            return 1
        if index >= len(self.text):
            return max(1, len(self.lines))
        return self.text.count("\n", 0, index) + 1

    def snippet(self, line_start, line_end):
        if not self.lines:
            return ""
        a = max(1, line_start)
        b = min(len(self.lines), max(a, line_end))
        if b - a > 14:
            b = a + 14
        chunk = "\n".join(self.lines[a - 1:b]).strip()
        if len(chunk) > 800:
            chunk = chunk[:800] + "..."
        return chunk

    def window(self, index, radius=8):
        line = self.line_of(index)
        a = max(1, line - radius)
        b = min(len(self.lines), line + radius)
        return "\n".join(self.lines[a - 1:b])

    def methods(self):
        if self._methods is None:
            self._methods = list(_iter_methods(self.text))
        return self._methods

    def method_at(self, index):
        found = [m for m in self.methods() if m.start <= index < m.end]
        if not found:
            return None
        return min(found, key=lambda m: m.end - m.start)

    def body_at(self, index, radius=30):
        method = self.method_at(index)
        if method is not None:
            return method.text
        return self.window(index, radius)


def brace_end(text, open_idx):
    """open_idx 指向 '{'。返回配对 '}' 后一位；配不上就返回 len(text)。"""
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        c = text[i]
        if c in ('"', "'", "`"):
            i = _skip_string(text, i)
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def extract_paren(text, open_idx):
    """open_idx 指向 '('。返回括号内的文本。"""
    if open_idx >= len(text) or text[open_idx] != "(":
        return ""
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        c = text[i]
        if c in ('"', "'", "`"):
            i = _skip_string(text, i)
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i]
        i += 1
    return text[open_idx + 1:]


def top_level_commas(fragment):
    depth = 0
    count = 0
    i = 0
    n = len(fragment)
    while i < n:
        c = fragment[i]
        if c in ('"', "'", "`"):
            i = _skip_string(fragment, i)
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            count += 1
        i += 1
    return count


def _skip_string(text, i):
    quote = text[i]
    i += 1
    n = len(text)
    if quote == "`":
        while i < n and text[i] != "`":
            i += 1
        return min(n, i + 1)
    while i < n:
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == quote:
            return i + 1
        i += 1
    return n


def _iter_methods(text):
    cursor = 0
    while True:
        brace = text.find("{", cursor)
        if brace < 0:
            return
        header = text[max(0, brace - 220):brace]
        tail = header.rstrip()
        if _METHOD_REJECT.search(tail) and not re.search(r"\bfunc\b", tail):
            cursor = brace + 1
            continue
        is_func = re.search(r"\bfunc\b", tail) is not None
        # 以 ) 结尾就当方法。类声明以类名结尾，不会被收进来。
        # ponytail: new Runnable() { } 这种匿名类也会被当成方法；升级时按 AST 区分。
        is_java = (
            re.search(r"\b(public|private|protected)\b", tail) is not None
            and re.search(r"\)\s*(throws[\w\s.,<>]*)?$", tail) is not None
        )
        if not (is_func or is_java):
            cursor = brace + 1
            continue
        end = brace_end(text, brace)
        yield Method(brace, end, text[brace:end], header)
        cursor = brace + 1
