# -*- coding: utf-8 -*-
"""阶段 1：扫哪些文件。"""

import os

# 规范点名的业务目录。mapper/mybatis 是补上的：MyBatis XML 经常不在 dao/ 里，
# 不补的话分片键规则会扫空。lindorm/hbase 同理。
INCLUDE_DIR_NAMES = {
    "dao",
    "repository",
    "service",
    "manager",
    "dal",
    "cache",
    "search",
    "mapper",
    "mybatis",
    "lindorm",
    "hbase",
    "controller",
    "web",
    "api",
    "facade",
    "endpoint",
}
EXCLUDE_DIR_NAMES = {"vendor", "node_modules", "target", "build", ".git", "testdata"}
SOURCE_SUFFIXES = {".java", ".go", ".xml"}
CONFIG_SUFFIXES = {".properties", ".yml", ".yaml"}


def is_generated_or_test(name):
    if name.endswith("_test.go") or name.endswith(".pb.go"):
        return True
    if name.endswith("Test.java") or name.endswith("Generated.java"):
        return True
    return False


def is_excluded(path):
    parts = set(path.replace("\\", "/").split("/"))
    if parts & EXCLUDE_DIR_NAMES:
        return True
    return is_generated_or_test(os.path.basename(path))


def in_business_scope(path):
    norm = path.replace("\\", "/")
    suffix = os.path.splitext(norm)[1].lower()
    name = os.path.basename(norm).lower()
    if suffix in CONFIG_SUFFIXES and name.startswith("application"):
        return True
    if suffix not in SOURCE_SUFFIXES:
        return False
    parts = {p.lower() for p in norm.split("/") if p}
    return bool(parts & INCLUDE_DIR_NAMES)


def iter_source_files(repo):
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIR_NAMES and not d.startswith(".")]
        for name in files:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, repo).replace("\\", "/")
            if is_excluded(rel) or not in_business_scope(rel):
                continue
            yield rel
