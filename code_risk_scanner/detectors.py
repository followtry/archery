# -*- coding: utf-8 -*-
"""阶段 2、3 的确定性检测。

ponytail: 用正则和括号配对，不是语法树。字符串里的示例 SQL、注释里的代码可能误报；
分页上限如果写在另一个函数里会漏报。升级路径：Java/Go 换 tree-sitter，再沿调用链追到入口。
"""

import re

from code_risk_scanner.catalog import DEFAULT_SHARD_KEYS
from code_risk_scanner.source import brace_end, extract_paren, top_level_commas

_SHARD_CTX = re.compile(
    r"tddl|sharding|分库|分表|shard[_-]?key|shardingkey|logic[_-]?table",
    re.I,
)
_HETERO = re.compile(r"异构索引|逆向索引|走\s*ES|via\s+es", re.I)
_SQL_PREFIX = re.compile(
    r"(?i)(?:(sql|query|dml|stmt)\s*(?::=|=)\s*$|"
    r"@(?:Select|Update|Delete)\s*\(\s*$|"
    r"\.(?:Exec|ExecContext|Query|QueryContext|QueryRow|Raw)\s*\(\s*$)"
)
_WHERE_TAIL = re.compile(
    r"(?is)\bwhere\b(.*?)(\border\s+by\b|\bgroup\s+by\b|\blimit\b|\bhaving\b|\bunion\b|$)"
)
_COL = re.compile(
    r"(?i)(?:^|\band\b|\bor\b)\s*(?:\w+\.)?([a-zA-Z_][\w]*)\s*(?:=|\bin\b|\blike\b|>=|<=|<>|!=|>|<)"
)
_SQL_WORDS = {
    "and", "or", "not", "in", "is", "null", "like", "between", "exists",
    "select", "from", "where", "on", "as", "by", "set", "update", "delete",
}
_OFFSET_CAP = re.compile(
    r"(?i)(?:Math|Integer)\.min\s*\(|\bmaxOffset\b|\bMAX_OFFSET\b|"
    r"if\s*\([^)]{0,80}(?:offset|start|pageNo|pageNum|page)[^)]{0,40}(?:>|>=)\s*\d{3,}"
)
_FUNC = (
    r"date|from_unixtime|unix_timestamp|concat|left|right|substr|substring|"
    r"cast|convert|lower|upper|ifnull|nvl|abs|mod"
)
_LOW_FREQ = re.compile(r"(?://|/\*|<!--)[^\n]{0,80}低频[^\n]{0,80}后台")


def features_of(path, text):
    feats = set()
    lower = path.lower()
    if lower.endswith(".java"):
        feats.add("java")
    if lower.endswith(".go"):
        feats.add("go")
    if re.search(r"(?i)tddl|sharding|mybatis|\bsql\b|database/sql|\bgorm\b", text):
        feats.add("tddl")
    if lower.endswith(".xml") and re.search(r"(?i)<(select|update|delete|insert|mapper)\b", text):
        feats.add("tddl")
    if re.search(r"(?i)@Transactional\b|\.Begin\s*\(|\bMapper\b|jdbc|SqlSession", text):
        feats.add("tddl")
    if re.search(r"(?i)lindorm|hbase|addColumn|withStartRow|new\s+Scan\s*\(|new\s+Put\s*\(", text):
        feats.add("lindorm")
    if re.search(r"(?i)jedis|redisson|lettuce|go-redis|\bredis\b", text):
        feats.add("redis")
    if re.search(
        r"(?i)elasticsearch|RestHighLevelClient|SearchSourceBuilder|olivere/elastic|"
        r"go-elasticsearch|wildcardQuery|WildcardQuery",
        text,
    ):
        feats.add("es")
    return feats


def scan_text(path, text, shard_keys=None):
    """对单个已经通过范围过滤的文件做检测。返回尚未套上规则文案的命中。"""
    keys = {k.lower() for k in (shard_keys or DEFAULT_SHARD_KEYS)}
    feats = features_of(path, text)
    hits = []
    if "tddl" in feats:
        hits.extend(_tddl(path, text, keys))
    if "lindorm" in feats:
        hits.extend(_lindorm(text))
    if "redis" in feats:
        hits.extend(_redis(text))
    if "es" in feats:
        hits.extend(_es(text))
    if "java" in feats:
        hits.extend(_java(text))
    if "go" in feats:
        hits.extend(_go(text))
    return _dedupe(hits)


def _dedupe(hits):
    seen = set()
    out = []
    for hit in hits:
        key = (hit["rule_id"], hit["start"])
        if key in seen:
            continue
        seen.add(key)
        out.append(hit)
    return out


def _hit(rule_id, start, end, evidence, severity=None, needs_review=False):
    item = {
        "rule_id": rule_id,
        "start": start,
        "end": max(start, end),
        "evidence": evidence,
        "needs_review": needs_review,
    }
    if severity:
        item["severity"] = severity
    return item


def _sql_spans(text):
    spans = []
    for match in re.finditer(r"(?is)<(select|update|delete)\b[^>]*>(.*?)</\1>", text):
        spans.append((match.start(2), match.end(2), match.group(2)))
    for match in re.finditer(r'(?is)("""|\'\'\'|`)(.*?)(\1)', text):
        body = match.group(2)
        if not re.match(r"(?is)\s*(select|update|delete)\b", body):
            continue
        prefix = text[max(0, match.start() - 80):match.start()]
        if _SQL_PREFIX.search(prefix):
            spans.append((match.start(2), match.end(2), body))
    for match in re.finditer(r'(?is)(["\'])(\s*(?:select|update|delete)\b[^"\']*)\1', text):
        prefix = text[max(0, match.start() - 80):match.start()]
        if _SQL_PREFIX.search(prefix):
            spans.append((match.start(2), match.end(2), match.group(2)))
    spans.sort(key=lambda item: item[0])
    deduped = []
    last = -1
    for start, end, sql in spans:
        if start == last:
            continue
        last = start
        deduped.append((start, end, sql))
    return deduped


def _where_columns(sql):
    match = _WHERE_TAIL.search(sql)
    if not match:
        return None
    cols = set()
    for name in _COL.findall(match.group(1)):
        lowered = name.lower()
        if lowered not in _SQL_WORDS:
            cols.add(lowered)
    return cols


def _is_write(sql):
    return re.match(r"(?is)\s*(update|delete)\b", sql) is not None


def _shard_context(text):
    return _SHARD_CTX.search(text) is not None


def _tddl(path, text, keys):
    del path
    hits = []
    sharded = _shard_context(text)
    for start, end, sql in _sql_spans(text):
        cols = _where_columns(sql)
        if _is_write(sql) and not cols:
            hits.append(_hit(
                "TDDL-004", start, end,
                "UPDATE/DELETE 没有可用的列条件，会整表写入。",
            ))
        elif sharded and cols is not None and not (cols & keys):
            evidence = "WHERE 列为 {0}，没有分片键。".format(", ".join(sorted(cols)) or "空")
            if _HETERO.search(sql) or _HETERO.search(text[max(0, start - 200):end + 80]):
                hits.append(_hit("TDDL-001", start, end, evidence + " 附近提到异构索引或 ES。", "Suggestion", True))
            else:
                hits.append(_hit("TDDL-001", start, end, evidence))
        elif sharded and cols is None and not _is_write(sql):
            nearby = text[max(0, start - 200):end + 80]
            if _HETERO.search(sql) or _HETERO.search(nearby):
                hits.append(_hit("TDDL-001", start, end, "分片表上的 SELECT 没有 WHERE。附近提到异构索引或 ES。", "Suggestion", True))
            else:
                hits.append(_hit("TDDL-001", start, end, "分片表上的 SELECT 没有 WHERE。"))
        if sharded and cols is not None:
            hits.extend(_shard_key_wrapped(sql, start, keys))
        if re.search(r"(?i)\bselect\s+\*\s+from\b", sql):
            hits.append(_hit("TDDL-007", start, end, "SQL 使用了 SELECT *。"))
        hits.extend(_deep_page_sql(text, sql, start))
    hits.extend(_deep_page_code(text))
    hits.extend(_in_concat(text))
    hits.extend(_transaction_loop(text))
    return hits


def _shard_key_wrapped(sql, start, keys):
    hits = []
    alternation = "|".join(re.escape(key) for key in sorted(keys, key=len, reverse=True))
    if not alternation:
        return hits
    func = re.search(
        r"(?i)\b(?:{func})\s*\(\s*[`\"]?(?:{keys})\b".format(func=_FUNC, keys=alternation),
        sql,
    )
    expr = re.search(r"(?i)\b({keys})\b\s*[\+\-\*/]".format(keys=alternation), sql)
    found = func or expr
    if found:
        hits.append(_hit(
            "TDDL-005", start, start + found.end(),
            "分片键被函数或表达式包裹，路由无法裁剪。",
        ))
    return hits


def _deep_page_sql(text, sql, start):
    hits = []
    for match in re.finditer(r"(?i)\blimit\s+(\d+)\s*,", sql):
        offset = int(match.group(1))
        if offset > 5000:
            hits.append(_hit(
                "TDDL-002", start + match.start(), start + match.end(),
                "LIMIT 偏移 {0} 超过 5000。".format(offset),
            ))
    for match in re.finditer(
        r"(?i)\blimit\s+#\{\s*(offset|start|pageOffset|startRow)\b|\boffset\s+#\{\s*(offset|start)\b",
        sql,
    ):
        if _OFFSET_CAP.search(_body(text, start)):
            continue
        hits.append(_hit(
            "TDDL-002", start + match.start(), start + match.end(),
            "分页偏移来自参数，当前方法没有看到 5000 的上限。",
        ))
    return hits


def _deep_page_code(text):
    hits = []
    for match in re.finditer(
        r"(?i)\b(page(?:No|Num|Index)?|offset)\s*\*\s*(pageSize|size|limit)\b",
        text,
    ):
        if _OFFSET_CAP.search(_body(text, match.start())):
            continue
        hits.append(_hit(
            "TDDL-002", match.start(), match.end(),
            "用页码乘以页大小计算偏移，没有看到上限。",
        ))
    return hits


def _in_concat(text):
    hits = []
    pattern = re.compile(r"""(?i)\bin\s*\(\s*(["'])\s*\+""")
    for match in pattern.finditer(text):
        hits.append(_hit("TDDL-006", match.start(), match.end(), "IN 列表由字符串拼接而成。"))
    for start, end, sql in _sql_spans(text):
        for group in re.finditer(r"(?i)\bin\s*\(([^)]*)\)", sql):
            items = [piece for piece in group.group(1).split(",") if piece.strip()]
            if len(items) > 500:
                hits.append(_hit(
                    "TDDL-006", start, end,
                    "IN 字面量有 {0} 个，超过 500。".format(len(items)),
                ))
    return hits


def _transaction_loop(text):
    hits = []
    for match in re.finditer(r"@Transactional\b", text):
        brace = text.find("{", match.end())
        if brace < 0:
            continue
        signature = text[match.end():brace]
        if re.search(r"\bclass\b", signature):
            continue
        end = brace_end(text, brace)
        block = text[match.start():end]
        if not (re.search(r"\bfor\s*\(", block) and re.search(
            r"(?i)\b(insert|update|save|delete|batchUpdate|batchInsert)\s*\(", block
        )):
            continue
        if re.search(r"同片|单分片|same shard", block, re.I):
            hits.append(_hit("TDDL-003", match.start(), end, "事务内循环写库，注释声明同片，需要复核分组。", "Suggestion", True))
        else:
            hits.append(_hit("TDDL-003", match.start(), end, "事务内循环执行写库，分片键若不相同就会跨分片。"))
    for match in re.finditer(r"\.Begin\s*\(", text):
        region = text[match.start():match.start() + 2500]
        cut = re.search(r"\.Commit\s*\(|\.Rollback\s*\(", region)
        if cut:
            region = region[:cut.start()]
        if re.search(r"\bfor\b", region) and re.search(r"(?i)\.(Exec|ExecContext)\s*\(", region):
            if re.search(r"同片|单分片|same shard", region, re.I):
                hits.append(_hit("TDDL-003", match.start(), match.start() + len(region), "事务内循环写库，注释声明同片。", "Suggestion", True))
            else:
                hits.append(_hit("TDDL-003", match.start(), match.start() + len(region), "Begin 到 Commit 之间的循环里有 Exec。"))
    return hits


def _lindorm(text):
    hits = []
    time_pattern = re.compile(
        r"System\.currentTimeMillis\s*\(\)|Instant\.now\s*\(\)|"
        r"time\.Now\s*\(\)\s*\.\s*Unix(?:Nano|Milli)?\s*\(\)"
    )
    for match in time_pattern.finditer(text):
        window = _window(text, match.start(), 8)
        if not re.search(r"rowkey|row_key|RowKey", window, re.I):
            continue
        if re.search(r"(?i)\bmd5\b|\bhash\b|\bsalt\b|reverse|MAX_VALUE\s*-|MaxInt64\s*-", window):
            continue
        hits.append(_hit("LINDORM-001", match.start(), match.end(), "RowKey 前缀使用单调时间，没有散列或反转。"))
    for match in re.finditer(r"new\s+Scan\s*\(", text):
        body = _body(text, match.start())
        has_start = re.search(r"(?i)withStartRow|setStartRow", body) is not None
        has_stop = re.search(r"(?i)withStopRow|setStopRow", body) is not None
        filtered = re.search(r"ValueFilter|SubstringComparator", body) is not None
        limited = re.search(r"(?i)setCaching|setLimit|withLimit", body) is not None
        if not (has_start and has_stop):
            hits.append(_hit("LINDORM-002", match.start(), match.end(), "Scan 没有同时设置 StartRow 和 StopRow。"))
        elif filtered and not limited:
            hits.append(_hit("LINDORM-002", match.start(), match.end(), "Scan 使用列值过滤，但没有 setLimit 或 setCaching。"))
    for match in re.finditer(r"addColumn\s*\(", text):
        window = text[match.start():match.start() + 350]
        if re.search(r"toJSONString|toJson|json\.Marshal|readAllBytes|ReadFile|writeValueAsString|writeValueAsBytes", window):
            hits.append(_hit("LINDORM-003", match.start(), match.end(), "列值来自整段 JSON 或整个文件。"))
    from code_risk_scanner.source import Source
    source = Source("lindorm", text)
    for method in source.methods():
        body = method.text
        if not (re.search(r"\bfor\b", body) and re.search(r"(?i)(?:puts|batch)\.add\s*\(", body)):
            continue
        if not re.search(r"(?i)\.(?:put|batch)\s*\(\s*puts\b", body):
            continue
        if re.search(r"(?i)subList|partition|BATCH_SIZE|batchSize|puts\.size\(\)\s*>=\s*\d+", body):
            continue
        hits.append(_hit("LINDORM-004", method.start, method.end, "批量 Put 随循环增长，没有分批阈值。"))
    return hits


def _redis(text):
    hits = []
    bigkey = re.compile(
        r"(?i)\.hgetall\s*\(|\.smembers\s*\(|"
        r"\blrange\b[^;\n]{0,40}\b0\b[^;\n]{0,8}-1|"
        r"\bzrange\b[^;\n]{0,40}\b0\b[^;\n]{0,8}-1|"
        r"\.lrange\s*\([^)]*\b0\s*,\s*-1|"
        r"\.zrange\s*\([^)]*\b0\s*,\s*-1|"
        r"opsForHash\(\)\s*\.entries\s*\(|"
        r"opsForSet\(\)\s*\.members\s*\(|"
        r"opsForList\(\)\s*\.range\s*\([^)]*0\s*,\s*-1|"
        r"opsForZSet\(\)\s*\.range\s*\([^)]*0\s*,\s*-1|"
        r"\bHGETALL\b|\bSMEMBERS\b"
    )
    for match in bigkey.finditer(text):
        line = _line(text, match.start())
        if re.search(r"(?i)config|dict|enum|dictionary|\bmeta\b", line):
            continue
        hits.append(_hit("REDIS-001", match.start(), match.end(), "一次命令读取整个集合。"))
    for match in re.finditer(r"(?i)\.setnx\s*\(|\bSETNX\b", text):
        window = text[match.end():match.end() + 400]
        if re.search(r"(?i)\.(?:expire|pexpire)\s*\(", window):
            evidence = "SETNX 和 EXPIRE 分成两条命令，中间崩溃会留下没有过期时间的锁。"
        else:
            evidence = "SETNX 没有设置过期时间。"
        hits.append(_hit("REDIS-002", match.start(), match.end(), evidence))
    for match in re.finditer(r"\.SetNX\s*\(", text):
        args = extract_paren(text, match.end() - 1)
        if re.search(r",\s*0\s*$", args.strip()):
            hits.append(_hit("REDIS-002", match.start(), match.end(), "SetNX 的过期时间是 0，锁不会自动释放。"))
    for match in re.finditer(r"\.setIfAbsent\s*\(", text):
        args = extract_paren(text, match.end() - 1)
        if top_level_commas(args) < 2:
            hits.append(_hit("REDIS-002", match.start(), match.end(), "setIfAbsent 没有传入过期时间。"))
    for match in re.finditer(r"(?i)\.(?:del|delete|unlink)\s*\(", text):
        args = extract_paren(text, match.end() - 1)
        body = _body(text, match.start())
        header = _header(text, match.start())
        if not (re.search(r"(?i)lock", args) or re.search(r"(?i)unlock|releaseLock", header)):
            continue
        if re.search(r"(?i)\.eval(?:sha)?\s*\(|\blua\b", body):
            continue
        hits.append(_hit("REDIS-002", match.start(), match.end(), "释放锁时直接删除 key，没有校验持有者。"))
    for match in re.finditer(r"(?i)\.(?:setex|expire|pexpire)\s*\(", text):
        args = extract_paren(text, match.end() - 1)
        if re.search(r'["\']\s*["\']', args):
            continue
        if not re.search(r"\b\d{2,}\b", args):
            continue
        if re.search(r"Random|ThreadLocalRandom|\brand\.", _body(text, match.start())):
            continue
        hits.append(_hit(
            "REDIS-003", match.start(), match.end(),
            "TTL 是固定数字，没有随机抖动。",
            needs_review=True,
        ))
    from code_risk_scanner.source import Source
    for method in Source("redis", text).methods():
        body = method.text
        if not re.search(r"(?i)jedis|redis|cache", body):
            continue
        if re.search(r"return\s+null\s*;", body) and re.search(r"==\s*null", body):
            if re.search(r"(?i)\.setex\s*\(|\.set\s*\(|\.setIfAbsent\s*\(", body):
                continue
            hits.append(_hit(
                "REDIS-003", method.start, method.end,
                "缓存未命中后直接返回空，没有写短 TTL 占位。",
                needs_review=True,
            ))
    for match in re.finditer(
        r"(?i)\.keys\s*\(|\bKEYS\s+['\"]?\*|\.flushAll\s*\(|\.flushDB\s*\(|\bFLUSHALL\b|\bFLUSHDB\b",
        text,
    ):
        hits.append(_hit("REDIS-004", match.start(), match.end(), "使用了会阻塞或清空 Redis 的命令。"))
    return hits


def _es(text):
    hits = []
    for match in re.finditer(r"(?i)(?:sourceBuilder|searchSourceBuilder|builder|ssb)\s*\.\s*from\s*\(|\.setFrom\s*\(", text):
        paren = text.find("(", match.start())
        args = extract_paren(text, paren).strip() if paren >= 0 else ""
        body = _body(text, match.start())
        if re.search(r"searchAfter|search_after", body):
            continue
        if re.search(r"from\s*\+\s*size\s*(?:>=|>|<=|<)\s*10000", body):
            continue
        if re.fullmatch(r"\d+", args) and int(args) < 10000:
            continue
        hits.append(_hit("ES-001", match.start(), match.end(), "from 没有封顶，也没有改成 search_after。参数是 {0}。".format(args or "未知")))
    for match in re.finditer(
        r"(?i)(?:wildcardQuery|WildcardQuery|NewWildcardQuery|regexpQuery|RegexpQuery|queryStringQuery|QueryStringQuery)\s*\(",
        text,
    ):
        args = extract_paren(text, match.end() - 1)
        if re.search(r"""["']\s*[\*\?]""", args):
            hits.append(_hit("ES-002", match.start(), match.end(), "模糊模式以 * 或 ? 开头。"))
    for match in re.finditer(r"(?i)new\s+Script\s*\(|ScriptQuery|script_score|scriptQuery\s*\(", text):
        hits.append(_hit("ES-003", match.start(), match.end(), "查询路径上构造了脚本。"))
    return hits


def _java(text):
    hits = []
    for match in re.finditer(
        r"Executors\.new(?:FixedThreadPool|SingleThreadExecutor|CachedThreadPool)\s*\(",
        text,
    ):
        hits.append(_hit("JAVA-001", match.start(), match.end(), "使用了队列或线程数没有上界的 Executors 工厂方法。"))
    for match in re.finditer(r"new\s+LinkedBlockingQueue\s*(?:<[^>]*>)?\s*\(", text):
        args = extract_paren(text, text.find("(", match.start()))
        if args.strip() == "":
            hits.append(_hit("JAVA-001", match.start(), match.end(), "LinkedBlockingQueue 没有容量。"))
    for match in re.finditer(r"CompletableFuture\s*\.\s*(?:supplyAsync|runAsync)\s*\(", text):
        args = extract_paren(text, match.end() - 1)
        if top_level_commas(args) < 1:
            hits.append(_hit(
                "JAVA-002", match.start(), match.end(),
                "异步任务没有传入业务线程池，会使用 ForkJoinPool.commonPool()。",
                needs_review=True,
            ))
    from code_risk_scanner.source import Source
    source = Source("java", text)
    for method in source.methods():
        if not re.search(r"supplyAsync|runAsync", method.text):
            continue
        if re.search(r"\.get\s*\(\s*\)", method.text) and not re.search(
            r"orTimeout\s*\(|\.get\s*\(\s*[^)\s]", method.text
        ):
            hits.append(_hit(
                "JAVA-002", method.start, method.end,
                "Future.get() 没有超时。",
                needs_review=True,
            ))
    for match in re.finditer(r"\bSimpleDateFormat\s+\w+\s*=\s*new\s+SimpleDateFormat\b", text):
        if source.method_at(match.start()) is not None:
            continue
        window = _window(text, match.start(), 2)
        if "ThreadLocal" in window:
            continue
        hits.append(_hit("JAVA-003", match.start(), match.end(), "SimpleDateFormat 放在字段上，会被多个线程共用。"))
    return hits


def _go(text):
    hits = []
    maps = set(re.findall(r"\b(\w+)\s*(?::=|=)\s*make\(\s*map\[", text))
    maps.update(re.findall(r"\b(\w+)\s*(?::=|=)\s*map\[", text))
    maps.update(re.findall(r"\bvar\s+(\w+)\s+map\[", text))
    for match in re.finditer(r"\bgo\s+func\s*\([^)]*\)\s*\{", text):
        brace = text.find("{", match.start())
        end = brace_end(text, brace)
        body = text[brace:end]
        if re.search(r"\b\w+\s*<-", body) and not re.search(r"\bselect\b|ctx\.Done\s*\(", body):
            hits.append(_hit("GO-001", match.start(), end, "goroutine 向 channel 发送，但没有 select 或 ctx.Done，发送可能永远堵着。"))
        for name in maps:
            if re.search(r"\b{0}\s*\[[^\]]+\]\s*=".format(re.escape(name)), body) and not re.search(
                r"\.Lock\s*\(|sync\.Map", body
            ):
                hits.append(_hit("GO-001", match.start(), end, "goroutine 写入 map {0}，体内没有加锁。".format(name)))
    for match in re.finditer(r"\bfor\b[^{;]*\{", text):
        brace = match.end() - 1
        end = brace_end(text, brace)
        for defer_at in _direct_defers(text[match.start():end], match.start()):
            hits.append(_hit("GO-002", defer_at, defer_at + 5, "defer Close 写在 for 循环里，要等整个函数返回才执行。"))
    for match in re.finditer(r"\bhttp\.Get\s*\(|\bhttp\.DefaultClient\b", text):
        hits.append(_hit("GO-003", match.start(), match.end(), "使用了没有超时的默认 HTTP 客户端。"))
    for match in re.finditer(r"http\.Client\s*\{", text):
        brace = text.find("{", match.start())
        end = brace_end(text, brace)
        literal = text[match.start():end]
        if "Timeout" not in literal:
            hits.append(_hit("GO-003", match.start(), end, "http.Client 没有设置 Timeout。"))
    return hits


def _direct_defers(block, absolute_start):
    """只看 for 自己这一层。套在立即执行函数里的 defer 是正确写法。"""
    rel = block.find("{")
    if rel < 0:
        return []
    depth = 0
    i = rel
    found = []
    while i < len(block):
        char = block[i]
        if char in ('"', "'", "`"):
            i = _skip_raw(block, i)
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                break
        elif depth == 1 and block.startswith("defer", i) and _boundary(block, i):
            window = block[i:i + 120]
            if re.search(r"\.Close\s*\(", window):
                found.append(absolute_start + i)
        i += 1
    return found


def _boundary(text, index):
    if index == 0:
        return True
    return not (text[index - 1].isalnum() or text[index - 1] == "_")


def _skip_raw(text, index):
    from code_risk_scanner.source import _skip_string
    return _skip_string(text, index)


def _line(text, index):
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    if end < 0:
        end = len(text)
    return text[start:end]


def _window(text, index, radius):
    line = text.count("\n", 0, index)
    lines = text.splitlines()
    a = max(0, line - radius)
    b = min(len(lines), line + radius + 1)
    return "\n".join(lines[a:b])


def _body(text, index):
    from code_risk_scanner.source import Source
    return Source("<mem>", text).body_at(index)


def _header(text, index):
    from code_risk_scanner.source import Source
    method = Source("<mem>", text).method_at(index)
    if method is None:
        return ""
    return method.header


def downgrade_background(text, line_no, severity):
    """低频后台注释不能把问题说成没有，只是不让它挡合入。"""
    lines = text.splitlines()
    if not lines:
        return severity, []
    idx = min(max(line_no - 1, 0), len(lines) - 1)
    window = "\n".join(lines[max(0, idx - 7):min(len(lines), idx + 4)])
    if severity == "Critical" and _LOW_FREQ.search(window):
        return "Warning", [
            "注释标明这是低频后台管理操作，已从 Critical 降为 Warning。命令本身仍然会阻塞，周期巡检继续提示，但不作为合入门禁。"
        ]
    return severity, []
