# Elasticsearch 规则

覆盖深分页、前导通配和查询脚本。

每条规则都给出原因、危害、对应过的故障形态，以及能照着改的修复示例。扫描器的判定以可重复的代码形态为准；这里的检测描述与扫描器一致。

级别只使用三档：

- **Critical**：已经能对应到线上故障，MR 合入门禁拦截，周期巡检立即告警。
- **Warning**：会带来性能或稳定性问题，不拦截合入，本迭代要修。
- **Suggestion**：确定性不足，必须人工复核，不拦截。

### [ES-001] from/size 深分页没有上限

- **Severity**: Critical
- **Middleware**: ES
- **分级动作**: 处置：立即修复。MR 模式拦截合入；周期巡检告警并让最近修改人认领。
- **原因**: Elasticsearch 的 from+size 要在每个分片上取出前 from+size 条再汇总。from 来自页码或在循环里累加，又没有 10000 的上限时，协调节点要持有越来越大的窗口。
- **危害**: 超过 index.max_result_window（默认 10000）直接报错；把窗口调大则会把协调节点堆内存打满。导出任务用递增 from 是常见触发方式。
- **历史故障**: 订单导出 for 循环里 sourceBuilder.from(from) 每次加 1000，跑到后半段集群出现 circuit breaker，搜索整体变慢。
- **检测**: sourceBuilder.from 或 setFrom 的参数不是小于 10000 的常量，且当前方法没有 search_after，也没有 from+size 与 10000 的比较。
- **降噪**: 方法里使用 searchAfter/search_after，或有 from+size 不超过 10000 的判断时不报。from(0) 这类小常量不报。
- **修复**:

在线翻页封死深度。全量遍历用 search_after，导出再加 PIT。

```java
if (from + size > 10000) {
    throw new IllegalArgumentException("use search_after");
}
sourceBuilder.searchAfter(sortValues);
sourceBuilder.size(size);
```

### [ES-002] 左通配或前导模糊匹配

- **Severity**: Warning
- **Middleware**: ES
- **分级动作**: 处置：本迭代修复。不拦截合入，周期报告里必须有人看。
- **原因**: Wildcard、regexp、query_string 的模式以 * 或 ? 开头时，倒排索引无法按前缀收窄，查询要扫很大一块 term 字典。
- **危害**: CPU 升高，慢查询拖住搜索线程池，同一集群的精确查询延迟跟着涨。
- **历史故障**: 商品搜索把用户输入包成 *keyword*，大促时搜索节点 CPU 打满。
- **检测**: wildcardQuery、regexpQuery、queryStringQuery、NewWildcardQuery 的参数字符串以 * 或 ? 开头。
- **降噪**: 后缀通配 keyword* 不报。match/term 不报。
- **修复**:

写入时用 ngram 或 edge_ngram，查询用 match 或 term。不要在查询里做前导星号。

```java
QueryBuilders.matchQuery("name.ngram", keyword);
```

### [ES-003] 查询路径上跑脚本

- **Severity**: Warning
- **Middleware**: ES
- **分级动作**: 处置：本迭代修复。不拦截合入，周期报告里必须有人看。
- **原因**: painless、ScriptQuery、script_score 在查询阶段对命中的文档做解释执行，开销在协调和数据节点上随命中数增长。
- **危害**: 脚本查询容易把 search 线程池打满，并触发 circuit breaker。它没有 from/size 那么容易被默认配置挡住。
- **历史故障**: 用脚本按复杂公式重算排序，索引变大后搜索线程池拒绝普通查询。
- **检测**: 出现 new Script(、ScriptQuery、script_score 或 scriptQuery。
- **降噪**: 扫描器分不清脚本用在查询还是一次性 reindex。所以是 Warning。确认只在离线任务且有超时后再人工放过。
- **修复**:

把计算结果做成写入时的字段，查询只做 match/term/range。必须用脚本时放到离线任务，并设置请求超时。

```java
sourceBuilder.query(QueryBuilders.rangeQuery("score").gte(minScore));
sourceBuilder.timeout(TimeValue.timeValueMillis(200));
```
