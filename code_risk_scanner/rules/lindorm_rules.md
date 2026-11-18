# Lindorm / HBase 宽表规则

覆盖 RowKey 热点、无界 Scan、大 Cell 和无上限批量写。

每条规则都给出原因、危害、对应过的故障形态，以及能照着改的修复示例。扫描器的判定以可重复的代码形态为准；这里的检测描述与扫描器一致。

级别只使用三档：

- **Critical**：已经能对应到线上故障，MR 合入门禁拦截，周期巡检立即告警。
- **Warning**：会带来性能或稳定性问题，不拦截合入，本迭代要修。
- **Suggestion**：确定性不足，必须人工复核，不拦截。

### [LINDORM-001] RowKey 以递增时间开头，写入打在同一个 Region

- **Severity**: Critical
- **Middleware**: Lindorm
- **分级动作**: 处置：立即修复。MR 模式拦截合入；周期巡检告警并让最近修改人认领。
- **原因**: Lindorm/HBase 按 RowKey 字典序切 Region。前缀如果是 currentTimeMillis 或 time.Now().Unix() 这种单调值，同一时段的写入落在同一段 RowKey 上，也就是同一个 RegionServer。
- **危害**: 单台机器 CPU、磁盘和 handler 打满，其它机器闲着。写入延迟变高，严重时这个 Region 一直分裂、一直热点。
- **历史故障**: 日志表用毫秒时间戳当 RowKey 前缀，高峰期单个 RegionServer 写延迟到秒级，集群其它节点利用率不到两成。
- **检测**: RowKey 赋值附近出现 System.currentTimeMillis、Instant.now 或 time.Now().Unix，且同一窗口没有 md5、hash、salt、反转或 MAX_VALUE 减时间。
- **降噪**: 时间戳前面已经有 hash/md5/salt，或用 Long.MAX_VALUE - ts 做反转时不报。
- **修复**:

前缀用散列把写入打散，时间放在后面便于范围扫。

```java
String rowKey = md5(id).substring(0, 4) + System.currentTimeMillis() + id;
```

```text
反转时间（只要按时间倒序、不需要打散时再用）：
Long.MAX_VALUE - System.currentTimeMillis()
```

### [LINDORM-002] Scan 没有行界，或用列值过滤器扫全表

- **Severity**: Critical
- **Middleware**: Lindorm
- **分级动作**: 处置：立即修复。MR 模式拦截合入；周期巡检告警并让最近修改人认领。
- **原因**: Scan 不设 StartRow/StopRow 就是全表扫。ValueFilter、SubstringComparator 要读出列值才能判断，服务端无法靠 RowKey 跳过数据块。
- **危害**: RegionServer 读放大，缓存被冲掉，和在线点查抢 handler。一次全表扫可以把集群读延迟整体抬高。
- **历史故障**: 运营查询用 SubstringComparator 在用户宽表上找昵称，Scan 没有行界，集群读 P99 在任务跑完之前一直异常。
- **检测**: new Scan() 所在方法没有同时设置 StartRow 和 StopRow；或者用了 ValueFilter/SubstringComparator 却没有 setLimit/setCaching。
- **降噪**: 同一方法里 StartRow 和 StopRow 都在，并且过滤器场景设了 limit，不报。
- **修复**:

用 RowKey 前缀圈定范围。列值模糊匹配不要做在线 Scan，改到检索引擎。

```java
Scan scan = new Scan().withStartRow(start).withStopRow(stop);
scan.setLimit(100);
```

### [LINDORM-003] 单个 Cell 写入整段 JSON 或整个文件

- **Severity**: Warning
- **Middleware**: Lindorm
- **分级动作**: 处置：本迭代修复。不拦截合入，周期报告里必须有人看。
- **原因**: addColumn 的值来自整对象 JSON 序列化或整个文件的字节。宽表的一个 Cell 会进 memstore、WAL 和缓存，大小没有在代码里封顶。
- **危害**: 单个 Cell 到几百 KB 以上时，compaction 和 GC 停顿变长，热点 Region 更容易把 RegionServer 打满。
- **历史故障**: 把活动详情的完整 JSON 列表塞进一个 qualifier，Region 压缩时 Old Gen 被大对象撑满，出现长时间 GC。
- **检测**: addColumn 附近调用了 toJSONString、json.Marshal、readAllBytes、ReadFile 或 writeValueAsString。
- **降噪**: 只写入 URL 或主键的 getBytes 不报。扫描器看不出运行时字节长度，所以这是 Warning 不是 Critical。
- **修复**:

单 Cell 控制在 100KB 内。大对象拆成多行多列，或把正文放到对象存储，宽表里只留地址。

```java
put.addColumn(CF, URL_QUAL, ossUrl.getBytes(StandardCharsets.UTF_8));
```

### [LINDORM-004] 循环攒批后一次提交，没有分批上限

- **Severity**: Warning
- **Middleware**: Lindorm
- **分级动作**: 处置：本迭代修复。不拦截合入，周期报告里必须有人看。
- **原因**: for 循环把 Put 放进列表，循环结束后一次 table.put(puts)。列表长度等于入参长度。
- **危害**: 一次 RPC 的 body 过大，RegionServer 堆上出现大数组，超时后重试会把同一批再打一遍。
- **历史故障**: 日终任务把几十万行放进一个 batch 提交，请求超过 RPC 上限，任务重试把同一个 Region 反复打热。
- **检测**: 方法里有 for、puts.add（或 batch.add）以及 table.put(puts)/batch(puts)，且没有 subList、partition 或 puts.size() 阈值。
- **降噪**: 看到分批阈值就认为已防护。阈值写得过大（比如一百万）扫描器不会算，这是漏报边界。
- **修复**:

按固定大小切开再提交。

```java
if (puts.size() >= 100) {
    table.put(puts);
    puts.clear();
}
```
