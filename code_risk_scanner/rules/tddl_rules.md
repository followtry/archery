# TDDL / 分库分表规则

覆盖广播扫描、深分页、跨分片写、全表写、路由列被包住、IN 拼接和 SELECT *。这些条和仓库里的 MySQL 设计规范对齐：分区键必须出现在 SQL 里，DML 必须有 WHERE，IN 列表控制在 500 以内，禁止 SELECT *。

每条规则都给出原因、危害、对应过的故障形态，以及能照着改的修复示例。扫描器的判定以可重复的代码形态为准；这里的检测描述与扫描器一致。

级别只使用三档：

- **Critical**：已经能对应到线上故障，MR 合入门禁拦截，周期巡检立即告警。
- **Warning**：会带来性能或稳定性问题，不拦截合入，本迭代要修。
- **Suggestion**：确定性不足，必须人工复核，不拦截。

### [TDDL-001] 缺少分片键，SQL 广播到全部分片

- **Severity**: Critical
- **Middleware**: TDDL
- **分级动作**: 处置：立即修复。MR 模式拦截合入；周期巡检告警并让最近修改人认领。
- **原因**: 分库分表靠 WHERE 里的分片键算路由。条件里没有分片键，或只有 status、create_time 这类非路由列时，中间件无法裁剪分片，只能把同一条 SQL 发到每一个库。
- **危害**: 一次查询或更新打满所有分片：连接池被占满、每个库都出现慢 SQL、RT 抖动，严重时把整条业务链路拖超时。分片越多，放大越厉害。
- **历史故障**: 大促按 status 批量改订单，逻辑表背后一千多个分片全部执行，数据库连接耗尽，下单接口成片超时。
- **检测**: 文件或 SQL 能看出是分库分表（tddl、sharding、分表、logic table），且 SELECT/UPDATE/DELETE 的 WHERE 没有命中分片键。无 WHERE 的写语句归 TDDL-004，不在这里重复报。
- **降噪**: 注释写明走异构索引、逆向索引或 ES 检索时，降为 Suggestion。无法确认是分片表时不报 Critical。
- **修复**:

WHERE 带上分片键。业务上确实没有分片键时，先查异构索引或 ES，不要直接广播。

```sql
-- 修复前：只按状态扫，TDDL 广播
SELECT id, status FROM order_tab WHERE status = #{status}
-- 修复后
SELECT id, status FROM order_tab WHERE user_id = #{userId} AND status = #{status}
```

### [TDDL-002] 大偏移量深度分页

- **Severity**: Warning
- **Middleware**: TDDL
- **分级动作**: 处置：本迭代修复。不拦截合入，周期报告里必须有人看。
- **原因**: LIMIT offset, size 在分库分表下要在每个分片上先取出 offset+size 行，再在中间件里归并排序，最后丢掉前 offset 行。offset 没有上限时，页码可以一直被调用方加大。
- **危害**: 内存和网络随 offset 线性涨，归并排序把应用堆和数据库一起打高。单表深分页本身也慢，分片之后是乘数。
- **历史故障**: 后台导出用 pageNo * pageSize 一直翻页，offset 到十万以后每个分片都在排序前十万行，数据库 CPU 打满。
- **检测**: SQL 里出现 LIMIT 数字且偏移大于 5000，或 LIMIT/OFFSET 使用 offset、page 变量，且当前方法没有把偏移截到 5000 以内。
- **降噪**: 同一方法里有 offset > 5000 的拦截、Math.min / Integer.min，视为已防护，不报。
- **修复**:

不要深翻页。用上一页的主键做游标；如果必须用 offset，在入口把上限定死。

```sql
SELECT id, status FROM order_tab
WHERE user_id = #{userId} AND id > #{lastId}
ORDER BY id LIMIT #{pageSize}
```

```java
if (offset > 5000) {
    throw new IllegalArgumentException("offset must be <= 5000");
}
```

### [TDDL-003] 事务里按循环写多行，可能跨分片

- **Severity**: Warning
- **Middleware**: TDDL
- **分级动作**: 处置：本迭代修复。不拦截合入，周期报告里必须有人看。
- **原因**: 一个本地事务或 tx.Begin 里循环 INSERT/UPDATE/DELETE。循环项的分片键如果不是同一个值，提交会变成跨库事务，或者把锁挂在多个分片上直到方法结束。
- **危害**: 事务时间变长，锁范围变大，容易锁等待、连接堆积；跨库两阶段提交失败时会出现部分成功、部分回滚的脏状态。
- **历史故障**: 一个请求里循环更新不同 user_id 的订单，事务跨十几个分片，持锁数十秒，同库其它写入全部排队。
- **检测**: Java 方法带 @Transactional，或 Go 在 Commit 之前调用了 Begin，块内有 for 循环并且有 insert/update/delete/Exec。
- **降噪**: 注释写明同片或已按分片键分组时，降为 Suggestion，需人工复核分组是否真的生效。
- **修复**:

先按分片键分组，每组一个短事务，组内走批量写。跨分片用最终一致，不要拉长一个大事务。

```java
Map<Long, List<Order>> byUser = groupByUserId(orders);
for (List<Order> sameShard : byUser.values()) {
    orderMapper.batchUpdate(sameShard); // 一组一个事务，组内都是同一个 user_id
}
```

### [TDDL-004] UPDATE 或 DELETE 没有有效 WHERE

- **Severity**: Critical
- **Middleware**: TDDL
- **分级动作**: 处置：立即修复。MR 模式拦截合入；周期巡检告警并让最近修改人认领。
- **原因**: 写语句没有 WHERE，或 WHERE 里没有列条件（例如 WHERE 1=1）。数据库会锁住并改掉整张表；分片表上还会先广播再全表写。
- **危害**: 数据被整表改掉或删掉，主从延迟拉大，回滚成本通常是全量恢复。这是发布窗口里反复出现的事故，不依赖是不是分片表。
- **历史故障**: 订正脚本漏写 WHERE，把订单状态全部改成已关闭，只能从备份捞回。
- **检测**: 字符串、注解或 MyBatis 标签里的 UPDATE/DELETE，WHERE 不存在，或 WHERE 中提不出列条件。
- **降噪**: 注释同时写明低频和后台管理时，Critical 降为 Warning。这仍然是全表写，只是不挡合入。
- **修复**:

写语句必须带上能命中索引的条件，分片表还要带分片键。订正脚本先 SELECT 出主键再按主键更新。

```sql
UPDATE order_tab SET status = 0 WHERE user_id = #{userId} AND id = #{id}
```

### [TDDL-005] 分片键被函数或表达式包住，路由失效

- **Severity**: Warning
- **Middleware**: TDDL
- **分级动作**: 处置：本迭代修复。不拦截合入，周期报告里必须有人看。
- **原因**: 路由只用分片键的原始列值。对分片键做函数、隐式转换或四则运算后，优化器不能用这个列裁剪分片，SQL 退回到广播。单表场景下同样用不上索引。
- **危害**: 看起来 WHERE 里有分片键，实际仍打全部分片，排查时容易被放过。
- **历史故障**: WHERE DATE(create_time) 一类写法用在路由列上，执行计划从裁剪一个分片变成扫描全部分片。
- **检测**: 分片上下文中，分片键出现在 date/substr/concat/cast 等函数参数里，或写成 user_id + 数字 这种表达式。
- **降噪**: 没有分片上下文时不报，避免把普通索引列的函数误判成分片广播。
- **修复**:

函数挪到常量一侧，分片键保持裸列。时间范围写成两个边界，不要包列。

```sql
-- 修复前
WHERE substr(user_id, 1, 4) = #{prefix}
-- 修复后：路由列裸值比较，前缀过滤改到写入时的冗余列
WHERE user_id = #{userId}
```

### [TDDL-006] IN 列表被字符串拼接或长到失控

- **Severity**: Warning
- **Middleware**: TDDL
- **分级动作**: 处置：本迭代修复。不拦截合入，周期报告里必须有人看。
- **原因**: 把外部传入的 id 串拼进 IN (...)。列表长度由调用方决定，SQL 文本本身也不再是预编译参数。
- **危害**: 超过 max_allowed_packet 直接报错；没爆包时解析和优化变慢，主从复制延迟上升。拼接还把注入口子打开。
- **历史故障**: 前端一次勾选上万条，拼进一条 IN，语句超过包长限制，连接被断开，重试把数据库打得更满。
- **检测**: 出现 in (" +、in (' + 这类拼接，或 SQL 文本里的 IN 字面量超过 500 个。
- **降噪**: MyBatis foreach 配绑定变量且调用方有长度校验时，静态扫描看不到拼接，不会报。这是漏报边界。
- **修复**:

用绑定变量，并在拼 SQL 之前把列表截到 500 以内，多的分批查。

```java
if (ids.size() > 500) {
    throw new IllegalArgumentException("in-list must be <= 500");
}
// MyBatis: AND user_id IN <foreach collection="ids" item="id" open="(" separator="," close=")">#{id}</foreach>
```

### [TDDL-007] SELECT * 把整行拖过网络

- **Severity**: Warning
- **Middleware**: TDDL
- **分级动作**: 处置：本迭代修复。不拦截合入，周期报告里必须有人看。
- **原因**: 星号会把调用方不需要的列，包括 text、blob、扩展字段，一起读出来。表结构一加列，所有没改过的查询都会变胖。
- **危害**: 网卡、应用内存和分片间的归并流量一起涨。只为了拿两列 id 时也会把大字段读进缓冲。
- **历史故障**: 订单表加了快照 JSON 之后，旧的 SELECT * 列表接口 RT 翻倍，应用 Full GC。
- **检测**: SQL 文本匹配 SELECT * FROM。count(*) 不匹配。
- **降噪**: 没有。星号是写法问题，能确定就报 Warning，不升到 Critical，避免把历史代码全挡在门外。
- **修复**:

列出真正要用的列。

```sql
SELECT id, user_id, status FROM order_tab WHERE user_id = #{userId}
```
