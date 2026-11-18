# -*- coding: utf-8 -*-
"""规则目录。扫描器和 rules/*.md 都从这里出，避免两套文案各写各的。"""

import os

from code_risk_scanner import __version__

VERSION = __version__

# 给不出库表路由配置时用的默认分片键。仓库根目录 .code-risk.json 的 sharding_keys 会整表替换它。
DEFAULT_SHARD_KEYS = [
    "user_id", "uid", "tenant_id", "order_id", "buyer_id", "seller_id",
    "shop_id", "merchant_id", "biz_id", "member_id", "account_id",
    "partition_id", "shard_key", "sharding_key", "route_id",
    "customer_id", "org_id",
]

SLA = {
    "Critical": "处置：立即修复。MR 模式拦截合入；周期巡检告警并让最近修改人认领。",
    "Warning": "处置：本迭代修复。不拦截合入，周期报告里必须有人看。",
    "Suggestion": "处置：排期评估。确定性不够，报告里标注需人工复核。",
}

RULE_FILES = {
    "TDDL": "tddl_rules.md",
    "Lindorm": "lindorm_rules.md",
    "Redis": "redis_rules.md",
    "ES": "es_rules.md",
    "Java": "lang_java_go.md",
    "Go": "lang_java_go.md",
    "Env": "env_rules.md",
    "Security": "security_rules.md",
}

RULES = {
    "TDDL-001": {
        "severity": "Critical",
        "middleware": "TDDL",
        "title": "缺少分片键，SQL 广播到全部分片",
        "cause": "分库分表靠 WHERE 里的分片键算路由。条件里没有分片键，或只有 status、create_time 这类非路由列时，中间件无法裁剪分片，只能把同一条 SQL 发到每一个库。",
        "harm": "一次查询或更新打满所有分片：连接池被占满、每个库都出现慢 SQL、RT 抖动，严重时把整条业务链路拖超时。分片越多，放大越厉害。",
        "incident": "大促按 status 批量改订单，逻辑表背后一千多个分片全部执行，数据库连接耗尽，下单接口成片超时。",
        "detect": "文件或 SQL 能看出是分库分表（tddl、sharding、分表、logic table），且 SELECT/UPDATE/DELETE 的 WHERE 没有命中分片键。无 WHERE 的写语句归 TDDL-004，不在这里重复报。",
        "denoise": "注释写明走异构索引、逆向索引或 ES 检索时，降为 Suggestion。无法确认是分片表时不报 Critical。",
        "remediation": """WHERE 带上分片键。业务上确实没有分片键时，先查异构索引或 ES，不要直接广播。

```sql
-- 修复前：只按状态扫，TDDL 广播
SELECT id, status FROM order_tab WHERE status = #{status}
-- 修复后
SELECT id, status FROM order_tab WHERE user_id = #{userId} AND status = #{status}
```""",
    },
    "TDDL-002": {
        "severity": "Warning",
        "middleware": "TDDL",
        "title": "大偏移量深度分页",
        "cause": "LIMIT offset, size 在分库分表下要在每个分片上先取出 offset+size 行，再在中间件里归并排序，最后丢掉前 offset 行。offset 没有上限时，页码可以一直被调用方加大。",
        "harm": "内存和网络随 offset 线性涨，归并排序把应用堆和数据库一起打高。单表深分页本身也慢，分片之后是乘数。",
        "incident": "后台导出用 pageNo * pageSize 一直翻页，offset 到十万以后每个分片都在排序前十万行，数据库 CPU 打满。",
        "detect": "SQL 里出现 LIMIT 数字且偏移大于 5000，或 LIMIT/OFFSET 使用 offset、page 变量，且当前方法没有把偏移截到 5000 以内。",
        "denoise": "同一方法里有 offset > 5000 的拦截、Math.min / Integer.min，视为已防护，不报。",
        "remediation": """不要深翻页。用上一页的主键做游标；如果必须用 offset，在入口把上限定死。

```sql
SELECT id, status FROM order_tab
WHERE user_id = #{userId} AND id > #{lastId}
ORDER BY id LIMIT #{pageSize}
```

```java
if (offset > 5000) {
    throw new IllegalArgumentException("offset must be <= 5000");
}
```""",
    },
    "TDDL-003": {
        "severity": "Warning",
        "middleware": "TDDL",
        "title": "事务里按循环写多行，可能跨分片",
        "cause": "一个本地事务或 tx.Begin 里循环 INSERT/UPDATE/DELETE。循环项的分片键如果不是同一个值，提交会变成跨库事务，或者把锁挂在多个分片上直到方法结束。",
        "harm": "事务时间变长，锁范围变大，容易锁等待、连接堆积；跨库两阶段提交失败时会出现部分成功、部分回滚的脏状态。",
        "incident": "一个请求里循环更新不同 user_id 的订单，事务跨十几个分片，持锁数十秒，同库其它写入全部排队。",
        "detect": "Java 方法带 @Transactional，或 Go 在 Commit 之前调用了 Begin，块内有 for 循环并且有 insert/update/delete/Exec。",
        "denoise": "注释写明同片或已按分片键分组时，降为 Suggestion，需人工复核分组是否真的生效。",
        "remediation": """先按分片键分组，每组一个短事务，组内走批量写。跨分片用最终一致，不要拉长一个大事务。

```java
Map<Long, List<Order>> byUser = groupByUserId(orders);
for (List<Order> sameShard : byUser.values()) {
    orderMapper.batchUpdate(sameShard); // 一组一个事务，组内都是同一个 user_id
}
```""",
    },
    "TDDL-004": {
        "severity": "Critical",
        "middleware": "TDDL",
        "title": "UPDATE 或 DELETE 没有有效 WHERE",
        "cause": "写语句没有 WHERE，或 WHERE 里没有列条件（例如 WHERE 1=1）。数据库会锁住并改掉整张表；分片表上还会先广播再全表写。",
        "harm": "数据被整表改掉或删掉，主从延迟拉大，回滚成本通常是全量恢复。这是发布窗口里反复出现的事故，不依赖是不是分片表。",
        "incident": "订正脚本漏写 WHERE，把订单状态全部改成已关闭，只能从备份捞回。",
        "detect": "字符串、注解或 MyBatis 标签里的 UPDATE/DELETE，WHERE 不存在，或 WHERE 中提不出列条件。",
        "denoise": "注释同时写明低频和后台管理时，Critical 降为 Warning。这仍然是全表写，只是不挡合入。",
        "remediation": """写语句必须带上能命中索引的条件，分片表还要带分片键。订正脚本先 SELECT 出主键再按主键更新。

```sql
UPDATE order_tab SET status = 0 WHERE user_id = #{userId} AND id = #{id}
```""",
    },
    "TDDL-005": {
        "severity": "Warning",
        "middleware": "TDDL",
        "title": "分片键被函数或表达式包住，路由失效",
        "cause": "路由只用分片键的原始列值。对分片键做函数、隐式转换或四则运算后，优化器不能用这个列裁剪分片，SQL 退回到广播。单表场景下同样用不上索引。",
        "harm": "看起来 WHERE 里有分片键，实际仍打全部分片，排查时容易被放过。",
        "incident": "WHERE DATE(create_time) 一类写法用在路由列上，执行计划从裁剪一个分片变成扫描全部分片。",
        "detect": "分片上下文中，分片键出现在 date/substr/concat/cast 等函数参数里，或写成 user_id + 数字 这种表达式。",
        "denoise": "没有分片上下文时不报，避免把普通索引列的函数误判成分片广播。",
        "remediation": """函数挪到常量一侧，分片键保持裸列。时间范围写成两个边界，不要包列。

```sql
-- 修复前
WHERE substr(user_id, 1, 4) = #{prefix}
-- 修复后：路由列裸值比较，前缀过滤改到写入时的冗余列
WHERE user_id = #{userId}
```""",
    },
    "TDDL-006": {
        "severity": "Warning",
        "middleware": "TDDL",
        "title": "IN 列表被字符串拼接或长到失控",
        "cause": "把外部传入的 id 串拼进 IN (...)。列表长度由调用方决定，SQL 文本本身也不再是预编译参数。",
        "harm": "超过 max_allowed_packet 直接报错；没爆包时解析和优化变慢，主从复制延迟上升。拼接还把注入口子打开。",
        "incident": "前端一次勾选上万条，拼进一条 IN，语句超过包长限制，连接被断开，重试把数据库打得更满。",
        "detect": "出现 in (\" +、in (' + 这类拼接，或 SQL 文本里的 IN 字面量超过 500 个。",
        "denoise": "MyBatis foreach 配绑定变量且调用方有长度校验时，静态扫描看不到拼接，不会报。这是漏报边界。",
        "remediation": """用绑定变量，并在拼 SQL 之前把列表截到 500 以内，多的分批查。

```java
if (ids.size() > 500) {
    throw new IllegalArgumentException("in-list must be <= 500");
}
// MyBatis: AND user_id IN <foreach collection="ids" item="id" open="(" separator="," close=")">#{id}</foreach>
```""",
    },
    "TDDL-007": {
        "severity": "Warning",
        "middleware": "TDDL",
        "title": "SELECT * 把整行拖过网络",
        "cause": "星号会把调用方不需要的列，包括 text、blob、扩展字段，一起读出来。表结构一加列，所有没改过的查询都会变胖。",
        "harm": "网卡、应用内存和分片间的归并流量一起涨。只为了拿两列 id 时也会把大字段读进缓冲。",
        "incident": "订单表加了快照 JSON 之后，旧的 SELECT * 列表接口 RT 翻倍，应用 Full GC。",
        "detect": "SQL 文本匹配 SELECT * FROM。count(*) 不匹配。",
        "denoise": "没有。星号是写法问题，能确定就报 Warning，不升到 Critical，避免把历史代码全挡在门外。",
        "remediation": """列出真正要用的列。

```sql
SELECT id, user_id, status FROM order_tab WHERE user_id = #{userId}
```""",
    },
    "LINDORM-001": {
        "severity": "Critical",
        "middleware": "Lindorm",
        "title": "RowKey 以递增时间开头，写入打在同一个 Region",
        "cause": "Lindorm/HBase 按 RowKey 字典序切 Region。前缀如果是 currentTimeMillis 或 time.Now().Unix() 这种单调值，同一时段的写入落在同一段 RowKey 上，也就是同一个 RegionServer。",
        "harm": "单台机器 CPU、磁盘和 handler 打满，其它机器闲着。写入延迟变高，严重时这个 Region 一直分裂、一直热点。",
        "incident": "日志表用毫秒时间戳当 RowKey 前缀，高峰期单个 RegionServer 写延迟到秒级，集群其它节点利用率不到两成。",
        "detect": "RowKey 赋值附近出现 System.currentTimeMillis、Instant.now 或 time.Now().Unix，且同一窗口没有 md5、hash、salt、反转或 MAX_VALUE 减时间。",
        "denoise": "时间戳前面已经有 hash/md5/salt，或用 Long.MAX_VALUE - ts 做反转时不报。",
        "remediation": """前缀用散列把写入打散，时间放在后面便于范围扫。

```java
String rowKey = md5(id).substring(0, 4) + System.currentTimeMillis() + id;
```

```text
反转时间（只要按时间倒序、不需要打散时再用）：
Long.MAX_VALUE - System.currentTimeMillis()
```""",
    },
    "LINDORM-002": {
        "severity": "Critical",
        "middleware": "Lindorm",
        "title": "Scan 没有行界，或用列值过滤器扫全表",
        "cause": "Scan 不设 StartRow/StopRow 就是全表扫。ValueFilter、SubstringComparator 要读出列值才能判断，服务端无法靠 RowKey 跳过数据块。",
        "harm": "RegionServer 读放大，缓存被冲掉，和在线点查抢 handler。一次全表扫可以把集群读延迟整体抬高。",
        "incident": "运营查询用 SubstringComparator 在用户宽表上找昵称，Scan 没有行界，集群读 P99 在任务跑完之前一直异常。",
        "detect": "new Scan() 所在方法没有同时设置 StartRow 和 StopRow；或者用了 ValueFilter/SubstringComparator 却没有 setLimit/setCaching。",
        "denoise": "同一方法里 StartRow 和 StopRow 都在，并且过滤器场景设了 limit，不报。",
        "remediation": """用 RowKey 前缀圈定范围。列值模糊匹配不要做在线 Scan，改到检索引擎。

```java
Scan scan = new Scan().withStartRow(start).withStopRow(stop);
scan.setLimit(100);
```""",
    },
    "LINDORM-003": {
        "severity": "Warning",
        "middleware": "Lindorm",
        "title": "单个 Cell 写入整段 JSON 或整个文件",
        "cause": "addColumn 的值来自整对象 JSON 序列化或整个文件的字节。宽表的一个 Cell 会进 memstore、WAL 和缓存，大小没有在代码里封顶。",
        "harm": "单个 Cell 到几百 KB 以上时，compaction 和 GC 停顿变长，热点 Region 更容易把 RegionServer 打满。",
        "incident": "把活动详情的完整 JSON 列表塞进一个 qualifier，Region 压缩时 Old Gen 被大对象撑满，出现长时间 GC。",
        "detect": "addColumn 附近调用了 toJSONString、json.Marshal、readAllBytes、ReadFile 或 writeValueAsString。",
        "denoise": "只写入 URL 或主键的 getBytes 不报。扫描器看不出运行时字节长度，所以这是 Warning 不是 Critical。",
        "remediation": """单 Cell 控制在 100KB 内。大对象拆成多行多列，或把正文放到对象存储，宽表里只留地址。

```java
put.addColumn(CF, URL_QUAL, ossUrl.getBytes(StandardCharsets.UTF_8));
```""",
    },
    "LINDORM-004": {
        "severity": "Warning",
        "middleware": "Lindorm",
        "title": "循环攒批后一次提交，没有分批上限",
        "cause": "for 循环把 Put 放进列表，循环结束后一次 table.put(puts)。列表长度等于入参长度。",
        "harm": "一次 RPC 的 body 过大，RegionServer 堆上出现大数组，超时后重试会把同一批再打一遍。",
        "incident": "日终任务把几十万行放进一个 batch 提交，请求超过 RPC 上限，任务重试把同一个 Region 反复打热。",
        "detect": "方法里有 for、puts.add（或 batch.add）以及 table.put(puts)/batch(puts)，且没有 subList、partition 或 puts.size() 阈值。",
        "denoise": "看到分批阈值就认为已防护。阈值写得过大（比如一百万）扫描器不会算，这是漏报边界。",
        "remediation": """按固定大小切开再提交。

```java
if (puts.size() >= 100) {
    table.put(puts);
    puts.clear();
}
```""",
    },
    "REDIS-001": {
        "severity": "Critical",
        "middleware": "Redis",
        "title": "一次性读出整个集合",
        "cause": "HGETALL、SMEMBERS、LRANGE 0 -1、ZRANGE 0 -1 以及对应的 entries/members/range(0,-1) 会在一次命令里把整个 key 拷出来。Redis 单线程执行这条命令时，其它命令都在排队。",
        "harm": "大 key 一次就能把实例的延迟打到毫秒甚至秒级，所有业务共用这台 Redis 时一起抖动。应用侧还会为这一份全量数据分配大块内存。",
        "incident": "会话哈希涨到上百 MB 后，一个 HGETALL 堵住主线程，同实例的登录态读取全部超时。",
        "detect": "调用 hgetAll/HGetAll、smembers、lrange/zrange 的 0 到 -1、opsForHash().entries()、opsForSet().members()。",
        "denoise": "同一行能看出是 config、dict、enum、meta 这类有界小字典时不报。",
        "remediation": """改成游标，按批取。集合本身也不要无界增长。

```java
ScanResult<Map.Entry<String, String>> page = jedis.hscan(key, cursor);
```

```java
// 列表按页，不要 0, -1
jedis.lrange(key, 0, 99);
```""",
    },
    "REDIS-002": {
        "severity": "Critical",
        "middleware": "Redis",
        "title": "分布式锁不是原子加锁，或释放时不校验持有者",
        "cause": "SETNX 和 EXPIRE 是两条命令，进程死在中间就留下一把没有过期时间的锁。解锁如果直接 DEL，删掉的可能是别人刚加上的锁。Go 的 SetNX 超时参数传 0 同样没有 TTL。setIfAbsent 只传 key 和 value 时也没有过期时间。",
        "harm": "锁永远不释放，后面的请求全部失败；或者锁被误删，两台机器同时认为自己持有锁，库存、余额一类的互斥失效。",
        "incident": "发布时进程被杀掉，SETNX 已成功、EXPIRE 没执行到，这个用户的下单锁一直占着，只能人工 DEL。另一次事故是解锁没校验 uuid，把下一个请求的锁删掉，出现超卖。",
        "detect": "setnx/SETNX、SetNX(..., 0)、两个参数的 setIfAbsent；解锁方法对 lock key 调用 del/delete/unlink，且同一方法没有 eval/lua。",
        "denoise": "SET key value NX PX ttl，或 setIfAbsent 带上 Duration/TimeUnit，视为原子加锁。解锁走 eval/evalsha 不报。Redisson 的 getLock 不会命中这些 API。",
        "remediation": """加锁一条命令带上 TTL 和持有者。解锁用 Lua 先比对再删。有条件就直接用 Redisson，它自带看门狗。

```java
jedis.set(lockKey, uuid, "NX", "PX", 30_000);
String lua = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end";
jedis.eval(lua, Collections.singletonList(lockKey), Collections.singletonList(uuid));
```""",
    },
    "REDIS-003": {
        "severity": "Suggestion",
        "middleware": "Redis",
        "title": "缓存同时过期，或空结果不占位",
        "cause": "大量 key 用同一个固定 TTL，会在同一秒一起失效，请求同时打到数据库。查询发现空值就 return null、不写短 TTL 占位时，不存在的 key 每次都穿透到数据库。",
        "harm": "失效那一秒数据库 QPS 被放大到缓存未命中的总量，可能把库打挂。穿透场景下，一个被刷的不存在 id 会稳定地打库。",
        "incident": "活动配置统一 expire 3600，整点数据库 CPU 打满；另一个接口被不存在的商品 id 刷，缓存永远不命中。",
        "detect": "setex/expire 的参数里有两位以上的数字字面量，且当前方法没有 Random。或者读缓存得到 null 后直接 return null，方法里没有写入占位值。",
        "denoise": "TTL 表达式里有 Random/ThreadLocalRandom，或写入的是空串占位，不报这一处。这条规则确定性低，一律需人工复核。",
        "review": True,
        "remediation": """TTL 加抖动。数据库也没有的结果写一个短 TTL 空值。热点 key 再加单飞，避免击穿。

```java
int ttl = 3600 + ThreadLocalRandom.current().nextInt(300);
jedis.setex(key, ttl, value);
if (value == null) {
    jedis.setex(key, 60, "");
    return null;
}
```""",
    },
    "REDIS-004": {
        "severity": "Critical",
        "middleware": "Redis",
        "title": "KEYS 或 FLUSH 会堵住整个实例",
        "cause": "KEYS 按全库扫描并且在跑完之前不处理其它命令。FLUSHALL/FLUSHDB 会清空数据。它们出现在业务仓库里，就有被请求或定时任务触发的路径。",
        "harm": "生产 Redis 卡死数秒甚至更久，依赖它的接口一起超时。FLUSH 还会直接丢数据。",
        "incident": "运维习惯写成的 keys(\"user:*\") 被留在管理接口里，一次调用让缓存集群所有节点排队。",
        "detect": "jedis.keys(、KEYS 命令、flushAll、flushDB、FLUSHALL、FLUSHDB。",
        "denoise": "附近注释同时包含“低频”和“后台”时，从 Critical 降为 Warning：人少不代表命令不阻塞，所以仍然要改，只是不挡合入。",
        "remediation": """线上禁止 KEYS 和 FLUSH。遍历用 SCAN。清理用明确的 key，带上业务前缀，不要清库。

```java
String cursor = "0";
do {
    ScanResult<String> page = jedis.scan(cursor, new ScanParams().match(prefix + "*").count(100));
    cursor = page.getCursor();
} while (!"0".equals(cursor));
```""",
    },
    "ES-001": {
        "severity": "Critical",
        "middleware": "ES",
        "title": "from/size 深分页没有上限",
        "cause": "Elasticsearch 的 from+size 要在每个分片上取出前 from+size 条再汇总。from 来自页码或在循环里累加，又没有 10000 的上限时，协调节点要持有越来越大的窗口。",
        "harm": "超过 index.max_result_window（默认 10000）直接报错；把窗口调大则会把协调节点堆内存打满。导出任务用递增 from 是常见触发方式。",
        "incident": "订单导出 for 循环里 sourceBuilder.from(from) 每次加 1000，跑到后半段集群出现 circuit breaker，搜索整体变慢。",
        "detect": "sourceBuilder.from 或 setFrom 的参数不是小于 10000 的常量，且当前方法没有 search_after，也没有 from+size 与 10000 的比较。",
        "denoise": "方法里使用 searchAfter/search_after，或有 from+size 不超过 10000 的判断时不报。from(0) 这类小常量不报。",
        "remediation": """在线翻页封死深度。全量遍历用 search_after，导出再加 PIT。

```java
if (from + size > 10000) {
    throw new IllegalArgumentException("use search_after");
}
sourceBuilder.searchAfter(sortValues);
sourceBuilder.size(size);
```""",
    },
    "ES-002": {
        "severity": "Warning",
        "middleware": "ES",
        "title": "左通配或前导模糊匹配",
        "cause": "Wildcard、regexp、query_string 的模式以 * 或 ? 开头时，倒排索引无法按前缀收窄，查询要扫很大一块 term 字典。",
        "harm": "CPU 升高，慢查询拖住搜索线程池，同一集群的精确查询延迟跟着涨。",
        "incident": "商品搜索把用户输入包成 *keyword*，大促时搜索节点 CPU 打满。",
        "detect": "wildcardQuery、regexpQuery、queryStringQuery、NewWildcardQuery 的参数字符串以 * 或 ? 开头。",
        "denoise": "后缀通配 keyword* 不报。match/term 不报。",
        "remediation": """写入时用 ngram 或 edge_ngram，查询用 match 或 term。不要在查询里做前导星号。

```java
QueryBuilders.matchQuery("name.ngram", keyword);
```""",
    },
    "ES-003": {
        "severity": "Warning",
        "middleware": "ES",
        "title": "查询路径上跑脚本",
        "cause": "painless、ScriptQuery、script_score 在查询阶段对命中的文档做解释执行，开销在协调和数据节点上随命中数增长。",
        "harm": "脚本查询容易把 search 线程池打满，并触发 circuit breaker。它没有 from/size 那么容易被默认配置挡住。",
        "incident": "用脚本按复杂公式重算排序，索引变大后搜索线程池拒绝普通查询。",
        "detect": "出现 new Script(、ScriptQuery、script_score 或 scriptQuery。",
        "denoise": "扫描器分不清脚本用在查询还是一次性 reindex。所以是 Warning。确认只在离线任务且有超时后再人工放过。",
        "remediation": """把计算结果做成写入时的字段，查询只做 match/term/range。必须用脚本时放到离线任务，并设置请求超时。

```java
sourceBuilder.query(QueryBuilders.rangeQuery("score").gte(minScore));
sourceBuilder.timeout(TimeValue.timeValueMillis(200));
```""",
    },
    "JAVA-001": {
        "severity": "Warning",
        "middleware": "Java",
        "title": "线程池队列或线程数没有上界",
        "cause": "Executors.newFixedThreadPool 和 newSingleThreadExecutor 内部是无界 LinkedBlockingQueue。newCachedThreadPool 是无界建线程。手写 ThreadPoolExecutor 时 new LinkedBlockingQueue<>() 同样不设容量。",
        "harm": "下游变慢后任务堆在队列里，最终 OOM 把进程打死。缓存池则会先把线程数打到机器扛不住。",
        "incident": "固定线程池接住一个变慢的下游，队列里堆积的任务对象把堆撑满，进程被系统杀掉，正在处理的请求全部丢失。",
        "detect": "Executors.newFixedThreadPool、newSingleThreadExecutor、newCachedThreadPool，或 new LinkedBlockingQueue() / new LinkedBlockingQueue<>() 没有容量参数。",
        "denoise": "new LinkedBlockingQueue<>(1000) 这种带容量的写法不报。",
        "remediation": """队列给容量，并写上拒绝策略。调用方要能感知拒绝，而不是无限排队。

```java
ExecutorService pool = new ThreadPoolExecutor(
        4, 8, 60L, TimeUnit.SECONDS,
        new LinkedBlockingQueue<>(1000),
        new ThreadPoolExecutor.CallerRunsPolicy());
```""",
    },
    "JAVA-002": {
        "severity": "Suggestion",
        "middleware": "Java",
        "title": "CompletableFuture 占用公共线程池或没有超时",
        "cause": "supplyAsync/runAsync 不传 Executor 时用 ForkJoinPool.commonPool()。这个池是整个 JVM 共享的。get() 不带超时则一直等到对方完成。",
        "harm": "一个慢任务把公共池占满，别的无关功能一起卡住。没有超时的 get() 会把调用线程永久挂住，线程池被耗尽。",
        "incident": "公共池被一个无超时的外部调用占满，健康检查和业务异步任务同时停住。",
        "detect": "supplyAsync/runAsync 的参数在顶层没有逗号（没有传入线程池），或同一方法里对 future 调用了无参 get()，且没有 orTimeout、也没有带参数的 get。",
        "denoise": "传入了业务线程池，并且 get(timeout, unit) 或 orTimeout 存在时不报。确定性有限，需人工复核是不是公共池。",
        "review": True,
        "remediation": """使用业务自己的有界线程池，等待必须带超时。

```java
return CompletableFuture.supplyAsync(() -> query(), bizPool).get(1, TimeUnit.SECONDS);
```""",
    },
    "JAVA-003": {
        "severity": "Warning",
        "middleware": "Java",
        "title": "SimpleDateFormat 被多个线程共用",
        "cause": "SimpleDateFormat 内部持有可被改写的 Calendar。把它做成 static 或成员字段后，多个请求会同时 format/parse 同一实例。",
        "harm": "结果错乱，或者抛出 ArrayIndexOutOfBoundsException、NumberFormatException，而且很难复现。",
        "incident": "静态日期格式化器在高峰期把订单时间格式化成错误的日期，对账对不上。",
        "detect": "字段赋值形如 SimpleDateFormat 名字 = new SimpleDateFormat，且不在方法内部，周围也没有 ThreadLocal。",
        "denoise": "方法里的局部变量不报。用 ThreadLocal 包起来，或改用 DateTimeFormatter 时不报。",
        "remediation": """用不可变的 DateTimeFormatter，或每个线程一份。

```java
private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd");
```""",
    },
    "GO-001": {
        "severity": "Critical",
        "middleware": "Go",
        "title": "goroutine 发了没人收，或并发写同一个 map",
        "cause": "go func 里向 channel 发送，但没有 select 和 ctx.Done。调用方一旦提前返回，接收者消失，这个发送永远堵着，goroutine 就泄漏了。多个 goroutine 写同一个原生 map 且没有锁时，运行时会直接检测到数据竞争。",
        "harm": "泄漏把内存和线程慢慢吃满，进程越来越慢。并发写 map 会 fatal error: concurrent map writes，进程立刻退出。",
        "incident": "超时路径先 return，留在后台的发送 goroutine 每个请求漏一个，几小时后内存告警。另一起是多个 goroutine 填同一个 map，进程在高峰直接崩溃。",
        "detect": "go func 体内有 ch <- 发送，且没有 select 或 ctx.Done。或者体内对 make(map) 出来的变量做下标赋值，且体内没有 Lock 或 sync.Map。",
        "denoise": "发送包在 select 里并监听 ctx.Done，或写 map 前有 Mutex/RWMutex，不报。带缓冲、由别的文件负责接收的 channel，扫描器看不到，可能误报，看到之后按调用方核对。",
        "remediation": """发送要能被取消。map 用锁或者 sync.Map。

```go
go func() {
    select {
    case ch <- item:
    case <-ctx.Done():
        return
    }
}()
```

```go
mu.Lock()
m[k] = v
mu.Unlock()
```""",
    },
    "GO-002": {
        "severity": "Warning",
        "middleware": "Go",
        "title": "在 for 循环里直接 defer Close",
        "cause": "defer 在函数返回时才执行，不是在这一次循环结束时执行。写在 for 里面的 Close 会堆到整个函数结束。",
        "harm": "文件句柄、连接和响应体一直占着，循环次数一多就触发 too many open files，后续请求失败。",
        "incident": "循环里对下游发请求并 defer Body.Close，批量任务跑到一半把进程的 fd 打满。",
        "detect": "for 循环的花括号体内、不在更内层的 func 里，出现 defer ...Close()。",
        "denoise": "每次迭代套一个立即执行的函数，defer 写在这个函数里，视为正确写法，不报。",
        "remediation": """把一次迭代收进函数，让 defer 在这次迭代结束时跑。

```go
for _, u := range urls {
    func() {
        resp, err := client.Get(u)
        if err != nil {
            return
        }
        defer resp.Body.Close()
    }()
}
```""",
    },
    "GO-003": {
        "severity": "Warning",
        "middleware": "Go",
        "title": "HTTP 客户端没有超时",
        "cause": "http.Get 和 http.DefaultClient 的 Timeout 是 0，表示一直等。自己 new 的 http.Client 字面量里如果没有 Timeout 字段，也是一样。",
        "harm": "下游卡住时，每个请求留一个 goroutine 和一条连接。请求持续进来就会把进程的 goroutine 和 fd 打满，最后连健康的下游也调不出去。",
        "incident": "支付回调使用 http.Get，对方负载均衡黑洞，服务 goroutine 从几百涨到几十万后无响应。",
        "detect": "出现 http.Get(、http.DefaultClient，或 http.Client{ 复合字面量里没有 Timeout。",
        "denoise": "使用设置了 Timeout 的 *http.Client，并且没有再调用 http.Get，不报。",
        "remediation": """每个外部调用都用带超时的 client，超时按这个接口的预算来，不要用默认客户端。

```go
client := &http.Client{Timeout: 2 * time.Second}
resp, err := client.Get(u)
```""",
    },
    "ENV-001": {
        "severity": "Critical",
        "middleware": "Env",
        "title": "连接地址写死了某一个环境",
        "cause": "JDBC、Redis 或 HTTP 地址里带了日常、预发、灰度或生产的域名，又写在没有环境后缀的代码或默认配置里。这份配置打到哪个环境，连的都是同一个地址。",
        "harm": "日常任务会打进生产库，或者生产发布后仍连着日常库。两边的数据串在一起，订正和缓存都会污染另一套环境。",
        "incident": "默认 application.properties 写了 daily 的 RDS 地址，生产发布后订单写进了日常库，线上查不到单。",
        "detect": "文件名看不出环境，连接串主机名里带 daily、pre、gray 或 online/prod。",
        "denoise": "application-daily、application-prod 这类文件名已经声明环境，并且地址和文件名一致时不报。地址是 ${} 占位符时不报。",
        "remediation": """按环境拆配置，地址从环境自己的配置中心读，不要写死。

```properties
# application-daily.properties
spring.datasource.url=jdbc:mysql://rm-xxx.daily.mysql.rds.aliyuncs.com:3306/trade
# application-prod.properties 使用生产地址，不要复用日常域名
spring.datasource.url=${db.url}
```""",
    },
    "ENV-002": {
        "severity": "Critical",
        "middleware": "Env",
        "title": "配置文件声明的环境和连接地址不是一套",
        "cause": "文件名已经标明日常、预发、灰度或生产，里面的连接串却指向另一套环境。发布系统按文件名选配置，连上去的却是别的库。",
        "harm": "生产配置指向日常或预发时，线上读写打到错误的库，出现丢单、脏写和缓存串环境。灰度配置指向生产主库时，灰度流量直接改生产数据。",
        "incident": "application-prod.properties 里留着 daily 的 MySQL 地址，生产发布后支付结果写进日常库。",
        "detect": "文件名能判断环境，连接串里的环境标记和文件名不一致。",
        "denoise": "地址是占位符，或和文件名是同一环境时不报。",
        "remediation": """生产和低环境的地址分开。生产文件里只留生产地址。

```properties
# application-prod.properties
spring.datasource.url=jdbc:mysql://rm-prod.online.mysql.rds.aliyuncs.com:3306/trade
```""",
    },
    "ENV-003": {
        "severity": "Warning",
        "middleware": "Env",
        "title": "同一份默认配置混了多套环境",
        "cause": "一份没有环境后缀的配置里同时写了两套及以上环境的连接串。用哪一套取决于调用方有没有选对 key，选错就串环境。",
        "harm": "灰度、预发和生产共用这份文件时，很容易拿错 key，把流量打到另一套库或缓存。",
        "incident": "一份 application.yml 同时写了 daily 和 online 的地址，预发发版时读到了 online 那一项。",
        "detect": "文件名没有环境后缀，连接串里出现至少两种环境。",
        "denoise": "已经拆成 application-daily、application-prod 的文件不在这里报。",
        "remediation": """一种环境一个文件，默认配置里不放具体地址。

```yaml
# 默认文件只留占位
spring.datasource.url: ${db.url}
```""",
    },
    "SEC-001": {
        "severity": "Critical",
        "middleware": "Security",
        "title": "密码或密钥明文写在仓库里",
        "cause": "password、accessKey、secret 被赋成一个具体字符串，而不是配置中心或加密占位符。仓库能被克隆，密钥就跟着出去。",
        "harm": "数据库、缓存和开放接口的口令泄露后，可以直接登录生产或日常资源，数据被读走或改掉。",
        "incident": "数据源密码写在 application.properties 里，仓库权限放大后被用来直连订单库。",
        "detect": "password、secret_key、access_key、appsecret 后面是长度不少于 4 的字面量，或 setPassword/setSecret 传入了同样的字面量。",
        "denoise": "值是 ${...}、ENC(...)、星号占位或空值时不报。注释行不报。",
        "remediation": """密钥放配置中心或加密项，仓库里只留占位符。

```properties
spring.datasource.password=${db.password}
```""",
    },
    "SEC-002": {
        "severity": "Critical",
        "middleware": "Security",
        "title": "回调或通知入口没有验签",
        "cause": "路径或方法名是 notify、callback，方法里直接 update/delete/insert，但没有验签。外部只要知道地址和单号就能改状态。",
        "harm": "支付、退款、履约回调可以被伪造，订单被改成已支付或已退款，造成资损。",
        "incident": "支付通知没有校验签名，伪造的成功回调把未付款订单推进了履约。",
        "detect": "方法签名或映射里有 notify/callback，方法体有写库，且没有 verify、checkSign、signature、验签或 HMAC/RSA。",
        "denoise": "同一方法里已经调用验签时不报。扫描器看不到另一个过滤器里的验签，这种情况需要人工看过滤器链。",
        "remediation": """先验签，通过之后才改状态。验签失败直接拒绝。

```java
@PostMapping("/pay/notify")
public void onNotify(String body, String sign) {
    if (!rsa.verify(body, sign)) {
        throw new IllegalArgumentException("bad sign");
    }
    payOrderDao.markPaid(body);
}
```""",
    },
    "SEC-003": {
        "severity": "Critical",
        "middleware": "Security",
        "title": "按外部传入的单号改数据，没有校验是不是当前用户的",
        "cause": "orderId、refundId 来自请求参数，更新或删除语句的 WHERE 里没有 user_id、buyer_id 这类归属列，方法里也没有归属校验。知道或猜到单号就能改别人的单。",
        "harm": "跨用户改状态、改金额或删数据。交易链路上这就是越权，影响的是别人的订单、退款和支付。",
        "incident": "退款接口只按 refundId 更新，调用方替换单号后改掉了其他买家的退款单。",
        "detect": "方法从 getParameter 或 @RequestParam 拿 orderId/bizOrderId/refundId，同一方法里的 UPDATE/DELETE 没有用户归属列，也没有 checkOwner、登录用户或鉴权调用。",
        "denoise": "WHERE 里有 buyer_id、user_id 等归属列，或方法里有归属校验时不报。校验如果写在另一个类里，这里会漏，需要沿调用链再看。",
        "remediation": """WHERE 带上当前登录用户，或先做归属校验再写。

```java
String buyerId = session.getCurrentUser();
String sql = "update refund set status = 1 where id = #{id} and buyer_id = #{buyerId}";
```""",
    },
}


def rule(rule_id):
    item = dict(RULES[rule_id])
    item["id"] = rule_id
    item["sla"] = SLA[item["severity"]]
    item["review"] = bool(item.get("review", item["severity"] == "Suggestion"))
    return item


def iter_rules():
    for rule_id in RULES:
        yield rule(rule_id)


def render_rule(item):
    return "\n".join([
        "### [{id}] {title}".format(**item),
        "",
        "- **Severity**: {severity}".format(**item),
        "- **Middleware**: {middleware}".format(**item),
        "- **分级动作**: {sla}".format(**item),
        "- **原因**: {cause}".format(**item),
        "- **危害**: {harm}".format(**item),
        "- **历史故障**: {incident}".format(**item),
        "- **检测**: {detect}".format(**item),
        "- **降噪**: {denoise}".format(**item),
        "- **修复**:",
        "",
        item["remediation"].rstrip(),
        "",
    ])


def render_file(middleware_names, title, intro):
    parts = [
        "# {0}".format(title),
        "",
        intro.rstrip(),
        "",
        "级别只使用三档：",
        "",
        "- **Critical**：已经能对应到线上故障，MR 合入门禁拦截，周期巡检立即告警。",
        "- **Warning**：会带来性能或稳定性问题，不拦截合入，本迭代要修。",
        "- **Suggestion**：确定性不足，必须人工复核，不拦截。",
        "",
    ]
    for item in iter_rules():
        if item["middleware"] in middleware_names:
            parts.append(render_rule(item))
    return "\n".join(parts).rstrip() + "\n"


def render_all():
    common = (
        "每条规则都给出原因、危害、对应过的故障形态，以及能照着改的修复示例。"
        "扫描器的判定以可重复的代码形态为准；这里的检测描述与扫描器一致。"
    )
    docs = {
        "tddl_rules.md": render_file(
            ["TDDL"],
            "TDDL / 分库分表规则",
            "覆盖广播扫描、深分页、跨分片写、全表写、路由列被包住、IN 拼接和 SELECT *。"
            "这些条和仓库里的 MySQL 设计规范对齐：分区键必须出现在 SQL 里，DML 必须有 WHERE，IN 列表控制在 500 以内，禁止 SELECT *。\n\n" + common,
        ),
        "lindorm_rules.md": render_file(
            ["Lindorm"],
            "Lindorm / HBase 宽表规则",
            "覆盖 RowKey 热点、无界 Scan、大 Cell 和无上限批量写。\n\n" + common,
        ),
        "redis_rules.md": render_file(
            ["Redis"],
            "Redis 缓存与分布式锁规则",
            "覆盖大 key 全量读取、锁的原子性、缓存同时失效和 KEYS/FLUSH。\n\n" + common,
        ),
        "es_rules.md": render_file(
            ["ES"],
            "Elasticsearch 规则",
            "覆盖深分页、前导通配和查询脚本。\n\n" + common,
        ),
        "lang_java_go.md": render_file(
            ["Java", "Go"],
            "Java 与 Go 并发和资源规则",
            "覆盖无界线程池、CompletableFuture、共享的 SimpleDateFormat、goroutine 泄漏、并发 map、循环 defer 和无超时的 HTTP 客户端。\n\n" + common,
        ),
        "env_rules.md": render_file(
            ["Env"],
            "环境隔离规则（日常、预发、灰度、生产）",
            "覆盖写死的环境地址、配置文件和连接串不是一套环境、一份默认配置混多套环境。\n\n" + common,
        ),
        "security_rules.md": render_file(
            ["Security"],
            "安全防护规则",
            "覆盖明文密码或密钥、回调没有验签、按外部单号跨用户修改。\n\n" + common,
        ),
    }
    return docs


def write_rule_docs(root=None):
    base = root or os.path.join(os.path.dirname(__file__), "rules")
    os.makedirs(base, exist_ok=True)
    paths = []
    for name, text in render_all().items():
        path = os.path.join(base, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        paths.append(path)
    return paths


if __name__ == "__main__":
    for path in write_rule_docs():
        print(path)
