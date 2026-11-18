# Redis 缓存与分布式锁规则

覆盖大 key 全量读取、锁的原子性、缓存同时失效和 KEYS/FLUSH。

每条规则都给出原因、危害、对应过的故障形态，以及能照着改的修复示例。扫描器的判定以可重复的代码形态为准；这里的检测描述与扫描器一致。

级别只使用三档：

- **Critical**：已经能对应到线上故障，MR 合入门禁拦截，周期巡检立即告警。
- **Warning**：会带来性能或稳定性问题，不拦截合入，本迭代要修。
- **Suggestion**：确定性不足，必须人工复核，不拦截。

### [REDIS-001] 一次性读出整个集合

- **Severity**: Critical
- **Middleware**: Redis
- **分级动作**: 处置：立即修复。MR 模式拦截合入；周期巡检告警并让最近修改人认领。
- **原因**: HGETALL、SMEMBERS、LRANGE 0 -1、ZRANGE 0 -1 以及对应的 entries/members/range(0,-1) 会在一次命令里把整个 key 拷出来。Redis 单线程执行这条命令时，其它命令都在排队。
- **危害**: 大 key 一次就能把实例的延迟打到毫秒甚至秒级，所有业务共用这台 Redis 时一起抖动。应用侧还会为这一份全量数据分配大块内存。
- **历史故障**: 会话哈希涨到上百 MB 后，一个 HGETALL 堵住主线程，同实例的登录态读取全部超时。
- **检测**: 调用 hgetAll/HGetAll、smembers、lrange/zrange 的 0 到 -1、opsForHash().entries()、opsForSet().members()。
- **降噪**: 同一行能看出是 config、dict、enum、meta 这类有界小字典时不报。
- **修复**:

改成游标，按批取。集合本身也不要无界增长。

```java
ScanResult<Map.Entry<String, String>> page = jedis.hscan(key, cursor);
```

```java
// 列表按页，不要 0, -1
jedis.lrange(key, 0, 99);
```

### [REDIS-002] 分布式锁不是原子加锁，或释放时不校验持有者

- **Severity**: Critical
- **Middleware**: Redis
- **分级动作**: 处置：立即修复。MR 模式拦截合入；周期巡检告警并让最近修改人认领。
- **原因**: SETNX 和 EXPIRE 是两条命令，进程死在中间就留下一把没有过期时间的锁。解锁如果直接 DEL，删掉的可能是别人刚加上的锁。Go 的 SetNX 超时参数传 0 同样没有 TTL。setIfAbsent 只传 key 和 value 时也没有过期时间。
- **危害**: 锁永远不释放，后面的请求全部失败；或者锁被误删，两台机器同时认为自己持有锁，库存、余额一类的互斥失效。
- **历史故障**: 发布时进程被杀掉，SETNX 已成功、EXPIRE 没执行到，这个用户的下单锁一直占着，只能人工 DEL。另一次事故是解锁没校验 uuid，把下一个请求的锁删掉，出现超卖。
- **检测**: setnx/SETNX、SetNX(..., 0)、两个参数的 setIfAbsent；解锁方法对 lock key 调用 del/delete/unlink，且同一方法没有 eval/lua。
- **降噪**: SET key value NX PX ttl，或 setIfAbsent 带上 Duration/TimeUnit，视为原子加锁。解锁走 eval/evalsha 不报。Redisson 的 getLock 不会命中这些 API。
- **修复**:

加锁一条命令带上 TTL 和持有者。解锁用 Lua 先比对再删。有条件就直接用 Redisson，它自带看门狗。

```java
jedis.set(lockKey, uuid, "NX", "PX", 30_000);
String lua = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end";
jedis.eval(lua, Collections.singletonList(lockKey), Collections.singletonList(uuid));
```

### [REDIS-003] 缓存同时过期，或空结果不占位

- **Severity**: Suggestion
- **Middleware**: Redis
- **分级动作**: 处置：排期评估。确定性不够，报告里标注需人工复核。
- **原因**: 大量 key 用同一个固定 TTL，会在同一秒一起失效，请求同时打到数据库。查询发现空值就 return null、不写短 TTL 占位时，不存在的 key 每次都穿透到数据库。
- **危害**: 失效那一秒数据库 QPS 被放大到缓存未命中的总量，可能把库打挂。穿透场景下，一个被刷的不存在 id 会稳定地打库。
- **历史故障**: 活动配置统一 expire 3600，整点数据库 CPU 打满；另一个接口被不存在的商品 id 刷，缓存永远不命中。
- **检测**: setex/expire 的参数里有两位以上的数字字面量，且当前方法没有 Random。或者读缓存得到 null 后直接 return null，方法里没有写入占位值。
- **降噪**: TTL 表达式里有 Random/ThreadLocalRandom，或写入的是空串占位，不报这一处。这条规则确定性低，一律需人工复核。
- **修复**:

TTL 加抖动。数据库也没有的结果写一个短 TTL 空值。热点 key 再加单飞，避免击穿。

```java
int ttl = 3600 + ThreadLocalRandom.current().nextInt(300);
jedis.setex(key, ttl, value);
if (value == null) {
    jedis.setex(key, 60, "");
    return null;
}
```

### [REDIS-004] KEYS 或 FLUSH 会堵住整个实例

- **Severity**: Critical
- **Middleware**: Redis
- **分级动作**: 处置：立即修复。MR 模式拦截合入；周期巡检告警并让最近修改人认领。
- **原因**: KEYS 按全库扫描并且在跑完之前不处理其它命令。FLUSHALL/FLUSHDB 会清空数据。它们出现在业务仓库里，就有被请求或定时任务触发的路径。
- **危害**: 生产 Redis 卡死数秒甚至更久，依赖它的接口一起超时。FLUSH 还会直接丢数据。
- **历史故障**: 运维习惯写成的 keys("user:*") 被留在管理接口里，一次调用让缓存集群所有节点排队。
- **检测**: jedis.keys(、KEYS 命令、flushAll、flushDB、FLUSHALL、FLUSHDB。
- **降噪**: 附近注释同时包含“低频”和“后台”时，从 Critical 降为 Warning：人少不代表命令不阻塞，所以仍然要改，只是不挡合入。
- **修复**:

线上禁止 KEYS 和 FLUSH。遍历用 SCAN。清理用明确的 key，带上业务前缀，不要清库。

```java
String cursor = "0";
do {
    ScanResult<String> page = jedis.scan(cursor, new ScanParams().match(prefix + "*").count(100));
    cursor = page.getCursor();
} while (!"0".equals(cursor));
```
