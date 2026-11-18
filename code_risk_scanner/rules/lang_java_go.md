# Java 与 Go 并发和资源规则

覆盖无界线程池、CompletableFuture、共享的 SimpleDateFormat、goroutine 泄漏、并发 map、循环 defer 和无超时的 HTTP 客户端。

每条规则都给出原因、危害、对应过的故障形态，以及能照着改的修复示例。扫描器的判定以可重复的代码形态为准；这里的检测描述与扫描器一致。

级别只使用三档：

- **Critical**：已经能对应到线上故障，MR 合入门禁拦截，周期巡检立即告警。
- **Warning**：会带来性能或稳定性问题，不拦截合入，本迭代要修。
- **Suggestion**：确定性不足，必须人工复核，不拦截。

### [JAVA-001] 线程池队列或线程数没有上界

- **Severity**: Warning
- **Middleware**: Java
- **分级动作**: 处置：本迭代修复。不拦截合入，周期报告里必须有人看。
- **原因**: Executors.newFixedThreadPool 和 newSingleThreadExecutor 内部是无界 LinkedBlockingQueue。newCachedThreadPool 是无界建线程。手写 ThreadPoolExecutor 时 new LinkedBlockingQueue<>() 同样不设容量。
- **危害**: 下游变慢后任务堆在队列里，最终 OOM 把进程打死。缓存池则会先把线程数打到机器扛不住。
- **历史故障**: 固定线程池接住一个变慢的下游，队列里堆积的任务对象把堆撑满，进程被系统杀掉，正在处理的请求全部丢失。
- **检测**: Executors.newFixedThreadPool、newSingleThreadExecutor、newCachedThreadPool，或 new LinkedBlockingQueue() / new LinkedBlockingQueue<>() 没有容量参数。
- **降噪**: new LinkedBlockingQueue<>(1000) 这种带容量的写法不报。
- **修复**:

队列给容量，并写上拒绝策略。调用方要能感知拒绝，而不是无限排队。

```java
ExecutorService pool = new ThreadPoolExecutor(
        4, 8, 60L, TimeUnit.SECONDS,
        new LinkedBlockingQueue<>(1000),
        new ThreadPoolExecutor.CallerRunsPolicy());
```

### [JAVA-002] CompletableFuture 占用公共线程池或没有超时

- **Severity**: Suggestion
- **Middleware**: Java
- **分级动作**: 处置：排期评估。确定性不够，报告里标注需人工复核。
- **原因**: supplyAsync/runAsync 不传 Executor 时用 ForkJoinPool.commonPool()。这个池是整个 JVM 共享的。get() 不带超时则一直等到对方完成。
- **危害**: 一个慢任务把公共池占满，别的无关功能一起卡住。没有超时的 get() 会把调用线程永久挂住，线程池被耗尽。
- **历史故障**: 公共池被一个无超时的外部调用占满，健康检查和业务异步任务同时停住。
- **检测**: supplyAsync/runAsync 的参数在顶层没有逗号（没有传入线程池），或同一方法里对 future 调用了无参 get()，且没有 orTimeout、也没有带参数的 get。
- **降噪**: 传入了业务线程池，并且 get(timeout, unit) 或 orTimeout 存在时不报。确定性有限，需人工复核是不是公共池。
- **修复**:

使用业务自己的有界线程池，等待必须带超时。

```java
return CompletableFuture.supplyAsync(() -> query(), bizPool).get(1, TimeUnit.SECONDS);
```

### [JAVA-003] SimpleDateFormat 被多个线程共用

- **Severity**: Warning
- **Middleware**: Java
- **分级动作**: 处置：本迭代修复。不拦截合入，周期报告里必须有人看。
- **原因**: SimpleDateFormat 内部持有可被改写的 Calendar。把它做成 static 或成员字段后，多个请求会同时 format/parse 同一实例。
- **危害**: 结果错乱，或者抛出 ArrayIndexOutOfBoundsException、NumberFormatException，而且很难复现。
- **历史故障**: 静态日期格式化器在高峰期把订单时间格式化成错误的日期，对账对不上。
- **检测**: 字段赋值形如 SimpleDateFormat 名字 = new SimpleDateFormat，且不在方法内部，周围也没有 ThreadLocal。
- **降噪**: 方法里的局部变量不报。用 ThreadLocal 包起来，或改用 DateTimeFormatter 时不报。
- **修复**:

用不可变的 DateTimeFormatter，或每个线程一份。

```java
private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd");
```

### [GO-001] goroutine 发了没人收，或并发写同一个 map

- **Severity**: Critical
- **Middleware**: Go
- **分级动作**: 处置：立即修复。MR 模式拦截合入；周期巡检告警并让最近修改人认领。
- **原因**: go func 里向 channel 发送，但没有 select 和 ctx.Done。调用方一旦提前返回，接收者消失，这个发送永远堵着，goroutine 就泄漏了。多个 goroutine 写同一个原生 map 且没有锁时，运行时会直接检测到数据竞争。
- **危害**: 泄漏把内存和线程慢慢吃满，进程越来越慢。并发写 map 会 fatal error: concurrent map writes，进程立刻退出。
- **历史故障**: 超时路径先 return，留在后台的发送 goroutine 每个请求漏一个，几小时后内存告警。另一起是多个 goroutine 填同一个 map，进程在高峰直接崩溃。
- **检测**: go func 体内有 ch <- 发送，且没有 select 或 ctx.Done。或者体内对 make(map) 出来的变量做下标赋值，且体内没有 Lock 或 sync.Map。
- **降噪**: 发送包在 select 里并监听 ctx.Done，或写 map 前有 Mutex/RWMutex，不报。带缓冲、由别的文件负责接收的 channel，扫描器看不到，可能误报，看到之后按调用方核对。
- **修复**:

发送要能被取消。map 用锁或者 sync.Map。

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
```

### [GO-002] 在 for 循环里直接 defer Close

- **Severity**: Warning
- **Middleware**: Go
- **分级动作**: 处置：本迭代修复。不拦截合入，周期报告里必须有人看。
- **原因**: defer 在函数返回时才执行，不是在这一次循环结束时执行。写在 for 里面的 Close 会堆到整个函数结束。
- **危害**: 文件句柄、连接和响应体一直占着，循环次数一多就触发 too many open files，后续请求失败。
- **历史故障**: 循环里对下游发请求并 defer Body.Close，批量任务跑到一半把进程的 fd 打满。
- **检测**: for 循环的花括号体内、不在更内层的 func 里，出现 defer ...Close()。
- **降噪**: 每次迭代套一个立即执行的函数，defer 写在这个函数里，视为正确写法，不报。
- **修复**:

把一次迭代收进函数，让 defer 在这次迭代结束时跑。

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
```

### [GO-003] HTTP 客户端没有超时

- **Severity**: Warning
- **Middleware**: Go
- **分级动作**: 处置：本迭代修复。不拦截合入，周期报告里必须有人看。
- **原因**: http.Get 和 http.DefaultClient 的 Timeout 是 0，表示一直等。自己 new 的 http.Client 字面量里如果没有 Timeout 字段，也是一样。
- **危害**: 下游卡住时，每个请求留一个 goroutine 和一条连接。请求持续进来就会把进程的 goroutine 和 fd 打满，最后连健康的下游也调不出去。
- **历史故障**: 支付回调使用 http.Get，对方负载均衡黑洞，服务 goroutine 从几百涨到几十万后无响应。
- **检测**: 出现 http.Get(、http.DefaultClient，或 http.Client{ 复合字面量里没有 Timeout。
- **降噪**: 使用设置了 Timeout 的 *http.Client，并且没有再调用 http.Get，不报。
- **修复**:

每个外部调用都用带超时的 client，超时按这个接口的预算来，不要用默认客户端。

```go
client := &http.Client{Timeout: 2 * time.Second}
resp, err := client.Get(u)
```
