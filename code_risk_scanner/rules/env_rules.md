# 环境隔离规则（日常、预发、灰度、生产）

覆盖写死的环境地址、配置文件和连接串不是一套环境、一份默认配置混多套环境。

每条规则都给出原因、危害、对应过的故障形态，以及能照着改的修复示例。扫描器的判定以可重复的代码形态为准；这里的检测描述与扫描器一致。

级别只使用三档：

- **Critical**：已经能对应到线上故障，MR 合入门禁拦截，周期巡检立即告警。
- **Warning**：会带来性能或稳定性问题，不拦截合入，本迭代要修。
- **Suggestion**：确定性不足，必须人工复核，不拦截。

### [ENV-001] 连接地址写死了某一个环境

- **Severity**: Critical
- **Middleware**: Env
- **分级动作**: 处置：立即修复。MR 模式拦截合入；周期巡检告警并让最近修改人认领。
- **原因**: JDBC、Redis 或 HTTP 地址里带了日常、预发、灰度或生产的域名，又写在没有环境后缀的代码或默认配置里。这份配置打到哪个环境，连的都是同一个地址。
- **危害**: 日常任务会打进生产库，或者生产发布后仍连着日常库。两边的数据串在一起，订正和缓存都会污染另一套环境。
- **历史故障**: 默认 application.properties 写了 daily 的 RDS 地址，生产发布后订单写进了日常库，线上查不到单。
- **检测**: 文件名看不出环境，连接串主机名里带 daily、pre、gray 或 online/prod。
- **降噪**: application-daily、application-prod 这类文件名已经声明环境，并且地址和文件名一致时不报。地址是 ${} 占位符时不报。
- **修复**:

按环境拆配置，地址从环境自己的配置中心读，不要写死。

```properties
# application-daily.properties
spring.datasource.url=jdbc:mysql://rm-xxx.daily.mysql.rds.aliyuncs.com:3306/trade
# application-prod.properties 使用生产地址，不要复用日常域名
spring.datasource.url=${db.url}
```

### [ENV-002] 配置文件声明的环境和连接地址不是一套

- **Severity**: Critical
- **Middleware**: Env
- **分级动作**: 处置：立即修复。MR 模式拦截合入；周期巡检告警并让最近修改人认领。
- **原因**: 文件名已经标明日常、预发、灰度或生产，里面的连接串却指向另一套环境。发布系统按文件名选配置，连上去的却是别的库。
- **危害**: 生产配置指向日常或预发时，线上读写打到错误的库，出现丢单、脏写和缓存串环境。灰度配置指向生产主库时，灰度流量直接改生产数据。
- **历史故障**: application-prod.properties 里留着 daily 的 MySQL 地址，生产发布后支付结果写进日常库。
- **检测**: 文件名能判断环境，连接串里的环境标记和文件名不一致。
- **降噪**: 地址是占位符，或和文件名是同一环境时不报。
- **修复**:

生产和低环境的地址分开。生产文件里只留生产地址。

```properties
# application-prod.properties
spring.datasource.url=jdbc:mysql://rm-prod.online.mysql.rds.aliyuncs.com:3306/trade
```

### [ENV-003] 同一份默认配置混了多套环境

- **Severity**: Warning
- **Middleware**: Env
- **分级动作**: 处置：本迭代修复。不拦截合入，周期报告里必须有人看。
- **原因**: 一份没有环境后缀的配置里同时写了两套及以上环境的连接串。用哪一套取决于调用方有没有选对 key，选错就串环境。
- **危害**: 灰度、预发和生产共用这份文件时，很容易拿错 key，把流量打到另一套库或缓存。
- **历史故障**: 一份 application.yml 同时写了 daily 和 online 的地址，预发发版时读到了 online 那一项。
- **检测**: 文件名没有环境后缀，连接串里出现至少两种环境。
- **降噪**: 已经拆成 application-daily、application-prod 的文件不在这里报。
- **修复**:

一种环境一个文件，默认配置里不放具体地址。

```yaml
# 默认文件只留占位
spring.datasource.url: ${db.url}
```
