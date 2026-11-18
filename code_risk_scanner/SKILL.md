---
name: enterprise-code-risk-scanner
description: 对 Java/Go 以及 TDDL、Lindorm、Redis、ES 做全量周期巡检或 MR 增量扫描，输出带原因、危害和修复的结构化报告。
version: 1.2.0
triggers:
  - "周期扫描"
  - "代码隐患巡检"
  - "code risk scan"
---

# 角色

你是分布式系统代码审计。任务是发现中间件误用、性能放大和并发资源问题，并给出能直接改的结论。每条命中必须写清三件事：原因、可能的危害、如何修复。

不要复述规则清单充数。先跑确定性扫描器，再只对它标了「需人工复核」的条目补上下文。

# 级别

只使用三档。门禁只看 Critical。

| 级别 | 含义 | MR 增量 | 周期全量 |
| --- | --- | --- | --- |
| Critical | 对应过线上故障，代码形态已经能确定 | `gate_status=BLOCK`，退出码 1，拦住合入 | 退出码 0，告警并 @ 最近修改人 |
| Warning | 性能或稳定性问题，本迭代要修 | 不拦截 | 写进报告 |
| Suggestion | 确定性不够 | 不拦截，正文必须写「需人工复核」 | 同左 |

附近注释同时写了「低频」和「后台」时，Critical 降为 Warning。问题还在，只是不挡合入。

# 工作流

按顺序做，不能跳。

## 1. 范围

忽略 `vendor/`、`node_modules/`、`target/`、`build/`、`.git/`、`testdata/`，以及 `*_test.go`、`*Test.java`、`*.pb.go`、`*Generated.java`。`testdata/` 是扫描器自己的反例，不是业务代码。

只看业务目录里的 `.java`、`.go`、`.xml`：`dao/`、`repository/`、`service/`、`manager/`、`dal/`、`cache/`、`search/`。另外加上 `mapper/`、`mybatis/`、`lindorm/`、`hbase/`。MyBatis XML 和宽表访问经常不在 dao 目录里，不加上去分片键和 Scan 规则会扫空。

## 2. 按特征加载规则

扫描器只在文件里真有对应 API 时跑该组规则，避免把普通 `Get` 方法当成 HBase。人工复核时按下表决定要不要打开规则文件：

| 文件里有 | 规则文件 |
| --- | --- |
| tddl、sharding、mybatis、sql、database/sql、gorm、@Transactional | `rules/tddl_rules.md` |
| lindorm、hbase、Scan、Put、addColumn | `rules/lindorm_rules.md` |
| jedis、redisson、lettuce、go-redis、redis | `rules/redis_rules.md` |
| elasticsearch、RestHighLevelClient、SearchSourceBuilder、wildcardQuery | `rules/es_rules.md` |
| 任意 `.java` / `.go` | `rules/lang_java_go.md` |
| 连接串、`application*.properties/yml` | `rules/env_rules.md` |
| 密码、回调、按单号更新 | `rules/security_rules.md` |

分片键默认是 `user_id`、`tenant_id`、`order_id` 等常见路由列。这个仓库如果不是这些列，在仓库根放 `.code-risk.json`，用 `sharding_keys` 整表替换。样例在 `schemas/code-risk.example.json`。`suppress_rules` 和 `suppress_paths` 用来关掉已经评估过的误报，不要在代码里把规则改弱。

## 3. 降噪

扫描器已经处理了这些情况，不要再报成 Critical：

- 同一方法里把 offset 截到 5000，或 `from + size` 与 10000 做了比较
- RowKey 前缀已有 md5/hash/salt，或用了 `MAX_VALUE - timestamp`
- Scan 同时有 StartRow 和 StopRow
- 锁是 `SET key value NX PX ttl`，解锁走 Lua；或 `SetNX` 带了非 0 过期
- 线程池队列写了容量
- `defer Close` 写在循环内的立即执行函数里
- goroutine 的发送包在 `select` + `ctx.Done` 里，map 写入有锁
- 注释写明低频后台

跨文件才能确定的事，扫描器会漏。典型的是分页上限写在 Controller，而 SQL 在 DAO。这种漏报留在人工复核里补，不要为了补漏把单文件规则改成猜。

## 4. 输出

流水线以扫描器写出的 JSON 为准，契约是 `schemas/output_schema.json`。字段里 `cause` 是原因，`harm` 是危害，`remediation_suggestion` 是修复和示例，`risk_analysis` 把这三样加上触发证据和历史故障合成一段。

`critical_count > 0` 时 `gate_status` 必须是 `BLOCK`，否则 `PASS`。

你自己补复核意见时也要沿用这份结构，不要在 JSON 外面加寒暄。

# 怎么跑

确定性扫描器不调用模型，规则文案和检测在同一份目录里。

```bash
python3 code_risk_scanner/run_scanner.py \
  --repo-path "$WORKSPACE" \
  --skill-dir code_risk_scanner \
  --scan-mode FULL_PERIODIC \
  --output scan_report.json
```

MR：

```bash
DIFF_BASE=origin/master code_risk_scanner/periodic/run_mr_gate.sh scan_report.json
```

周期：

```bash
code_risk_scanner/periodic/run_periodic.sh scan_report.json
```

`BLAME=1` 时用 `git log -L` 填 `owner`。`DINGTALK_WEBHOOK` 有值才发钉钉，没有就只落盘。

自检：

```bash
python3 -m unittest code_risk_scanner.tests.test_scanner
```

# 周期流水线

在 AONE 上给应用单独建流水线，例如 `[AI-Scan] 核心服务代码隐患周期巡检`。关掉 push 触发，Cron 用 `0 0 3 * * 1,4`（北京时间每周一、周四 03:00）。

1. 拉生产分支。
2. 跑上面的周期脚本。工作目录是仓库根。
3. 告警正文在 `scan_report.md`。需要点名时打开 `BLAME=1`，用 `owner` 去 @。
4. 周期模式退出码保持 0。MR 流水线改用 `run_mr_gate.sh`，`BLOCK` 时退出码 1，合入失败。

# 环境隔离和安全防护

环境只认四套：日常、预发、灰度、生产。连接串写死某一套、配置文件名和地址不是一套、一份默认配置混了多套，分别对应 ENV-001、ENV-002、ENV-003。

安全防护看三件事：明文密码或密钥（SEC-001）、回调没有验签（SEC-002）、外部传入单号却不校验用户归属（SEC-003）。命中一样写原因、危害和修复。

# 交易团队试点轮次

应用名单以 `https://code.alibaba-inc.com/AOS-TMP/stability_ai/blob/master/data/apps.json` 为准，分成逆向、正向、支付履约。当前环境访问这个内网地址会超时，所以扫描器不内置那份名单。流水线在内网把文件放到 `--apps`。

1. 逆向团队里名字匹配 `kernel*` 的服务。
2. 逆向团队全部应用。
3. 正向和支付履约团队全部应用。
4. 交易团队全部应用。

```bash
python3 code_risk_scanner/run_scanner.py \
  --list-round --round 1 \
  --apps /path/to/stability_ai/data/apps.json
```

扫描某个应用仓库时加上同样的 `--round` 和 `--apps`，报告的 `scan_metadata.rollout` 会记下这一轮覆盖了哪些应用。轮次不代替代码扫描，它决定这一轮拉哪些应用。

# 规则从哪来

原有 TDDL / Lindorm / Redis / ES / Java / Go 规则都保留，并按这个仓库的 MySQL 设计规范和常见故障补了几条：无 WHERE 的写、分片键被函数包住、IN 拼接、`SELECT *`、`KEYS`/`FLUSH`、查询脚本、无上限批量 Put、共享的 `SimpleDateFormat`、没有超时的 `http.Get`。

每条规则的原因、危害、历史故障、检测、降噪和修复写在 `rules/*.md`，和扫描器共用同一份目录，避免文档和代码各说各的。
