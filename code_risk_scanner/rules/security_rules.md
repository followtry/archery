# 安全防护规则

覆盖明文密码或密钥、回调没有验签、按外部单号跨用户修改。

每条规则都给出原因、危害、对应过的故障形态，以及能照着改的修复示例。扫描器的判定以可重复的代码形态为准；这里的检测描述与扫描器一致。

级别只使用三档：

- **Critical**：已经能对应到线上故障，MR 合入门禁拦截，周期巡检立即告警。
- **Warning**：会带来性能或稳定性问题，不拦截合入，本迭代要修。
- **Suggestion**：确定性不足，必须人工复核，不拦截。

### [SEC-001] 密码或密钥明文写在仓库里

- **Severity**: Critical
- **Middleware**: Security
- **分级动作**: 处置：立即修复。MR 模式拦截合入；周期巡检告警并让最近修改人认领。
- **原因**: password、accessKey、secret 被赋成一个具体字符串，而不是配置中心或加密占位符。仓库能被克隆，密钥就跟着出去。
- **危害**: 数据库、缓存和开放接口的口令泄露后，可以直接登录生产或日常资源，数据被读走或改掉。
- **历史故障**: 数据源密码写在 application.properties 里，仓库权限放大后被用来直连订单库。
- **检测**: password、secret_key、access_key、appsecret 后面是长度不少于 4 的字面量，或 setPassword/setSecret 传入了同样的字面量。
- **降噪**: 值是 ${...}、ENC(...)、星号占位或空值时不报。注释行不报。
- **修复**:

密钥放配置中心或加密项，仓库里只留占位符。

```properties
spring.datasource.password=${db.password}
```

### [SEC-002] 回调或通知入口没有验签

- **Severity**: Critical
- **Middleware**: Security
- **分级动作**: 处置：立即修复。MR 模式拦截合入；周期巡检告警并让最近修改人认领。
- **原因**: 路径或方法名是 notify、callback，方法里直接 update/delete/insert，但没有验签。外部只要知道地址和单号就能改状态。
- **危害**: 支付、退款、履约回调可以被伪造，订单被改成已支付或已退款，造成资损。
- **历史故障**: 支付通知没有校验签名，伪造的成功回调把未付款订单推进了履约。
- **检测**: 方法签名或映射里有 notify/callback，方法体有写库，且没有 verify、checkSign、signature、验签或 HMAC/RSA。
- **降噪**: 同一方法里已经调用验签时不报。扫描器看不到另一个过滤器里的验签，这种情况需要人工看过滤器链。
- **修复**:

先验签，通过之后才改状态。验签失败直接拒绝。

```java
@PostMapping("/pay/notify")
public void onNotify(String body, String sign) {
    if (!rsa.verify(body, sign)) {
        throw new IllegalArgumentException("bad sign");
    }
    payOrderDao.markPaid(body);
}
```

### [SEC-003] 按外部传入的单号改数据，没有校验是不是当前用户的

- **Severity**: Critical
- **Middleware**: Security
- **分级动作**: 处置：立即修复。MR 模式拦截合入；周期巡检告警并让最近修改人认领。
- **原因**: orderId、refundId 来自请求参数，更新或删除语句的 WHERE 里没有 user_id、buyer_id 这类归属列，方法里也没有归属校验。知道或猜到单号就能改别人的单。
- **危害**: 跨用户改状态、改金额或删数据。交易链路上这就是越权，影响的是别人的订单、退款和支付。
- **历史故障**: 退款接口只按 refundId 更新，调用方替换单号后改掉了其他买家的退款单。
- **检测**: 方法从 getParameter 或 @RequestParam 拿 orderId/bizOrderId/refundId，同一方法里的 UPDATE/DELETE 没有用户归属列，也没有 checkOwner、登录用户或鉴权调用。
- **降噪**: WHERE 里有 buyer_id、user_id 等归属列，或方法里有归属校验时不报。校验如果写在另一个类里，这里会漏，需要沿调用链再看。
- **修复**:

WHERE 带上当前登录用户，或先做归属校验再写。

```java
String buyerId = session.getCurrentUser();
String sql = "update refund set status = 1 where id = #{id} and buyer_id = #{buyerId}";
```
