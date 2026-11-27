# batch51-py-safety-r-01

## 题面

网关侧这周连出三张互相打脸的工单：一张说令牌头里 alg 写成 none 的请求畅通无阻进了订单接口；另一张更吓人，攻击者把租户公钥原文当成 HMAC 密钥自己签了个 HS256 令牌，网关照认；值班翻日志还看到 kid 写成 ../../ 的请求一路摸到了隔壁租户的密钥，而 claims 早就过期的令牌却一律报签名失败，根本分不清是攻击还是时钟漂移。范围是 gsb/batch51-py-safety-r-01 的 jwt_alg_confusion_guard.py，类 JwtAlgConfusionGuard，负责多租户令牌的解析、选钥、算法与密钥类型绑定、声明校验以及审计快照。

公开接口：JwtAlgConfusionGuard(*, allowed_algs=("RS256","ES256"), clock_skew=0, max_token_bytes=8192, max_nesting_depth=1, max_keys_per_tenant=64)；register_tenant(tenant, *, issuer, audience)；install_key(tenant, kid, *, alg, material, kind, not_before=0, expires_at=None)；rotate_key(tenant, kid, *, new_kid, alg, material, kind, expires_at, now)；revoke_key(tenant, kid, *, now)；decode_header(token)；resolve_key(token, *, tenant, now)；verify(token, *, tenant, now, backend, expected_aud=None)；key_inventory(tenant, *, now=None)；audit_log()；snapshot()；restore(state)；stats()。时间一律整数 epoch 秒；令牌是三段点分 base64url（无填充），第二段是 JSON 声明，第三段原样交给注入的 backend(alg, material, signing_input, signature) 判真伪，其中 signing_input 是前两段的点分原串。拒绝与非法输入抛 JwtError(code, detail)，码与 detail 要能自解释。

要修的行为：① 段数不是三段、超过 max_token_bytes、任一段 base64url 解不开，一律 JWT_MALFORMED，不得触达密钥库；② alg 为空、写成 none、或不在 allowed_algs 里，一律 JWT_ALG_REJECTED；alg 所属家族与密钥 kind 不符（HS256 配 rsa 材料这种混淆）报 JWT_ALG_CONFUSION，detail 至少给出 kid、alg、kind 三项；算法层面的拒绝都发生在签名核对之前，不得调用 backend；③ kid 为空、含 / 或 \、含 .. 一律 JWT_KID_REJECTED，这一步发生在查库之前，不计密钥查询；④ 查不到 kid 报 JWT_KEY_UNKNOWN，已吊销报 JWT_KEY_REVOKED，超出有效期报 JWT_KEY_EXPIRED，尚未生效报 JWT_KEY_NOT_YET_VALID；每次真正落到密钥库计一次 lookups；revoke_key 返回本次改动的记录数，重复吊销同一 kid 返回 0 且 revocations 只加一次；key_inventory 按租户返回密钥记录元组，已吊销的仍在列；⑤ 签名核对必须先于任何声明校验，签名不过只回 JWT_SIGNATURE_INVALID，不能把过期或受众不符的结论混进来；通过时返回 Verdict，带 tenant、subject、kid、alg、claims、warnings、key_lookups 七项；⑥ 声明侧 exp 早于 now 减 clock_skew 报 JWT_EXPIRED，nbf 晚于 now 加 clock_skew 报 JWT_NOT_YET_VALID，iat 落在未来报 JWT_ISSUED_IN_FUTURE，iss 与租户资料不符报 JWT_ISSUER_MISMATCH，aud 不含期望值（未显式传 expected_aud 时取租户登记值）报 JWT_AUDIENCE_MISMATCH；⑦ 轮换把旧 kid 置为只读，仍可验签直到自身 expires_at，验签通过时 warnings 里要带 JWT_KEY_READ_ONLY，新 kid 已存在报 JWT_KEY_CONFLICT，成功轮换计一次 rotations；⑧ 单租户密钥条数受 max_keys_per_tenant 硬顶，超出报 JWT_KEY_CAPACITY；⑨ 每次 verify 落一条审计，含 code、tenant、kid、alg、key_lookups、detail，成功记 JWT_OK；⑩ 快照含 version、tenants、keys、audit、stats 五项，取出后与实例不共享可变结构，恢复要校验结构与类型，非法报 JWT_SNAPSHOT_INVALID 且不动现有数据，成功计一次 restores；⑪ stats 给出 verdicts、rejected、rotations、revocations、lookups、restores 六项；⑫ 同一租户并发验签与轮换时，任一方不得看到半写状态。

还有三个现场要一并兜住：一是同一 kid 在轮换窗口内同时存在新旧两把密钥（换算法期间只换 alg 不换 kid），选钥只能用 alg 匹配且未吊销的那把，不能取库里第一条；二是 exp 与 nbf 同时越界、iat 落在未来、aud 写成字符串或字符串数组混用时，错误码必须区分开，不能统一折算成签名失败；三是嵌套 JWT（第二段本身又是一枚 JWT）只允许解一层，超出 max_nesting_depth 按不可判定拒绝并报 JWT_NESTING_LIMIT，且不消耗密钥查询配额。

硬约束：同租户的选钥、轮换、吊销与审计写入要串行裁决，锁外读不到半写状态；快照恢复后租户资料、密钥、审计与计数必须自洽；单租户密钥数受上限硬顶。验收：python3 -m pytest -q tests 15 条必须全过，不得改测试、不得跳过、不得按固定输入写死；并发与重启场景自行验证；只做本地实现，不引入第三方依赖。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 其他
- type: Bugfix
- module: jwt_alg_confusion_guard
- typeName: JwtAlgConfusionGuard
