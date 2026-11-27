# batch51-py-safety-r-02

## 题面

授权服务器这个月的告警几乎全压在回调和授权码上：有客户截图证明同一个 state 在两个浏览器里各换出了一枚令牌；有接入方把 code_challenge_method 改成 plain 之后照样走到发行环节；安全团队拿两个租户的注册信息做对照，发现只比主机名的实现把回调地址放宽成了另一个租户的路径；还有人拿一周前的授权码反复重放，每次响应都不一样，等于告诉对方这个 state 到底存不存在。范围是 gsb/batch51-py-safety-r-02 的 oauth_state_replay_guard.py，类 OauthStateReplayGuard，管住授权请求、回调发码与授权码兑换的全过程。

公开接口：OauthStateReplayGuard(*, state_ttl=600, code_ttl=120, max_pending_per_client=32, min_verifier_len=43, max_verifier_len=128, max_clients=64)；register_client(tenant, client_id, *, redirect_uris, methods=("S256",))；begin_authorization(tenant, client_id, *, redirect_uri, state, code_challenge, challenge_method="S256", scopes=("openid",), now)；handle_callback(tenant, client_id, *, state, subject, now)；exchange_code(tenant, client_id, *, state, code, redirect_uri, code_verifier, now)；revoke_client(tenant, client_id, *, now)；pending_for(tenant, client_id)；audit_log()；snapshot()；restore(state)；stats()。时间一律整数 epoch 秒；code_challenge 与 verifier 的对应关系按 base64url(sha256(verifier)) 去填充比对。拒绝抛 OauthError(code, detail)。

要修的行为：① state 长度须在 8 到 128 之间且只含字母数字与 . _ ~ -，否则 OAUTH_INVALID_REQUEST；回调地址按注册值整串比对，未登记报 OAUTH_REDIRECT_URI_MISMATCH；② challenge_method 不是 S256、或该客户端没登记这种方式，一律 OAUTH_PKCE_METHOD_REJECTED；发起成功返回 AuthorizationRequest，含 tenant、client_id、state、redirect_uri、code_challenge、challenge_method、scopes、issued_at、expires_at、code、code_issued_at、consumed，pending_for 按签发顺序返回未消费的请求元组；③ code_challenge 必须是 43 位 base64url 且不得带 = 号，否则 OAUTH_INVALID_REQUEST；④ 发起请求时 state 已被占用或已被消费报 OAUTH_STATE_REUSED，计入 replays；⑤ 回调阶段未注册或被撤销的客户端报 OAUTH_CLIENT_UNKNOWN，state 不认识报 OAUTH_STATE_UNKNOWN，过了 state_ttl 报 OAUTH_STATE_EXPIRED，成功发码返回带 code 与 code_issued_at 的记录、consumed 仍为 False；⑥ 兑换时 code 对不上报 OAUTH_CODE_MISMATCH，超过 code_ttl 报 OAUTH_CODE_EXPIRED；⑦ code_verifier 不在 43 到 128 位或字符集越界报 OAUTH_VERIFIER_INVALID，与登记的 challenge 不匹配报 OAUTH_VERIFIER_MISMATCH；⑧ 兑换失败一律不得消耗 state，用户重试同一条请求必须还能成功；⑨ 兑换成功后该 state 立即失效，再兑换报 OAUTH_STATE_CONSUMED 并计入 replays；⑩ 单个客户端未消费且未过期的请求数受 max_pending_per_client 硬顶，超出报 OAUTH_CAPACITY_EXCEEDED；⑪ revoke_client 清空该客户端待处理请求、作废已发令牌，返回清掉的待处理条数，之后对它的请求一律 OAUTH_CLIENT_UNKNOWN，成功撤销计一次 revoked；⑫ 兑换回执要原样带回租户、客户端、资源拥有者、scopes、state 与 redirect_uri，token_id 为 32 位小写十六进制；⑬ 每次发起、回调、兑换、撤销都往审计里落一条，含 action、tenant、client_id、state 与原因码；stats 给出 authorizations、callbacks、exchanges、replays、rejections、revoked、restores 七项；⑭ 快照含 version、clients、requests、tokens、audit、stats 六项，取出后与实例不共享可变结构，恢复要校验结构与类型，非法报 OAUTH_SNAPSHOT_INVALID 且不动现有数据，成功计一次 restores。

另外三个现场请一并兜住：一是两个租户在同一主机上注册了不同路径的回调地址时，比对必须落到完整路径，不能只比主机与端口；二是 code_verifier 长度或字符集不合法要报独立原因码 OAUTH_VERIFIER_INVALID，不能落成普通兑换失败；三是授权码过期后重放同一 state，响应必须与首次失败逐字一致，不能因为 state 是否还存在而给出不同结论。

硬约束：并发兑换同一个 state 只能有一次成功，其余必须拿到已经被消费的结论，计数不得重复累加；快照恢复后客户端、请求、令牌、审计与计数必须自洽；单客户端待处理请求数受上限硬顶。验收：python3 -m pytest -q tests 15 条必须全过，不得改测试、不得跳过、不得按固定输入写死；并发与重启场景自行验证；只做本地实现，不引入第三方依赖。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 其他
- type: Bugfix
- module: oauth_state_replay_guard
- typeName: OauthStateReplayGuard
