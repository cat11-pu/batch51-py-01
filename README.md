# batch51-py-safety-a-14

## 题面

单点登出这周两头挨骂：一端浏览器已经退出，另一端的业务系统还留着会话；另一端是登出广播把同一家客户的两个回调地址各发了两遍，确认回执却只剩一条。运营还发现回执没有按注册方分别留痕，出了争议查不出是谁先确认的，回执口径与广播条数也对不上。范围是 gsb/batch51-py-safety-a-14 的 frontchannel_logout_broadcaster.py，类 FrontchannelLogoutBroadcaster，按会话维护参与方、扇出登出地址并汇总确认。

公开接口：FrontchannelLogoutBroadcaster(*, timeout_ms=800, max_attempts=3, clock=None)；register_participant(*, session_id, participant_id, url, now=None)；participants_for(session_id)；broadcast(*, session_id, signer_key, now=None)；collect(*, session_id, participant_id, token, ok=True, now=None)；fallback(*, session_id, now=None)；pending_for(session_id)；attempts_for(*, session_id, participant_id)；close_session(session_id)；snapshot()；restore(state)；stats()。签名参数按 sha256("signer|session|participant") 取十六进制小写；时间用秒级 ISO 8601 字符串；close_session 清掉该会话绑定与广播并返回移除的参与方数量。拒绝抛 FrontchannelError(code, detail)，错误码统一为 FRONTCHANNEL_ 前缀，取值包括 REQUEST_INVALID、SESSION_UNKNOWN、NOT_BROADCAST、BAD_TOKEN、PARTICIPANT_UNKNOWN、DUPLICATE_ACK、SNAPSHOT_INVALID。广播返回 Broadcast(session_id、started_at、entries)，条目为 LogoutEntry(participant_id、url、token、status)，status 取 pending、confirmed、failed、exhausted；登记返回 Participant(session_id、participant_id、url、registered_at)。

要修的行为：① 参与方登记校验会话、标识与非空 http/https 地址，同一会话内按标识升序返回；② 广播只发给绑定到该会话的参与方，未知会话与空签名密钥拒绝；③ 每条登出地址追加 session 与 sig 两个参数，原地址已有查询串时用 & 连接；④ 广播条目按参与方标识升序，重复广播返回同一结果且不重复计数；⑤ 回执必须带广播时下发的令牌，令牌不符按令牌非法拒绝；⑥ 未广播先回执按未广播拒绝；回执按会话、广播、参与方、令牌的顺序校验，未知参与方按参与方不存在拒绝，重复回执按重复确认拒绝；⑦ 确认成功的参与方退出待处理集合，确认失败的单独计数；⑧ 扇出并发执行且不阻塞会话终止，确认与超时互不影响；⑨ 到达超时时刻仍未回执的参与方进入兜底重试，返回本次重试的参与方标识，未到超时时刻不得重试；⑩ 兜底重试次数达到上限后该参与方转为耗尽并从待处理集合移除；⑪ 参与方重复注册同一地址时只扇出一次，但各注册方的确认结果需分别记录；⑫ 广播过程中该用户建立新会话时，新会话不得继承旧会话的登出结果。

硬约束：同一参与方并发回执只能有一个成功，其余按重复确认拒绝，确认计数与重复计数之和必须等于回执数；兜底重试不得把已确认的参与方重新拉回待处理，广播结果与回执要能逐条对上；快照深拷贝，恢复后绑定、广播结果、待处理、重试次数与幂等结果都在，非法结构整体拒绝；超时兜底次数上限是硬顶。

验收：python3 -m pytest -q tests 15 条必须全过；不得改测试、跳过、按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch51-py-safety-a-14
- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: frontchannel_logout_broadcaster
- typeName: FrontchannelLogoutBroadcaster
