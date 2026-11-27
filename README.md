# batch51-py-safety-a-11

## 题面

认证网关这周反复告警：有内网客户端把同一段协商报文重放到另一台文件服务上，居然也被放行；还有两台代理串联时挑战被转手使用，执行过程记录里只能看到一次成功、后面全被当成新请求。范围是 gsb/batch51-py-safety-a-11 的 ntlm_relay_guard.py，类 NtlmRelayGuard，维护挑战与目标服务、来源通道的绑定关系，并在应答校验时判定重放与扩展保护。

公开接口：NtlmRelayGuard(*, challenge_ttl=120, max_pending_per_account=8, clock=None)；register_target(*, service_id, channel_id, epa_policy="optional")；target_info(service_id)；issue_challenge(*, account, service_id, channel_id, nonce=None, now=None)；bind_target(*, challenge_id, service_id, channel_id, now=None)；verify_response(*, challenge_id, account, channel_id, response_digest, now=None)；check_epa(*, service_id, client_digest=None)；pending_for(account, *, now=None)；expire_pending(*, now=None)；snapshot()；restore(state)；stats()。时间一律传秒级 ISO 8601 字符串并保留原时区偏移；应答摘要按 sha256("nonce|account|channel") 取十六进制小写。拒绝抛 NtlmRelayError(code, detail)，错误码统一为 NTLM_ 前缀，取值包括 TARGET_UNKNOWN、REQUEST_INVALID、CHANNEL_MISMATCH、PENDING_LIMIT、CHALLENGE_CONSUMED、REPLAY_DETECTED、ACCOUNT_MISMATCH、RESPONSE_MISMATCH、CHALLENGE_EXPIRED、SNAPSHOT_INVALID。挑战对象字段为 challenge_id、account、service_id、channel_id、nonce、issued_at、expires_at、state，state 取 pending、consumed、expired；校验通过返回 ResponseVerdict(challenge_id、account、service_id、channel_id、status)，status 取 accepted；扩展保护结论为 EpaVerdict(service_id、policy、status、bound)，status 取 disabled、ok、required。

要修的行为：① 目标服务登记记录服务、通道与扩展保护策略，重复登记同一服务覆盖策略，未登记服务不能签发挑战，空标识按请求非法拒绝；② 挑战绑定签发时的服务与通道，账户与通道非空才允许签发，挑战编号自 1 递增且不重复；③ 签发时传入的通道必须与该服务登记通道一致，否则按通道不匹配拒绝；④ 应答摘要不符只拒绝本次校验，挑战保持待处理并可再次提交；⑤ 通道与绑定值不一致按通道不匹配拒绝，通道不匹配与摘要不匹配分开计入统计；⑥ 同一挑战被再次提交按重放拒绝，重放不得改写挑战状态或计数；⑦ 提交时账户与挑战所属账户不一致按账户不匹配拒绝，挑战仍可被正确账户使用；⑧ 恰好到期时刻仍可校验，超过到期时刻按过期拒绝并把挑战置为过期；⑨ bind_target 只能在挑战未消费时改绑，改绑后原目标与通道一律不再接受；⑩ 每账户未消费挑战有上限，超限签发拒绝，消费后可继续签发；待处理列表按签发时间升序，expire_pending 批量置过期并返回条数；⑪ 目标声明扩展保护必需而客户端未提供时按拒绝处理，不得降级为只校验应答；⑫ 同一账户在多个会话中并行认证时各自挑战互不影响，绑定表不得串用。响应校验按挑战存在、账户、重放、过期、通道、摘要的顺序判定，前一步拒绝后不再看后面的值。

硬约束：同一挑战被多线程并发提交时只允许一次成功，其余全部按重放拒绝，成功计数与重放计数之和必须等于提交次数；快照深拷贝，恢复后目标、挑战、绑定与统计原样可用，且不得与快照对象共享可变结构，非法结构整体拒绝且在线数据不变；每账户待处理挑战上限是硬顶。

验收：python3 -m pytest -q tests 15 条必须全过；不得改测试、跳过、按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch51-py-safety-a-11
- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: ntlm_relay_guard
- typeName: NtlmRelayGuard
