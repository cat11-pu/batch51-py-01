# batch51-py-safety-a-15

## 题面

认证侧这周收到两种互相矛盾的报告：一种说客户端明明报了支持通道绑定的机制，实际消息里却没带绑定数据，服务端照样放行；另一种说链路在协商中途重建后，旧会话还能拿着重建前的绑定值通过校验。安全评审给的结论很直接：机制列表只是声明，不能当作已经完成绑定的证据。范围是 gsb/batch51-py-safety-a-15 的 scram_channel_binding_guard.py，类 ScramChannelBindingGuard，记录双方机制、通道摘要与协商状态。

公开接口：ScramChannelBindingGuard(*, policy="require", supported=None, clock=None)；offer(*, session_id, mechanisms, binding_data=None)；select_mechanism(*, session_id, mechanism=None)；bind_channel(*, session_id, channel_digest)；verify_binding(*, session_id, binding_data)；reject_downgrade(*, session_id, mechanism)；session_state(session_id)；close_session(session_id)；snapshot()；restore(state)；stats()。机制集合默认包含 SCRAM-SHA-256-PLUS 与 SCRAM-SHA-256。拒绝抛 ScramError(code, detail)，错误码统一为 SCRAM_ 前缀，取值包括 REQUEST_INVALID、MECHANISM_UNSUPPORTED、MECHANISM_NOT_OFFERED、NO_ACCEPTABLE_MECHANISM、DOWNGRADE_REJECTED、STATE_INVALID、BINDING_MISMATCH、CHANNEL_UNBOUND、SESSION_CLOSED、SESSION_UNKNOWN、SNAPSHOT_INVALID。offer 返回 Offer(session_id、mechanisms、has_binding、state)，state 取 offered、negotiated、verified、rejected；校验通过返回 BindingVerdict(session_id、mechanism、status、digest)，status 为 verified。

要修的行为：① offer 记录去重后按字典序升序的机制列表，空列表、非字符串与不支持的机制分别拒绝；② require 策略下自动选择只挑带绑定变体，没有绑定变体按无可用机制拒绝；③ 显式请求非绑定机制在 require 策略下按降级拒绝并记录原因、单独计数；④ 未 offer 就选择、重复选择按会话不存在与状态非法区分，选择后才进入已协商状态；⑤ 选择的机制必须在 offer 列表里，未提供按机制未提供拒绝；⑥ optional 策略允许选择非绑定机制，后续校验仍按实际绑定数据判定；⑦ 绑定校验要求通道摘要已登记，未登记按通道未绑定拒绝；⑧ 绑定数据与当前通道摘要一致才算通过，不一致按绑定不匹配拒绝且状态停在已协商；⑨ 客户端机制列表包含绑定变体但实际发送非绑定消息时按拒绝处理，不得按列表推断已绑定；⑩ 通道在协商中途重建时绑定需重新校验，旧会话不得继续使用；⑪ 显式拒绝降级只能对非绑定机制发起，重复拒绝按状态非法拒绝；⑫ 关闭会话后不再接受 offer 并释放协商记录，快照深拷贝且非法结构整体拒绝。绑定数据缺失与绑定数据不符按不同原因拒绝，便于对账时区分客户端漏带还是通道不一致。

硬约束：同一会话的机制选择与绑定校验必须原子，多线程同时选择只能产生一个结果；协商状态要能区分声明、已选择、已校验三段，任何一段都不能跳步；不同会话的协商互不串用，统计口径要能把降级拒绝与绑定不匹配分开；快照恢复后会话状态、通道摘要与计数原样可用，关闭后资源必须释放。

验收：python3 -m pytest -q tests 15 条必须全过；不得改测试、跳过、按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch51-py-safety-a-15
- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: scram_channel_binding_guard
- typeName: ScramChannelBindingGuard
