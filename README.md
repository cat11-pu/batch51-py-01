# batch51-py-safety-a-04

## 题面

域内几台文件服务器开始间歇性拒绝域账号：抓包看协商走完了、类型 3 也到了，服务器仍然回 401；另一批机器反过来，客户端根本没带通道绑定也被放进来。范围是 gsb/batch51-py-safety-a-04 的 ntlm_channel_binding_guard.py，类 NtlmBindingGuard，在建立会话前核对通道绑定、目标名、MIC 与时间戳偏移。

公开接口：NtlmBindingGuard(*, max_skew_seconds=300, max_attempts=3, challenge_ttl=120)；register_service(service, *, spn, require_cbt=True, strict_mic=False)；service_policy(service)；begin(connection_id, *, service, client_flags, binding_material, source, at)；complete(connection_id, *, fields, at)；parse_type3(fields)；channel_binding_status(fields, binding_material)；verify_mic(fields, *, challenge_token)；session_key(connection_id)；attempts_left(connection_id)；refusals(*, source=None)；close(connection_id)；snapshot()；restore(state)；stats()。时间参数为整数 epoch 秒。

派生口径：挑战令牌取 sha256("challenge|连接号|服务名|客户端标志|绑定材料") 十六进制前 32 位；期望通道绑定取 sha256("cbt|绑定材料")；期望 MIC 取 sha256("mic|挑战令牌|nt_response")；会话密钥取 sha256("session|挑战令牌|nt_response") 的完整十六进制。三者都按小写十六进制比较。

要修的行为：① 未登记的服务不许开局，策略按服务保存 SPN、是否强制绑定与是否严格 MIC；② 类型 3 字段缺失、类型不对、nt_response 非十六进制或长度不对一律判消息非法并拒绝；③ 时间戳与本地时间偏差超过 max_skew_seconds 必须拒绝并消耗一次尝试额度；④ 目标名与本地 SPN 只在大小写上有差别时视为同一目标，域名部分不同必须判不匹配；⑤ 客户端声明支持通道绑定但 CBT 字段为空时必须拒绝，只有明确声明不支持绑定的客户端才按宽松策略放行；⑥ CBT 值与按绑定材料算出的期望值不一致必须拒绝，原因码要与缺失分开，通道绑定核对结果按 ok、missing、mismatch 三值回报；⑦ MIC 存在但校验值错误与 MIC 完全缺失是两种结果，前者直接拒绝且不消耗尝试额度，后者按策略降级并记一次告警；⑧ 严格 MIC 的服务缺 MIC 直接拒绝，宽松服务缺 MIC 放行但记告警；⑨ 通过后按公式派生会话密钥，同一连接重复完成只认第一次，第二次按已建立会话拒绝；⑩ 尝试额度用尽后不再解析消息，直接按额度耗尽拒绝；⑪ 拒绝记录可按来源查询，含连接号、原因码与时间，关闭连接后其会话不再可用；⑫ 快照要能还原服务策略、会话、尝试额度与拒绝记录，恢复后不共享可变结构，结构非法按原因码拒绝且不动现有数据。

排障时还要能按来源把一次失败讲清楚：是绑定材料对不上、目标名不在本地 SPN 里，还是签名或时钟出了问题；拒绝原因不能混成一个笼统的认证失败。

硬约束：同一连接并发完成只能建立一次会话，会话表在锁内写入且不得出现半初始化的密钥；拒绝计数与拒绝原因必须与判定同源，不得先记后判；服务策略变更只影响之后开始的连接。

验收：python3 -m pytest -q tests 15 条必须全过，不得改测试、不得跳过、不得按固定输入写死；并发与重启场景自行验证；只做本地实现，不引入第三方依赖。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: ntlm_channel_binding_guard
- typeName: NtlmBindingGuard
