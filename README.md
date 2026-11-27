# batch51-py-safety-a-12

## 题面

运维值班这周被一次性口令刷屏：同一条口令在两台前置机上前后脚提交，两边都回成功；用户换手机后手动校准计数器，校准完口令反而连续失效；服务重启后计数归零，旧口令又能用一次。值班同学手工把计数器往前推一格能恢复，推过头又得整批重置，业务侧已经开始拒付。范围是 gsb/batch51-py-safety-a-12 的 hotp_counter_ledger.py，类 HotpCounterLedger，按用户维护计数器、已消费记录与前视窗口。

公开接口：HotpCounterLedger(*, lookahead=5, max_users=64, window_size=32, clock=None)；register(*, user, secret, counter=0)；verify(*, user, code)；consume(*, user, counter)；counter_of(user)；resync(*, user, counter, code)；consumed_for(user)；lookahead_of(user)；unregister(user)；snapshot()；restore(state)；stats()。口令按 sha256("secret:counter") 取十六进制小写前 6 位，传入口令必须是 6 位小写十六进制串。拒绝抛 HotpError(code, detail)，错误码统一为 HOTP_ 前缀，取值包括 USER_EXISTS、USER_UNKNOWN、REQUEST_INVALID、CAPACITY_EXCEEDED、COUNTER_ROLLBACK、RESYNC_MISMATCH、SNAPSHOT_INVALID。用户记录为 UserRecord(user、counter、lookahead、consumed)；verify 返回 VerifyResult(user、accepted、counter、next_counter、reason)，reason 取 ok、replayed、stale、no_match，未命中时 counter 为空且 next_counter 等于当前值。

要修的行为：① 登记用户后计数器从给定值起步、消费记录为空，重复登记、空用户、空密钥、负起始值一律拒绝；② 校验从当前计数器到当前值加前视窗口逐位比对，命中前视位置时计数器推进到命中值加一；③ 命中已消费记录按重放拒绝，计数器不动，也不改写消费窗口；④ 口令对应位置小于当前计数器按过期位拒绝，计数器不动；⑤ 前视窗口内没有任何匹配按不匹配拒绝，同样不推进；⑥ 口令长度或字符集不合法、用户不存在分别按请求非法与用户不存在拒绝；⑦ 前视窗口为 0 时只接受当前计数器那一条；⑧ consume 直接消费指定计数器并把计数器推进一格，低于当前值的消费按回退拒绝；⑨ resync 用目标计数器上的口令做校准，成功把计数器推进到目标值加一，口令不符只拒绝不动计数器；⑩ 重同步给出的计数器小于等于当前值时按拒绝处理，不得回退；⑪ 消费记录按计数器升序返回且只保留最近 window_size 条，快照包含密钥、计数器与消费窗口；⑫ 每用户登记数有上限，超限拒绝，注销后释放名额，恢复后从落盘值继续推进。

硬约束：前视窗口内的值被并发提交时只能有一个成功，其余按已消费拒绝且不得推进计数器，成功数与拒绝数之和必须等于提交次数；窗口内已消费的序号不得二次生效，重放与窗口外不匹配要能落到不同统计口径；快照深拷贝且非法结构整体拒绝，在线数据保持原样；每用户数量上限与消费窗口长度都是硬顶。

验收：python3 -m pytest -q tests 15 条必须全过；不得改测试、跳过、按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch51-py-safety-a-12
- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: hotp_counter_ledger
- typeName: HotpCounterLedger
