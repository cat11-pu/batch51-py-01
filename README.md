# batch51-py-safety-a-03

## 题面

两位客户的恢复流程同时卡住：一位把守护人从名单里删掉之后，之前的授权票还在被计数，重置照样放行；另一位连续投了四次票被算成四票，直接跳过等待期拿回账号。范围是 gsb/batch51-py-safety-a-03 的 guardian_recovery_quorum.py，类 GuardianRecoveryQuorum，为账号维护守护人名单与恢复案件。

公开接口：GuardianRecoveryQuorum(*, threshold=2, wait_seconds=86400, max_guardians=8)；add_guardian(account, guardian)；remove_guardian(account, guardian)；guardians(account)；open_case(account, *, case_id, at, requested_by=None)；cast_approval(case_id, *, guardian, ticket_id, device_id, at)；cast_objection(case_id, *, guardian, at, note="")；finalize_case(case_id, *, at)；cancel_case(case_id, *, actor, at)；case_state(case_id)；login_frozen(account, *, at)；recovery_epoch(account)；snapshot()；restore(state)；stats()。时间参数为整数 epoch 秒。

要修的行为：① 守护人名单按字典序返回、重复加入不重复计数，名单规模受上限硬顶；② 守护人不足阈值时不许建案，账号已有未结案件时不许再建，案件号全局唯一；③ 每条授权票一次性且绑定案件、账号与守护人，受理后回受理成功原因码，同一守护人重复投票只计一票，换设备标识也不能绕过；④ 非名单成员投票直接拒绝且不计票，窗口关闭后的票不再接受；⑤ 结算早于等待窗口结束时只回等待中，不得提前放行，也不改任何状态；⑥ 窗口结束且有效票达到阈值才放行，放行后账号恢复代次加一，同一案件只能结算一次；⑦ 票数不足时结算为拒绝并关闭案件，恢复代次不变；⑧ 窗口内任一守护人异议立即作废全部票据，案件转作废状态，之后结算按异议理由关闭；⑨ 守护人被移出名单后，其在移出前投出的票据在结算时必须作废，不能因为投票时间更早就继续有效；⑩ 申请人主动取消的案件重新发起恢复要重新计时，不得继承上一案件已经走过的等待时间；⑪ 案件未结期间该账号登录处于冻结，案件放行、拒绝、作废或取消后解除，名下没有未结案件的账号一律不冻结；⑫ 快照要能还原名单、案件、票据与恢复代次，恢复后不共享可变结构，结构非法按原因码拒绝且不动现有数据；stats 至少给出建案、授权、异议、结算与放行计数。

客服侧的抱怨集中在两处：同一案件反复点授权也能把票数堆上去，以及取消之后隔天重开居然直接跳过等待期。结算结果要能一次说清是放行、被拒还是仍在等待，方便工单回填。

硬约束：同一案件并发结算只能生效一次，票据与票数在锁内更新；等待窗口、票据一次性与异议作废三者的先后顺序必须一致，不得出现已作废案件被结算放行；案件与票据表可随快照完整重启。

验收：python3 -m pytest -q tests 15 条必须全过，不得改测试、不得跳过、不得按固定输入写死；并发与重启场景自行验证；只做本地实现，不引入第三方依赖。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: guardian_recovery_quorum
- typeName: GuardianRecoveryQuorum
