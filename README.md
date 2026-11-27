# batch51-py-safety-a-01

## 题面

账号侧这个月连出互相矛盾的工单：有的客户刚改完口令又被弹回登录页，有的账号口令过期三个月还能照常进系统，安全审计还发现员工把上一代口令原样改回来居然通过。范围是 gsb/batch51-py-safety-a-01 的 password_history_rotation_policy.py，类 PasswordHistoryPolicy，负责维护每个账号的口令历史代次、到期宽限与强制改密状态。

公开接口：PasswordHistoryPolicy(*, history_depth=12, max_age_days=90, grace_logins=3)；enroll_account(account, *, digest, now)；submit_change(account, *, digest, now)；check_login(account, *, now)；record_login(account, *, now)；admin_reset(account, *, digest, now)；update_policy(*, history_depth=None, max_age_days=None, grace_logins=None)；history_of(account)；account_state(account, *, now)；snapshot()；restore(state)；stats()。时间参数一律用整数 epoch 秒，拒绝与非法输入抛 PasswordPolicyError(code, detail)。

要修的行为：① 新账号登记后历史只有一代、代次从 1 起，统计里登记数加一；② 提交与保留窗口内任一代相同摘要的口令必须判重用，状态与代次都不许变；③ 通过的口令追加为新代次，历史按 history_depth 从尾部保留，被裁掉的条数计入 trimmed；④ 到期账号登录先走宽限：账面上仍允许一次进入并把宽限余量报出来，余量用尽后再进改密引导而不是直接踢掉；⑤ record_login 只在账号已到期且未强制改密时消耗一次宽限，正常账号不消耗；⑥ 强制改密置位期间登录只回改密动作，口令改成功后置位解除、宽限归零；⑦ 管理员重置追加一代并重新置位强制改密，历史链不清空——重置后把口令设回重置前的旧值仍要判重用；⑧ 历史深度从 12 调到 4 后，被裁掉的老摘要不再作为重用依据，但已经置位的强制改密状态不能因为裁剪被解除；⑨ 摘要必须是长度不少于 8、不含空白的字符串，账号名空串、重复登记、非法摘要一律带原因码拒绝；⑩ 快照要能完整还原历史、代次、置位状态、宽限消耗与统计，恢复后与源对象不共享可变结构，结构非法按原因码拒绝且不动现有数据；⑪ 同一账号并发提交改密只能有一次通过，其余必须判重用，代次只加一；⑫ stats 至少给出 enrolled、changed、reused、resets、logins、trimmed 六项计数。

另外请把工单里反复出现的三个现场也一并兜住：一是账号到期后运维往往先放开宽限再通知用户，宽限余量要在每次登录后立刻可见；二是重置工单里有客服图省事直接复用旧摘要做临时口令，这种提交必须被历史链挡住；三是批量调整策略时不能把正在强制改密的账号顺手放出来。

硬约束：同账号并发改密要串行裁决，锁外不得读到半写状态；快照恢复后历史链、代次、置位与统计必须自洽，恢复失败不得留下半套数据；单账号历史条目数受 history_depth 硬顶。

验收：python3 -m pytest -q tests 15 条必须全过，不得改测试、不得跳过、不得按固定输入写死；并发与重启场景自行验证；只做本地实现，不引入第三方依赖。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: password_history_rotation_policy
- typeName: PasswordHistoryPolicy
