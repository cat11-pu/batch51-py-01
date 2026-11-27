# batch51-py-game-a-20

## 题面

后台指令平台改版之后连着出了三次事故：一次是发起人自己顺手点了复核，三分钟内把两千个账号的道具一次性发了出去；一次是预演时选的是一百个目标，正式执行却按全服目标跑，事后谁也拿不出改动前的参数；还有一次批量封禁中途失败，整批被记成失败，实际已经封掉的账号没人恢复，客服只能手工一个个解。范围是 gsb/batch51-py-game-a-20 的 gm_command_auditor.py，类型 GmCommandAuditor，负责高权限后台指令的权限校验、双人复核、干跑预演、执行与回滚计划，并留下可追溯的操作日志。

公开接口：GmCommandAuditor(*, max_log=1000, retention_ms=86400000)；register_command(command_id, *, required_role, kind, max_targets=1)；grant_role(principal, role)；submit(request_id, command_id, *, operator, reviewer, params, targets, reason, at_ms)；authorize(request_id, *, at_ms)；dry_run(request_id, *, at_ms)；execute(request_id, *, at_ms)；rollback_plan(request_id)；audit_log(*, request_id=None, limit=None)；request_of(request_id)；pending_approvals()；snapshot()、restore(state)、stats()。违规抛 GmError(code, detail)，越权或复核不合法抛 GmPermissionError(code, detail)。

要修的行为：①指令注册与提交校验：指令号重复注册报 GM_COMMAND_EXISTS，指令类型或必须角色非法报 GM_INVALID_COMMAND，提交未知指令报 GM_UNKNOWN_COMMAND，理由为空报 GM_REASON_REQUIRED；②越权与复核人校验：操作人缺少该指令要求的角色报 GM_FORBIDDEN 并计入拒绝数，复核人为空报 GM_REVIEWER_REQUIRED，复核人没有审批角色报 GM_REVIEWER_NOT_QUALIFIED；③请求状态只有 pending_approval、approved、executed 三种，复核通过后请求进入 approved 并清出待审队列，未审批就干跑报 GM_NOT_APPROVED，重复授权报 GM_ALREADY_AUTHORIZED；④请求号幂等：submit 返回 request_id 与 status，同一请求号重复提交返回 duplicate，不新增请求也不覆盖首次提交的目标；⑤干跑只读：返回 command_id、targets、count 与 digest 四项，重复干跑不改变请求状态、不增加已执行数；⑥execute 返回 status 与 applied、failed 两个元组，按目标提交顺序排列，单个目标要么整条生效要么整条不生效；⑦同一请求号重复执行返回 duplicate，已执行计数与已生效目标数不得翻倍；⑧rollback_plan 只对已执行请求可用，未执行报 GM_NOT_EXECUTED，每个操作带 op 固定为 revert、target 与 command_id，按已生效目标的逆序排列；⑨操作日志按发生顺序保留自增 seq、phase、request_id、操作人、复核人、目标与时间，phase 取 submitted、authorized、dry_run、executed，limit 只取最近若干条，条数上限 max_log、超出淘汰最旧；快照保留指令表、角色、请求、日志与计数，结构不符报 GM_SNAPSHOT_INVALID 且不得改动在线数据；⑩复核人不能是发起人本人，代填复核意见的请求要在授权阶段直接拒绝；⑪干跑与实际执行的参数必须逐字段一致，执行时重新校验，防止预演之后被改写；⑫批量指令部分对象失败时按已成功对象生成回滚计划，不能整批标记失败。

stats 返回 requests、approved、executed、applied、failed、denied、log_entries 七项，均为成功操作的累计计数，被拒绝的提交只增加 denied。硬约束：同一请求号的执行在整个进程内只允许生效一次，并发提交与并发执行都要收敛到同一份结果；执行期间按目标对象加锁，日志与请求状态要么一起写入要么都不写；日志条数与保留期都是硬顶，超出淘汰最旧的条目而不是截断新条目。

验收：`python3 -m pytest -q tests` 的 15 条用例全过，测试不得修改、跳过或按固定输入写死；代复核、参数篡改与部分失败回滚自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: gm_command_auditor
- typeName: GmCommandAuditor
- topic: 后台指令审计：双人复核、干跑预演与失败批次回滚
