# batch51-py-safety-d-10

## 题面

一台老工控机换了采集代理之后，端口权限开始乱套：原本只开 0x300 到 0x30F 的进程，撤销中间一段之后整条权限都没了，后面依赖那段相邻端口的读写全部超时；子进程被拉起来以后，父进程再补开端口，子进程跟着就能访问，隔离形同虚设；最要命的是某次把提升级别从 3 降回 0，表面上降级成功，实际端口仍能直接读写，安全审计把这台机器判为高危。现在每次改端口都要有人手工核对位图，夜间窗口干脆不敢再动，变更单积压了一周。范围是 gsb/batch51-py-safety-d-10 的 ioperm_range_guard.py，类 IopermRangeGuard，负责按区间的端口授权、提升级别与 fork/exec 后的清零规则。

公开接口：grant_range(pid, start, end, *, cap_rawio=True, now=None)；revoke_range(pid, start, end)；revoke_all(pid)；set_iopl(pid, level, *, cap_rawio=True)；fork_child(parent_pid, child_pid, *, inherit=False)；exec_reset(pid)；allowed(pid, port)；ranges(pid)；process_level(pid)；processes()；snapshot()；restore(state)；stats()。拒绝时统一抛 IoportError(code, detail)。

要修的故障与边界：①授权按闭区间记录，重叠或首尾相接的区间合并成一段，同一区间重复申请幂等但计数照记；②结果按起点升序返回 (start, end) 元组序列，多次授权后位图必须收敛到最少段数，进程不存在时 ranges 报 IOPORT_UNKNOWN_PROCESS；③端口只允许 0 到 65535，start 大于 end、负数、越界都报 IOPORT_INVALID_RANGE 并带上 {"start": s, "end": e}，pid 非正报 IOPORT_INVALID_PID；④撤销按差集处理，被更大区间完整覆盖的子区间要把原区间拆成两段而不是整段删除；⑤与位图不重叠的撤销是幂等的，返回原序列且不报错；⑥从 iopl 3 降回 0 之后，此前靠提升级别拿到的端口访问必须全部失效，只能按位图判定，不能残留隐含权限；⑦提升级别只支持 0 和 3，其它值报 IOPORT_INVALID_LEVEL；⑧缺少 CAP_SYS_RAWIO 时 grant 与高权限级别都报 IOPORT_CAP_MISSING，失败不得留下半个进程记录；⑨fork 子进程默认零权限零级别，只有显式继承才复制父进程位图，父进程事后新增的授权子进程不得看到；⑩exec 之后位图与级别一律清零，exec_reset 返回子进程快照并计入次数，pid 不存在报 IOPORT_UNKNOWN_PROCESS；⑪单进程区间数与全局区间总数都有硬顶，超限报 IOPORT_LIMIT_EXCEEDED 且原位图不变；⑫fork 到已存在的 pid 报 IOPORT_PID_EXISTS；⑬allowed 对未知 pid 返回 False，对越界端口报 IOPORT_INVALID_RANGE。

硬约束：同一进程的 grant、revoke 与 fork 必须持同一把锁串行，合并后的区间序列与计数不能出现交叉写坏，并发补开相邻端口最终必须收敛成一段；快照保存进程位图、级别与计数，恢复后 allowed 判定与恢复前逐端口一致，非法快照整份拒绝且不污染现有状态；降级、exec 与 fork 都不得把父进程或其它进程的位图串过去。stats 至少返回 processes、grants、revokes、forks、exec_resets、iopl_changes 六个计数。

验收：`python3 -m pytest -q tests` 的 15 条用例全过，测试不得修改、跳过或按固定输入写死；并发授权与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: ioperm_range_guard
- typeName: IopermRangeGuard
