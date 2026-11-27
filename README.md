# batch51-py-safety-c-16

## 题面

运维平台的进程核查服务这两天在几台机器上给出互相矛盾的结论：安全值班把一个进程号拉进黑名单，几十秒后同一个号已经换成了别的程序，页面仍显示"已确认是原进程"，值班按老结论继续封端口；反过来，一个刚重启的进程明明活着，核查结果却说身份变了，工单被打回重查。追查下来，身份没有按"进程号加启动时间加命名空间"整体固化，而是每次拿进程号现查可执行文件和工作目录，进程号一旦被复用就认错人。范围是 gsb/batch51-py-safety-c-16 下的 proc_identity_pinner.py，类 ProcIdentityPinner，负责把进程观测表固化成身份句柄，并在之后的核对里只比对身份三元组。

公开接口：ProcIdentityPinner(*, max_handles=8, idle_timeout=60)；ingest_proc_table(entries)；pin(pid, *, owner="default", now=None)；resolve(handle_id, *, now=None)；still_alive(handle_id, *, now=None)；invalid_reason(handle_id)；release(handle_id, *, now=None)；release_owner(owner, *, now=None)；handles_for(owner)；reap_idle(now=None)；snapshot()；restore(state)；stats()。观测表每条记录含 pid、start_time、namespace、state、exe、cwd 六个字段。拒绝时抛 ProcError(code, detail)，code 为大写串。

要修的行为：① ingest_proc_table 整表替换当前观测并返回接收条数，任一条字段缺失或类型不对就整表拒收并抛 PROC_TABLE_INVALID，旧观测与已有句柄不受影响；② pin 取当前观测的三元组建句柄，编号按 h-1、h-2 递增，观测里查不到该进程号抛 PROC_UNKNOWN_PID 且不留下半个句柄；③ 句柄建立后 resolve 只比对三元组，一致才返回 exe、cwd，路径信息以最近一次观测为准；④ 进程号被复用（启动时间或命名空间任一不同）时 resolve 抛 PROC_HANDLE_STALE，detail 为 pid_reused，still_alive 返回 False；⑤ 进程号从观测表消失后 still_alive 为 False，detail 为 process_gone；⑥ 已释放句柄 resolve 抛 PROC_HANDLE_STALE、detail 为 released，invalid_reason 也返回 released，重复释放返回 False；⑦ release_owner 只清该属主的句柄并返回数量，其他属主不受影响；⑧ 存活句柄数不得超过 max_handles，超限时回收 last_used 最早的空闲句柄，被回收者 invalid_reason 返回 evicted；⑨ reap_idle 回收空闲超过 idle_timeout 的句柄并返回条数，原因记为 idle_reaped，pin、resolve、still_alive 各算一次使用；⑩ 状态为僵尸的记录仍算存活，但不得再去读它的可执行文件与工作目录；⑪ 同一进程号短时间内两次固化各自独立，释放其中一个不影响另一个；⑫ 未知句柄号做 resolve 或 invalid_reason 抛 PROC_HANDLE_UNKNOWN。

快照结构为 {"processes": [...], "handles": {...}, "stats": {...}}，必须深拷贝；restore 遇到字段缺失或类型不符抛 PROC_SNAPSHOT_INVALID 且原状态一字不动。stats 返回 pins、releases、evictions、stale、reaped、pids_ingested、live_handles。

硬约束：同一属主并发 pin 时编号不得重复、计数不得丢，容量判定要么看到回收前要么看到回收后，不能出现一个句柄被两个调用方同时认定有效；restore 之后句柄、属主、最后使用时间、计数全部可往返，且恢复出来的结构不与入参共享内存。句柄上限是硬顶，任何路径都不得越界。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过、按固定输入写死；并发与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch51-py-safety-c-16
- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: proc_identity_pinner
- typeName: ProcIdentityPinner
