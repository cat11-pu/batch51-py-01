# batch51-py-safety-d-09

## 题面

内核观测平台上新后，SRE 组一晚上踩了四个坑：两个租户的采集任务都往同一个实例名里注册探针，后注册的把先注册的过滤条件冲掉了；有人在过滤表达式里多打了一个左括号，整条事件订阅静默失效，面板上看起来只是没数据；某个采集进程读得太慢，缓冲区满之后写入侧被拖住，主机 load 直接翻倍；还有一次删实例时目录被强删，仍挂着的 trace_pipe 读取者拿到半截数据。范围是 gsb/batch51-py-safety-d-09 的 tracefs_access_guard.py，类 TracefsAccessGuard，负责实例生命周期、探针注册与读取者配额。

公开接口：create_instance(name, *, tenant, buffer_size_kb=1024, filter=None)；destroy_instance(name, *, force=False)；instances(tenant=None)；register_probe(instance, *, symbol, kind="kprobe", offset=0, filter="")；probes(instance)；describe(probe_id)；enable_event(instance, event, *, enable=True)；attach_reader(instance, *, tenant, reader_id=None)；detach_reader(reader_id)；emit_event(instance, event, *, count=1)；read(reader_id, *, max_events=64)；snapshot()；restore(state)；stats()。拒绝时统一抛 TraceError(code, detail)。

要修的故障与边界：①实例名只允许小写字母数字下划线与短横线且不超过 32 字符，重复名报 TRACE_INSTANCE_EXISTS，空租户报 TRACE_INVALID_REQUEST；②buffer_size_kb 只接受 1 到 16384，越界报 TRACE_BUFFER_INVALID；③过滤表达式只允许标识符、数字、空白与比较连接符号，括号必须配对，含分号等注入字符或括号不配对整条报 TRACE_FILTER_INVALID，失败时不得留下半成品实例；④探针只允许注册在白名单符号及其偏移窗口内，白名单外报 TRACE_PROBE_SYMBOL_DENIED，偏移越界报 TRACE_PROBE_OFFSET_INVALID；⑤uprobe 的符号必须是绝对路径且不含 .. 路径段，kprobe 与 uprobe 之外的 kind 报 TRACE_INVALID_REQUEST；⑥同一符号上重复注册相同探针要幂等，不同过滤条件视为不同探针，探针编号从 p1 起全局递增；⑦describe 只能返回脱敏视图，内核地址一律给 0x***，不得回显原始地址，未知编号报 TRACE_PROBE_UNKNOWN；⑧enable_event 只翻转该实例上同符号的探针并返回条数，没有匹配探针报 TRACE_EVENT_UNKNOWN；⑨读取者必须与实例同租户，跨租户报 TRACE_TENANT_MISMATCH，非属主不得读取；⑩单实例与全局的探针数、读取者数、实例数都有硬顶，超限报 TRACE_LIMIT_EXCEEDED，被拒请求不分配编号；⑪实例销毁要先停用事件再释放缓冲，返回 {"probes": n, "readers": m}，还有读取者挂着且未声明强制时报 TRACE_READERS_ATTACHED；⑫慢读者写满配额后按丢弃处理并计入该读取者的丢失，不能阻塞写入方向，emit_event 返回 {"delivered": n, "dropped": m}；⑬read 按入队顺序返回事件名，读到空队列返回空列表，已关闭或未知读取者报 TRACE_READER_CLOSED 与 TRACE_READER_UNKNOWN。

硬约束：同一实例上的 enable、emit、销毁必须串行，探针状态与读取者水位不能被并发写坏；快照保存实例、探针、读取者队列与计数，恢复后未读事件仍按原顺序可读，非法快照整份拒绝且不污染现有状态；跨租户隔离在实例列表、读取与销毁三处都要生效。stats 至少返回 instances、probes、enabled_probes、readers、emitted、delivered、dropped 七个计数。

验收：`python3 -m pytest -q tests` 的 15 条用例全过，测试不得修改、跳过或按固定输入写死；并发启用与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: tracefs_access_guard
- typeName: TracefsAccessGuard
