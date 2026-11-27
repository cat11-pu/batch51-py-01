# batch51-py-game-b-09

## 题面

移动端版本更新后，中低端机的帧时间从 11 毫秒涨到 15 毫秒，抓帧工具显示每个渲染目标在每一趟 pass 都在整块读写，连从来没人采样的深度预通道也在来回搬。图形组的同学手工关掉几个 store 之后画面又出问题：后期合成读到的是上一帧的旧颜色，MSAA 目标解析出来的边缘发黑，某些目标在帧末被外部截图系统读走却被当成可丢。请修 `gsb/batch51-py-game-b-09` 的 `render_target_loadop_optimizer.py`，类 `LoadOpOptimizer` 分析每个渲染目标在一帧内的读写序列，为首末使用选择清空、保留或丢弃，并核算节省的带宽，拒绝时统一抛 `LoadOpError(code, detail)`。

公开接口：`LoadOpOptimizer(*, max_targets=64, max_uses_per_target=64)`；`declare_target(name, *, bytes_per_frame, samples=1, persistent=False, external_read=False)`；`declare_external_read(name)`；`declare_use(target, pass_index, kind, *, resolve=False, sampled=False)`；`plan()`；`load_op_of(target, pass_index)`；`store_op_of(target, pass_index)`；`bandwidth_saved()`；`target_state(name)`；`uses_of(target)`；`snapshot()`；`restore(state)`；`stats()`。

要修的行为：①目标名须非空字符串，`bytes_per_frame` 为正整数，`samples` 只接受 1、2、4、8，重复声明报 `LOADOP_TARGET_EXISTS`，目标数受 `max_targets` 硬顶，超限报 `LOADOP_CAPACITY_EXCEEDED`。②`kind` 只接受 write、read、read_write，`pass_index` 须为非负整数，同一目标同一 pass 只能声明一次，冲突报 `LOADOP_PASS_CONFLICT`，未知目标报 `LOADOP_NO_SUCH_TARGET`。③计划的顺序按目标名升序再按 pass 升序，重复调用结果逐项一致，不依赖字典插入顺序。④首次使用为写时清空，后续使用为写时丢弃旧内容；读与读写都保留内容，`kind=read` 的末次使用不产生存储。⑤下一次使用需要旧内容（读、读写或解析）时前一次必须存储，否则前一次可丢弃；纯写链上的中间存储全部省掉。⑥帧末被外部系统读取或需要跨帧保留的目标，末次使用必须存储，外部读取要通过 `declare_external_read` 或声明时的 persistent/external 标记显式给出，没有声明的一律按可丢处理。⑦先写后读再写时，中间那次写不能丢弃，否则读到的还是更早的内容。⑧声明 resolve 的使用只在多重采样目标上合法，非多重采样报 `LOADOP_RESOLVE_NOT_MSAA`；解析本身算一次读取，解析前一次内容若已被丢弃，解析结果未定义，计划必须拒绝并报 `LOADOP_RESOLVE_AFTER_DISCARD`。⑨解析成功后按解析结果存储，`store_op` 记为 resolve，解析前的多重采样内容不再保留。⑩带宽账按目标逐项核算：基准是把每次使用都算一整次读加一整次写，实际成本里 load 与 store、resolve 各计一帧字节，clear 与 discard 不计，差额即节省量。⑪每目标使用次数受 `max_uses_per_target` 硬顶，超限报 `LOADOP_USE_LIMIT`，已声明的使用不受影响。⑫快照含 `version`、`targets`、`uses`、`counters` 四项且为深拷贝，结构不符报 `LOADOP_SNAPSHOT_INVALID` 且现有状态不变。

硬约束：同一目标的 use 声明可能来自多个渲染管线线程，八路并发声明不同 pass 后必须一条不少，计划里 pass 严格升序且带宽账与串行结果一致；计划是纯查询，不得改写已声明的使用；快照要能把目标声明、使用序列与计数一起恢复到新实例，恢复后的计划与原实例逐项相同。

`stats()` 返回 `targets`、`uses`、`plans`、`rejected`。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发声明与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: render_target_loadop_optimizer
- typeName: LoadOpOptimizer
