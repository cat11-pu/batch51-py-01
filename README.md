# batch51-py-game-a-17

## 题面

生存服上了新的需求表之后客服单子翻倍：玩家下线再上线，饥饿值原地不动，挂机一整晚反而比一直在线的角色更耐饿；喝了水口渴度只掉不回，吃两口熟食饥饿度直接顶过上限；有角色被两个持续掉血的诅咒同时挂上以后血量瞬间清零，救起来一秒又躺回去。范围是 gsb/batch51-py-game-a-17 的 survival_needs_ledger.py，类型 SurvivalNeedsLedger，负责饥饿、口渴、体温三类需求的自然衰减、消耗品恢复、增益减益覆盖与离线补算，运营要求同一份状态在任意时间点重算出来的数值完全一致。

公开接口：SurvivalNeedsLedger(*, decay=None, tick_ms=1000, cap=100)；register(character_id, *, needs=None, at_ms=0)；consume(character_id, need, amount)；apply_effect(character_id, effect)；tick(character_id, at_ms)；offline_catchup(character_id, *, from_ms, to_ms)；state_of(character_id)；needs_of(character_id)；effects_of(character_id)；revive(character_id, *, at_ms)；snapshot()、restore(state)、stats()。register、tick、needs_of、offline_catchup 的返回值都是需求名到数值的映射，consume 返回恢复后的单个数值。违规抛 SurvivalError(code, detail)。

要修的行为：①需求值限定在零到上限之间、上限默认一百，重复注册报 SN_DUPLICATE_CHARACTER，出现未知需求名报 SN_UNKNOWN_NEED；②consume 只接受正数，零或负数报 SN_INVALID_AMOUNT，恢复后按上限夹住不溢出；③自然衰减按服务器毫秒数折算成每秒速率，每种需求的速率互相独立，时间为负或倒退报 SN_TIME_REWIND；④同一时刻重复调用 tick 只结算一次，返回值与当前需求一致且不再扣减，多人在线时各自按自己的时钟推进；⑤任一需求归零立刻进入濒死，state_of 返回 normal 或 dying，濒死后自然衰减停止，直到被救治；⑥revive 只对濒死角色有效，非濒死报 SN_NOT_DYING，救治后需求抬到 25 的下限并回到正常状态；⑦apply_effect 接收 effect_id、need、multiplier、priority、expires_at_ms 五个字段，效果只作用于它声明的那一种需求，其他需求按基础速率衰减，到期时刻之前生效、到期之后按基础速率，effects_of 按需求与效果号升序返回 Effect 元组；⑧离线补算以服务器时间窗口为准，结果必须与连续 tick 逐字段一致，窗口倒置报 SN_TIME_REWIND；⑨快照要保留每个角色的时钟、需求、效果剩余时间与濒死状态，恢复后继续结算的结果与未中断时一致，结构不符报 SN_SNAPSHOT_INVALID 且不得改动在线数据；⑩离线补算跨越多个效果到期点时要按段计算，不能只拿最终效果一次性结算；⑪同类型增益只取最强的那一个而不是叠加，替换时剩余时间按新效果重算；⑫濒死后被救治要清空持续掉血来源，否则下一 tick 立刻再次进入濒死。

stats 返回 characters、ticks、consumes、catchups、revivals、dying 六项，除 characters 是当前角色数外都是成功操作的累计次数，catchups 只计补算成功的调用。硬约束：同一角色的结算必须串行，跨角色之间可以并行，快照与恢复不得读到半个角色；每个角色的效果栈条数与补算窗口长度设上限，超出报错不静默截断；需求上限与衰减速率在构造时确定，运行期不得被外部改写。

验收：`python3 -m pytest -q tests` 的 15 条用例全过，测试不得修改、跳过或按固定输入写死；多角色并发结算、分段补算与救治清零自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: survival_needs_ledger
- typeName: SurvivalNeedsLedger
- topic: 生存需求衰减：离线补算、增益覆盖与濒死状态机
