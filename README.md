# batch51-py-game-a-16

## 题面

大逃杀新赛季上线后决赛圈报错成灾：有玩家站在白圈边缘被瞬间扣光血，有玩家在缩圈动画里明明已经进了圈还在持续掉血，观战端画的圈和服务器判定的圈对不上；运维还发现帧率一掉就整段跳过缩圈阶段，掉帧重连后直接进了下一圈，赛后复盘拿不到任何可对照的结算记录。范围是 gsb/batch51-py-game-a-16 的 br_zone_shrinker.py，类型 BrZoneShrinker，负责按阶段推进安全区、维护当前圈与下一个圈、结算圈外玩家的持续伤害，并保证同一场比赛任意时刻重放出来的圈与服务器一致。

公开接口：BrZoneShrinker(*, tick_ms=1000, damage_per_tick=1, respawn_protect_ms=5000)；configure_phases(phases)；advance(elapsed_ms)；current_zone()；next_zone()；player_entered(player_id, *, x, y, at_ms=0)；player_respawn(player_id, *, x, y, at_ms)；move_player(player_id, *, x, y)；damage_tick()；players_outside()；health_of(player_id)；snapshot()、restore(state)、stats()。违规抛 ZoneError(code, detail)。

要修的行为：①阶段号必须从零开始连续递增，中间缺口、乱序或重复都报 ZS_INVALID_PHASE；②半径逐段严格变小、只有末段允许为零，新圈心必须落在上一圈内，越界报 ZS_CENTER_OUTSIDE，hold_ms 不得为负且首段没有收缩过程、shrink_ms 必须为零；③阶段表只允许配置一次，第二次调用报 ZS_PHASES_LOCKED，阶段数硬顶 8，超限报 ZS_TOO_MANY_PHASES；④掉帧一次跨过多个缩圈起点时，advance 必须把经过的阶段号按先后顺序全部放进返回的元组，不能只返回最后一个，时钟倒流报 ZS_CLOCK_REWIND；⑤保持阶段内 current_zone 返回配置原值，缩圈窗口内圆心与半径按已过时间线性插值，插值结果不随调用次数变化，zone 的 phase 取该时刻正在生效或正在收缩进入的阶段号；⑥next_zone 给出当前段之后的目标圈，已经进入最后一次收缩后返回 None；⑦圈外判定一律用插值后的圈，移动只改坐标不动血量，新进场玩家满血一百；⑧damage_tick 返回玩家号到本次扣血量的字典，按已过的 tick 数批量扣血，同一个 tick 重复调用返回空字典且不得改动任何玩家血量；⑨血量归零的玩家移出圈外名单，players_outside 按玩家号升序返回元组；⑩收缩过程中被新圈覆盖的玩家按进入圈内的时刻停止伤害，不能等下一阶段生效；⑪复活与跳伞进入的玩家带一段保护期，保护期内不掉血但仍计入圈外统计；⑫最终圈半径为零时直接判定胜者，不得继续对圈内玩家结算伤害。

stats 返回 clock_ms、phase、phases、players、outside、ticks 六项。硬约束：同一 tick 的伤害结算必须幂等，重复调用不得二次扣血；快照要带比赛时钟、已结算 tick、阶段表与每个玩家的坐标血量，恢复后继续推进的结果必须与未中断时逐字段一致，结构不符报 ZS_SNAPSHOT_INVALID 且不得改动在跑的比赛；阶段上限与每 tick 伤害在构造时确定，运行期不得被外部改写。

验收：`python3 -m pytest -q tests` 的 15 条用例全过，测试不得修改、跳过或按固定输入写死；掉帧跨段、保护期、最终圈判定与恢复续跑自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: br_zone_shrinker
- typeName: BrZoneShrinker
- topic: 大逃杀安全区收缩：阶段推进、圈心插值与圈外伤害结算
