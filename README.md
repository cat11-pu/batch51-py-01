# batch51-py-game-a-05

## 题面

副本难度调了三个月，玩家一直说小怪血量忽高忽低，同一个本上午难得离谱晚上又太软；开荒队在首领战里被系统连升两档，血条直接翻倍，第二天全服都在传这个事故；还有人中途离队重进，系统把离队前队友的死亡算进了新队伍，进门就挨了一轮升档；运维改完配置重启服务，档位又跳回零档，前一天的调整记录一条都不剩。范围是 gsb/batch51-py-game-a-05 的 dynamic_difficulty_director.py，类 DifficultyDirector，按遭遇指标在档位区间内升降并映射怪物系数。

公开接口：DifficultyDirector(*, scaling=None, up_threshold_bps=12000, down_threshold_bps=4000, hysteresis_bps=1500, min_interval_ms=30000, max_tier=3, max_history=8)；observe(*, deaths=0, wipes=0, kills=0, kill_ms=0, healing=0, members=4, at_ms=0) 返回窗口快照；metrics()；tier_of()；coefficients_of(tier=None)；evaluate_adjust(at_ms=0) 返回 Adjustment(seq, from_tier, to_tier, changed, reason, stress_bps, at_ms, window)；freeze(reason, *, at_ms=0) 与 unfreeze(*, at_ms=0)；is_frozen()；reason_of(tier=None)；history_of(limit=None)；snapshot / restore / stats。拒绝统一抛 DirectorError(code, detail)。

要修的行为：①压力按 deaths 乘 10000 加 wipes 乘 20000 再整除 kills 归一，kills 为零按一除，窗口里的 kill_ms_avg 为累计耗时整除击杀数；②指标为负或队伍人数小于 1 报 DIRECTOR_INVALID_METRIC 且窗口不变；③升档线为 up_threshold_bps 加当前档位乘 hysteresis_bps，降档线为 down_threshold_bps 减当前档位乘 hysteresis_bps；④档位只在零到 max_tier 之间，越界求系数报 DIRECTOR_INVALID_TIER，系数表未配置时用内置四档；⑤队伍成员中途离开后指标窗口按剩余成员重新归一，离队前的死亡不得计入新窗口；⑥连续失败触发的升档不得超过配置上限，到顶后只记录建议档位不实际提升；⑦每次实际调整记下触发压力、窗口快照与旧新档位，reason 记 ADJUST_UP 或 ADJUST_DOWN，历史只收实际变更并按序号升序；⑧两次调整之间至少间隔 min_interval_ms，间隔内返回 COOLDOWN，档位不动但窗口继续累计；⑨冻结期间只累计指标，evaluate_adjust 返回 FROZEN 且不进历史，freeze 与 unfreeze 各返回是否真的改变了状态；⑩冻结期间积压的指标在解冻时一次性参与判定，最短间隔从解冻时刻重新起算；⑪判定结束后无论是否调整都把窗口清零；⑫历史只保留最近 max_history 条实际变更，零号档的初始原因记 INITIAL。

硬约束：指标累加与档位变更必须串行，同一指标序列重放得到同一档位，决策不得依赖当前时间或随机数，十六路并发上报的计数不得丢；窗口只对应当前副本与当前队伍，换场景或换队后旧指标不得带入新窗口；快照保存档位、窗口、历史、各档触发原因、冻结状态与计数，结构必须含 version、tier、window、history、reasons、frozen、stats 七个键，结构不符报 DIRECTOR_SNAPSHOT_INVALID 且不污染现有数据，恢复后仍冻结的副本不可调档。stats 返回 observations、evaluations、adjustments、freezes。

验收：`python3 -m pytest -q tests` 的 15 条用例全过，测试不得修改、跳过或按固定输入写死；并发上报与快照恢复自行验证，调整记录要能导出复盘；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: dynamic_difficulty_director
- typeName: DifficultyDirector
