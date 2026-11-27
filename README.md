# batch51-py-game-a-15

## 题面

高光集锦上线后剪辑组天天返工：一波团战被切成三四段，前后两段其实只隔半秒；有玩家的三杀被重复上报的事件抬成五杀，标题直接写错；片段配额满了以后先上报的垃圾片段把关键目标夺取挤掉，同一名玩家还占了好几个名额。范围是 gsb/batch51-py-game-a-15 的 match_highlight_selector.py，类 HighlightSelector，负责从对局事件流里挑选多杀、残血反杀与关键目标夺取，按时间窗合并并输出带起止时刻的片段。

公开接口：HighlightSelector(*, per_player_cap=2, per_match_cap=12, streak_window=5.0)；open_match(match_id, *, end_at, merge_gap=2.5) 返回 MatchInfo；ingest(match_id, event_id, *, kind, player, at, priority=0, duration=1.0) 返回布尔；merge_window(match_id, *, gap=None) 返回 Clip 元组；select(match_id, *, limit=5)；clips_of(match_id)；export(match_id)；quota_of(player)；remove_event(match_id, event_id)；snapshot、restore、stats。拒绝抛 HighlightError(code, detail)。

要修的行为：①对局号为空或重复注册报 HL_INVALID_REQUEST 与 HL_MATCH_EXISTS，结束时刻必须大于零且作为片段时长的硬边界；②事件类型只接受 multi_kill、low_hp_clash、objective，事件号与玩家号不能为空，发生时刻不能为负或越过对局结束，时长必须为正，优先级取 0 到 100，违规报 HL_INVALID_EVENT，未知对局报 HL_UNKNOWN_MATCH；③事件按事件号幂等，重复投递返回假且不得改变已有片段的优先级与连杀等级；④合并前按发生时刻与事件号稳定排序，相邻事件间隔不超过合并阈值时并入同一片段，片段的事件列表按该顺序排列；⑤两个高光窗口间隔小于合并阈值时合并，合并后的时长可以超过单事件上限但不得跨过对局结束时刻；⑥片段优先级取窗口内事件的最高值，参与者去重后按玩家号升序，片段号按起始时刻从 c0 递增；⑦同一玩家在同一秒内的多次击杀只计一次多杀等级，事件重复上报不得抬高等级；⑧select 先按优先级降序、再按起始时刻升序取前 limit 条，limit 为零返回空元组，负数报 HL_INVALID_REQUEST；⑨每名玩家与每局片段数设上限，超限按优先级与时间淘汰，只移除最低优先级的片段，同等优先级保留发生时间较早的，不得依赖插入顺序；⑩export 返回 match_id、count 与按起始时刻排列的片段字典，每个片段带 clip_id、start、end、priority、players、events 六个键；⑪quota_of 统计一名玩家在所有对局里现存的片段数，未出现过的玩家返回零；⑫remove_event 删除事件后该对局的片段必须整体重建，不能继续返回含已删除事件的旧片段。

硬约束：并发导入同一对局的事件时片段集合必须完整，不能丢事件也不能产生重复片段；快照整体替换，结构必须包含 version、matches、events、clips、counters、stats 六个键，结构不符报 HL_SNAPSHOT_INVALID 且不影响在跑的导入；每局与每名玩家的片段数都是硬顶，重复合并同一对局的结果必须逐字段一致，不能受插入顺序影响。stats 返回 matches、events、duplicates、clips、merges、evicted。

验收：`python3 -m pytest -q tests` 的 15 条用例全过，测试不得修改、跳过或按固定输入写死；并发与恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: match_highlight_selector
- typeName: HighlightSelector
