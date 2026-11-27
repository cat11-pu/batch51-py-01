# batch51-py-game-a-07

## 题面

跨服首杀公告连着出了三起错判：A 服先推倒首领却在半小时后才被记为第二，B 服拿着比首杀晚两分钟的日志顶了上去，C 服同一场战斗被上传了两遍，榜单上多出一条并列首杀。跨服机器时钟本来就不同步，旧逻辑只比时间戳，证据摘要和申报顺序全没用上，事后追查作弊时也说不清哪一笔被谁取代过。请修 `gsb/batch51-py-game-a-07` 的 `world_first_race_ledger.py`，类 `WorldFirstLedger` 按首领、难度与赛季维护唯一首杀记录，参数非法或状态不符抛 `RaceError(code, detail)`。

公开接口：`WorldFirstLedger(*, skew_tolerance=30)`；`claim(boss_id, difficulty, season, *, server, killed_at, digest, claim_seq)`；`verify(claim_id, *, digest, ok, reason="")`；`invalidate(claim_id, reason)`；`first_of(boss_id, difficulty, season)`；`history(boss_id, difficulty, season)`；`claim_of(claim_id)`；`snapshot()`；`restore(state)`；`stats()`。

需要落地的行为：①difficulty 只接受 normal、heroic、mythic，season 与 killed_at 必须是非布尔整数，claim_seq 为不小于 0 的整数，其余标识不得为空串，否则抛 WORLD_INVALID_REQUEST；②同一组首领、难度、赛季、分服、证据摘要的重复申报返回首笔记录，status 为 duplicate、reason 为 WORLD_DUPLICATE_EVIDENCE，claims 不加而 duplicates 加一；③空榜申报直接成为首杀，status 为 accepted、reason 为 WORLD_FIRST_CLAIM，promotions 加一，evidence_ok 初始为假；④击杀时刻早于当前首杀且超出 skew_tolerance 的申报改判为首杀，原记录转 superseded 并在 history 里保留，status 记 accepted、reason 记 WORLD_DISPLACED，supersessions 加一；⑤击杀时刻晚于当前首杀且超出 skew_tolerance 的申报只入历史，status 为 recorded、reason 为 WORLD_NOT_FASTER，首杀不动；⑥两者击杀时刻之差不超过 skew_tolerance 时以 claim_seq 小者为准，序号相同再比分服名，最后比 claim_id，偏差之内击杀时刻更早但申报序号更大仍维持原判，序号更小则改判并把原记录置为被取代；⑦history 按 (killed_at, claim_seq, server, claim_id) 升序返回全部申报，含已撤销与被取代的记录，查不到时返回空元组；⑧verify 用入参摘要与记录比对，不一致抛 WORLD_EVIDENCE_MISMATCH 且不改任何状态，一致且 ok 为真时把 evidence_ok 置真并返回 accepted，ok 为假时按撤销处理；⑨撤销首杀后由仍有效申报里排名最前的一笔接任，一笔不剩时 first_of 返回 None；⑩撤销只改状态，记录永不删除，已撤销的首领可以重新竞争，新申报按空榜处理；⑪未知 claim_id 抛 WORLD_UNKNOWN_CLAIM。

顺延只按排名顺序取第一笔仍未失效的申报，排名靠后的申报不会因为前面有记录失效就越过它提前上位；同一分服对同一首领的两次击杀只认第一次有效申报，第二次只进历史不参与首杀竞争。

硬约束：跨服申报会被多路网关并发写入，同一首领同一难度同一赛季只能存在一个首杀，并发下不得出现两条 first；撤销与申报并发时撤销只作用于明确的 claim_id，不得连带改写别的记录；快照含 version、config、claims、first、stats 五项且为深拷贝，恢复后首杀、历史、证据位与计数完全一致，结构不符抛 WORLD_SNAPSHOT_INVALID 且原状态一字不动；申报时序只由显式入参决定，不得依赖字典遍历顺序或进程内随机。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发申报与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: world_first_race_ledger
- typeName: WorldFirstLedger
