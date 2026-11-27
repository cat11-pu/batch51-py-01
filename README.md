# batch51-py-game-a-03

## 题面

放量开关切到三成之后客服发现第一批玩家今天能进活动明天进不去，同一台手机上换个账号结果就反了；有人把父开关关了子开关还在放人，白名单里的大客户被一起关在门外；配置换代那一瞬读到的版本号和实际命中的规则对不上，客服拿着版本号去查审计又查不到对应记录。活动运营和客服手里各有一份命中名单，对不上的时候没人能说清是哪一版配置算出来的结果。范围是 gsb/batch51-py-game-a-03 的 liveops_flag_cohort_router.py，类 FlagCohortRouter，做稳定分桶、定向与依赖求值。

公开接口：FlagCohortRouter(*, max_flags=128, max_audit=256, salt="cohort-v1")；define_flag(name, *, enabled=False, rollout_bps=0, regions=(), platforms=(), versions=(), whitelist=(), depends_on=()) 返回配置版本号；set_rollout(name, bps)；set_dependencies(name, flags)；remove_flag(name)；evaluate(account, flag, *, region=None, platform=None, version=None) 返回 Decision(flag, enabled, reason, source, version)；bulk_evaluate(account, flags, ...)；audit_of(flag=None)；spec_of(name)；config_version()；snapshot / restore / stats。拒绝统一抛 FlagError(code, detail)。

要修的行为：①名字去空白后为空、重名、超过 max_flags 分别报 FLAG_INVALID_NAME、FLAG_ALREADY_DEFINED、FLAG_CAPACITY_EXCEEDED；②每次定义、改放量、改依赖、下线都让配置版本号加一，求值结果必须带当时的版本号；③总开关关闭时直接判关，reason 记 FLAG_DISABLED，source 记 switch；④白名单命中优先于定向与分桶，reason 记 WHITELIST；⑤地域、平台、版本都是集合匹配，任一不在集合内即 TARGET_MISS，三个参数都没传而开关配了定向同样算不命中；⑥百分比从一成调到三成时原先命中的账号必须继续命中，不能重新洗牌；⑦分桶结果只与账号和 salt 有关，与放量比例无关；⑧依赖的父开关被总开关强制关闭时，子开关即使自身命中也要返回关闭并标注被父级压制；⑨bulk_evaluate 按依赖拓扑序返回，父在前子在后，一次调用里每个开关统计一次求值；⑩依赖不存在或成环在写入前拒绝，报 FLAG_UNKNOWN_DEPENDENCY 与 FLAG_DEPENDENCY_CYCLE 且版本号不动；⑪未知开关在任何入口都报 FLAG_UNKNOWN，放量值不在 0 到 10000 报 FLAG_INVALID_ROLLOUT；⑫审计只保留最近 max_audit 条，按序号升序，每条带 seq、flag、kind、version、detail，改放量的 detail 形如 {"from": 旧值, "to": 新值}。

硬约束：配置版本号与审计在并发变更下必须严格递增且不丢条，八路同时改放量要拿到八个互不相同的版本；快照换代瞬间并发求值只能读到旧版本或新版本之一，返回结果里的版本号必须与实际命中规则一致，不许半新半旧；求值只读配置不改配置，一次判定里父开关与子开关必须来自同一版本；快照整体替换，结构必须含 version、flags、audit、counters、stats 五个键，结构不符报 FLAG_SNAPSHOT_INVALID 且不影响在跑求值，恢复后审计条数与版本号跟快照一致。stats 返回 flags、evaluations、audit、version。

验收：`python3 -m pytest -q tests` 的 15 条用例全过，测试不得修改、跳过或按固定输入写死；并发放量与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: liveops_flag_cohort_router
- typeName: FlagCohortRouter
