# batch51-py-game-a-19

## 题面

周更维护结束之后排行榜、商店和每日任务在三个服上表现各不相同：北美服在夏令时切换那天提前一小时刷新，玩家还没下线奖励就发了两次；维护窗口跨了两天的服只补了一次重置，第二天的签到直接被吞；还有服换了机房顺带改了时区，排队的重置时间仍旧按旧时区算，一直到第二天才恢复。范围是 gsb/batch51-py-game-a-19 的 daily_reset_scheduler.py，类型 DailyResetScheduler，负责按各服务器本地墙钟计算每日与每周重置时刻、触发任务与商店刷新，并在维护跨日时补算遗漏的重置，运营要求每一次重置都能按周期号追溯到底发没发出。

公开接口：DailyResetScheduler(*, max_servers=64, default_hour=5, default_minute=0)；register_server(server_id, *, timezone, daily_hour=None, daily_minute=None, weekly_weekday=0)；set_timezone(server_id, timezone)；server_of(server_id)；servers()；next_reset(server_id, after_ms, period="daily")；run_due(server_id, now_ms)；catch_up(server_id, *, from_ms, to_ms)；mark_done(server_id, cycle_key)；pending(server_id)；snapshot()、restore(state)、stats()。违规抛 ResetError(code, detail)。

要修的行为：①register_server 返回 ServerSchedule，时区必须是可解析的 IANA 名称，非法报 DR_INVALID_TIMEZONE，服务器号为空报 DR_INVALID_SERVER，重复注册报 DR_SERVER_EXISTS，servers 返回升序元组；②每日小时、分钟与每周星期几都要落在合法区间内，越界报 DR_INVALID_SCHEDULE，服务器数量有硬顶，超出报 DR_SERVER_LIMIT；③每日重置按服务器本地墙钟的时与分计算，返回严格大于给定时刻的下一个重置毫秒，给定时刻正好等于某个重置时刻时要给下一次；④每周重置落在配置的星期几与时刻上，weekly_weekday 用零表示周一，pending 按周期先后返回待办键元组；⑤未知服务器报 DR_UNKNOWN_SERVER，周期只接受 daily 与 weekly，其他取值报 DR_INVALID_PERIOD；⑥周期号用 daily:YYYY-MM-DD 与 weekly:YYYY-Www 表示，run_due 第一次调用只建立基线、不补历史，之后只把窗口内新到的周期放进待办并按先后顺序以元组返回；⑦同一服务器同一周期重复触发返回空元组，不重复入账；⑧mark_done 首次返回真、再次返回假，从未物化过的周期报 DR_UNKNOWN_CYCLE；⑨catch_up 按显式窗口补算并保持先后顺序，不受 run_due 基线影响，窗口倒置报 DR_TIME_REWIND，已经结算过的周期不再重复补算；⑩夏令时切换当天可能出现二十三或二十五小时，重置时刻按当地墙钟算而不是按固定偏移；⑪维护跨越两个重置周期时要补两次并按顺序发放，合并成一次会少发一天的奖励；⑫服务器时区变更后已排队的重置要重新计算，不能沿用旧时区的触发时间。

stats 返回 servers、materialized、done、catchups 四项，materialized 累计新入待办的周期数，done 累计已结算的周期数，catchups 只计成功的补算调用。硬约束：同一服务器同一周期只能成功重置一次，重复触发要返回已处理而不是再发一份奖励；不同服务器可以多线程同时推进，状态写入必须原子，快照与恢复期间不得读到半个服务器；待办周期与已结算周期都设条数上限，超出报错不静默丢弃；时区与重置时刻在注册时确定，运行期不得被外部直接改写。

验收：`python3 -m pytest -q tests` 的 15 条用例全过，测试不得修改、跳过或按固定输入写死；夏令时切换、跨周期补算与时区变更自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: daily_reset_scheduler
- typeName: DailyResetScheduler
- topic: 每日重置调度：服务器时区、跨日补算与重复触发幂等
