# batch51-py-safety-b-15

## 题面

联邦房间里两个 homeserver 对同一个房间的状态给出不同答案：一边认为话题是安全公告，另一边还是旧公告；被标记软失败的事件过一会儿又出现在当前状态里；房间升级到新版本之后，补历史的旧版本事件把新房间状态改了回去，客户端看到的成员权限来回跳。值班同学对比两边的 DAG，发现同一批事件在不同节点上解析出了不同的赢家，软失败标记也没有传递下去。问题定位在 gsb/batch51-py-safety-b-15 的 matrix_state_resolver.py，类型 MatrixStateResolver，维护事件 DAG、当前状态与鉴权链，拒绝统一抛 FederationError(code, detail)。

对外接口保持：ingest_event(event)->IngestResult；resolve_state()->tuple；authorize(event)->AuthResult；soft_fail(event_id, reason)->bool；backfill(events)->int；upgrade_room(new_version)->str；room_version、event_depth、pending_events、dag_heads、power_levels、snapshot/restore、stats。

需要修好的行为：①事件必须按 prev_events 接入，前驱或 auth_events 缺失时进入待定而不是直接接受，前驱到齐后按 event_id 顺序补入；②重复 event_id 返回 duplicate，不得重复计数或重复入 DAG；③同一 (type, state_key) 的候选按 depth 升序、event_id 字典序取最大，结果与到达顺序无关，resolve_state 按 (type, state_key) 升序返回；④depth 更低的状态事件晚到不得覆盖当前状态；⑤鉴权按发送者 power level 判定，状态事件用 events[type] 或 state_default，消息用 events_default，不足时 reason 为 insufficient_power；⑥未加入房间的发送者 reason 为 not_joined，仅邀请房间的加入必须先有邀请，否则 membership_denied；⑦power_levels 的发送者不得授出高于自身的等级，否则整条拒绝；⑧被拒绝的事件保留在 DAG，但不得进入当前状态，也不得影响后续鉴权；⑨soft_fail 把事件移出当前状态并保留在 DAG，只依赖软失败事件的后继同样软失败，不得因为自身鉴权通过就抬回当前状态；⑩两个分支的 power_levels 冲突时按 depth 与 event_id 稳定排序，不能依赖到达顺序，重放后结果必须一致；⑪房间升级到新版本后，旧版本事件仍可 backfill，但不得改变新房间的当前状态；⑫单房间 DAG 深度与待定事件数是硬上限，超限分别报 FEDERATION_DAG_LIMIT 与 FEDERATION_PENDING_LIMIT。

硬约束：ingest_event 与 backfill 会被多个联邦连接并发调用，同一房间的 DAG、当前状态与鉴权缓存必须用 RLock 串行，任何时刻读到的状态要么是接入前的完整快照、要么是接入后的完整快照；快照要带走 DAG 头、当前状态、待定事件、软失败集合与房间版本，restore 遇到版本不符抛 FEDERATION_SNAPSHOT_INVALID 且不破坏现场。统计接口 stats 按 accepted、pending、rejected、duplicates、soft_failed、backfilled、upgraded 如实计数。

验收：python3 -m pytest -q tests 的 15 条用例必须全过，测试不得修改、不得跳过、不得按固定输入写死；确定性重放、软失败后继与升级后补历史请自行构造场景验证，并留下可复核的执行记录；只做本地实现，交付源码、测试记录与改动说明，不改上游仓库。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: matrix_state_resolver
- typeName: MatrixStateResolver
