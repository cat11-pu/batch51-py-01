# batch51-py-game-a-02

## 题面

仓库合并上线后道具部门连着报了三类账：一把剑同时挂在两个角色名下，客服只能手动挑一个封号；玩家把十组材料拆成小堆之后来源全丢了，追赃追不回去；还有人把销毁的项链找回来，结果历史持有人被改成了客服号，玩家拿着截图来投诉。运营还发现堆叠合并后来源分段被直接抹掉，事后没法判断哪几组材料进了同一把武器。范围是 gsb/batch51-py-game-a-02 的 item_provenance_ledger.py，类 ItemProvenanceLedger，按道具实例号记录来源事件、持有人变更链与隔离区。

公开接口：ItemProvenanceLedger(*, max_chain=64, max_quarantine=32)；ingest_event(kind, instance, *, actor, qty=1, event_key=None, at=None) 返回全局事件号；transfer(instance, from_owner, to_owner, *, event_key=None, at=None)；owner_of / qty_of / holdings_of；chain_of(instance)；segments_of(instance)；split(instance, qty, *, new_instance, at=None)；merge(target, sources, *, at=None)；destroy / recover；scan_duplicates(observed=None) 与 quarantine()；snapshot / restore / stats。拒绝统一抛 LedgerError(code, detail)，来源事件只接受 drop、craft、trade、mail 四类。

要修的行为：①事件号全局单调递增，其它 kind、空实例号、空持有者、qty 小于等于 0 一律报 LEDGER_INVALID_EVENT；②同一 event_key 重复投递按幂等丢弃并返回原事件号，不得重复写链；③同一本账内同一实例号二次投递报 LEDGER_DUPLICATE_INSTANCE，原记录与数量都不动；④transfer 的 from_owner 必须等于当前持有人，否则报 LEDGER_STALE_HOLDER，持有人与链都不动；⑤chain_of 按事件号升序返回全链，实例未知一律报 LEDGER_NO_SUCH_INSTANCE；⑥split 生成的子实例继承父实例拆分前已有的事件作为前缀，父实例追加拆出事件、子实例追加拆入事件，两段数量之和守恒；⑦split 的数量必须大于零且小于当前数量，新实例号不得已存在，分别报 LEDGER_QTY_INVALID 与 LEDGER_DUPLICATE_INSTANCE；⑧merge 把来源数量并入目标、来源转入归档，目标链尾记合并事件，来源链仍可查但 owner_of 报 LEDGER_NO_SUCH_INSTANCE；⑨对账时同一实例号在两个分片各自合法生成，scan_duplicates 以先落库事件的全局序号判定归属，迟到一侧整体转入隔离而不是就地覆盖，单本账内的重复投递仍按第③条处理；⑩道具销毁后由客服找回，找回事件接在原链尾部并标记恢复来源，不得重写历史持有人；⑪堆叠拆分按数量分摊到原有来源分段，分摊后为零数量的分段必须裁掉；⑫单实例链长与隔离区条数各自受配置上限约束，超限报 LEDGER_CHAIN_LIMIT 与 LEDGER_QUARANTINE_FULL。

硬约束：同一实例的事件写入与链查询必须串行，查询只能看到完整链，写了一半的链不得被读到，同一实例的并发转移只能有一个胜出；destroy 与 merge 归档只追加事件不删链，归档实例仍可按实例号复盘；快照深拷贝整份账本，结构必须含 version、instances、chains、events、counters、stats 六个键，restore 遇到结构不符报 LEDGER_SNAPSHOT_INVALID 且现有数据一条不动。stats 返回 instances、live、events、duplicates、transfers、splits、merges、quarantined。

验收：`python3 -m pytest -q tests` 的 15 条用例全过，测试不得修改、跳过或按固定输入写死；并发转移、链查询与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: item_provenance_ledger
- typeName: ItemProvenanceLedger
