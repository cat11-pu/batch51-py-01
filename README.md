# batch51-py-game-a-21

## 题面

渠道对账每晚跑完都要人工补单：微信侧同一笔支付回调前后发了三次，账上被记了三笔；支付宝有一单实际到账 99 元、内部订单是 100 元，系统直接按 100 元入账并标记已支付；客服给玩家做了一次部分退款之后，玩家余额还没扣干净就又能继续领月卡；还有一单用户先退款、渠道的补单流水第二天才到，补单把那笔已经冲正的记录又救回来了。范围是 `gsb/batch51-py-game-a-21` 的 `payment_reconcile_ledger.py`，类 `PaymentReconcileLedger` 负责订单、渠道流水与账户余额三方对账，参数非法或状态不符抛 `ReconcileError(code, detail)`。

公开接口：`PaymentReconcileLedger(*, currency="CNY", max_pending_orders=2000)`；`register_order(order_id, account, *, channel, currency, amount, created_at)`；`ingest(txn)`；`match(order_id)`；`reconcile(order_id=None)`；`refund(order_id, amount, *, at)`；`reverse_grant(order_id, *, at)`；`balance_of(account)`；`fees_total(channel)`；`spend(account, amount, *, kind="normal")`；`deliver_scheduled(account, grant_id, amount)`；`pending_orders()`；`snapshot()`；`restore(state)`；`stats()`。

需要落地的行为：①订单注册校验：`order_id` 重复报 `PAYMENT_ORDER_EXISTS`，币种与台账不一致报 `PAYMENT_CURRENCY_MISMATCH`，金额非正报 `PAYMENT_INVALID_AMOUNT`，账号为空报 `PAYMENT_INVALID_REQUEST`，未结算订单数超过 `max_pending_orders` 报 `PAYMENT_QUEUE_FULL`；②`ingest` 按 `txn_id` 幂等，首笔返回 `applied`、重复返回 `duplicate`，`stats` 里 `ingested` 与 `duplicate_txns` 分开累计，重复回调不得让余额变化；③流水与订单币种不符、金额非正、订单不存在分别拒绝，`kind` 只接受 `pay`；④`match` 用订单金额精确比对，返回 `matched`、`unmatched`、`amount_mismatch` 三种状态，差额记在 `delta`，渠道手续费单独记入费用台账、不冲减充值金额；⑤同一订单出现多笔同额回调时只认 `paid_at` 最早的一笔，其余在 `stats` 的 `duplicate_pay` 里累计，绝不重复入账；⑥`reconcile` 按 `(created_at, order_id)` 顺序逐笔处理，已结算订单再对账只出一条 `duplicate` 行且 `credited` 为 0，`pending_orders` 只列未结算订单；⑦部分退款累计不得超过该订单已入账金额，超出整笔拒绝并报 `PAYMENT_REFUND_EXCEEDS`、余额不动，未结算订单退款报 `PAYMENT_NOT_SETTLED`；⑧`reverse_grant` 冲正该订单剩余全部额度，账户余额允许为负并把账号置为挂起，重复冲正报 `PAYMENT_ALREADY_REVERSED`；⑨挂起账号的赠送类消费必须拒绝，月卡定时发放改为暂停而不是直接取消；⑩同一订单先退款、后到补单时按 `paid_at` 时间顺序处理，后到的补单不得把已冲正状态覆盖回已入账；⑪消费校验：金额非正报 `PAYMENT_INVALID_AMOUNT`，`kind` 只接受 `normal`、`gift`，余额不足报 `PAYMENT_INSUFFICIENT`；⑫快照含 `version`、`config`、`orders`、`txns`、`balances`、`settled`、`suspended`、`counters` 八项且为深拷贝，结构不符的恢复报 `PAYMENT_SNAPSHOT_INVALID` 且原状态一字不动。

硬约束：同一 `txn_id` 的并发回调只能入账一次，账本写入串行且原子；对账、退款、冲正与查询并发时，读方只能看到完整的旧状态或新状态，不允许看到入账到一半的订单；进程重启后从快照恢复订单、流水、余额、已结算记录、挂起名单与计数，重复回调仍按幂等处理，未结算订单照常续跑。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发入账与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: payment_reconcile_ledger
- typeName: PaymentReconcileLedger
