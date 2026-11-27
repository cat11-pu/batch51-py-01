# batch51-py-safety-d-07

## 题面

办公区换了批蓝牙键鼠之后，桌面组一个下午收到四张单子：同一副耳机在会议室的适配器和前台的适配器上各配了一次，删掉其中一台机器上的绑定，另一台也跟着掉线；有台笔记本明明要求输入六位配对码，却直接静默配对成功，安全审计判定为降级；还有同事在配对弹窗上点了取消，界面一直停在“正在配对”，过了一分多钟再点也没反应；适配器断电重启后，界面上的绑定还在，但连接一建立就报密钥错误。范围是 gsb/batch51-py-safety-d-07 的 bluetooth_pairing_guard.py，类 BluetoothPairingGuard，负责配对方式决策、配对窗口与长期绑定。

公开接口：register_adapter(adapter_id, *, powered=True, io_caps=None, max_bonds=8)；set_powered(adapter_id, powered)；pair_request(adapter_id, address, *, transport="le", peer_caps=None, requires_mitm=False, now=None)；confirm_passkey(session_id, value, *, now=None)；complete_pairing(session_id, *, confirm=True, now=None)；remove_bond(adapter_id, address, *, transport=None)；bond_for(adapter_id, address, *, transport="le")；bonds(adapter_id)；pending_sessions()；snapshot()；restore(state)；stats()。拒绝时统一抛 PairingError(code, detail)，传输只有 classic 与 le 两种。

要修的故障与边界：①配对方式按双方 IO 能力矩阵选：两边都能显示且能输入取 numeric_comparison，本端能显示对端能输入取 passkey_display，本端能输入对端能显示取 passkey_entry，除此之外才落到 just_works；②just_works 只有在双方都没有显示也没有输入时才成立，否则报 PAIRING_IO_INSUFFICIENT；③要求 MITM 的请求不得落在 just_works 上，报 PAIRING_MITM_REQUIRED；④配对会话编号从 s1 起全局递增，六位数字配对码由地址派生，窗口默认 60 秒，deadline 为发起时刻加窗口；⑤同一适配器同一地址同一传输已有未完成会话时报 PAIRING_SESSION_EXISTS，不同传输可以并存；⑥配对码错误按次累计，detail 给 {"attempts": n, "remaining": m}，达到上限报 PAIRING_ATTEMPTS_EXHAUSTED 并进入冷却，冷却期内再发起报 PAIRING_COOLDOWN，detail 给 {"retry_after": s}；⑦非 just_works 的方式必须确认过配对码才能完成，否则 PAIRING_NOT_CONFIRMED；⑧超过 deadline 的会话在确认或完成时报 PAIRING_SESSION_EXPIRED 并释放，超时或失败都不占用会话编号；⑨绑定按适配器隔离，同一个地址重新配对必须覆盖旧绑定并换新密钥，绑定数量不增加；⑩单适配器绑定数封顶，超限报 PAIRING_BOND_LIMIT，但覆盖已有地址不受限制；⑪remove_bond 不传传输时清掉该地址全部绑定，返回删除条数，重复删除返回 0；⑫适配器未上电或未登记分别报 PAIRING_ADAPTER_OFFLINE 与 PAIRING_ADAPTER_UNKNOWN，被拒请求计入 rejected。

硬约束：同一 peer 的并发配对与确认必须串行，尝试次数、冷却截止与绑定表不得互相覆盖；重启后绑定仍在，但链路密钥必须重新协商，不得把旧会话的密钥直接复用；快照保存适配器、未完成会话、绑定与冷却表，非法快照整份拒绝且不污染现有状态；bonds 按地址与传输升序返回，pending_sessions 按编号升序返回。stats 至少返回 adapters、sessions、confirmed、bonds、removed、cooldowns、rejected 七个计数。

验收：`python3 -m pytest -q tests` 的 15 条用例全过，测试不得修改、跳过或按固定输入写死；并发配对与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: bluetooth_pairing_guard
- typeName: BluetoothPairingGuard
