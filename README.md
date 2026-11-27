# batch51-py-safety-d-05

## 题面

会议室终端上线后连着出问题：两个会话同时抢同一块触摸板，先抓到的会话在切到锁屏后被后台录屏进程继续吃按键；一把键盘拔插之后 event 号从 event7 变成 event11，旧句柄还在收事件，另一个会话却抢先绑上了新节点；还有一次抓取进程崩溃，设备一直显示被占，直到整机重启才恢复；值班手里只有一张按设备名打印的表，既看不出是哪个会话，也无法判断重插后的节点算不算同一台设备。现场查下来，抓取记录只认设备名不认会话，能力校验和授权各写各的，租约更是根本没有，同一块键盘的两个接口还能被拆开分给两个人。范围是 gsb/batch51-py-safety-d-05 的 input_device_grab_guard.py，类 InputDeviceGrabGuard，负责输入设备的登记、独占抓取、热插拔重绑与会话释放。

公开接口：InputDeviceGrabGuard(*, max_devices=64, max_grabs=32, max_grabs_per_session=4, lease_ttl=30)；register_device(physical_path, *, event_nodes, capabilities, inode, keyboard=False)；unplug(device_id)；rebind(device_id, *, event_node, inode, session, now=0)；grab(device_id, *, session, pid, purpose, now=0, authorized=False)；ungrab(grab_id, *, session=None)；release_session(session)；heartbeat(grab_id, *, now=0)；expire(*, now=0)；set_session_locked(session, locked)；delivery_target(grab_id)；device_state(device_id)；session_state(session)；enumerate()；grabs(*, session=None)；snapshot、restore、stats。拒绝统一抛 InputGrabError(code, detail)。

要修的行为与边界：①register_device 校验物理路径以 / 开头、event 节点非空、capabilities 非空、inode 为正，设备数超 max_devices 抛 INPUT_CAPACITY（detail 带 limit），enumerate 按登记顺序返回；②grab 先校验设备存在与在位，未知设备抛 INPUT_DEVICE_UNKNOWN（detail 带 device），已拔出抛 INPUT_DEVICE_ABSENT；③用途只取 keyboard-capture、pointer-capture、hotkey-capture，键盘抓取要求 keyboard 设备且带 EV_KEY，指针抓取要求 EV_REL 或 EV_ABS，热键抓取要求 EV_KEY，缺能力抛 INPUT_CAPABILITY_MISSING（detail 带 purpose），session 为空或用途非法抛 INPUT_INVALID_REQUEST；④键盘类设备抓取必须 authorized 为真，否则抛 INPUT_AUTH_REQUIRED（detail 带 device）；⑤同一设备同一时刻只允许一个会话，被占时抛 INPUT_DEVICE_BUSY（detail 带持有会话），同会话同用途重复抓取合并回原句柄并刷新租约、计 merged；⑥单会话抓取数与总抓取数设上限，分别抛 INPUT_SESSION_LIMIT（detail 带 session 与 limit）与 INPUT_CAPACITY（detail 带 limit）；⑦ungrab 只能由持有会话发起，否则抛 INPUT_NOT_OWNER（detail 带请求会话），未知句柄返回 False，release_session 释放该会话全部抓取并返回条数，真正释放过才计 session_releases；⑧unplug 把设备标为不在位并让句柄失效，rebind 按同一物理路径更新 event 节点与 inode、恢复在位，并给原持有者续租；⑨heartbeat 刷新句柄到期时间并返回新值，expire 回收 lease_expires 小于等于 now 的句柄并返回条数；⑩同一物理键盘的多个 event 接口要作为一个逻辑设备整体授权，不能只抓其中一个；⑪设备拔出再插入后 inode 变化但物理路径相同，重绑只允许原持有者，其他会话不得抢占；⑫会话切到锁屏后抓取保持，但按键不得投递给后台会话。

硬约束：并发 grab 按设备串行，归属判定、合并与各项计数不得读到中间态；快照含 version、devices、grabs、sessions、counters 五项，与现场深拷贝隔离，非法结构抛 INPUT_SNAPSHOT_INVALID 且不改现场；device_state 给出 present 与 holder，session_state 给出 locked 与 grabs，stats 返回 registered、grabbed、merged、ungrabbed、expired、session_releases 六项计数。

验收：python3 -m pytest -q tests 的 15 条全部通过，不得修改测试、跳过或按固定输入写死；并发与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: input_device_grab_guard
- typeName: InputDeviceGrabGuard
