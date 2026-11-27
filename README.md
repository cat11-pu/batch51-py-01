# batch51-py-safety-d-06

## 题面

视频会议上线后的第一个工作日，客服组连着报了三起摄像头占用：上午的例会开到一半，另一个窗口点开取流一直转圈，界面上没有任何提示；下午录屏工具在后台被谁打开过也无从查起，任务栏上的使用提示一直亮着，直到注销才灭；晚上有人撤掉了摄像头的授权，麦克风那边却同时断了，通话直接掉线。安全组复核后认定，会话授权、独占流和隐私指示三件事各管各的，缺一套统一的状态机。范围是 gsb/batch51-py-safety-d-06 的 media_device_access_guard.py，类 MediaDeviceAccessGuard，维护设备目录、按会话与设备类别的授权、独占与共享流以及使用指示。

公开接口：register_device(device_id, kind, *, present=True)；unplug_device(device_id)；enumerate_devices(*, kind=None)；request_access(session, kind, devices=None, *, now=None)；open_stream(session, device_id, *, mode="read", shared=False, now=None)；close_stream(stream_id)；revoke(session, kind=None, *, now=None)；end_session(session, *, now=None)；indicator_state()；snapshot()；restore(state)；stats()。拒绝时统一抛 MediaAccessError(code, detail)，设备类别只有 CAMERA 与 MICROPHONE 两种。

要修的故障与边界：①设备目录按（类别, 标识）升序返回，注销过又插回的设备要恢复 present；②request_access 不传设备时取该类别全部在场设备，去重后升序写进授权，空会话、空设备表、未知类别一律 MEDIA_INVALID_REQUEST，未登记设备 MEDIA_DEVICE_UNKNOWN；③同一集合重复申请保持原 revision 与 granted_at，扩大集合取并集并把 revision 加一、刷新时间；④开流必须命中该会话对该类别的授权，否则 MEDIA_ACCESS_DENIED；⑤设备撤出后从已有授权里移除，拔掉期间开流报 MEDIA_DEVICE_ABSENT，重新插回要重新申请授权；⑥非共享流对同一设备独占，第二个请求报 MEDIA_DEVICE_BUSY；共享旁路只在只读下成立，带写意图的请求按独占路径处理；⑦mode 只接受 read 与 write，其它值在改动任何状态前报 MEDIA_INVALID_REQUEST；⑧流标识形如 `<device_id>/s<n>`，n 从 1 开始全局递增；⑨只要有活动流，indicator_state 的 active 为真、kinds 为该类别去重升序，全部关闭后两个字段一起清空；⑩close_stream 幂等，首次关闭返回 True，重复关闭或未知标识返回 False；⑪单会话活动流数与全局活动流数各有硬顶，超限报 MEDIA_STREAM_LIMIT，关闭后额度立刻释放；⑫撤销强制关闭该会话该类别下的活动流并返回条数，没有可撤授权时返回 0；⑬end_session 收回全部授权、关闭全部流，返回 {"grants": n, "streams": m}，其它会话不受影响；⑭注销设备把该设备上的活动流置为失效并返回条数。

硬约束：多路页面并发开流、撤权时必须串行，活动流计数与指示状态不得出现负数或残留；快照保存设备、授权、流与计数，恢复后指示状态和流标识必须能继续对上，非法快照整份拒绝且不污染现有状态；授权只按会话与设备类别生效，撤销与设备热插拔都不得让别的会话借到权限。stats 至少返回 grants、streams_opened、streams_closed、streams_forced_closed、sessions_ended 五个计数。

验收：`python3 -m pytest -q tests` 的 15 条用例全过，测试不得修改、跳过或按固定输入写死；并发开流与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: media_device_access_guard
- typeName: MediaDeviceAccessGuard
