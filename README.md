# batch51-py-game-b-07

## 题面

QA 反馈上周的 GPU 崩溃复现不出来：现场只留了一张截图，等开发人员赶到机器已经热重启，之前几十帧的顶点与绘制数据全丢了。后来上了帧捕获，新的问题又来了——玩家昵称和公会聊天框被原样带进了导出包，法务直接叫停；开了捕获之后渲染线程偶尔卡到 200 毫秒，帧率掉到个位数；连续点了几次捕获按钮，环形缓冲里的预录帧被清空，一次都没导出来。请修 `gsb/batch51-py-game-b-07` 的 `frame_capture_scheduler.py`，类 `FrameCaptureScheduler` 维护最近若干帧的轻量快照，在触发时把触发前一段与触发后一段一起打包，拒绝时统一抛 `CaptureError(code, detail)`。

公开接口：`FrameCaptureScheduler(*, ring_size=64, pre_frames=30, post_frames=10, max_active=2, min_interval_frames=0, max_bytes=8000000)`；`arm(*, pre_frames=None, post_frames=None, ring_size=None)`；`on_frame(frame_no, *, payload_size=1024, now=None)`；`trigger(reason, *, frame_no=None, now=None)`；`finalize(capture_id, *, now=None)`；`mask_region(*, x, y, width, height)`；`capture_of(capture_id)`；`captures()`；`active_captures()`；`ring_frames()`；`snapshot()`；`restore(state)`；`stats()`。

要修的行为：①`on_frame` 的帧号必须严格递增，重复或回退报 `CAPTURE_FRAME_ORDER`，帧号非整数或载荷为负报 `CAPTURE_INVALID_ARGUMENT`；环形缓冲只保留最近 `ring_size` 帧，淘汰计数单独累加。②`trigger` 未给帧号时取最近一帧，给出的帧号必须仍在环形缓冲里，捕获窗口是 `[触发帧-pre_frames, 触发帧+post_frames]`，预录段从缓冲回填，触发帧本身也算在内。③同一帧只能属于一次捕获，已被别的捕获占用的帧在本窗口内跳过，因此新捕获的起始帧可能晚于窗口起点。④触发帧已被占用时报 `CAPTURE_FRAME_CLAIMED`，不得改动已有捕获与缓冲。⑤后段帧收齐之前捕获处于 recording，收齐后转为 ready，只有 ready 才能 `finalize`，否则报 `CAPTURE_NOT_READY`；重复 `finalize` 报 `CAPTURE_ALREADY_FINALIZED`。⑥导出记录的 `bytes_total` 是窗口内各帧载荷之和，`frame_count` 与实际纳入的帧数一致。⑦`mask_region` 只登记导出时要套用的隐私区域，导出记录的 `masked_regions` 按登记顺序给出、`masks_applied` 是套用次数；宽或高非正报 `CAPTURE_INVALID_ARGUMENT`。⑧遮罩只作用于导出产物，环形缓冲里的原始帧保持不变，导出前必须按当时登记的完整遮罩重新套一遍。⑨触发时按窗口内已有帧的实际载荷加上后段帧数乘以最近一帧载荷估算总字节，超过 `max_bytes` 报 `CAPTURE_QUOTA_EXCEEDED`，此时不得登记捕获，也不得丢弃预录帧。⑩同时未完成的捕获数达到 `max_active` 再触发按同一错误码拒绝，拒绝不影响进行中的捕获，也不清空预录帧。⑪`min_interval_frames` 大于零时，间隔小于该值的连续触发合并成一次捕获，窗口取并集，只产生一个捕获号，合并次数单独计数。⑫快照含 `version`、`config`、`ring`、`captures`、`claimed`、`masks`、`counters` 七项且为深拷贝，结构不符报 `CAPTURE_SNAPSHOT_INVALID` 且现有状态不变。

硬约束：同一帧在多路同时触发时只能被一个捕获占用，八路并发进来也只有一路成功；捕获登记与环形缓冲推进必须串行，期间不得阻塞渲染线程，登记失败不能留下半成品捕获；快照要能把进行中的捕获（含已回填帧与遮罩）恢复到新实例继续接收后段帧并正常导出。

`stats()` 返回 `frames`、`captures`、`finalized`、`rejected`、`dropped_frames`、`merged`、`masks`。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发触发与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: frame_capture_scheduler
- typeName: FrameCaptureScheduler
