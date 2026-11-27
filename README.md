# batch51-py-game-c-04

## 题面

排练室的键盘手换了一台控制器之后，同一段钢琴副歌开始有音符按下去就不松，像被无限延长；踏板松开后仍然响，只能整通道复位。另一头是鼓机：同一音高在极短时间内被连打几下，抬起时只放掉了一部分，剩下的就一直挂着，监听耳返里持续嗡。还有一次是控制器热插拔，拔掉之后那台设备发出的音全部卡住，其他键盘的正常演奏也被一起掐掉，现场直接停了十几秒。

范围收到 MIDI 事件调度这一层，代码在 gsb/batch51-py-game-c-04 的 midi_note_scheduler.py，类 MidiNoteScheduler，维护每通道每音高的按下状态、延音踏板与待释放音符，按时间戳稳定排序调度事件，并处理卡音清理。

公开接口：MidiNoteScheduler(*, max_stack=4, stuck_timeout_ms=5000, max_pending=64)；note_on(*, channel, pitch, velocity, at_ms, device)；note_off(*, channel, pitch, at_ms, device)；pedal(*, channel, down, at_ms)；all_notes_off(*, at_ms, channel=None, reason="all_notes_off")；tick(*, now_ms)；device_disconnect(*, device, at_ms)；schedule(*, events)；active_notes(*, channel=None)；pedal_down(*, channel)；snapshot()；restore(state)；stats()。拒绝时抛 MidiError(code, detail)。NoteRef 记录 note_id、channel、pitch、velocity、at_ms、device、state。

故障与边界：

一、channel 必须在 0 到 15，pitch 在 0 到 127，velocity 在 1 到 127，at_ms 为非负整数，device 去掉首尾空白后非空，否则 MIDI_INVALID。

二、note_on 返回 NoteRef，note_id 从 1 开始单调递增，state 为 down；同通道同音高的活动音符数达到 max_stack 时报 MIDI_STACK_LIMIT，换一个音高不受影响。

三、note_off 按通道、音高、设备三项找活动音符，找不到报 MIDI_NOT_ACTIVE；踏板没按下时该音符直接释放（返回的 state 为 released），踏板按下时转为 sustained 并把 sustained 计数加一。

四、pedal 的 down 必须是布尔值，否则 MIDI_INVALID；与当前状态相同报 MIDI_PEDAL_STATE；抬起时把该通道所有 sustained 音符释放。

五、all_notes_off 释放指定通道（不传 channel 则全部通道）的全部活动音符，返回释放条数，并把 reason 写进 stats 的 last_reason（初始为 None）。

六、tick 把 at_ms 加 stuck_timeout_ms 不大于 now_ms 的活动音符按卡音释放，返回释放的音符元组，state 为 stuck，并计入 stuck_cleaned。

七、device_disconnect 释放该设备来源的全部活动音符并返回条数，计入 disconnect_released；设备名不存在时返回 0。

八、schedule 接收事件序列，每个事件必须含整数且非负的 at_ms，空序列、缺字段或类型不对报 MIDI_INVALID；返回按 at_ms 升序、同一时间戳按本次调用内到达顺序排列的新字典元组，每个字典带 index、at_ms、serial 三个键，index 是原序列下标，serial 是本实例内的到达序号（从 0 开始，跨多次调用递增）；原序列不得被改动。

九、active_notes 返回按 note_id 升序的活动音符元组（down 与 sustained 都算活动），带 channel 时只返回该通道。

十、pedal_down 返回该通道踏板当前是否按下，未操作过的通道为 False。

十一、snapshot 返回 version、notes、pedals、next_id、stats 五个键，notes 每项含 note_id、channel、pitch、velocity、at_ms、device、state；快照是深拷贝，改快照不影响实例。

十二、restore 对缺键、类型不对、状态取值不认识或 version 不认识的快照抛 MIDI_SNAPSHOT_INVALID，原状态一字不动；合法快照恢复后活动音符、踏板状态、下一个 note_id 与计数器都要一致。

十三、stats 固定返回 note_on、note_off、sustained、pedal_down、pedal_up、stuck_cleaned、disconnect_released、scheduled、pending、last_reason 十个键；pending 与 last_reason 是当前值，其余都是累计值。

硬约束：同一音高连续按下多次时按后到先出配对，一次 note_off 只结束最近的一次按下，更早的那次仍留在按下态；踏板抬起只释放挂起的音符，物理上仍按住的音符不得释放；设备断开只释放该设备来源的音符，其他设备同音高的音符不受影响。同一通道的事件可能被多路输入并发调用，note_id 分配与状态迁移必须原子，pending 不得超过 max_pending，超出报 MIDI_CAPACITY。快照要带走活动音符、踏板、待释放标记与计数器。

验收：python3 -m pytest -q tests 的 15 条必须全过；不得修改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现，只用标准库。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: midi_note_scheduler
- typeName: MidiNoteScheduler
