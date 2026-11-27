# batch51-py-game-c-07

## 题面

直播转码网关换上新版 AV1 切片器后，播放端偶发黑一帧；某路 4K 流切了一次分辨率，后面整段画面冻结，日志里一条错误都没有；采集端把一帧的瓦片组拆成两个网络分片送达，解析器收下前半截后把后半截当垃圾丢掉，整条流报废。运维复盘发现时间单元边界一直按硬编码字节偏移切，序列头只在启动时读一次，帧头引用的参考帧落在前一个单元就找不到。

请在 `gsb/batch51-py-game-c-07` 的 `obu_temporal_parser.py` 里补完 `ObuTemporalParser`：增量接收字节流，按对象头切分，组装时间单元并校验序列头、帧头与瓦片组的顺序和长度。拒绝一律抛 `ObuError(code, detail)`。

码流格式按下面口径实现：一个对象是 1 字节头加 leb128 长度再加载荷，头高 4 位为类型，最低位表示带扩展；类型 1 序列头、2 时间分隔符、3 帧头、4 瓦片组、5 元数据、6 填充，0 与 7 以上非法；序列头载荷 4 字节：profile、位深、宽度高低字节；时间分隔符载荷必须为空；帧头载荷 6 字节，依次为帧号两字节、帧类型一字节（0 关键帧、1 前向参考帧）、参考帧号两字节（0xFFFF 表示无参考）、显示标志一字节；瓦片组载荷至少 2 字节帧号加瓦片数据；元数据与填充载荷任意；leb128 最多 4 字节。

公开接口：`ObuTemporalParser(*, max_buffer_bytes=65536, max_pending_frames=32)`；`push(data)`；`buffered_bytes()`；`next_temporal_unit()`；`flush()`；`sequence_header()`；`frame_header(frame_id)`；`pending_frames()`；`frame_count()`；`stats()`；`reset()`；`snapshot()`；`restore(state)`。`SequenceHeader` 记 `profile`、`bit_depth`、`width`；`FrameHeader` 记 `frame_id`、`frame_type`、`ref_frame_id`、`show_frame`；`TemporalUnit` 记 `index`、`frames`、`tiles`、`size_bytes`。

要修的行为：

① `push` 只追加字节并返回当前缓冲字节数；缓冲总量超过 `max_buffer_bytes` 抛 `OBU_BUFFER_LIMIT`，这一批一个字节都不追加。

② 头不完整或载荷还没到齐时 `next_temporal_unit` 返回 `None` 并原样保留字节，不许把半个对象当错误，也不许丢字节。

③ 类型为 0 或 7 以上抛 `OBU_INVALID_TYPE`；leb128 超过 4 字节，或声明载荷超过 `max_buffer_bytes`，抛 `OBU_LENGTH_OVERFLOW`；这两类错误都清空缓冲并计入 `rejected`，之后可继续喂新数据。

④ 时间分隔符结束前一个时间单元：分隔符之前已解析的对象组成一个单元，流首分隔符不产生空单元，单元从零编号，`frames` 与 `tiles` 按到达顺序记帧号。

⑤ 流尾没有后续分隔符时用 `flush` 定稿当前单元并返回定稿个数，再取一次即可拿到该单元；没有内容返回 0。

⑥ 首个帧头之前必须有序列头，否则抛 `OBU_SEQUENCE_MISSING`。

⑦ 前向参考帧的参考号必须是同一或更早单元里已接受的帧头，未知参考抛 `OBU_UNKNOWN_FRAME`，被拒帧头不进 `frame_header`。

⑧ 瓦片组必须与本单元内的帧头配对：帧号从未出现过抛 `OBU_UNKNOWN_FRAME`，帧头已在更早单元交出抛 `OBU_ORDER`。

⑨ 已接受但还没有瓦片组的帧头计入待组装，数量超过 `max_pending_frames` 抛 `OBU_PENDING_LIMIT`。

⑩ 长度字段为零的对象在填充、元数据这些类型上是合法的，不能当空载荷丢弃，也不能报截断，解析器照常前进并计入跳过数。

⑪ 时间单元边界由时间分隔符决定；分隔符缺失时按帧头里的显示标志与帧类型推断，关键帧且显示标志为 1 的帧头开启新单元，不能把两段不相干的帧硬拼进一个单元。

⑫ 序列头中途变化要重置参考帧状态并报 `OBU_SEQUENCE_CHANGED`。

硬约束：`push` 与 `next_temporal_unit` 会被喂线程和读线程同时调用，缓冲区、帧表与计数不得互相踩；一次失败的解析要么把缓冲整段清空、要么完全不动。`snapshot` 要含 `version`、`buffer`、`sequence`、`frames`、`pending`、`stats` 六项且为深拷贝，`restore` 能恢复到新实例并从断点继续解析，非法结构抛 `OBU_SNAPSHOT_INVALID` 且状态一字不动。缓冲字节数与待组装帧数是硬上限，`reset` 清空缓冲、序列头、帧表、待组装与计数。`stats()` 固定返回 `bytes_in`、`obu_seen`、`units`、`frames`、`tiles`、`skipped`、`rejected`。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；分片到达与快照续解析自行验证；只做本地实现，只用标准库。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: obu_temporal_parser
- typeName: ObuTemporalParser
