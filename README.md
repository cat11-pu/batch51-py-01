# batch51-py-game-c-13

## 题面

点播平台这个月被 CDN 账单和首帧投诉同时打中：一批新上传的片子要等整段下载完才能起播，用户拖进度条时黑屏十几秒；运维把索引挪到文件头之后播放器能起播了，可拖到中段就花屏，日志显示样本偏移全部错了位；更麻烦的是同一批文件被流水线重跑了一次，头部出现两份索引，播放器直接拒绝打开。范围是 gsb/batch51-py-game-c-13 的 faststart_relocator.py，类 FaststartRelocator，负责把索引原子搬到文件头并重写所有样本块的绝对偏移。

公开接口：FaststartRelocator(*, max_boxes=128, alignment=8)；scan(blob)；boxes()；plan(*, force_co64=False)；offset_table()；apply()；verify(blob)；stats()；snapshot()；restore(state)；reset()。只处理顶层 32 位长度的原子：[4 字节长度][4 字节类型][载荷]，拒绝一律抛 FaststartError(code, detail)。

要修的行为：

① scan 按顺序解析顶层原子，返回 BoxInfo(type, offset, size)；长度小于 8、越过文件尾或类型为空抛 FASTSTART_BAD_BOX；顶层原子数超过 max_boxes 抛 FASTSTART_BOX_LIMIT。

② ftyp、moov、mdat 缺任何一个抛 FASTSTART_MISSING_BOX；索引里的样本偏移必须落在 mdat 载荷范围内，越界抛 FASTSTART_BAD_OFFSET。

③ plan 在未 scan 时抛 FASTSTART_STATE；输入已是索引在前时返回 moved 为假、delta 为零的计划，不做任何搬动。

④ 需要搬动时把 moov 紧插到 ftyp 之后，ftyp 与 moov 之间原本的原子整体后移新 moov 的大小，delta 等于新的 moov 大小（含对齐填充与六十四位切换带来的增长）。

⑤ 每个样本的绝对偏移按实际位移量修正，必须仍指向原数据且长度不变；offset_table 按 OffsetEntry(index, old_offset, new_offset) 升序给出。

⑥ 原子头部预留空间不足时要整体后移，位移量按实际移动距离计算，不能对所有偏移套一个固定增量。

⑦ 编辑列表与分片索引里也可能含绝对偏移，遗漏会让定位点错位，这类偏移要跟样本偏移一样按位移量修正。

⑧ 计划与执行分开：plan 只读，重复调用结果一致；apply 幂等，同一实例连续两次返回同一份字节，不得插入重复索引；同一文件重复执行搬迁要识别已优化状态并直接返回原字节，不能再次插入索引。

⑨ 索引里的块偏移超过三十二位范围，或 force_co64 为真时改写成 co64，条目改为八字节；转换后 moov 变大，位移量按新尺寸重算，每块多四字节。

⑩ 未知原子原样保留，字节不改、顺序不丢；结果按 alignment 对齐，必要时在 moov 后补 free 原子。

⑪ verify 独立复核结果：索引在 mdat 之前、每个样本偏移落在 mdat 载荷内、块数一致，返回 ok、moov_before_mdat、chunks、offset_width、size；不合规抛 FASTSTART_VERIFY_FAILED。stats 固定给出 boxes、chunks、moov_bytes、optimized。

⑫ snapshot 含 version、blob、boxes、chunks、plan、limits 且为深拷贝，restore 能恢复到新实例继续执行计划，非法结构抛 FASTSTART_SNAPSHOT_INVALID 且现有状态一字不动；reset 回到未扫描状态。

硬约束：apply 要么产出完整的新文件、要么一个字节都不返回，不允许写出半份结构；计划只读、执行幂等；顶层原子数与块数是硬上限。

验收：python3 -m pytest -q tests 15 条必须全过，不得改测试、不得跳过、不得按固定输入写死；并发与重启场景自行验证；只做本地实现，不引入第三方依赖。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: faststart_relocator
- typeName: FaststartRelocator
