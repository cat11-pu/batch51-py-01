# batch51-py-game-c-15

## 题面

字幕外包这批片子被打回三次：一段四十分钟的访谈，前十分钟字幕准，后半小时字幕比人声慢出两三秒，越往后越偏；有一段主讲人连说五个词，语音段只标了一个起点，导出的字幕五个词挤在同一毫秒，播放器只能显示最后一个；两人抢话的段落被强行排成一前一后，字幕和口型对不上。范围是 gsb/batch51-py-game-c-15 的 transcript_timing_aligner.py，类 TranscriptTimingAligner，负责把词序列对齐到语音段、校正累计漂移并导出字幕条。

公开接口：TranscriptTimingAligner(*, max_words=5000, max_segments=2000, cue_max_chars=42, cue_max_duration_ms=6000, cue_gap_ms=700)；load_transcript(words)；load_segments(segments)；align()；word_timings()；segments()；shift(offset_ms)；merge_speakers(*, max_gap_ms=0)；drift_correct(anchors)；export_cues(*, max_chars=None, max_duration_ms=None)；stats()；snapshot()；restore(state)；reset()。时间一律整数毫秒，拒绝一律抛 TranscriptError(code, detail)。

要修的行为：

① words 必须是非空、不含空白的字符串列表，个数超过 max_words 抛 TRANSCRIPT_LIMIT，非法词抛 TRANSCRIPT_INVALID_WORD。

② segments 是（start_ms, end_ms, speaker, word_count）四元组：start 小于 end、非负、speaker 非空、word_count 为非负整数，否则抛 TRANSCRIPT_INVALID_SEGMENT；起点递减抛 TRANSCRIPT_UNSORTED_SEGMENTS；个数超过 max_segments 抛 TRANSCRIPT_LIMIT。

③ 未加载就 align 抛 TRANSCRIPT_NOT_LOADED；词表或语音段为空抛 TRANSCRIPT_EMPTY；各段 word_count 之和与词数不等抛 TRANSCRIPT_MISMATCH。

④ align 按段顺序取词，返回对齐词数；词级时间戳落在所属段起止之间，整体单调不减且不重叠；只有一个词的段由该词占满整段；align 可重复执行，同样的输入必须得到同样的时间戳，计数只增不改结果。

⑤ 语音段数量少于词数时按词的字符数比例分摊该段时长，不能给所有词同一时间点；每个词至少占一毫秒并在段尾收口。

⑥ 词间空隙按语音段边界分配，词不得跨进静音区；段与段之间的空白不分配给任何词。

⑦ shift 整体平移段与词的时间，结果为负抛 TRANSCRIPT_NEGATIVE_TIME 且一个字段都不改，返回平移的词数。

⑧ merge_speakers 只合并同一说话人且间隙不超过 max_gap_ms 的相邻段，跨越静音的段不得合并，词数一并累加；返回合并次数。

⑨ 全局漂移校正只作用于段边界，段内词位置按比例缩放，避免词被推出所在段；锚点下标越界或新起点递减抛 TRANSCRIPT_INVALID_ANCHOR。

⑩ 说话人重叠的区段不强行串行化，时间戳可重叠，但同一说话人内部必须单调。

⑪ export_cues 按说话人、字数上限、时长上限与 cue_gap_ms 切条，返回 Cue(index, start_ms, end_ms, text, speaker)，每条起止取首词起点与末词终点；未对齐时抛 TRANSCRIPT_NOT_ALIGNED；stats 固定给出 words、segments、cues、aligned、duration_ms，duration_ms 是全部语音段的最晚终点减最早起点。

⑫ snapshot 含 version、words、segments、timings、cues、counters、limits 且为深拷贝，restore 能恢复到新实例继续导出，非法结构抛 TRANSCRIPT_SNAPSHOT_INVALID 且现有状态一字不动；reset 清空全部状态。

硬约束：长音频按段分段对齐后要按全局漂移统一修正，段内结果不得被子段顺序影响；同一实例的 align 与 export_cues 会被预览线程和导出线程同时调用，词表、段表与时间戳不得读到半写状态；词数与段数是硬上限。

验收：python3 -m pytest -q tests 15 条必须全过，不得改测试、不得跳过、不得按固定输入写死；并发与重启场景自行验证；只做本地实现，不引入第三方依赖。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: transcript_timing_aligner
- typeName: TranscriptTimingAligner
