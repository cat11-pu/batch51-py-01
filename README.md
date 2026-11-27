# batch51-py-game-c-06

## 题面

节拍工具上线两周，三个外包作曲组同时投诉：同一段 120 BPM 的鼓循环，第一拍落在 0.42 秒，剪辑师按它对齐后整条配乐晚了半拍；有人交来一段前奏两小节无鼓的钢琴，网格一片空白；还有人在桥段手动打了四个点，网格出现了，可自动段与手动段交界处的拍点间距从 500 毫秒缩到 320 毫秒，导出后听得出抽动。变速曲目更糟：前半段 100 BPM、后半段 128 BPM，工具把整条拉成平均速度，到第三分钟差了整整一拍。

请在 `gsb/batch51-py-game-c-06` 的 `beat_grid_analyzer.py` 里补完 `BeatGridAnalyzer`：接收逐帧包络做增量分析，检出起音、估计主拍间隔，构建带相位的网格，并允许人工打点覆盖局部网格。所有拒绝都抛 `BeatError(code, detail)`，非法参数与容量越界不许静默吞掉。

公开接口：`BeatGridAnalyzer(*, frame_hz=100.0, onset_threshold=0.5, rise_ratio=2.0, max_frames=200000, max_onsets=8192)`；`feed(frames, *, frame_hz=None)`；`onsets()`；`estimate_tempo(*, min_bpm=40.0, max_bpm=240.0)`；`beat_times()`；`beat_at(index)`；`snap(timestamp, *, tolerance=0.03)`；`tap_correct(start, end, *, bpm, anchor=None)`；`grid_segments()`；`tempo_at(timestamp)`；`clear_taps()`；`snapshot()`；`restore(state)`；`stats()`。`BeatPoint` 记 `index`、`time`、`bpm`；`TapSegment` 记 `start`、`end`、`bpm`、`anchor`；`GridSegment` 记 `start`、`end`、`bpm`、`source`，`source` 只取 `auto` 与 `manual`。

要修的行为：

① 每一帧是一个能量值：本帧能量不低于 `onset_threshold`，且不低于上一帧能量乘 `rise_ratio` 时判为起音，首帧的上一帧能量按零算；起音时刻取帧序号除以 `frame_hz`。

② `feed` 收空序列抛 `BEAT_EMPTY_BUFFER`；传入的 `frame_hz` 与构造值不一致抛 `BEAT_FRAME_RATE`；负能量、非数值或 NaN 抛 `BEAT_INVALID`。

③ 帧数与候选起音数都是硬顶，越顶抛 `BEAT_CAPACITY`，且这次 `feed` 一帧都不生效。

④ 主拍速度取全部相邻起音间隔的中位数（偶数个取中间两个的平均），bpm 等于 60 除以中位间隔并保留两位小数；起音不足两个抛 `BEAT_EMPTY_GRID`；算出的 bpm 落在 `min_bpm` 到 `max_bpm` 之外抛 `BEAT_TEMPO_RANGE`；区间非法（非正、上界不大于下界）抛 `BEAT_INVALID`。

⑤ 拍点从零时刻起按相位铺满已分析窗口，窗口时长等于帧数除以 `frame_hz`，含末尾时刻；相位由第一个可信起音回推，拍点时间严格递增，同一时刻只出现一次。

⑥ `beat_at` 下标必须落在网格内，负数与越界抛 `BEAT_INDEX`；`snap` 在容差内返回最近拍点，等距取较早那个，超出返回 `None`，负时间戳抛 `BEAT_INVALID`。

⑦ 前奏没有明显鼓点时也必须给出网格，相位从第一个可信起音反推，不允许把起点钉死在零，更不许因为开头安静返回空网格。

⑧ 人工打点与自动网格重叠时以人工为准：新打点段盖住的重叠部分，旧打点段被裁短或整段删除，`grid_segments` 在同一时刻只能有一个来源；交界处拍点间距要平滑过渡，不许突变。

⑨ 变速曲目按段记录速度：相邻起音间隔相对段首间隔变化超过 5% 处切出新段，段速度取段内间隔中位数；段边界落在两拍之间时按就近吸附到拍点，不能把整段拉平成平均速度。

⑩ `tempo_at` 返回覆盖该时刻的段速度，负时间戳抛 `BEAT_INVALID`；`clear_taps` 清空全部人工段并返回被删条数。

⑪ 打点参数：`start` 非负且小于 `end`，`bpm` 落在 20 到 300 之间，`anchor` 缺省取 `start` 且必须落在 `start` 到 `end` 之内，违规抛 `BEAT_INVALID`；被拒的打点不落记录。

⑫ `snapshot` 返回 `version`、`frame_hz`、`onset_threshold`、`rise_ratio`、`frames`、`onsets`、`taps`、`stats` 八项且为深拷贝；`restore` 对缺键、类型不对或 `version` 不认识的快照抛 `BEAT_SNAPSHOT_INVALID`，现有状态一字不动。

硬约束：`feed` 会被分析线程与界面线程同时调用，帧数、起音与计数必须自洽，八路并发喂入同一批帧后总帧数等于各次之和；一次 `feed` 要么全生效要么全不生效，越顶与非法帧都不许留下半批数据。快照要能把帧数、起音、人工段与计数一起恢复到新实例，恢复后 `beat_times` 与 `grid_segments` 与原实例逐项一致，继续 `feed` 也接着快照进度走。帧数与起音数封顶，长音频的内存不随喂入时长无界增长。`stats()` 固定返回 `frames`、`onsets`、`taps`、`beats`、`segments`、`rejected`。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发与快照恢复自行验证；只做本地实现，只用标准库。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: beat_grid_analyzer
- typeName: BeatGridAnalyzer
