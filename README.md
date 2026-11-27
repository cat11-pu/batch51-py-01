# batch51-py-game-c-12

## 题面

直播间的虚拟背景这两周被投诉了三次：穿绿衣的主播一抬手，袖口边缘漏出一圈绿边，肤色在灯下泛灰；背景布被灯打出的褶皱阴影被整块抠掉，人像背后出现一块会抖动的空洞；主播快速转身时，肩线拖出一条半透明的绿影，慢动作回放尤其明显。范围是 gsb/batch51-py-game-c-12 的 chroma_key_matte.py，类 ChromaKeyMatte，负责按键色在色度平面上的距离生成遮罩、抑制主体溢色、做边缘羽化与时域稳定。

公开接口：ChromaKeyMatte(*, width, height, key_color=(0,255,0), similarity=60, softness=40, feather_radius=1, history_limit=4, shadow_luma=48, shadow_keep=0.6, history_weight=0.5, motion_penalty=0.25)；set_key_color(color)；set_thresholds(*, similarity=None, softness=None)；matte(frame)；despill(frame, *, strength=1.0)；feather(alpha, radius=None)；temporal_stabilize(alpha, *, motion=0.0)；history()；stats()；snapshot()；restore(state)；reset()。帧是 height 行、每行 width 个（r, g, b）整数三元组，遮罩同样为二维列表。拒绝一律抛 ChromaKeyError(code, detail)。

要修的行为：

① 色度距离按 max(|Δ(b-g)|, |Δ(r-g)|) 计算，以键色的（b-g, r-g）为原点；距离不大于 similarity 的保留度为零，不小于 similarity+softness 的为一，中间线性过渡。

② 键色三分量必须是 0 到 255 的整数，长度不对或越界抛 CHROMA_KEY_INVALID_COLOR；similarity 与 softness 为非负整数且之和不超过 510，否则抛 CHROMA_KEY_INVALID_THRESHOLD。

③ 遮罩值域限定在 0 到 1；softness 为零时退化为硬抠，不允许出现中间值。

④ 键色区域内的阴影要按亮度区分保留：亮度低于 shadow_luma 的键色像素按差距抬升保留度，最多抬到 shadow_keep，不能与纯键色一起被完全抠掉。

⑤ 边缘羽化用半径内的方框平均，边界按实际窗口大小归一；半径必须是 0 到 64 的整数，否则抛 CHROMA_KEY_INVALID_RADIUS；半径为 0 返回独立副本。

⑥ 羽化不得让主体内部出现透明孔洞：整片不透明的区域羽化后仍为一，边界裁剪不能让角落被压暗。

⑦ 溢色抑制只作用于键色方向的分量：把键色主通道压到另外两个通道的较大值，其余通道原样保留，整体去饱和会让肤色发灰；strength 取 0 到 1，越界抛 CHROMA_KEY_INVALID_STRENGTH。

⑧ 时域稳定按 history_weight 与 motion 衰减历史权重：w = max(0, history_weight - motion * motion_penalty)，结果为 w 倍历史加（1-w）倍当前；没有历史时直接采用当前帧。

⑨ 主体快速移动时要降低历史权重，否则边缘会拖出残影；motion 为非负数。

⑩ 历史帧只保留最近 history_limit 帧，超出后丢最旧的，内存不随片段长度增长；set_key_color 与 reset 清空历史。

⑪ stats 固定给出 frames、keyed、partial、opaque、spill、stabilized 六项累计计数；keyed 是保留度恰为零的像素，partial 是严格介于零与一之间，opaque 是恰为一。

⑫ 帧尺寸或像素结构不合规抛 CHROMA_KEY_BAD_FRAME；snapshot 含 version、width、height、key_color、similarity、softness、feather_radius、history_limit、history、stats 且为深拷贝，restore 能恢复到新实例继续处理，非法结构抛 CHROMA_KEY_SNAPSHOT_INVALID 且现有状态一字不动。

硬约束：matte、despill、feather 会被解码线程并行调用，历史队列与计数必须持锁更新，任何一次调用不得读到半写的历史；历史深度是硬上限；被拒的调用不得改动历史与计数。

验收：python3 -m pytest -q tests 15 条必须全过，不得改测试、不得跳过、不得按固定输入写死；并发与重启场景自行验证；只做本地实现，不引入第三方依赖。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: chroma_key_matte
- typeName: ChromaKeyMatte
