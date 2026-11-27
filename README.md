# batch51-py-game-b-11

## 题面

大世界关卡接入新的延迟管线后，移动端战斗场景的显存峰值一路顶到上限，帧率从四十五掉到二十二。抓帧记录显示：一张只在阴影通道使用的深度图和一张只在后期合成使用的中间颜色，生命周期根本不相交，却各自占了一段显存；而真正同时在用的 G-Buffer 与 HDR 目标被反复换进换出，堆里全是碎片。请修 `gsb/batch51-py-game-b-11` 的 `transient_attachment_aliaser.py`，类 `TransientAttachmentAliaser`：为一帧内的通道与瞬时附件算出堆内偏移表，让生命周期不重叠的附件共享同一段显存，重叠的必须错开。未知句柄一律抛 `KeyError`，非法尺寸、非法状态与超限抛 `ValueError`。

公开接口：`TransientAttachmentAliaser(*, heap_bytes=1048576, alignment=256, max_passes=64, max_attachments=32)`；`declare_pass(index, name)`；`declare_attachment(name, *, width, height, bytes_per_pixel=4, kind="color", external=False, backbuffer=False)`；`declare_use(name, pass_index, mode="write")`；`plan()`；`offset_of(name)`；`heap_usage()`；`attachment_state(name)`；`uses_of(name)`；`barriers()`；`snapshot()`；`restore(state)`；`stats()`。

要修的行为：①通道索引须为非负整数且不重复，重名或负索引抛 `ValueError`，通道数量受 `max_passes` 硬顶。②附件名非空且不重复，宽高与每像素字节数为正整数，`kind` 只接受 color 与 depth，附件数量受 `max_attachments` 硬顶，违规一律 `ValueError`。③使用声明只能引用已声明的通道与附件，未知句柄抛 `KeyError`，`mode` 只接受 read、write、read_write，其余抛 `ValueError`。④生命周期取该附件全部使用通道的首末闭区间，只有一个通道时区间就是该通道本身。⑤`plan()` 返回附件名到偏移的映射，按首个使用通道升序、同通道按名称升序贪心落位，与声明顺序无关，重复调用逐项一致。⑥生命周期严格不相交的附件复用最低可用偏移，有交集的必须落在互不重叠的区间。⑦单个附件占用量按行跨度（宽度乘每像素字节数补齐到四字节）乘高度，再补齐到堆对齐粒度，偏移与用量都必须是该粒度的整数倍。⑧`external` 与 `backbuffer` 附件不参与别名，按名称升序紧接在别名区之后分配。⑨深度附件与颜色附件共用一段显存时，两者生命周期之间至少要留出一个空通道并记录全屏障，紧贴通道边界的复用直接拒绝。⑩同一通道内既读又写的附件，其生命周期要延伸到下一个通道，不能只看首末通道就判定可以复用。⑪堆总量是硬上限，任何一次规划超出 `heap_bytes` 必须整体拒绝且不留下部分偏移，`offset_of` 继续抛 `KeyError`；快照含 version、passes、attachments、uses、plan、stats 六项且为深拷贝，结构不符抛 `ValueError` 且现有状态不变。

硬约束：规划与查询会被多个渲染线程同时调用，八路并发下偏移表与堆用量必须与串行结果逐项相同；快照要能把通道、附件、使用序列与偏移表一起恢复到新实例，恢复后的规划与原实例一致；堆上限是硬门槛，不允许先分配一部分再报错。`stats()` 返回 passes、attachments、uses、plans、rejected。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: transient_attachment_aliaser
- typeName: TransientAttachmentAliaser
