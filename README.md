# batch51-py-game-a-12

## 题面

关卡编辑器上线后，自制地图的投诉没断过：有作者在审核通过之后、发布之前又改了一遍内容，线上直接跑起了没审过的版本；有地图下架之后换个入口还能玩到旧数据；同一张图连点提交，后台堆出好几张审核单，客服分不清哪张有效。范围是 gsb/batch51-py-game-a-12 的 ugc_publish_gate.py，类 UgcPublishGate，负责草稿、送审、审核、发布与下架的全过程，并把线上可玩版本与草稿彻底分开。

公开接口：UgcPublishGate(*, max_levels=500, max_audit=500)；fingerprint_of(content) 返回内容指纹；save_draft(level_id, player, content, *, now=None) 返回 DraftInfo；submit_review(level_id, player, *, now=None) 返回 ReviewTicket；review(ticket_id, reviewer, *, approved, note="", now=None) 返回 ReviewTicket；publish(ticket_id, player, *, now=None) 返回 PublishedVersion；takedown(level_id, actor, *, reason="", now=None)；version_of(level_id) 返回 LevelStatus；content_of(level_id)；audit_of(level_id)；snapshot、restore、stats。拒绝抛 UgcError(code, detail)。

要修的行为：①内容指纹是规范序列化后的 SHA-256 十六进制串，字段顺序不同但内容相同必须得到同一个指纹；②每存一次草稿版本号加一，首次为一，编辑已发布关卡只生成新草稿，线上版本号与线上内容都不动，送审前必须已有草稿；③未知关卡报 UGC_UNKNOWN_LEVEL，空关卡号、空作者、内容不是可序列化结构报 UGC_INVALID_REQUEST；④同一关卡同时只允许一个待审单，已有待审单且内容不同时再提交报 UGC_REVIEW_PENDING，detail 带原审核单号；⑤审核只接受待审单，重复审核或审核已关闭的单报 UGC_TICKET_CLOSED，审核人不能为空，审核拒绝只影响草稿，作者可以继续改草稿并重新送审；⑥发布必须持有已通过的审核单，否则报 UGC_NOT_APPROVED，未知单号报 UGC_UNKNOWN_TICKET；⑦发布把当前草稿固化成线上只读副本，之后的草稿编辑不得改动线上内容；⑧下架只对线上版本生效，重复下架或对从未发布的关卡下架报 UGC_NOT_PUBLISHED；⑨已发布关卡下架后再上架必须重新走审核，不能直接复用原审核结论；⑩审核通过后发布前内容被改动时，以指纹不一致拒绝发布并要求重新送审；⑪同一玩家重复提交完全相同的草稿只生成一个审核单，指纹相同但版本号不同也算重复；⑫每关卡的审计只保留最近 max_audit 条，按序号升序，每条带 seq、level、kind、version、detail，content_of 只在状态为已发布时返回线上内容，其余状态一律报 UGC_NOT_PUBLISHED，返回的是深拷贝。

硬约束：同一关卡的存档、送审、发布并发进行时版本号必须严格递增且不重复，线上副本不能被半成品草稿污染；快照整体替换，结构必须包含 version、levels、tickets、audit、counters、stats 六个键，结构不符报 UGC_SNAPSHOT_INVALID 且不影响正在服务的线上版本；关卡总数受 max_levels 硬顶，超出报 UGC_CAPACITY_EXCEEDED，编辑已有草稿不受此限。stats 返回 levels、drafts、submitted、approved、rejected、published、taken_down、pending。

验收：`python3 -m pytest -q tests` 的 15 条用例全过，测试不得修改、跳过或按固定输入写死；并发与恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: ugc_publish_gate
- typeName: UgcPublishGate
