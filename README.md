# batch51-py-game-a-18

## 题面

外观商城改版之后客服工单集中爆发：同一件外套在德鲁伊和战士身上显示成两套颜色，玩家在试衣间调好的染色一穿上就错位；收藏里明明有整套赛季外观，一键幻化却只生效了一半，剩下的部位还留着旧样子；更麻烦的是有人把跨甲种的板甲外观收藏下来以后直接幻化到布甲角色身上，模型和属性一起乱掉。范围是 gsb/batch51-py-game-a-18 的 wardrobe_transmog_guard.py，类型 WardrobeTransmogGuard，负责账号级收藏解锁、染色通道的保存与继承、以及套装幻化的原子应用，任何一步失败都不允许留下半套外观。

公开接口：WardrobeTransmogGuard(*, max_collection=2000, dye_channels=("primary","secondary","accent"))；unlock(account_id, appearance_id, *, slot, armor_class, source)；collection(account_id)；appearance_of(appearance_id)；register_character(account_id, character_id, *, armor_class)；dye(account_id, appearance_id, channel, color_id)；dye_channels_of(account_id, appearance_id)；slot_dyes_of(account_id, character_id)；transmog(account_id, character_id, slot, appearance_id)；transmog_of(account_id, character_id)；save_set(account_id, set_id, entries)；preview(account_id, character_id, set_id)；apply_set(account_id, character_id, set_id)；snapshot()、restore(state)、stats()。违规抛 WardrobeError(code, detail)。

要修的行为：①解锁幂等，重复解锁同一件返回 False 且不重复计数，同一外观换部位或换来源重复登记报 WD_APPEARANCE_CONFLICT，appearance_of 返回登记时的 Appearance；②collection 返回按外观号升序的元组，外观号为空或部位不在允许集合内报 WD_INVALID_APPEARANCE；③每个账号的收藏数量是硬顶，超出报 WD_COLLECTION_FULL，其他账号不受影响；④染色按通道记录，色号零表示恢复默认、要把该通道从记录里删掉而不是写零，dye 返回该外观当前的非默认通道表，写默认色不算一次写入，非法通道报 WD_UNKNOWN_CHANNEL，色号越界报 WD_INVALID_COLOR；⑤未解锁的外观不能染色也不能幻化，报 WD_NOT_UNLOCKED，register_character 返回登记后的 Character，角色重复登记报 WD_CHARACTER_EXISTS，甲种为空报 WD_INVALID_CHARACTER；⑥同一部位只能有一件幻化，再次幻化覆盖旧件并返回被替换的外观号，空部位返回空串，transmog_of 返回部位到外观号的映射；⑦外观所属部位与目标部位不一致报 WD_SLOT_MISMATCH，部位名非法报 WD_UNKNOWN_SLOT；⑧套装按账号保存并按版本递增，每次保存都换出新版本，条目里同一部位出现两次报 WD_DUPLICATE_SLOT，空套装报 WD_INVALID_SET；⑨preview 只读，返回版本、部位映射与缺失清单且不改当前幻化，apply_set 要么整体生效要么整体拒绝，成功时按外观号升序返回已应用的外观号元组，缺失项列在 detail 的 missing 里；⑩跨甲种解锁的外观可以先收进账号收藏，但幻化到不匹配的部位必须拦下，收藏与可装备分开判断；⑪套装里包含已过期活动外观时整套拒绝并指出缺失项，不能静默跳过；⑫染色通道在更换外观之后按通道语义继承，不能按色号索引直接搬用导致颜色错位。

stats 返回 unlocks、dyes、transmogs、sets、applies 五项，都是成功操作的累计次数，sets 按保存次数累计、同一套重复保存也分别计数。硬约束：解锁与幻化并发时以账号锁串行，同一账号的收藏数量不得越过硬顶；套装应用期间不得让外界看到一半新一半旧的角色幻化；快照要保留收藏、染色通道、角色幻化与套装版本，恢复后逐字段一致，结构不符报 WD_SNAPSHOT_INVALID 且不得改动在线数据。

验收：`python3 -m pytest -q tests` 的 15 条用例全过，测试不得修改、跳过或按固定输入写死；跨甲种判断、套装缺失与染色继承自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: wardrobe_transmog_guard
- typeName: WardrobeTransmogGuard
- topic: 外观衣橱：账号级收藏解锁、染色通道与套装幻化原子应用
