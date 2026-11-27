# batch51-py-safety-c-13

## 题面

设备节点权限最近反复出问题：同一块 USB 设备被两条规则同时命中，实际生效的权限取决于规则文件里谁写在后面，机器之间还不一致；运维删掉一条旧规则后，本该由另一条规则接管的节点权限没有重新算，仍然沿用删除前的值。值班同学把两台机器的规则文件逐行比对过，内容完全一致，合成出来的权限却不同，只能怀疑遍历顺序在作怪。热插拔时更乱，已经存在的节点被重复应用规则，权限来回翻，另有一批带空格与引号的属性值在写回规则文件后解析成两条，权限直接丢失。请修 gsb/batch51-py-safety-c-13 下的 udev_rule_synthesizer.py，类 UdevRuleSynthesizer，负责规则合成、特异度决胜、热插拔补挂与落盘对账。

对外接口：UdevRuleSynthesizer(*, max_rules=64)；add_rule(match, *, mode="0660", owner="root", group="root", priority=50, rule_id=None)；rule(rule_id)；rules()；remove_rule(rule_id)；effective(device, attrs)；synthesize(devices)；reconcile(devices, actual)；apply_hotplug(devices, *, existing=())；render_rule(rule_id)；parse_rule(text, *, rule_id="rule-parsed")；snapshot()；restore(state)；stats()。拒绝时抛 UdevError(code, detail)。规则包含 rule_id、match、mode、owner、group、priority 六个字段，缺省规则号从 rule-0001 起递增；节点权限包含 device、mode、owner、group、rule_id 五个字段；stats 返回 added、removed、synthesized、hotplugged、skipped、refused 六个计数；snapshot 返回 version、rules、next_id、synth、stats 五个键。rule 对未知规则号返回 None。

要修的点：①匹配条件按键升序去重，规则号缺省递增生成，重复规则号报 UDEV_RULE_EXISTS；②空匹配、非法权限位（必须是四位八进制且以 0 开头）、空属主、带空白的组名、非字符串属性值、空规则号报 UDEV_INVALID_RULE；③应用顺序为优先级升序、匹配条件数量升序、规则号升序，最后一条命中者生效，结果不依赖插入顺序或字典遍历；④同优先级下更具体的规则压过更宽的规则，条件完全相同再比规则号；⑤未被任何规则命中的设备使用 0600 root root 的默认权限，规则号为空串；⑥synthesize 按设备名升序输出，多次调用结果一致；⑦remove_rule 删除不存在的规则返回 False 且不产生副作用，删除被遮蔽的规则后原本被遮蔽的规则必须重新参与合成；⑧reconcile 按设备名升序返回权限与合成结果不一致或缺失的设备；⑨apply_hotplug 只处理不在 existing 里的新设备，已存在设备计数为跳过，重复调用不重复应用；⑩规则号上限是硬顶，超限报 UDEV_RULE_LIMIT；⑪属性值含空格与引号时 render_rule 必须正确转义，parse_rule 回读后与原条件等价，render_rule 对未登记规则报 UDEV_RULE_UNKNOWN；⑫快照深拷贝，restore 校验规则字段、匹配结构、合成缓存与统计，非法报 UDEV_SNAPSHOT_INVALID 且原状态不变。

硬约束：并发增删规则必须持锁，合成结果在任何并发下都必须是同一份确定顺序，统计不得丢更新；合成结果落盘后重启要与现有节点实际权限对账，快照恢复后规则、合成缓存与计数必须全部还原，不能出现规则在而缓存空的情况；规则条数是硬上限。所有对外查询都要返回同一份排序视图，调用方两次拿到的顺序必须完全可复现。

验收：python3 -m pytest -q tests 15 条必须全过；不得改测试、跳过或用固定输入写死；并发与重启场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: udev_rule_synthesizer
- typeName: UdevRuleSynthesizer
