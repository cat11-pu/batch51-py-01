# batch51-py-safety-d-02

## 题面

合规检查前一周，运维发现同一批站点目录的标签时不时被改成上一版的类型：策略包重装后，/var/www 下的路径有的落到发行版默认，有的还留着本地改动；一个别名目录被单独规则命中后，整个等效类里其它路径的标签也跟着漂移；还有人手工删掉一条默认规则，那个路径直接变成未标注，审计报告里出现一片空洞。更麻烦的是标注计划生成之后规则又被改过，执行时把新旧两版规则混着用，同一个目录在两台机器上贴出了不同标签。范围是 gsb/batch51-py-safety-d-02 的 selinux_context_labeler.py，类 SelinuxContextLabeler，负责规则装载、上下文解析、标注计划与执行。

公开接口：SelinuxContextLabeler(*, max_rules=512, max_plan_entries=4096, default_mls="s0")；load_rules(rules, *, source="distro")；remove_rule(pattern, *, source="distro")；rules(*, source=None)；add_equivalence(primary, *members)；equivalence_of(path)；observe_path(path, *, file_type="-d", exists=True, current=None)；resolve_context(path, *, file_type=None)；plan_relabel(paths)；apply(entries)；verify(paths)；watermark()；snapshot、restore、stats。拒绝统一抛 LabelError(code, detail)。

要修的行为与边界：①规则必须是可编译正则与合法上下文（user:role:type 三段，或再带 level），file_type 合法，非法整条拒绝并计 rejected，不影响已装规则；每次 load_rules 成功返回都把规则版本加一；②解析先看 local 区块，local 无匹配再落 distro，同一区块内按正则字面前缀长度取最特异，长度相同取声明靠后的一条，rules 按声明顺序返回；③等效类成员共用主路径标签，计划对每个类只出一条重标注，其余成员动作为 alias、detail 写主路径，同一类不得重复标注；④当前标签已等于解析结果时动作为 unchanged、不重复标注，unchanged 与 planned 分别累计；verify 返回期望、实际与 ok，watermark 返回经 apply 写过的去重路径数；⑤路径被显式标为不存在时计划保留 pending、detail 为 missing，apply 跳过且不报错，没有规则命中时动作为 unlabeled、context 为空串、detail 为 no matching rule；⑥计划条目数超 max_plan_entries 抛 LABEL_PLAN_TOO_LARGE（detail 带 limit），规则总数超 max_rules 抛 LABEL_CAPACITY_EXCEEDED（detail 带 limit）并保留原规则块；⑦apply 的每条计划都带规则版本，任一版本不符抛 LABEL_STALE_PLAN，整份计划一个标签都不写；⑧本地规则只有三段时沿用同一路径发行版匹配到的 level，没有发行版匹配时用 default_mls，本地显式 level 与发行版不一致按放宽抛 LABEL_MLS_WIDENED（detail 带 path）；⑨remove_rule 按 pattern 删除并返回是否存在，删除后解析按剩余规则重新裁决，source 非法抛 LABEL_INVALID_REQUEST；⑩路径同时命中 /var(/.*)? 与 /var/www(/.*)? 时按更具体的那条，不能按文件系统遍历顺序；⑪等效类中的路径被单独规则覆盖时单独规则优先，但等价类其余路径仍按等效标签；⑫本地修改删除某条默认规则后，该路径必须回落到上一条匹配而不是变成未标注。

硬约束：并发 apply 用 RLock 串行，同一路径只能写一次且水位不丢；快照含 version、distro、local、equivalences、paths、watermark、stats 七项，与现场深拷贝隔离，非法结构抛 LABEL_SNAPSHOT_INVALID 且不改现场；stats 返回 loaded、rejected、resolved、planned、applied、unchanged、restores 七项计数。

验收：python3 -m pytest -q tests 的 15 条全部通过，不得修改测试、跳过或按固定输入写死；并发与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: selinux_context_labeler
- typeName: SelinuxContextLabeler
