# batch51-py-safety-c-42

## 题面

蓝队这季度做检测覆盖复盘，报表上写着七成以上的技战术已经覆盖，真被红队打穿时才发现数字是虚的：同一条规则被三个人各登记了一遍，置信度直接相加顶到了满分；一个月前废弃的技术编号还挂在映射表里，报表仍按满分计入；子技术上有一条规则命中，父技术就被算成已覆盖，缺口清单因此少了一整页。安全委员会要求把归属关系重新算清楚，并且能解释每一个百分点的来源。

范围是 gsb/batch51-py-safety-c-42，文件名 technique_coverage_mapper.py，主类 TechniqueCoverageMapper，记录类型 Rule、Technique、Mapping、TechniqueCoverage、CoverageGap，异常统一抛 MappingError(code, detail)。技术目录由构造参数 techniques 传入，每项含名称、权重与可选父技术。

对外接口：TechniqueCoverageMapper(*, techniques=None, exempt=(), max_rules=500, max_mappings=2000, max_techniques=200)；register_rule(rule_id, *, name, source)；map_technique(rule_id, technique_id, *, confidence, source)；retire_technique(technique_id)；retire_rule(rule_id)；coverage_report()；gaps()；rules_for(technique_id)；mappings_for(rule_id)；snapshot()；restore(state)；stats()。

需要落实的故障与边界：①规则编号与名称必须是非空字符串，来源不能为空，重复编号抛 MAPPING_RULE_DUPLICATE，规则总数超上限抛 MAPPING_CAPACITY_EXCEEDED；②映射必须指向目录里的技术，未知编号拒绝并抛 MAPPING_TECHNIQUE_UNKNOWN，不能静默丢弃；③置信度只接受大于 0 且不超过 1 的数值，越界或非数值抛 MAPPING_CONFIDENCE_INVALID，来源为空抛 MAPPING_INVALID_REQUEST；④同一规则对同一技术在相同置信度下重复登记按幂等处理，不新增映射也不抬计数；置信度不同时取最高值而不是累加；⑤单技术覆盖取有效映射里的最高置信度，不按条数累加；总覆盖率按技术权重加权，不能只数规则条数，结果保留四位小数；⑥技术被标记废弃后，引用它的规则仍保留在映射表里但不再计入覆盖，依赖该技术的父技术要一起重算；⑦子技术覆盖不等于父技术覆盖，报表按编号分别展开每个技术，不能把子技术命中直接算成父技术已覆盖；⑧被豁免的技术单独列出，既不计入缺口也不进加权分母；⑨gaps 只列未覆盖与部分覆盖的技术，按权重降序、同权重按编号升序，理由分别为 no_coverage 与 partial_coverage；⑩规则下线后其覆盖立即回收，已下线规则不能再建立新映射，抛 MAPPING_RULE_RETIRED；⑪coverage_report 的键为 weighted_coverage、techniques、exempt、retired、counts，技术明细按编号升序，counts 含 rules、mappings、techniques 三项，stats 返回 rules、mappings、techniques、retired_rules、retired_techniques 五项；⑫映射总数、技术总数与规则数都设硬顶，超限抛 MAPPING_CAPACITY_EXCEEDED；快照深拷贝 version、rules、techniques、mappings、stats 五个键，restore 遇非法结构抛 MAPPING_SNAPSHOT_INVALID 且现场不变。

两条硬约束：并发更新用可重入锁保护，多线程同时登记映射与规则时计数与覆盖不得丢更新；快照恢复到新实例后，规则、技术、映射、废弃标记与各项计数必须与恢复前一致，不能丢也不能重复累计。

验收：python3 -m pytest -q tests 的 15 条必须全过；不得修改测试、不得跳过、不得按固定输入写死；并发与重启场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: technique_coverage_mapper
- typeName: TechniqueCoverageMapper
