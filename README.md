# batch51-py-safety-d-08

## 题面

日志采集单元升级后，运维连着遇到三件怪事：同一份 drop-in 在新旧两台机器上生效结果不一样，一台把 /data/logs 放开了，另一台仍然只读；有次在片段里写了个空值想清空路径白名单，结果白名单里多出一条空路径，服务启动直接失败；还有一次先按 strict 收紧、后来又被上层片段改回 yes，之前给 strict 加的路径例外没有重新核对，服务能写进受保护目录。审计要求把主文件与全部片段的合并过程做成可复算的一步。范围是 gsb/batch51-py-safety-d-08 的 unit_sandbox_merger.py，类 UnitSandboxMerger，负责片段覆盖、列表指令与路径例外的解析。

公开接口：load_unit(text, *, name="unit")；add_dropin(filename, text)；clear_dropins()；merge()；effective(name)；origins(name)；conflicts()；resolve_paths(name)；validate()；snapshot()；restore(state)；stats()。拒绝时统一抛 SandboxUnitError(code, detail)；片段文件名必须是两位数字加短横线的 .conf，按文件名字典序叠加在主文件之后。

要修的故障与边界：①注释行、空行和方括号段落头不参与合并，指令按第一次出现的位置记录来源；②标量指令后赋值覆盖前值，origins 按应用顺序去重返回，跨来源才算冲突，冲突名在结果里标出来；③列表指令累加并按首次出现顺序去重，空值表示重置该列表，不能用空串占位；④RestrictAddressFamilies 取各次赋值的交集而不是并集；⑤布尔型 ProtectHome、PrivateTmp 取最后一次赋值，非法布尔值整份拒绝并报 SANDBOX_INVALID_VALUE；⑥未知指令保留在结果里并给出 unknown directive 告警，不能静默丢弃；⑦路径列表里减号前缀表示允许路径不存在，解析时不能把它算进路径字符；⑧路径统一去掉尾部斜杠后按字典序返回 (路径, 是否允许缺失) 二元组；⑨ProtectSystem 为 strict 时 /usr、/boot、/etc 受保护，ReadWritePaths 的例外必须落在受保护前缀内，否则报 SANDBOX_PATH_ESCAPE 并带上越界路径；⑩ProtectSystem 从 strict 改回 yes 后，之前 strict 下的路径例外要重新校验，不能让旧例外继续生效；⑪片段数、单文件指令数与合并后指令总数都有硬顶，超限报 SANDBOX_LIMIT_EXCEEDED，失败的文件整份不入库；⑫文件名非法报 SANDBOX_DROPIN_INVALID，同名片段后写覆盖前写而不是并存；⑬对非路径指令调用 resolve_paths 报 SANDBOX_NOT_PATH_DIRECTIVE，未知指令名报 SANDBOX_UNKNOWN_DIRECTIVE。

硬约束：多实例并发 merge 必须串行，来源表、冲突集和有效值不能互相污染，同一份输入任意时刻合并结果必须完全一致；快照保存主文件、片段与计数，恢复后 merge 结果与恢复前逐字段相等，非法快照整份拒绝且不污染现有状态；解析与合并全程不得改写调用方传入的文本对象。stats 至少返回 parses、dropins、merges、directives 四个计数。

验收：`python3 -m pytest -q tests` 的 15 条用例全过，测试不得修改、跳过或按固定输入写死；并发合并与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: unit_sandbox_merger
- typeName: UnitSandboxMerger
