# batch51-py-safety-c-21

## 题面

内容审核平台这两天接连出岔子：市场同事把供应商发来的商品描述文档丢进预览，服务进程内存一路涨到被内核杀掉；另一次预览页把内网一台机器上的配置文件原样贴了出来，运维才发现文档里写着一条指向内网地址的外部实体；值班后来补了白名单，同一个文档却时好时坏，谁也说不清到底拦没拦住。范围是 gsb/batch51-py-safety-c-21 下的 xxe_entity_guard.py，类 XxeEntityGuard，负责在真正解析之前把文档里的实体声明与引用摸清楚，按展开预算决定放行还是拒绝。

公开接口：XxeEntityGuard(*, max_depth=6, max_bytes=2048)；declare_namespace(namespace, *, prefix)；revoke_namespace(namespace)；block_external(namespace, *, allow=False)；inspect_dtd(document)；expand_budget(document)；parse_report(document)；describe_entity(name)；entity_names()；reference_count(name)；reset()；snapshot()；restore(state)；stats()。拒绝时抛 XxeError(code, detail)，code 为大写串。

文档是普通文本：可带 `<!DOCTYPE root SYSTEM "uri">`，可写 `<!ENTITY 名 "字面值">`、`<!ENTITY 名 SYSTEM "uri">`、`<!ENTITY % 名 "字面值">`，正文与属性值里用 `&名;` 引用；`<!-- -->` 与 `<? ?>` 属于原样片段。

要修的行为：① 空文档、纯空白文档、没有任何实体声明的文档一律抛 XXE_DTD_INVALID；② 同名实体重复声明抛 XXE_DTD_INVALID，detail 为 {"entity": 名}，整份文档不再继续扫描；③ inspect_dtd 返回 DtdInspection，declarations 只数实体声明（外部子集不算），internal、external、parameter 三个元组按声明顺序给出名字，external_subset 为外部子集标识或 None；④ 内部实体按字面值递归展开，expand_budget 返回 declared、per_entity、max_depth、references、expanded_bytes 五个字段，per_entity 给出每个实体展开后的字节数，无嵌套记 1 层，max_depth 记最深层数；⑤ 递归层数超过 max_depth 立即中止，expand_budget 抛 XXE_DEPTH_EXCEEDED，detail 为 {"entity": 触发实体名, "depth": 实际层数}；⑥ 展开累计字节超过 max_bytes 立即中止，抛 XXE_BUDGET_EXCEEDED，detail 为 {"entity": 触发实体名, "bytes": 累计值}；⑦ 引用未声明的实体抛 XXE_UNKNOWN_ENTITY，parse_report 则把 code 记为 XXE_UNKNOWN_ENTITY、trigger 记为该名字；⑧ 外部实体与外部子集默认阻断，parse_report 返回 accepted 为 False、code 为 XXE_EXTERNAL_BLOCKED，trigger 为引用的实体名（外部子集时为 None），external 按出现顺序列出本文档涉及的外部标识；⑨ 外部标识命中已登记命名空间且该命名空间被放行时正常通过，external 仍列出该标识，references 计 1 次，展开字节按 0 计，block_external 返回改动前的放行状态，登记表里没有的命名空间抛 XXE_UNKNOWN_NAMESPACE；⑩ 注释与处理指令里的 `&名;` 按原文保留，既不展开也不计入展开字节与引用次数；⑪ 同一实体被多处引用时按每次引用累计，不按定义去重，per_entity 仍是单份定义的大小；⑫ 实体字面值直接或间接引用自己抛 XXE_CYCLE，detail 为 {"entity": 名}。

parse_report 返回 accepted、code、trigger、references、expanded_bytes、external 六个字段，限制类问题不抛异常，只落在返回值里，便于批量过一遍文档。stats 返回 parses、accepted、rejected、blocked_external、restores 五个计数；reset 只清计数与最近一次报告，命名空间与放行策略保留。

硬约束：同一实例被多个线程同时喂文档时，计数与最近一次报告不得互相覆盖，一次判定要么完整放行要么完整拒绝；快照为深拷贝，restore 后命名空间、放行策略、限额与计数原样往返，结构不符抛 XXE_SNAPSHOT_INVALID 且原状态一字不动；内部实体展开是预算硬顶，任何引用路径都不得突破。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过、按固定输入写死；并发与快照自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: xxe_entity_guard
- typeName: XxeEntityGuard
- file: xxe_entity_guard.py
