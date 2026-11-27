# batch51-py-safety-c-22

## 题面

游戏后端的安全组这周收到两起告警：玩家上传的自定义存档在反序列化时把进程直接带走了，日志里只剩一串 java 类型名，没人说得清是哪一步被接上的；另一起更麻烦，运营加完白名单之后，一份只有前半截的存档流被当成合法的空对象放过，把线上的存档覆盖了。范围是 gsb/batch51-py-safety-c-22 下的 deser_gadget_chain_scanner.py，类 DeserGadgetChainScanner，负责在真正反序列化之前判定流格式、把对象图走一遍，按来源与用途给类型分级，并量出危险链有多长。

流是四字节魔数加四字节大端长度再加正文：JSE1、PKL2、MPK1 分别对应 java-serial-v1、pickle-proto2、msgpack-map；正文第一行是 {"root": 对象编号}，之后每行一条 {"id": …, "type": …, "fields": {…}}，fields 的值要么是对象编号，要么是普通标量。

公开接口：DeserGadgetChainScanner(*, max_depth=8, allowlist=None)；register_type(type_name, *, origin, purpose)；revoke_type(type_name)；check_allowlist(type_name)；sniff_format(stream)；walk_objects(stream)；chain_depth(stream, start_id=None)；dangerous_starts(stream)；report(stream)；describe_object(stream, object_id)；snapshot()；restore(state)；stats()；reset()。origin 只取 local、vendor，purpose 只取 data、exec。拒绝时抛 DeserError(code, detail)。

要修的行为：① 魔数不认识抛 DESER_UNKNOWN_FORMAT，长度字段与实际正文对不上时按截断处理，不许当成空流；② 遍历按字段名升序深度优先，根对象算 1 层，walk_objects 返回的 visited 是访问顺序的元组，depth 是实际到达的最深层数；③ fields 里指向不存在对象的引用记为悬空，按出现顺序进 dangling，不中断遍历；④ 类型分级为：本地来源加数据用途 trusted，本地来源加执行用途与第三方来源加数据用途 reviewed，第三方来源加执行用途与未登记类型一律拒绝，check_allowlist 抛 DESER_TYPE_DENIED，detail 为类型名，第三方来源加执行用途连登记都拒绝；⑤ register_type 返回分级名，来源或用途超出取值范围抛 DESER_INVALID_ARGUMENT，revoke_type 返回是否真的撤销；⑥ 危险类型为 java.lang.Runtime、java.lang.ProcessBuilder、java.lang.reflect.Method、javax.naming.InitialContext、java.util.PriorityQueue，另外 java.lang.reflect. 前缀的反射入口也算链起点；⑦ dangerous_starts 返回按遍历顺序排列的元组；chain_depth 不给起点时在所有链起点里取最长，没有链起点记 0，给了起点则从该对象起算，层数按经过的对象个数计；⑧ report 汇总 format、objects（成功解析的对象记录数）、depth、chain_depth、starts、denied_types（去重后升序）、dangling、truncated、allowed，其中 starts、denied_types、dangling 都是列表，出现任一被拒类型时 allowed 为 False；⑨ 流在任意位置被截断时，已经解析出来的记录作为部分结果返回，truncated 记为 True，已解析记录照常进入 report；⑩ 同一对象被多处引用时按编号只遍历一次，成环的引用不得把遍历卡死；⑪ describe_object 给出该对象的类型、字段数、分级与是否链起点，编号不存在抛 DESER_UNKNOWN_OBJECT；⑫ 超过 max_depth 的深层结构只走到上限，剩余部分不再展开。

stats 返回 walks、objects、denied、restores 四个计数；reset 清计数与最近一次遍历结果，已登记的类型保留。

硬约束：同一实例被多个线程同时扫描时，计数与最近一次结果不得互相覆盖，同一条流要么完整给出结论要么完整拒绝；快照必须深拷贝，restore 后类型分级、限额与计数原样往返，结构不符抛 DESER_SNAPSHOT_INVALID 且原状态一字不动；对象访问次数以上限封顶，任何环引用与重复引用都不得让遍历规模超过流里的对象数。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过、按固定输入写死；并发与快照自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: deser_gadget_chain_scanner
- typeName: DeserGadgetChainScanner
- file: deser_gadget_chain_scanner.py
