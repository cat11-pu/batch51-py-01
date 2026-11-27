# batch51-py-safety-c-37

## 题面

版本升级后安全评审对不上账：同一份接口文档的两个分支，评审说鉴权从 OAuth 换成了更弱的组合，平台却显示无变化；新加的接口完全没写鉴权，扫描器按声明缺失回退到全局策略，报成已保护；参数侧同样混乱，枚举从两个值扩到三个、required 从必填改成可选，报告里都只记成一条参数变更，分不出高危还是提示。范围是 gsb/batch51-py-safety-c-37/api_schema_security_diff.py，类 ApiSchemaSecurityDiff，负责比较两份文档的安全语义并输出可复核的差异。

公开接口：ApiSchemaSecurityDiff(*, max_operations=500)；load_spec(doc, *, name="spec")；effective_security(spec, path, method)；diff_security(base, head)；diff_parameters(base, head)；classify(changes)；report(security_changes, parameter_changes)；snapshot()；restore(state)；stats()；模块级 normalize_path(path) 与 normalize_security(requirements)。异常统一 SchemaError(code, detail)。

要修的行为：①路径折叠重复斜杠、去掉尾斜杠、模板参数名归一为 {}，方法转小写，operation 以 (path, method) 为键；②文档超 1000000 字符、operation 超 500 个、结构不合法，分别报 SCHEMA_TOO_LARGE、SCHEMA_TOO_MANY_OPERATIONS、SCHEMA_INVALID，失败的加载不动 revision 与计数；③内部 $ref 要展开，外部引用报 SCHEMA_EXTERNAL_REF，成环报 SCHEMA_REF_CYCLE；④security 归一为备选元组，每个备选内的 scheme 名排序，operation 级 security 覆盖全局，缺失才继承全局，缺失时 Operation 的 security 字段为 None；⑤diff_security 只比较两侧共有以及 head 新增的 operation，未知的 path 与方法报 SCHEMA_OPERATION_UNKNOWN，鉴权被删除报 removed、新增未鉴权 operation 报 unauthenticated，两者严重度都是 high；⑥强度取各备选里 scheme 数的最小值，变小报 weakened（medium），变大报 strengthened（info），数量相同但集合不同报 replaced（medium）；⑦diff_parameters 按 (location, name) 匹配，location 就是文档里的 in，枚举新增值报 enum_widened（medium）、删值报 enum_narrowed（low），required 由真变假报 required_relaxed（high）、反向报 required_tightened（low），新增可选参数报 optional_added（low）、新增必填报 required_added（high）、删除参数报 parameter_removed（medium），类型从整数变成 string 报 type_loosened（medium）；⑧路径参数按模板位置匹配，只改了名字报 renamed（info），参数名写成原名->新名，不再额外报删除与新增；⑨classify 返回 high、medium、low、info 四个计数加 verdict，verdict 取出现的最高档，没有变更时记 none；⑩report 分 security 与 parameters 两段，各自给 total 与按变更类型排序的 by_change，末尾给总 verdict；⑪快照为 baseline、revision、operation_count、counters 四项，counters 含 loads、security_changes、parameter_changes，必须深拷贝，非法结构报 SCHEMA_SNAPSHOT_INVALID 且原状态一字不改。差异结果按 path、method、参数名、变更类型升序排列，同一对文档重复执行时顺序与内容完全一致。

另有两处容易漏：operation 的 security 写成空数组表示显式关闭鉴权，不能当成缺失而回退到全局要求；请求体 schema 通过 allOf 组合把 required 放宽时，要展开后再判定，不能只看顶层。同一路径挂在多个 servers 前缀下重复出现时，按 path 与 method 归一后只能产生一条差异。

硬约束：并发 diff 不共享可变状态，同一实例连续加载文档时计数按调用累加；快照恢复后基线与差异结论可往返，恢复失败不得污染现有结论；所有判定只依赖传入的文档内容，不读网络也不读本地文件。

Operation 含 path、method、security、parameters、template，template 是模板参数名按出现顺序的元组；Parameter 含 name、location、required、schema_type、enum，enum 缺省为空元组；SecurityChange 含 change、path、method、before、after、severity；ParameterChange 含 change、path、method、parameter、severity。

验收：python3 -m pytest -q tests 15 条全过；不得改测试、跳过、按固定输入写死；并发与快照恢复自行验证；只做本地实现。交付改好的源码与自测输出，说明每处改动的触发条件。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: api_schema_security_diff
- typeName: ApiSchemaSecurityDiff
